"""Queued processing for active unused IAM-role Access Analyzer findings.

The dispatcher lists only tracked, active ``UnusedIAMRole`` findings and
publishes changed summaries to SQS. A single-concurrency SQS worker then
retrieves full details at a fixed RPS, preserving a strict account-wide rate
limit without a distributed token bucket.
"""

import json
import os
import time
import uuid

import boto3
from botocore.exceptions import ClientError

from lambda_function import (
    BOTO_CONFIG,
    _is_throttling_error,
    _iso,
    _scan_all,
    dynamodb,
    fetch_finding_detail,
    get_delegated_admin_client,
    is_tracked_role,
    parse_unusedaccess_finding,
    to_legacy_detail,
    unused_scope_filter,
)

UNUSED_ACCESS_ANALYZER_ARN = os.environ["UNUSED_ACCESS_ANALYZER_ARN"]
UNUSED_WORK_QUEUE_URL = os.environ["UNUSED_ROLE_WORK_QUEUE_URL"]
UNUSED_WORK_STATE_TABLE = os.environ["UNUSED_ROLE_WORK_STATE_TABLE"]
UNUSED_WORKER_RPS = float(os.environ.get("UNUSED_ROLE_WORKER_RPS", "0.5"))
UNUSED_WORKER_DELAY_SECONDS = 1.0 / UNUSED_WORKER_RPS
DISPATCH_LEASE_SECONDS = int(os.environ.get("UNUSED_ROLE_DISPATCH_LEASE_SECONDS", "900"))

if UNUSED_WORKER_RPS <= 0:
    raise ValueError("UNUSED_ROLE_WORKER_RPS must be greater than zero")
if DISPATCH_LEASE_SECONDS <= 0:
    raise ValueError("UNUSED_ROLE_DISPATCH_LEASE_SECONDS must be greater than zero")

sqs = boto3.client("sqs", config=BOTO_CONFIG)

_WORK_LEASE_KEY = "LEASE#unused-role-dispatcher"
_FINDING_KEY_PREFIX = "FINDING#"


def _current_account_id(context):
    """Return the Lambda account ID from the invocation ARN."""
    return context.invoked_function_arn.split(":")[4]


def _finding_work_key(finding_id):
    return f"{_FINDING_KEY_PREFIX}{finding_id}"


def _is_conditional_check_failure(error):
    return error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"


def _acquire_dispatch_lease(state_table, owner_id):
    """Acquire the dispatcher lease unless another invocation still owns it."""
    now = int(time.time())
    try:
        state_table.update_item(
            Key={"WorkKey": _WORK_LEASE_KEY},
            UpdateExpression=(
                "SET OwnerId = :owner, LeaseExpiresAt = :expires, UpdatedAt = :now"
            ),
            ConditionExpression=(
                "attribute_not_exists(WorkKey) OR LeaseExpiresAt < :now"
            ),
            ExpressionAttributeValues={
                ":owner": owner_id,
                ":expires": now + DISPATCH_LEASE_SECONDS,
                ":now": now,
            },
        )
        return True
    except ClientError as error:
        if _is_conditional_check_failure(error):
            return False
        raise


def _renew_dispatch_lease(state_table, owner_id):
    """Renew a held lease while paginating a large unused-role result set."""
    now = int(time.time())
    state_table.update_item(
        Key={"WorkKey": _WORK_LEASE_KEY},
        UpdateExpression="SET LeaseExpiresAt = :expires, UpdatedAt = :now",
        ConditionExpression="OwnerId = :owner",
        ExpressionAttributeValues={
            ":owner": owner_id,
            ":expires": now + DISPATCH_LEASE_SECONDS,
            ":now": now,
        },
    )


def _release_dispatch_lease(state_table, owner_id):
    """Mark a completed dispatch and release only the lease owned by this run."""
    state_table.update_item(
        Key={"WorkKey": _WORK_LEASE_KEY},
        UpdateExpression=(
            "SET LastCompletedAt = :now, UpdatedAt = :now "
            "REMOVE OwnerId, LeaseExpiresAt"
        ),
        ConditionExpression="OwnerId = :owner",
        ExpressionAttributeValues={":owner": owner_id, ":now": int(time.time())},
    )


def _checkpoint_versions(state_table_name, finding_ids):
    """Return the last enqueued version for up to one paginator page of IDs."""
    versions = {}
    pending_keys = [
        {"WorkKey": _finding_work_key(finding_id)} for finding_id in finding_ids
    ]
    client = dynamodb.meta.client

    while pending_keys:
        request_items = {
            state_table_name: {
                "Keys": pending_keys[:100],
                "ProjectionExpression": "WorkKey, LastEnqueuedUpdatedAt",
            }
        }
        pending_keys = pending_keys[100:]
        response = client.batch_get_item(RequestItems=request_items)
        for item in response.get("Responses", {}).get(state_table_name, []):
            versions[item["WorkKey"]] = item.get("LastEnqueuedUpdatedAt")

        unprocessed = response.get("UnprocessedKeys", {}).get(state_table_name, {})
        retry_keys = unprocessed.get("Keys", [])
        while retry_keys:
            time.sleep(0.2)
            retry_response = client.batch_get_item(
                RequestItems={state_table_name: {"Keys": retry_keys}}
            )
            for item in retry_response.get("Responses", {}).get(state_table_name, []):
                versions[item["WorkKey"]] = item.get("LastEnqueuedUpdatedAt")
            retry_keys = retry_response.get("UnprocessedKeys", {}).get(
                state_table_name, {}
            ).get("Keys", [])

    return versions


def _record_enqueued_version(state_table, finding_id, updated_at):
    """Persist an enqueue checkpoint only after SQS accepted the message."""
    state_table.update_item(
        Key={"WorkKey": _finding_work_key(finding_id)},
        UpdateExpression=(
            "SET LastEnqueuedUpdatedAt = :updated_at, LastEnqueuedAt = :now, "
            "UpdatedAt = :now"
        ),
        ExpressionAttributeValues={
            ":updated_at": updated_at,
            ":now": int(time.time()),
        },
    )


def _send_work_batch(state_table, messages):
    """Queue up to ten messages and checkpoint only the accepted entries."""
    entries = [
        {
            "Id": str(index),
            "MessageBody": json.dumps(message, separators=(",", ":")),
        }
        for index, message in enumerate(messages)
    ]
    response = sqs.send_message_batch(QueueUrl=UNUSED_WORK_QUEUE_URL, Entries=entries)
    failed_ids = {entry["Id"] for entry in response.get("Failed", [])}

    for index, message in enumerate(messages):
        if str(index) not in failed_ids:
            _record_enqueued_version(
                state_table,
                message["findingId"],
                message["summaryUpdatedAt"],
            )

    if failed_ids:
        failures = ", ".join(sorted(failed_ids))
        raise RuntimeError(f"SQS rejected unused-role work item(s): {failures}")


def _queue_changed_summaries(state_table, summaries, cycle_id):
    """Enqueue tracked summaries whose version has not already been queued."""
    if not summaries:
        return 0, 0

    checkpoint_versions = _checkpoint_versions(
        UNUSED_WORK_STATE_TABLE,
        [summary["id"] for summary in summaries],
    )
    changed = [
        summary
        for summary in summaries
        if checkpoint_versions.get(_finding_work_key(summary["id"]))
        != _iso(summary.get("updatedAt"))
    ]

    for start in range(0, len(changed), 10):
        batch = []
        for summary in changed[start : start + 10]:
            batch.append(
                {
                    "schemaVersion": 1,
                    "analyzerArn": UNUSED_ACCESS_ANALYZER_ARN,
                    "findingId": summary["id"],
                    "summaryUpdatedAt": _iso(summary.get("updatedAt")),
                    "resourceArn": summary.get("resource", ""),
                    "cycleId": cycle_id,
                }
            )
        _send_work_batch(state_table, batch)

    return len(changed), len(summaries) - len(changed)


def _delete_stale_unused_rows(unused_findings_table, active_ids):
    """Delete rows that are no longer active tracked unused-role findings."""
    existing_items = _scan_all(unused_findings_table, ProjectionExpression="FindingId")
    stale_ids = {
        item["FindingId"] for item in existing_items if item["FindingId"] not in active_ids
    }
    if not stale_ids:
        return 0

    with unused_findings_table.batch_writer() as batch:
        for finding_id in stale_ids:
            batch.delete_item(Key={"FindingId": finding_id})
    return len(stale_ids)


def unused_role_dispatcher_handler(event, context):
    """List and queue changed active tracked unused IAM-role finding summaries.

    A conditional lease prevents frequent EventBridge schedules from listing and
    enqueuing the same backlog concurrently. Detail retrieval is deliberately
    deferred to the single-concurrency SQS worker.
    """
    state_table = dynamodb.Table(UNUSED_WORK_STATE_TABLE)
    unused_findings_table = dynamodb.Table("AriaIdCUnusedAAFindings")
    owner_id = str(uuid.uuid4())

    if not _acquire_dispatch_lease(state_table, owner_id):
        print("unused_role_dispatcher: lease held; skipping overlapping run")
        return {
            "statusCode": 200,
            "body": {"lease_acquired": False, "queued": 0, "deleted": 0},
        }

    completed = False
    try:
        client = get_delegated_admin_client(_current_account_id(context))
        paginator = client.get_paginator("list_findings_v2")
        active_ids = set()
        queued = 0
        already_queued = 0
        matched = 0
        page_count = 0
        cycle_id = str(uuid.uuid4())

        for page in paginator.paginate(
            analyzerArn=UNUSED_ACCESS_ANALYZER_ARN,
            filter={
                "status": {"eq": ["ACTIVE"]},
                "findingType": {"eq": ["UnusedIAMRole"]},
                "resourceType": {"eq": ["AWS::IAM::Role"]},
            },
        ):
            page_count += 1
            tracked_summaries = [
                summary
                for summary in page.get("findings", [])
                if is_tracked_role(summary.get("resource", ""))
            ]
            matched += len(tracked_summaries)
            active_ids.update(summary["id"] for summary in tracked_summaries)
            page_queued, page_already_queued = _queue_changed_summaries(
                state_table, tracked_summaries, cycle_id
            )
            queued += page_queued
            already_queued += page_already_queued
            _renew_dispatch_lease(state_table, owner_id)

        deleted = _delete_stale_unused_rows(unused_findings_table, active_ids)
        completed = True
        print(
            "unused_role_dispatcher: "
            f"{matched} tracked role finding(s) across {page_count} page(s), "
            f"queued={queued}, already_queued={already_queued}, deleted={deleted}"
        )
        return {
            "statusCode": 200,
            "body": {
                "lease_acquired": True,
                "queued": queued,
                "already_queued": already_queued,
                "deleted": deleted,
                "matched": matched,
            },
        }
    finally:
        if completed:
            _release_dispatch_lease(state_table, owner_id)


def _output_is_current(unused_findings_table, finding_id, summary_updated_at):
    response = unused_findings_table.get_item(
        Key={"FindingId": finding_id}, ProjectionExpression="UpdatedAt"
    )
    return response.get("Item", {}).get("UpdatedAt") == summary_updated_at


def _process_work_record(client, unused_findings_table, record):
    """Process one SQS record and return a concise outcome for logging."""
    message = json.loads(record["body"])
    finding_id = message["findingId"]
    summary_updated_at = message["summaryUpdatedAt"]

    if message.get("schemaVersion") != 1:
        raise ValueError(f"Unsupported unused-role work schema for {finding_id}")
    if message.get("analyzerArn") != UNUSED_ACCESS_ANALYZER_ARN:
        raise ValueError(f"Unexpected analyzer ARN for {finding_id}")
    if _output_is_current(unused_findings_table, finding_id, summary_updated_at):
        return "already_current"

    time.sleep(UNUSED_WORKER_DELAY_SECONDS)
    finding_v2, _ = fetch_finding_detail(client, UNUSED_ACCESS_ANALYZER_ARN, finding_id)

    if (
        finding_v2.get("status") != "ACTIVE"
        or finding_v2.get("findingType") != "UnusedIAMRole"
        or finding_v2.get("resourceType") != "AWS::IAM::Role"
    ):
        unused_findings_table.delete_item(Key={"FindingId": finding_id})
        return "no_longer_eligible"

    detail = to_legacy_detail("unused", finding_v2)
    if "error" in detail or not unused_scope_filter(detail):
        unused_findings_table.delete_item(Key={"FindingId": finding_id})
        return "out_of_scope"

    parse_unusedaccess_finding({"detail": detail}, unused_findings_table)
    return "upserted"


def unused_role_detail_worker_handler(event, context):
    """Drain queued unused-role work serially and report partial batch failures."""
    client = get_delegated_admin_client(_current_account_id(context))
    unused_findings_table = dynamodb.Table("AriaIdCUnusedAAFindings")
    failures = []
    outcomes = {"upserted": 0, "already_current": 0, "no_longer_eligible": 0, "out_of_scope": 0}

    for record in event.get("Records", []):
        try:
            outcome = _process_work_record(client, unused_findings_table, record)
            outcomes[outcome] += 1
        except ClientError as error:
            message_id = record.get("messageId", "unknown")
            if _is_throttling_error(error):
                print(f"unused_role_worker: throttled processing SQS message {message_id}: {error}")
            else:
                print(f"unused_role_worker: API error processing SQS message {message_id}: {error}")
            failures.append({"itemIdentifier": message_id})
        except Exception as error:
            message_id = record.get("messageId", "unknown")
            print(f"unused_role_worker: failed processing SQS message {message_id}: {error}")
            failures.append({"itemIdentifier": message_id})

    print(
        "unused_role_worker: "
        f"upserted={outcomes['upserted']} already_current={outcomes['already_current']} "
        f"no_longer_eligible={outcomes['no_longer_eligible']} "
        f"out_of_scope={outcomes['out_of_scope']} failures={len(failures)}"
    )
    return {"batchItemFailures": failures}
