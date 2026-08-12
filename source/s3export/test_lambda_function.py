"""Unit tests for the s3export graph-projection Lambda, focused on the
Account Access Manager (AAM) additions.

The export helper ``export_dynamodb_to_s3`` builds its DynamoDB resource and S3
client *inside the call* (``boto3.resource('dynamodb')`` / ``boto3.client('s3')``)
and writes each CSV via ``s3.put_object(Bucket=..., Key=..., Body=csv_data)``
where ``csv_data`` is a string whose first line is the ``csv_headers`` row. The
tests therefore replace ``lambda_function.boto3`` with an in-memory fake that
records every ``put_object`` body, then parse those bodies back into rows.

moto is not used - the same rationale as the collection Lambda's tests: plain
fakes give exact control over scanned items and let us assert on the literal CSV
bytes that would be uploaded, with no AWS calls or credentials.

Requirement coverage:
  4.1 AAM roles emitted as RoleName nodes keyed by role ARN
  4.2 AAM role node carries a ``source:String`` property (AccountAccessManager)
  4.3 ASSIGNED_ROLE edge (~from = PrincipalId, ~to = IamRoleArn) headers
  4.5 empty AAM table => none of the three AAM CSVs written (has-items guard)
  (4.4 context) EXISTS_IN role->account edge headers + dedup on (IamRoleArn, AccountId)
"""

import csv
import io

import pytest

import lambda_function


# ---------------------------------------------------------------------------
# In-memory fakes for boto3's DynamoDB resource and S3 client
# ---------------------------------------------------------------------------

class FakeTable:
    """Minimal in-memory DynamoDB table.

    ``scan()`` returns ``{'Items': [...]}`` for the export path and
    ``{'Count': n}`` when ``Select='COUNT'`` for the has-items guard.
    """

    def __init__(self, name, items=None):
        self.name = name
        self.items = list(items or [])

    def scan(self, **kwargs):
        if kwargs.get('Select') == 'COUNT':
            return {'Count': len(self.items)}
        return {'Items': [dict(i) for i in self.items]}


class FakeDynamoDBResource:
    """Serves FakeTables by name, defaulting unknown names to empty tables so
    ``lambda_handler`` can run end-to-end without a KeyError."""

    def __init__(self, tables=None):
        self._tables = dict(tables or {})

    def Table(self, name):
        if name not in self._tables:
            self._tables[name] = FakeTable(name, [])
        return self._tables[name]


class FakeS3Client:
    """Records delete_object and put_object calls; put bodies are the CSVs."""

    def __init__(self):
        self.puts = {}       # key -> Body string
        self.deletes = []    # list of keys

    def delete_object(self, Bucket, Key):
        self.deletes.append(Key)

    def put_object(self, Bucket, Key, Body):
        self.puts[Key] = Body


class FakeBoto3:
    """Stand-in for the ``boto3`` module used inside lambda_function."""

    def __init__(self, dynamodb_resource, s3_client):
        self._dynamodb_resource = dynamodb_resource
        self._s3_client = s3_client

    def resource(self, service_name):
        assert service_name == 'dynamodb'
        return self._dynamodb_resource

    def client(self, service_name):
        assert service_name == 's3'
        return self._s3_client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_csv(body):
    """Parse an uploaded CSV body into (header_row, list_of_data_rows)."""
    rows = list(csv.reader(io.StringIO(body)))
    return rows[0], rows[1:]


def _install(monkeypatch, tables, s3=None):
    """Patch lambda_function.boto3 with fakes; return the FakeS3Client."""
    s3 = s3 or FakeS3Client()
    monkeypatch.setattr(
        lambda_function, 'boto3',
        FakeBoto3(FakeDynamoDBResource(tables), s3))
    return s3


# Representative AAM table rows. user-1 has two roles; role-a is entitled to two
# principals (user-1 and group-1); account 111... is shared by role-a and role-c.
ROLE_A = 'arn:aws:iam::111111111111:role/team/Analyst'
ROLE_B = 'arn:aws:iam::222222222222:role/Admin'
ROLE_C = 'arn:aws:iam::111111111111:role/ReadOnly'


def _aam_items():
    return [
        {'PrincipalId': 'user-1', 'IamRoleArn': ROLE_A, 'PrincipalType': 'USER',
         'PrincipalName': 'Alice', 'RoleName': 'Analyst', 'AccountId': '111111111111',
         'Source': 'AccountAccessManager'},
        {'PrincipalId': 'user-1', 'IamRoleArn': ROLE_B, 'PrincipalType': 'USER',
         'PrincipalName': 'Alice', 'RoleName': 'Admin', 'AccountId': '222222222222',
         'Source': 'AccountAccessManager'},
        {'PrincipalId': 'group-1', 'IamRoleArn': ROLE_A, 'PrincipalType': 'GROUP',
         'PrincipalName': 'Engineers', 'RoleName': 'Analyst', 'AccountId': '111111111111',
         'Source': 'AccountAccessManager'},
        {'PrincipalId': 'group-1', 'IamRoleArn': ROLE_C, 'PrincipalType': 'GROUP',
         'PrincipalName': 'Engineers', 'RoleName': 'ReadOnly', 'AccountId': '111111111111',
         'Source': 'AccountAccessManager'},
    ]


# Exact projection parameters the handler uses for each AAM CSV, so the direct
# export tests exercise the same headers/dedup the production code passes.
ROLE_NODE_KEY = 'AriaIdCAccountAccessRoles.csv'
ASSIGNED_ROLE_KEY = 'AriaIdCAccountAccess_Principal_Role_Edge.csv'
EXISTS_IN_KEY = 'AriaIdCAccountAccessRole_Account_Edge.csv'


def _export_role_node(s3_bucket='bucket'):
    return lambda_function.export_dynamodb_to_s3(
        'AriaIdCAccountAccessAssignments', s3_bucket, ROLE_NODE_KEY,
        ['IamRoleArn', 'AccountId', 'RoleName', 'Source', 'Label'],
        ['~id', 'accountid:String', 'rolename:String', 'source:String', '~label'],
        label='RoleName', dedup_fields=['IamRoleArn'])


def _export_assigned_role(s3_bucket='bucket'):
    return lambda_function.export_dynamodb_to_s3(
        'AriaIdCAccountAccessAssignments', s3_bucket, ASSIGNED_ROLE_KEY,
        ['UniqueId', 'PrincipalId', 'IamRoleArn', 'Label'],
        ['~id', '~from', '~to', '~label'],
        generate_uuid=True, label='ASSIGNED_ROLE',
        dedup_fields=['PrincipalId', 'IamRoleArn'])


def _export_exists_in(s3_bucket='bucket'):
    return lambda_function.export_dynamodb_to_s3(
        'AriaIdCAccountAccessAssignments', s3_bucket, EXISTS_IN_KEY,
        ['UniqueId', 'IamRoleArn', 'AccountId', 'Label'],
        ['~id', '~from', '~to', '~label'],
        generate_uuid=True, label='EXISTS_IN',
        dedup_fields=['IamRoleArn', 'AccountId'])


# ---------------------------------------------------------------------------
# Requirement 4.1 / 4.2 - RoleName node CSV: headers, dedup on IamRoleArn,
# source property
# ---------------------------------------------------------------------------

def test_role_node_csv_has_expected_headers(monkeypatch):
    s3 = _install(monkeypatch, {
        'AriaIdCAccountAccessAssignments': FakeTable('t', _aam_items())})

    _export_role_node()

    header, _ = _parse_csv(s3.puts[ROLE_NODE_KEY])
    assert header == ['~id', 'accountid:String', 'rolename:String',
                      'source:String', '~label']


def test_role_node_csv_dedupes_on_role_arn(monkeypatch):
    s3 = _install(monkeypatch, {
        'AriaIdCAccountAccessAssignments': FakeTable('t', _aam_items())})

    _export_role_node()

    _, rows = _parse_csv(s3.puts[ROLE_NODE_KEY])
    ids = [r[0] for r in rows]
    # Three distinct role ARNs (role-a appears twice in the table -> once here).
    assert sorted(ids) == sorted([ROLE_A, ROLE_B, ROLE_C])
    assert len(ids) == len(set(ids))


def test_role_node_csv_id_is_role_arn_and_source_is_aam(monkeypatch):
    s3 = _install(monkeypatch, {
        'AriaIdCAccountAccessAssignments': FakeTable('t', _aam_items())})

    _export_role_node()

    header, rows = _parse_csv(s3.puts[ROLE_NODE_KEY])
    by_id = {r[0]: dict(zip(header, r)) for r in rows}
    analyst = by_id[ROLE_A]
    assert analyst['accountid:String'] == '111111111111'
    assert analyst['rolename:String'] == 'Analyst'
    assert analyst['source:String'] == 'AccountAccessManager'
    # ~label is the constant node label, not per-item data.
    assert analyst['~label'] == 'RoleName'


# ---------------------------------------------------------------------------
# Requirement 4.3 - ASSIGNED_ROLE edge CSV: headers + from/to mapping
# ---------------------------------------------------------------------------

def test_assigned_role_edge_has_expected_headers(monkeypatch):
    s3 = _install(monkeypatch, {
        'AriaIdCAccountAccessAssignments': FakeTable('t', _aam_items())})

    _export_assigned_role()

    header, _ = _parse_csv(s3.puts[ASSIGNED_ROLE_KEY])
    assert header == ['~id', '~from', '~to', '~label']


def test_assigned_role_edge_maps_from_principal_to_role(monkeypatch):
    s3 = _install(monkeypatch, {
        'AriaIdCAccountAccessAssignments': FakeTable('t', _aam_items())})

    _export_assigned_role()

    header, rows = _parse_csv(s3.puts[ASSIGNED_ROLE_KEY])
    # ~from = PrincipalId, ~to = IamRoleArn, ~label = ASSIGNED_ROLE
    edges = {(r[1], r[2]) for r in rows}
    assert edges == {
        ('user-1', ROLE_A),
        ('user-1', ROLE_B),
        ('group-1', ROLE_A),
        ('group-1', ROLE_C),
    }
    assert {r[3] for r in rows} == {'ASSIGNED_ROLE'}
    # Every edge has a generated ~id (UUID), none blank.
    assert all(r[0] for r in rows)


def test_assigned_role_edge_dedupes_on_principal_and_role(monkeypatch):
    # Duplicate (user-1, ROLE_A) rows must collapse to a single edge.
    items = _aam_items() + [
        {'PrincipalId': 'user-1', 'IamRoleArn': ROLE_A, 'PrincipalType': 'USER',
         'PrincipalName': 'Alice', 'RoleName': 'Analyst', 'AccountId': '111111111111',
         'Source': 'AccountAccessManager'},
    ]
    s3 = _install(monkeypatch, {
        'AriaIdCAccountAccessAssignments': FakeTable('t', items)})

    _export_assigned_role()

    _, rows = _parse_csv(s3.puts[ASSIGNED_ROLE_KEY])
    pairs = [(r[1], r[2]) for r in rows]
    assert len(pairs) == 4
    assert len(pairs) == len(set(pairs))


# ---------------------------------------------------------------------------
# Requirement 4.4 (context) - EXISTS_IN edge CSV: headers + dedup on
# (IamRoleArn, AccountId)
# ---------------------------------------------------------------------------

def test_exists_in_edge_has_expected_headers(monkeypatch):
    s3 = _install(monkeypatch, {
        'AriaIdCAccountAccessAssignments': FakeTable('t', _aam_items())})

    _export_exists_in()

    header, _ = _parse_csv(s3.puts[EXISTS_IN_KEY])
    assert header == ['~id', '~from', '~to', '~label']


def test_exists_in_edge_maps_role_to_account_and_dedupes(monkeypatch):
    s3 = _install(monkeypatch, {
        'AriaIdCAccountAccessAssignments': FakeTable('t', _aam_items())})

    _export_exists_in()

    header, rows = _parse_csv(s3.puts[EXISTS_IN_KEY])
    # ~from = IamRoleArn, ~to = AccountId. role-a appears for both user-1 and
    # group-1 in the same account 111... -> a single (role-a, 111...) edge.
    edges = {(r[1], r[2]) for r in rows}
    assert edges == {
        (ROLE_A, '111111111111'),
        (ROLE_B, '222222222222'),
        (ROLE_C, '111111111111'),
    }
    assert {r[3] for r in rows} == {'EXISTS_IN'}
    pairs = [(r[1], r[2]) for r in rows]
    assert len(pairs) == len(set(pairs))  # deduped


# ---------------------------------------------------------------------------
# export_dynamodb_to_s3 general behaviour
# ---------------------------------------------------------------------------

def test_export_skips_put_when_table_empty(monkeypatch):
    s3 = _install(monkeypatch, {
        'AriaIdCAccountAccessAssignments': FakeTable('t', [])})

    _export_role_node()

    # Empty scan -> delete_object still issued, but no CSV written.
    assert ROLE_NODE_KEY not in s3.puts
    assert ROLE_NODE_KEY in s3.deletes


# ---------------------------------------------------------------------------
# Requirement 4.5 - has-items guard / empty-table skip
# ---------------------------------------------------------------------------

def test_check_table_has_items_false_when_empty(monkeypatch):
    _install(monkeypatch, {
        'AriaIdCAccountAccessAssignments': FakeTable('t', [])})
    assert lambda_function.check_table_has_items(
        'AriaIdCAccountAccessAssignments') is False


def test_check_table_has_items_true_when_populated(monkeypatch):
    _install(monkeypatch, {
        'AriaIdCAccountAccessAssignments': FakeTable('t', _aam_items())})
    assert lambda_function.check_table_has_items(
        'AriaIdCAccountAccessAssignments') is True


def test_handler_skips_all_three_aam_csvs_when_table_empty(monkeypatch):
    # Every table (including AAM) is empty -> the has-items guard is False, so
    # none of the three AAM CSVs may be written.
    s3 = _install(monkeypatch, {
        'AriaIdCAccountAccessAssignments': FakeTable('t', [])})

    result = lambda_function.lambda_handler({'s3bucket': 'bucket'}, None)

    assert result['statusCode'] == 200
    for key in (ROLE_NODE_KEY, ASSIGNED_ROLE_KEY, EXISTS_IN_KEY):
        assert key not in s3.puts


def test_handler_writes_all_three_aam_csvs_when_table_populated(monkeypatch):
    # Only the AAM table has items; the guard passes and all three AAM CSVs are
    # written. Other (empty) tables are skipped by convert_to_csv's empty check.
    s3 = _install(monkeypatch, {
        'AriaIdCAccountAccessAssignments': FakeTable('t', _aam_items())})

    result = lambda_function.lambda_handler({'s3bucket': 'bucket'}, None)

    assert result['statusCode'] == 200
    for key in (ROLE_NODE_KEY, ASSIGNED_ROLE_KEY, EXISTS_IN_KEY):
        assert key in s3.puts
