"""IaC/policy-wiring checks for the AriaIdCIAMUsers managed-policy consolidation.

Task 6.1: run cfn-lint on the affected templates and assert the two managed-policy
edits in templates/lambda-functions.yaml plus the wildcard-coverage and Step
Functions sequencing invariants.

Requirements: 7.2, 9.5, 9.6, 9.7, 9.8

Environment notes
-----------------
- PyYAML / pytest / boto3 may not be installed here, so this uses the stdlib
  ``unittest`` runner and a text/regex scan of the templates - mirroring
  tests/test_deploy_wiring.py.
- cfn-lint is run as a subprocess when it is on PATH; the test is skipped (not
  failed) when cfn-lint is unavailable so the wiring assertions still run.

Run with:
    python3 -m unittest tests/test_iam_users_policy_wiring.py
"""

import os
import re
import shutil
import subprocess
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LAMBDA_TEMPLATE = os.path.join(REPO_ROOT, "templates", "lambda-functions.yaml")
MAIN_TEMPLATE = os.path.join(REPO_ROOT, "templates", "main-stack.yaml")
STEP_FUNCTIONS_TEMPLATE = os.path.join(REPO_ROOT, "templates", "step-functions.yaml")

AFFECTED_TEMPLATES = [LAMBDA_TEMPLATE, MAIN_TEMPLATE, STEP_FUNCTIONS_TEMPLATE]

# Step names used to assert sequencing.
GET_IAM_ROLES_TASK = "List IAM Roles created by IAM Identity Center"  # GetIAMRoles
GET_TRUST_TASK = "Collect IAM Role Trust Policies"                     # GetTrustPolicies


def _read(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _managed_policy_block(text, resource_name):
    """Return the text of a top-level managed-policy resource block.

    Slices from the resource's declaration (two-space indent) to the next
    two-space-indented resource declaration, so per-policy assertions do not
    leak into a neighbouring policy.
    """
    start = re.search(r"(?m)^\s{2}%s:\s*$" % re.escape(resource_name), text)
    if start is None:
        raise AssertionError("resource %s not found in lambda-functions.yaml" % resource_name)
    rest = text[start.end():]
    nxt = re.search(r"(?m)^\s{2}\S", rest)
    return rest[: nxt.start()] if nxt else rest


DYNAMODB_ARN = 'arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/%s'


class GetIAMRolesPolicyTest(unittest.TestCase):
    """Req 9.7: GetIAMRoles lists AriaIdCIAMUsers in its explicit write resources."""

    def setUp(self):
        self.block = _managed_policy_block(_read(LAMBDA_TEMPLATE), "GetIAMRolesManagedPolicy")

    def test_lists_users_table_explicitly(self):
        self.assertIn(
            DYNAMODB_ARN % "AriaIdCIAMUsers",
            self.block,
            "GetIAMRolesManagedPolicy must list an explicit AriaIdCIAMUsers table ARN "
            "in its DynamoDB write resource list",
        )

    def test_retains_existing_explicit_resources(self):
        for table in ("AriaIdCIAMRoles", "AriaIdCProvisionedPermissionSets", "AriaIdCAccounts"):
            self.assertIn(
                DYNAMODB_ARN % table,
                self.block,
                "GetIAMRolesManagedPolicy must keep its explicit %s ARN" % table,
            )

    def test_uses_explicit_list_not_wildcard(self):
        # This policy enumerates resources explicitly; it must not silently rely on
        # an AriaIdC* wildcard for its DynamoDB writes.
        self.assertNotIn(
            DYNAMODB_ARN % "AriaIdC*",
            self.block,
            "GetIAMRolesManagedPolicy is expected to enumerate tables explicitly, "
            "not via the AriaIdC* wildcard",
        )


class WildcardCoverageTest(unittest.TestCase):
    """Req 9.5, 9.6: CreateTables + S3Export stay on the AriaIdC* wildcard.

    They must NOT gain an explicit AriaIdCIAMUsers ARN - the wildcard covers it.
    """

    def setUp(self):
        self.text = _read(LAMBDA_TEMPLATE)

    def test_createtables_scopes_to_wildcard(self):
        block = _managed_policy_block(self.text, "CreateTablesManagedPolicy")
        self.assertIn(
            DYNAMODB_ARN % "AriaIdC*",
            block,
            "CreateTablesManagedPolicy must scope DynamoDB actions to the AriaIdC* wildcard",
        )
        self.assertNotIn(
            DYNAMODB_ARN % "AriaIdCIAMUsers",
            block,
            "CreateTablesManagedPolicy must NOT add an explicit AriaIdCIAMUsers ARN "
            "(the AriaIdC* wildcard already covers it)",
        )

    def test_s3export_scopes_to_wildcard(self):
        block = _managed_policy_block(self.text, "S3ExportManagedPolicy")
        self.assertIn(
            DYNAMODB_ARN % "AriaIdC*",
            block,
            "S3ExportManagedPolicy must scope DynamoDB actions to the AriaIdC* wildcard",
        )
        self.assertNotIn(
            DYNAMODB_ARN % "AriaIdCIAMUsers",
            block,
            "S3ExportManagedPolicy must NOT add an explicit AriaIdCIAMUsers ARN "
            "(the AriaIdC* wildcard already covers it)",
        )


class GetTrustPoliciesNarrowedTest(unittest.TestCase):
    """Req 9.8: GetTrustPolicies is narrowed to a DynamoDB-only transform."""

    def setUp(self):
        self.block = _managed_policy_block(_read(LAMBDA_TEMPLATE), "GetTrustPoliciesManagedPolicy")

    def test_no_cross_account_assume_role(self):
        self.assertNotIn(
            "sts:AssumeRole",
            self.block,
            "GetTrustPoliciesManagedPolicy must no longer grant sts:AssumeRole",
        )

    def test_no_organizations_list_accounts(self):
        self.assertNotIn(
            "organizations:ListAccounts",
            self.block,
            "GetTrustPoliciesManagedPolicy must no longer grant organizations:ListAccounts",
        )

    def test_drops_accounts_table(self):
        self.assertNotIn(
            DYNAMODB_ARN % "AriaIdCAccounts",
            self.block,
            "GetTrustPoliciesManagedPolicy must no longer scan AriaIdCAccounts",
        )

    def test_drops_account_access_assignments_table(self):
        self.assertNotIn(
            DYNAMODB_ARN % "AriaIdCAccountAccessAssignments",
            self.block,
            "GetTrustPoliciesManagedPolicy must no longer scan AriaIdCAccountAccessAssignments",
        )

    def test_keeps_iam_roles_read(self):
        self.assertIn(
            DYNAMODB_ARN % "AriaIdCIAMRoles",
            self.block,
            "GetTrustPoliciesManagedPolicy must keep AriaIdCIAMRoles read access",
        )

    def test_keeps_trust_policies_read_write(self):
        self.assertIn(
            DYNAMODB_ARN % "AriaIdCRoleTrustPolicies",
            self.block,
            "GetTrustPoliciesManagedPolicy must keep AriaIdCRoleTrustPolicies read/write access",
        )

    def test_keeps_s3_and_logs(self):
        self.assertIn("s3:GetObject", self.block,
                      "GetTrustPoliciesManagedPolicy must keep s3:GetObject")
        self.assertIn("logs:PutLogEvents", self.block,
                      "GetTrustPoliciesManagedPolicy must keep the logs statements")

    def test_removes_unused_suppressions(self):
        # The W11 / CKV_AWS_107 suppressions only justified the dropped
        # organizations / sts statements, so they must be gone.
        self.assertNotIn("W11", self.block,
                         "GetTrustPoliciesManagedPolicy must drop the unused W11 cfn_nag suppression")
        self.assertNotIn("CKV_AWS_107", self.block,
                         "GetTrustPoliciesManagedPolicy must drop the unused CKV_AWS_107 checkov skip")


class StepFunctionsSequencingTest(unittest.TestCase):
    """Req 7.2: Step Functions still sequences GetIAMRoles -> GetTrustPolicies."""

    def setUp(self):
        self.text = _read(STEP_FUNCTIONS_TEMPLATE)

    def test_both_tasks_present(self):
        self.assertIn("%s:" % GET_IAM_ROLES_TASK, self.text)
        self.assertIn("%s:" % GET_TRUST_TASK, self.text)

    def test_get_iam_roles_precedes_and_nexts_into_trust(self):
        roles_pos = self.text.index("%s:" % GET_IAM_ROLES_TASK)
        trust_pos = self.text.index("%s:" % GET_TRUST_TASK)
        self.assertLess(
            roles_pos, trust_pos,
            "the GetTrustPolicies task must be defined after the GetIAMRoles task",
        )
        segment = self.text[roles_pos:trust_pos]
        self.assertRegex(
            segment,
            r"Next:\s*%s" % re.escape(GET_TRUST_TASK),
            "the GetIAMRoles task must Next into '%s'" % GET_TRUST_TASK,
        )


class CfnLintTest(unittest.TestCase):
    """Run cfn-lint on the affected templates when it is available."""

    def test_cfn_lint_affected_templates(self):
        cfn_lint = shutil.which("cfn-lint")
        if cfn_lint is None:
            self.skipTest("cfn-lint is not installed; skipping lint of affected templates")
        result = subprocess.run(
            [cfn_lint] + AFFECTED_TEMPLATES,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            0,
            result.returncode,
            "cfn-lint reported problems in the affected templates:\n%s\n%s"
            % (result.stdout, result.stderr),
        )


if __name__ == "__main__":
    unittest.main()
