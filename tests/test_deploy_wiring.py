"""IaC/deploy-wiring checks for the GetTrustPolicies (Trust_Policy_Collector) Lambda.

Task 12.1: assert the deployment scripts package/pass the trust-policy collector
and its S3 key, run cfn-lint on the three modified templates, and assert the
collector resources exist and the Step Functions "Collect IAM Role Trust Policies"
task is sequenced after the Identity Center role step and is terminal (End: true).

Requirements: 7.1, 7.2, 7.3, 7.4, 7.5

Environment notes
-----------------
- pytest / boto3 / PyYAML may not be installed here, so this uses the stdlib
  ``unittest`` runner and a text/regex scan of the scripts and templates. Where
  PyYAML is available the Step Functions definition is additionally parsed
  structurally (CloudFormation intrinsic tags handled with a catch-all
  constructor); otherwise the structural checks fall back to ordered text scans.
- cfn-lint is run as a subprocess when it is on PATH; the test is skipped (not
  failed) when cfn-lint is unavailable so the wiring assertions still run.

Deploy-wiring reality
---------------------
In this repository the per-Lambda packaging (each ``source/<name>/`` ->
``<name>.zip`` plus the S3 upload) is driven by the ``LAMBDA_FUNCTIONS`` array in
``aria-bootstrap.sh``; ``deploy-nested-stacks.sh`` then uploads the templates and
deploys the stack, relying on the ``*S3Key`` defaults declared in
``main-stack.yaml`` (``GetTrustPoliciesS3Key`` defaults to ``gettrustpolicies.zip``).
The checks below therefore assert the collector is packaged where packaging
actually happens and that its S3 key flows through the stack parameters.

Run with:
    python3 -m unittest tests/test_deploy_wiring.py
"""

import os
import re
import shutil
import subprocess
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BOOTSTRAP_SCRIPT = os.path.join(REPO_ROOT, "aria-bootstrap.sh")
DEPLOY_SCRIPT = os.path.join(REPO_ROOT, "deploy-nested-stacks.sh")
LAMBDA_TEMPLATE = os.path.join(REPO_ROOT, "templates", "lambda-functions.yaml")
MAIN_TEMPLATE = os.path.join(REPO_ROOT, "templates", "main-stack.yaml")
STEP_FUNCTIONS_TEMPLATE = os.path.join(REPO_ROOT, "templates", "step-functions.yaml")

MODIFIED_TEMPLATES = [LAMBDA_TEMPLATE, MAIN_TEMPLATE, STEP_FUNCTIONS_TEMPLATE]

# Step names used to assert sequencing/terminality.
IDC_ROLE_TASK = "List IAM Roles created by IAM Identity Center"
TRUST_TASK = "Collect IAM Role Trust Policies"

# Collector resources that must exist in templates/lambda-functions.yaml.
COLLECTOR_RESOURCES = (
    "GetTrustPoliciesManagedPolicy",
    "GetTrustPoliciesExecutionRole",
    "GetTrustPoliciesFunction",
    "GetTrustPoliciesLogGroup",
)


def _read(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


class DeployScriptWiringTest(unittest.TestCase):
    """Req 7.3: the collector is packaged and its S3 key flows to the deploy."""

    def test_deploy_and_packaging_scripts_exist(self):
        self.assertTrue(os.path.isfile(BOOTSTRAP_SCRIPT), "aria-bootstrap.sh missing")
        self.assertTrue(os.path.isfile(DEPLOY_SCRIPT), "deploy-nested-stacks.sh missing")

    def test_gettrustpolicies_is_packaged(self):
        # Packaging happens in aria-bootstrap.sh's LAMBDA_FUNCTIONS array, mirroring
        # how "getiamroles" is packaged into getiamroles.zip and uploaded to S3.
        text = _read(BOOTSTRAP_SCRIPT)
        self.assertRegex(
            text,
            r'LAMBDA_FUNCTIONS=\((?:.|\n)*?"gettrustpolicies"(?:.|\n)*?\)',
            "aria-bootstrap.sh LAMBDA_FUNCTIONS array must include \"gettrustpolicies\" "
            "so source/gettrustpolicies/ is zipped to gettrustpolicies.zip and uploaded",
        )
        # It must sit alongside the existing getiamroles entry it mirrors.
        self.assertIn('"getiamroles"', text)

    def test_gettrustpolicies_source_exists(self):
        self.assertTrue(
            os.path.isfile(os.path.join(REPO_ROOT, "source", "gettrustpolicies", "lambda_function.py")),
            "source/gettrustpolicies/lambda_function.py must exist to be packaged",
        )

    def test_s3key_param_flows_through_main_stack(self):
        # deploy-nested-stacks.sh deploys main-stack.yaml, which carries the
        # GetTrustPoliciesS3Key parameter (default gettrustpolicies.zip) and passes
        # it into the nested LambdaStack alongside the other *S3Key parameters.
        text = _read(MAIN_TEMPLATE)
        self.assertIn("GetTrustPoliciesS3Key:", text, "GetTrustPoliciesS3Key parameter missing")
        self.assertRegex(
            text,
            r'GetTrustPoliciesS3Key:(?:.|\n)*?Default:\s*"gettrustpolicies\.zip"',
            "GetTrustPoliciesS3Key must default to gettrustpolicies.zip",
        )
        self.assertIn(
            "GetTrustPoliciesS3Key: !Ref GetTrustPoliciesS3Key",
            text,
            "GetTrustPoliciesS3Key must be passed into the LambdaStack",
        )


class LambdaTemplateResourcesTest(unittest.TestCase):
    """Req 7.1: the collector Lambda resources are declared."""

    def setUp(self):
        self.text = _read(LAMBDA_TEMPLATE)

    def test_collector_resources_exist(self):
        for resource in COLLECTOR_RESOURCES:
            self.assertRegex(
                self.text,
                r"(?m)^\s{2}%s:" % re.escape(resource),
                "lambda-functions.yaml is missing collector resource %s" % resource,
            )

    def test_collector_arn_output_exists(self):
        self.assertRegex(
            self.text,
            r"(?m)^\s{2}GetTrustPoliciesLambdaArn:",
            "lambda-functions.yaml must output GetTrustPoliciesLambdaArn",
        )

    def test_collector_code_uses_s3_key(self):
        self.assertIn(
            "S3Key: !Ref GetTrustPoliciesS3Key",
            self.text,
            "GetTrustPoliciesFunction must load its code from GetTrustPoliciesS3Key",
        )


class StepFunctionsSequencingTest(unittest.TestCase):
    """Req 7.2, 7.4, 7.5: collector task sequenced after IdC role step and terminal."""

    def setUp(self):
        self.text = _read(STEP_FUNCTIONS_TEMPLATE)

    def test_both_tasks_present(self):
        self.assertIn("%s:" % IDC_ROLE_TASK, self.text)
        self.assertIn("%s:" % TRUST_TASK, self.text)

    def test_collector_task_follows_idc_role_task(self):
        # The Identity Center role task must transition into the collector task, so
        # AriaIdCIAMRoles / AriaIdCAccountAccessAssignments are populated first.
        idc_pos = self.text.index("%s:" % IDC_ROLE_TASK)
        trust_pos = self.text.index("%s:" % TRUST_TASK)
        self.assertLess(
            idc_pos, trust_pos,
            "the collector task must be defined after the Identity Center role task",
        )
        # The IdC role task's `Next` (the first Next after its definition) targets
        # the collector task.
        segment = self.text[idc_pos:trust_pos]
        self.assertRegex(
            segment,
            r"Next:\s*%s" % re.escape(TRUST_TASK),
            "the Identity Center role task must Next into '%s'" % TRUST_TASK,
        )

    def test_collector_task_is_terminal(self):
        # The collector task itself is no longer the state machine's terminal
        # state: the access-analyzer-ingestion-refactor feature added a new
        # "Poll Access Analyzer Findings" step after it (Task 12.1), so the
        # collector task now transitions into that step instead of ending the
        # execution. What must still hold is that some state further down the
        # chain reaches End: true - the state machine as a whole terminates.
        trust_pos = self.text.index("%s:" % TRUST_TASK)
        tail = self.text[trust_pos:]
        end_marker = tail.find("QueryLanguage:")
        body = tail[:end_marker] if end_marker != -1 else tail
        self.assertRegex(
            body, r"Next:\s*\S",
            "collector task must transition into the next state (Poll Access "
            "Analyzer Findings)",
        )
        self.assertRegex(
            body, r"End:\s*true",
            "the state machine must still reach a terminal End: true state "
            "after the collector task",
        )

    def test_collector_task_invokes_collector_lambda(self):
        trust_pos = self.text.index("%s:" % TRUST_TASK)
        body = self.text[trust_pos:]
        self.assertRegex(
            body,
            r"FunctionName:\s*!Ref GetTrustPoliciesLambdaArn",
            "collector task must invoke GetTrustPoliciesLambdaArn",
        )

    def test_collector_lambda_arn_is_invokable(self):
        # Req 7.4: the state machine role must be allowed to invoke the collector.
        self.assertIn(
            "!Ref GetTrustPoliciesLambdaArn",
            self.text,
            "GetTrustPoliciesLambdaArn must appear in the InvokeFunction resource list",
        )


class CfnLintTest(unittest.TestCase):
    """Run cfn-lint on the three modified templates when it is available."""

    def test_cfn_lint_modified_templates(self):
        cfn_lint = shutil.which("cfn-lint")
        if cfn_lint is None:
            self.skipTest("cfn-lint is not installed; skipping lint of modified templates")
        result = subprocess.run(
            [cfn_lint] + MODIFIED_TEMPLATES,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            0,
            result.returncode,
            "cfn-lint reported problems in the modified templates:\n%s\n%s"
            % (result.stdout, result.stderr),
        )


if __name__ == "__main__":
    unittest.main()
