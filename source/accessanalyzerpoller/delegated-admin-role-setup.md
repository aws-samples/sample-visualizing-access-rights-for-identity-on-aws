### Creating cross-account IAM Access Analyzer roles

The IAM Access Analyzer analyzers used by ARIA-gv can live in an account that
is different from the account where ARIA-gv is deployed. In that case, deploy
`aria-access-analyzer-poller-role.yaml` into the IAM Access Analyzer delegated
administrator account.

The template creates three least-privilege roles:

| Role                               | Used by                    | Access Analyzer permission                                          |
| ---------------------------------- | -------------------------- | ------------------------------------------------------------------- |
| `AriaAccessAnalyzerPollerRole`     | Internal/external poller   | `ListFindings`, `GetFinding` on the internal and external analyzers |
| `AriaAccessAnalyzerDispatcherRole` | Unused IAM-role dispatcher | `ListFindings` on the unused-access analyzer only                   |
| `AriaAccessAnalyzerWorkerRole`     | Unused IAM-role SQS worker | `GetFinding` on the unused-access analyzer only                     |

The dispatcher lists only active `UnusedIAMRole` findings with an
`AWS::IAM::Role` resource and queues changed tracked-role summaries. The worker
retrieves details at the configured strict global RPS. Separating the
cross-account roles prevents either component from receiving the other
component's Access Analyzer permission.

> This guide applies only when the IAM Access Analyzer delegated administrator
> is a different account from the ARIA-gv deployment account. In a same-account
> deployment, the three Lambda execution roles call Access Analyzer directly
> with their own scoped permissions and do not assume these roles.

#### Prerequisites

The delegated administrator account must already contain these
organization-scoped analyzers:

| Finding family  | Analyzer type                  |
| --------------- | ------------------------------ |
| Internal access | `ORGANIZATION_INTERNAL_ACCESS` |
| External access | `ORGANIZATION`                 |
| Unused access   | `ORGANIZATION_UNUSED_ACCESS`   |

Deploy the main ARIA-gv stack first, then obtain these stack outputs:

- `AccessAnalyzerPollerLambdaFunctionExecutionRoleArn`
- `AccessAnalyzerUnusedDispatcherLambdaFunctionExecutionRoleArn`
- `AccessAnalyzerUnusedWorkerLambdaFunctionExecutionRoleArn`

#### Deploy the roles

Run this command with credentials for the IAM Access Analyzer delegated
administrator account:

```bash
aws cloudformation deploy \
  --template-file aria-access-analyzer-poller-role.yaml \
  --stack-name aria-access-analyzer-poller-roles \
  --parameter-overrides \
    TrustedAccountId=<aria-gv-account-id> \
    AccessAnalyzerPollerLambdaExecutionRoleArn=<poller-role-arn> \
    AccessAnalyzerUnusedDispatcherLambdaExecutionRoleArn=<dispatcher-role-arn> \
    AccessAnalyzerUnusedWorkerLambdaExecutionRoleArn=<worker-role-arn> \
    InternalAccessAnalyzerArn=<internal-analyzer-arn> \
    ExternalAccessAnalyzerArn=<external-analyzer-arn> \
    UnusedAccessAnalyzerArn=<unused-analyzer-arn> \
  --capabilities CAPABILITY_NAMED_IAM
```

If you changed any role-name defaults in `config.yaml`, pass the matching
parameters to this template too:

```bash
RoleName=<accessAnalyzerPollerRoleName> \
DispatcherRoleName=<accessAnalyzerDispatcherRoleName> \
WorkerRoleName=<accessAnalyzerWorkerRoleName>
```

After the delegated-account stack completes, deploy or update the main
ARIA-gv stack with the same role names. The dispatcher and worker then assume
their dedicated roles automatically.
