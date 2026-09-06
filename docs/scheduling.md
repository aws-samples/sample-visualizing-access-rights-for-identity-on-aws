# Scheduling

[← Back to README](../README.md)

ARIA-gv supports **intelligent automatic scheduling** with event-driven
execution chaining:

1. **Data collection** - runs `AriaStateMachine` to collect fresh identity data.
2. **Automatic graph export** - when data collection completes successfully, `AriaExportGraphStateMachine` triggers automatically to refresh your Neptune Analytics graph.
3. **Independent scheduling** - optional time-based scheduling for additional graph export runs.
4. **Access Analyzer polling** - `AriaAccessAnalyzerStateMachine` polls IAM Access Analyzer findings on its own independent schedule, so findings can be refreshed much more frequently than the rest of the identity data.

This keeps your Neptune graph reflecting current data while optimizing cost and execution efficiency.

> For full configuration detail, see the [Scheduling Guide](../SCHEDULING_GUIDE.md).

## Scheduling options

### Data collection (`AriaStateMachine`)

- **Frequent updates**: `rate(6 hours)` - collect data every 6 hours
- **Daily updates**: `rate(1 day)` - collect data once per day
- **Business hours**: `cron(0 9 ? * MON-FRI *)` - collect at 9 AM on weekdays

### Graph export (`AriaExportGraphStateMachine`)

- **Daily export**: `rate(1 day)` - update the graph daily
- **Weekly export**: `rate(1 week)` - update the graph weekly
- **End of business**: `cron(0 18 ? * MON-FRI *)` - update at 6 PM on weekdays

### Access Analyzer polling (`AriaAccessAnalyzerStateMachine`)

Runs independently of `AriaStateMachine`, so it can be scheduled much more
frequently without re-running the full identity data collection each time.

- **Frequent updates**: `rate(15 minutes)` - dispatch unused role work every 15 minutes (default)
- **Hourly updates**: `rate(1 hour)` - dispatch unused role work once per hour
- **Business hours**: `cron(0/15 9-17 ? * MON-FRI *)` - dispatch every 15 minutes during business hours

The state machine starts the unused IAM-role dispatcher in parallel with the
retained internal/external polling loops. The dispatcher uses server-side
Access Analyzer filters and the current Identity Center/AAM role scope, then
places changed summaries on an SQS work queue. A single worker consumes that
queue at `unusedRoleWorkerRequestsPerSecond`, making the configured rate a
strict global detail-fetch limit. The worker DLQ is distinct from the scheduler
DLQ: the scheduler DLQ captures failed schedule deliveries, while the worker
DLQ retains individual finding messages that exhaust processing retries.

## Deployment script presets

| Preset                             | Behavior                                        |
| ---------------------------------- | ----------------------------------------------- |
| `daily-collection-and-export`      | Daily data collection and graph export          |
| `frequent-collection-daily-export` | 6-hour data collection, daily graph export      |
| `business-hours`                   | 9 AM data collection, 6 PM graph export (EST)   |
| `disabled`                         | All scheduling disabled (manual execution only) |

Example:

```bash
./deploy-nested-stacks.sh --scheduling-preset frequent-collection-daily-export
```

## Features

- **Event-driven execution** - graph export triggers automatically after data collection completes
- **Intelligent chaining** - the graph always uses the freshest data
- **Dual-trigger system** - event-driven plus optional time-based scheduling
- **Independent Access Analyzer polling** - `AriaAccessAnalyzerStateMachine` runs on its own schedule, so findings can be refreshed far more often than the full identity data collection
- **Flexible scheduling** - rate-based or cron-based expressions
- **Timezone support** - configure schedules for your local timezone
- **Error handling** - dead letter queues for failed executions
- **Monitoring** - CloudWatch logs and metrics
- **Cost optimization** - graph export runs only when there is new data
- **Validation** - built-in parameter validation and configuration summary

> **Note:** consider how often to run scheduled updates to keep data fresh while managing costs. Frequent scheduling increases Lambda and Step Functions costs.
