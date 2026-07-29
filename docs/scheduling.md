# Scheduling

[← Back to README](../README.md)

ARIA-gv supports **intelligent automatic scheduling** with event-driven
execution chaining:

1. **Data collection** - runs `AriaStateMachine` to collect fresh identity data.
2. **Automatic graph export** - when data collection completes successfully, `AriaExportGraphStateMachine` triggers automatically to refresh your Neptune Analytics graph.
3. **Independent scheduling** - optional time-based scheduling for additional graph export runs.

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
- **Flexible scheduling** - rate-based or cron-based expressions
- **Timezone support** - configure schedules for your local timezone
- **Error handling** - dead letter queues for failed executions
- **Monitoring** - CloudWatch logs and metrics
- **Cost optimization** - graph export runs only when there is new data
- **Validation** - built-in parameter validation and configuration summary

> **Note:** consider how often to run scheduled updates to keep data fresh while managing costs. Frequent scheduling increases Lambda and Step Functions costs.
