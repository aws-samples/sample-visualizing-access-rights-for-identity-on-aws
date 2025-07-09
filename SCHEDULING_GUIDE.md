# ARIA-gv Scheduling Guide

## Overview

The ARIA-gv solution now supports optional automatic scheduling for both core components:

1. **Data Collection Scheduling**: Automatically runs the `AriaStateMachine` to collect fresh identity data from AWS IAM Identity Center
2. **Graph Export Scheduling**: Automatically runs the `AriaExportGraphStateMachine` to refresh your Neptune Analytics graph with the latest data

This two-tier scheduling approach allows you to optimize data freshness while managing costs effectively.

## Scheduling Parameters

### Data Collection Scheduling (AriaStateMachine)

Configure automatic data collection from AWS IAM Identity Center:

#### EnableDataCollectionScheduling
- **Type**: String
- **Default**: `false`
- **Values**: `true` | `false`
- **Description**: Enable or disable automatic scheduling of identity data collection

#### DataCollectionScheduleExpression
- **Type**: String
- **Default**: `rate(6 hours)`
- **Description**: Schedule expression for data collection frequency
- **Examples**:
  - `rate(6 hours)` - Collect data every 6 hours
  - `rate(1 day)` - Collect data once per day
  - `cron(0 */4 * * ? *)` - Collect data every 4 hours

#### DataCollectionScheduleDescription
- **Type**: String
- **Default**: `Automated ARIA identity data collection every 6 hours`
- **Description**: Human-readable description for the scheduled data collection

#### DataCollectionScheduleTimezone
- **Type**: String
- **Default**: `UTC`
- **Description**: Timezone for cron-based schedules

### Graph Export Scheduling (AriaExportGraphStateMachine)

Configure automatic Neptune Analytics graph updates. The graph export now uses a **dual-trigger approach**:

1. **Event-Driven Trigger**: Automatically executes after data collection completes successfully
2. **Time-Based Schedule**: Independent execution based on your schedule (optional backup/additional runs)

### EnableScheduling
- **Type**: String
- **Default**: `false`
- **Values**: `true` | `false`
- **Description**: Enable or disable automatic scheduling of the graph export/import process

### ScheduleExpression
- **Type**: String
- **Default**: `rate(1 day)`
- **Description**: Schedule expression defining when to execute the state machine
- **Examples**:
  - `rate(1 day)` - Execute once per day
  - `rate(12 hours)` - Execute every 12 hours
  - `rate(1 week)` - Execute once per week
  - `cron(0 2 * * ? *)` - Execute daily at 2:00 AM UTC
  - `cron(0 9 ? * MON-FRI *)` - Execute weekdays at 9:00 AM UTC

### ScheduleDescription
- **Type**: String
- **Default**: `Daily execution of ARIA graph export and import`
- **Description**: Human-readable description for the scheduled execution

### ScheduleTimezone
- **Type**: String
- **Default**: `UTC`
- **Description**: Timezone for cron-based schedules
- **Examples**: `America/New_York`, `Europe/London`, `Asia/Tokyo`, `UTC`

## Schedule Expression Formats

### Rate Expressions
Rate expressions execute at regular intervals:
- `rate(value unit)`
- Units: `minute`, `minutes`, `hour`, `hours`, `day`, `days`
- Examples:
  - `rate(30 minutes)` - Every 30 minutes
  - `rate(2 hours)` - Every 2 hours
  - `rate(1 day)` - Every day

### Cron Expressions
Cron expressions provide more precise scheduling:
- Format: `cron(minute hour day-of-month month day-of-week year)`
- Examples:
  - `cron(0 2 * * ? *)` - Daily at 2:00 AM
  - `cron(0 9 ? * MON-FRI *)` - Weekdays at 9:00 AM
  - `cron(0 0 1 * ? *)` - First day of every month at midnight

## Deployment Examples

### Enable Both Data Collection and Graph Export Scheduling
```bash
aws cloudformation deploy \
  --template-file templates/main-stack.yaml \
  --stack-name aria-gv-setup \
  --parameter-overrides \
    EnableDataCollectionScheduling=true \
    DataCollectionScheduleExpression="rate(6 hours)" \
    EnableScheduling=true \
    ScheduleExpression="rate(1 day)" \
  --capabilities CAPABILITY_IAM
```

### Enable Only Data Collection Scheduling
```bash
aws cloudformation deploy \
  --template-file templates/main-stack.yaml \
  --stack-name aria-gv-setup \
  --parameter-overrides \
    EnableDataCollectionScheduling=true \
    DataCollectionScheduleExpression="rate(4 hours)" \
    EnableScheduling=false \
  --capabilities CAPABILITY_IAM
```

### Enable Daily Graph Export Scheduling
```bash
aws cloudformation deploy \
  --template-file templates/main-stack.yaml \
  --stack-name aria-gv-setup \
  --parameter-overrides \
    EnableScheduling=true \
    ScheduleExpression="rate(1 day)" \
    ScheduleDescription="Daily ARIA graph refresh" \
  --capabilities CAPABILITY_IAM
```

### Enable Business Hours Data Collection
```bash
aws cloudformation deploy \
  --template-file templates/main-stack.yaml \
  --stack-name aria-gv-setup \
  --parameter-overrides \
    EnableDataCollectionScheduling=true \
    DataCollectionScheduleExpression="cron(0 9 ? * MON-FRI *)" \
    DataCollectionScheduleDescription="Business hours ARIA data collection" \
    DataCollectionScheduleTimezone="America/New_York" \
  --capabilities CAPABILITY_IAM
```

### Disable All Scheduling
```bash
aws cloudformation deploy \
  --template-file templates/main-stack.yaml \
  --stack-name aria-gv-setup \
  --parameter-overrides \
    EnableDataCollectionScheduling=false \
    EnableScheduling=false \
  --capabilities CAPABILITY_IAM
```

## Execution Flow

### Automatic Execution Chain (When Both Scheduling Options Enabled)

1. **Data Collection**: AriaStateMachine runs on schedule (e.g., every 6 hours)
2. **Automatic Trigger**: Upon successful completion, EventBridge automatically triggers AriaExportGraphStateMachine
3. **Graph Update**: Neptune Analytics graph is refreshed with the latest data
4. **Independent Schedule**: AriaExportGraphStateMachine also runs on its own schedule as a backup

### Benefits of This Approach

✅ **Always Fresh Data**: Graph export always uses the most recently collected data  
✅ **Automatic Chaining**: No manual intervention required  
✅ **Fault Tolerance**: Independent schedule provides backup execution  
✅ **Cost Efficiency**: Graph export only runs when there's new data to process  
✅ **Flexible Timing**: Can still run graph export independently if needed  

## Architecture Components

When scheduling is enabled, the following resources are created:

### Data Collection Scheduling
- **AriaDataCollectionSchedule**: EventBridge Scheduler for data collection
- **AriaDataCollectionScheduleRole**: IAM role for the data collection scheduler

### Graph Export Triggering
- **AriaExportGraphTriggerRule**: EventBridge Rule that triggers after data collection completes
- **AriaExportGraphTriggerRole**: IAM role for the EventBridge trigger
- **AriaExportGraphSchedule**: Optional independent scheduler for graph export
- **AriaExportGraphScheduleRole**: IAM role for the independent scheduler

### Monitoring & Error Handling
- **AriaDataCollectionScheduleDLQ**: Dead Letter Queue for failed data collection executions
- **AriaExportGraphTriggerDLQ**: Dead Letter Queue for failed event-triggered executions
- **AriaExportGraphScheduleDLQ**: Dead Letter Queue for failed scheduled executions
- **Multiple Log Groups**: CloudWatch logs for comprehensive monitoring

## Monitoring Scheduled Executions

### CloudWatch Metrics
Monitor your scheduled executions using CloudWatch:
- Navigate to CloudWatch → Metrics → AWS/Scheduler
- View metrics for successful/failed executions

### Step Functions Console
- Navigate to Step Functions console
- View execution history for `AriaExportGraphStateMachine`
- Monitor execution status and duration

### Dead Letter Queue
Failed executions are sent to the DLQ:
```bash
# Check for failed executions
aws sqs get-queue-attributes \
  --queue-url https://sqs.region.amazonaws.com/account/stack-name-AriaExportGraphSchedule-DLQ \
  --attribute-names ApproximateNumberOfMessages
```

## Cost Considerations

### Scheduling Costs
- EventBridge Scheduler: $1.00 per million invocations
- Step Functions: $0.025 per 1,000 state transitions
- Lambda: Based on execution time and memory

### Optimization Tips
1. **Choose appropriate frequency**: Don't schedule more frequently than your data changes
2. **Monitor execution duration**: Optimize Lambda functions for faster execution
3. **Use business hours scheduling**: Avoid unnecessary weekend/holiday executions

## Troubleshooting

### Common Issues

#### Schedule Not Triggering
1. Check if `EnableScheduling` is set to `true`
2. Verify the schedule expression syntax
3. Check IAM permissions for the scheduler role

#### State Machine Failures
1. Check Step Functions execution logs
2. Verify Lambda function permissions
3. Check DynamoDB table accessibility

#### Timezone Issues
1. Ensure timezone is valid (e.g., `America/New_York`)
2. Remember that rate expressions ignore timezone
3. Use cron expressions for timezone-specific scheduling

### Useful Commands

```bash
# List all schedules
aws scheduler list-schedules

# Get schedule details
aws scheduler get-schedule --name stack-name-AriaExportGraphSchedule

# Manually trigger the state machine
aws stepfunctions start-execution \
  --state-machine-arn arn:aws:states:region:account:stateMachine:AriaExportGraphStateMachine

# Check recent executions
aws stepfunctions list-executions \
  --state-machine-arn arn:aws:states:region:account:stateMachine:AriaExportGraphStateMachine \
  --max-items 10
```

## Best Practices

1. **Start with manual execution**: Test the state machine manually before enabling scheduling
2. **Use appropriate frequency**: Match schedule frequency to your data change rate
3. **Monitor costs**: Track execution costs and optimize as needed
4. **Set up alerts**: Create CloudWatch alarms for failed executions
5. **Document your schedule**: Use descriptive schedule descriptions
6. **Test timezone settings**: Verify cron expressions work as expected in your timezone

## Security Considerations

- The scheduler role has minimal permissions (only `states:StartExecution`)
- Failed executions are logged but don't expose sensitive data
- All resources follow least-privilege access principles
- Dead letter queue messages are retained for 14 days maximum