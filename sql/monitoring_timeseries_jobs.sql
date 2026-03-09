/* Optional SQL Agent jobs (requires SQL Server Agent enabled). */
USE msdb;
GO

DECLARE @jobId UNIQUEIDENTIFIER;

IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'Monitoring Rollup Hourly')
BEGIN
    EXEC msdb.dbo.sp_add_job
        @job_name = N'Monitoring Rollup Hourly',
        @enabled = 1,
        @description = N'Build hourly/daily monitoring rollups from raw monitoring_metrics.',
        @job_id = @jobId OUTPUT;

    EXEC msdb.dbo.sp_add_jobstep
        @job_name = N'Monitoring Rollup Hourly',
        @step_name = N'BuildRollups',
        @subsystem = N'TSQL',
        @database_name = N'Shzari',
        @command = N'EXEC dbo.sp_monitoring_build_rollups @from_utc = DATEADD(HOUR, -6, SYSUTCDATETIME());';

    EXEC msdb.dbo.sp_add_schedule
        @schedule_name = N'Monitoring Rollup Every 15 Min',
        @freq_type = 4,
        @freq_interval = 1,
        @freq_subday_type = 4,
        @freq_subday_interval = 15,
        @active_start_time = 000000;

    EXEC msdb.dbo.sp_attach_schedule
        @job_name = N'Monitoring Rollup Hourly',
        @schedule_name = N'Monitoring Rollup Every 15 Min';

    EXEC msdb.dbo.sp_add_jobserver
        @job_name = N'Monitoring Rollup Hourly';
END;
GO

IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'Monitoring Retention Daily')
BEGIN
    EXEC msdb.dbo.sp_add_job
        @job_name = N'Monitoring Retention Daily',
        @enabled = 1,
        @description = N'Cleanup old monitoring raw and rollup data by retention policy.';

    EXEC msdb.dbo.sp_add_jobstep
        @job_name = N'Monitoring Retention Daily',
        @step_name = N'CleanupRetention',
        @subsystem = N'TSQL',
        @database_name = N'Shzari',
        @command = N'EXEC dbo.sp_monitoring_retention_cleanup @raw_days = 18250, @hourly_days = 18250, @daily_days = 36500;';

    EXEC msdb.dbo.sp_add_schedule
        @schedule_name = N'Monitoring Retention Daily 02AM',
        @freq_type = 4,
        @freq_interval = 1,
        @active_start_time = 020000;

    EXEC msdb.dbo.sp_attach_schedule
        @job_name = N'Monitoring Retention Daily',
        @schedule_name = N'Monitoring Retention Daily 02AM';

    EXEC msdb.dbo.sp_add_jobserver
        @job_name = N'Monitoring Retention Daily';
END;
GO

/* Ensure existing job uses current retention policy values. */
IF EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'Monitoring Retention Daily')
BEGIN
    EXEC msdb.dbo.sp_update_jobstep
        @job_name = N'Monitoring Retention Daily',
        @step_id = 1,
        @command = N'EXEC dbo.sp_monitoring_retention_cleanup @raw_days = 18250, @hourly_days = 18250, @daily_days = 36500;';
END;
GO
