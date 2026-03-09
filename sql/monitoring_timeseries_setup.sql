SET NOCOUNT ON;
SET XACT_ABORT ON;

BEGIN TRY
    BEGIN TRAN;

    /* 1) Normalize time on existing monitoring_metrics (current app writes collected_at as NVARCHAR). */
    IF COL_LENGTH('dbo.monitoring_metrics', 'collected_at_utc') IS NULL
    BEGIN
        ALTER TABLE dbo.monitoring_metrics
            ADD collected_at_utc DATETIME2(0) NULL;
    END;

    UPDATE m
    SET collected_at_utc = COALESCE(
        TRY_CONVERT(DATETIME2(0), m.collected_at, 126),
        TRY_CONVERT(DATETIME2(0), m.collected_at, 120),
        TRY_CONVERT(DATETIME2(0), m.collected_at),
        SYSUTCDATETIME()
    )
    FROM dbo.monitoring_metrics AS m
    WHERE m.collected_at_utc IS NULL;

    IF OBJECT_ID('dbo.trg_monitoring_metrics_set_collected_at_utc', 'TR') IS NULL
    EXEC ('
    CREATE TRIGGER dbo.trg_monitoring_metrics_set_collected_at_utc
    ON dbo.monitoring_metrics
    AFTER INSERT
    AS
    BEGIN
        SET NOCOUNT ON;
        UPDATE m
        SET m.collected_at_utc = COALESCE(
            TRY_CONVERT(DATETIME2(0), i.collected_at, 126),
            TRY_CONVERT(DATETIME2(0), i.collected_at, 120),
            TRY_CONVERT(DATETIME2(0), i.collected_at),
            SYSUTCDATETIME()
        )
        FROM dbo.monitoring_metrics AS m
        INNER JOIN inserted AS i ON i.id = m.id
        WHERE m.collected_at_utc IS NULL;
    END
    ');

    /* 2) Time-series table for per-interface polling samples. */
    IF OBJECT_ID('dbo.monitoring_interface_metrics', 'U') IS NULL
    BEGIN
        CREATE TABLE dbo.monitoring_interface_metrics (
            id BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
            device_name NVARCHAR(255) NOT NULL,
            host NVARCHAR(64) NULL,
            interface_name NVARCHAR(128) NOT NULL,
            interface_description NVARCHAR(255) NULL,
            oper_status NVARCHAR(32) NULL,
            tx_percent FLOAT NULL,
            rx_percent FLOAT NULL,
            speed_bps BIGINT NULL,
            in_errors BIGINT NULL,
            out_errors BIGINT NULL,
            details_json NVARCHAR(MAX) NULL,
            collected_at_utc DATETIME2(0) NOT NULL CONSTRAINT DF_monitoring_interface_metrics_collected_at_utc DEFAULT SYSUTCDATETIME()
        );
    END;

    /* 3) Rollup tables for fast long-range charts. */
    IF OBJECT_ID('dbo.monitoring_rollup_hourly', 'U') IS NULL
    BEGIN
        CREATE TABLE dbo.monitoring_rollup_hourly (
            device_name NVARCHAR(255) NOT NULL,
            bucket_start_utc DATETIME2(0) NOT NULL,
            sample_count INT NOT NULL,
            up_samples INT NOT NULL,
            down_samples INT NOT NULL,
            availability_pct DECIMAL(6,3) NULL,
            cpu_avg FLOAT NULL,
            cpu_min FLOAT NULL,
            cpu_max FLOAT NULL,
            memory_avg FLOAT NULL,
            memory_min FLOAT NULL,
            memory_max FLOAT NULL,
            sla_avg_ms FLOAT NULL,
            sla_min_ms FLOAT NULL,
            sla_max_ms FLOAT NULL,
            interfaces_down_avg FLOAT NULL,
            created_at_utc DATETIME2(0) NOT NULL CONSTRAINT DF_monitoring_rollup_hourly_created_at DEFAULT SYSUTCDATETIME(),
            updated_at_utc DATETIME2(0) NOT NULL CONSTRAINT DF_monitoring_rollup_hourly_updated_at DEFAULT SYSUTCDATETIME(),
            CONSTRAINT PK_monitoring_rollup_hourly PRIMARY KEY (device_name, bucket_start_utc)
        );
    END;

    IF OBJECT_ID('dbo.monitoring_rollup_daily', 'U') IS NULL
    BEGIN
        CREATE TABLE dbo.monitoring_rollup_daily (
            device_name NVARCHAR(255) NOT NULL,
            bucket_date DATE NOT NULL,
            sample_count INT NOT NULL,
            up_samples INT NOT NULL,
            down_samples INT NOT NULL,
            availability_pct DECIMAL(6,3) NULL,
            cpu_avg FLOAT NULL,
            cpu_min FLOAT NULL,
            cpu_max FLOAT NULL,
            memory_avg FLOAT NULL,
            memory_min FLOAT NULL,
            memory_max FLOAT NULL,
            sla_avg_ms FLOAT NULL,
            sla_min_ms FLOAT NULL,
            sla_max_ms FLOAT NULL,
            interfaces_down_avg FLOAT NULL,
            created_at_utc DATETIME2(0) NOT NULL CONSTRAINT DF_monitoring_rollup_daily_created_at DEFAULT SYSUTCDATETIME(),
            updated_at_utc DATETIME2(0) NOT NULL CONSTRAINT DF_monitoring_rollup_daily_updated_at DEFAULT SYSUTCDATETIME(),
            CONSTRAINT PK_monitoring_rollup_daily PRIMARY KEY (device_name, bucket_date)
        );
    END;

    /* 4) Performance indexes. */
    IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_monitoring_metrics_device_time' AND object_id = OBJECT_ID('dbo.monitoring_metrics'))
        CREATE INDEX IX_monitoring_metrics_device_time
            ON dbo.monitoring_metrics(device_name, collected_at_utc DESC)
            INCLUDE (status, severity, cpu_percent, memory_percent, interfaces_up, interfaces_down, sla_ms);

    IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_monitoring_metrics_time' AND object_id = OBJECT_ID('dbo.monitoring_metrics'))
        CREATE INDEX IX_monitoring_metrics_time
            ON dbo.monitoring_metrics(collected_at_utc DESC)
            INCLUDE (device_name, status, severity, cpu_percent, memory_percent, sla_ms);

    IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_monitoring_interface_metrics_device_iface_time' AND object_id = OBJECT_ID('dbo.monitoring_interface_metrics'))
        CREATE INDEX IX_monitoring_interface_metrics_device_iface_time
            ON dbo.monitoring_interface_metrics(device_name, interface_name, collected_at_utc DESC)
            INCLUDE (oper_status, tx_percent, rx_percent, interface_description);

    IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_monitoring_interface_metrics_device_time' AND object_id = OBJECT_ID('dbo.monitoring_interface_metrics'))
        CREATE INDEX IX_monitoring_interface_metrics_device_time
            ON dbo.monitoring_interface_metrics(device_name, collected_at_utc DESC)
            INCLUDE (interface_name, oper_status, tx_percent, rx_percent);

    /* 5) Rollup builder procedure (hourly + daily). */
    EXEC ('
    CREATE OR ALTER PROCEDURE dbo.sp_monitoring_build_rollups
        @from_utc DATETIME2(0) = NULL
    AS
    BEGIN
        SET NOCOUNT ON;

        DECLARE @start DATETIME2(0) = COALESCE(@from_utc, DATEADD(DAY, -7, SYSUTCDATETIME()));

        ;WITH src AS (
            SELECT
                m.device_name,
                m.collected_at_utc,
                m.status,
                m.cpu_percent,
                m.memory_percent,
                m.sla_ms,
                m.interfaces_down,
                DATETIMEFROMPARTS(YEAR(m.collected_at_utc), MONTH(m.collected_at_utc), DAY(m.collected_at_utc), DATEPART(HOUR, m.collected_at_utc), 0, 0, 0) AS bucket_hour,
                CAST(m.collected_at_utc AS DATE) AS bucket_date
            FROM dbo.monitoring_metrics AS m
            WHERE m.collected_at_utc >= @start
        ),
        agg_hour AS (
            SELECT
                device_name,
                bucket_hour,
                COUNT(1) AS sample_count,
                SUM(CASE WHEN LOWER(status) = ''up'' THEN 1 ELSE 0 END) AS up_samples,
                SUM(CASE WHEN LOWER(status) <> ''up'' THEN 1 ELSE 0 END) AS down_samples,
                AVG(cpu_percent) AS cpu_avg,
                MIN(cpu_percent) AS cpu_min,
                MAX(cpu_percent) AS cpu_max,
                AVG(memory_percent) AS memory_avg,
                MIN(memory_percent) AS memory_min,
                MAX(memory_percent) AS memory_max,
                AVG(sla_ms) AS sla_avg_ms,
                MIN(sla_ms) AS sla_min_ms,
                MAX(sla_ms) AS sla_max_ms,
                AVG(CONVERT(FLOAT, interfaces_down)) AS interfaces_down_avg
            FROM src
            GROUP BY device_name, bucket_hour
        )
        MERGE dbo.monitoring_rollup_hourly AS tgt
        USING (
            SELECT
                device_name,
                bucket_hour,
                sample_count,
                up_samples,
                down_samples,
                CASE WHEN sample_count = 0 THEN NULL ELSE (100.0 * up_samples) / sample_count END AS availability_pct,
                cpu_avg, cpu_min, cpu_max,
                memory_avg, memory_min, memory_max,
                sla_avg_ms, sla_min_ms, sla_max_ms,
                interfaces_down_avg
            FROM agg_hour
        ) AS srcm
        ON tgt.device_name = srcm.device_name AND tgt.bucket_start_utc = srcm.bucket_hour
        WHEN MATCHED THEN
            UPDATE SET
                sample_count = srcm.sample_count,
                up_samples = srcm.up_samples,
                down_samples = srcm.down_samples,
                availability_pct = srcm.availability_pct,
                cpu_avg = srcm.cpu_avg,
                cpu_min = srcm.cpu_min,
                cpu_max = srcm.cpu_max,
                memory_avg = srcm.memory_avg,
                memory_min = srcm.memory_min,
                memory_max = srcm.memory_max,
                sla_avg_ms = srcm.sla_avg_ms,
                sla_min_ms = srcm.sla_min_ms,
                sla_max_ms = srcm.sla_max_ms,
                interfaces_down_avg = srcm.interfaces_down_avg,
                updated_at_utc = SYSUTCDATETIME()
        WHEN NOT MATCHED THEN
            INSERT (
                device_name, bucket_start_utc, sample_count, up_samples, down_samples, availability_pct,
                cpu_avg, cpu_min, cpu_max, memory_avg, memory_min, memory_max,
                sla_avg_ms, sla_min_ms, sla_max_ms, interfaces_down_avg
            ) VALUES (
                srcm.device_name, srcm.bucket_hour, srcm.sample_count, srcm.up_samples, srcm.down_samples, srcm.availability_pct,
                srcm.cpu_avg, srcm.cpu_min, srcm.cpu_max, srcm.memory_avg, srcm.memory_min, srcm.memory_max,
                srcm.sla_avg_ms, srcm.sla_min_ms, srcm.sla_max_ms, srcm.interfaces_down_avg
            );

        ;WITH srcd AS (
            SELECT
                device_name,
                bucket_date,
                COUNT(1) AS sample_count,
                SUM(CASE WHEN LOWER(status) = ''up'' THEN 1 ELSE 0 END) AS up_samples,
                SUM(CASE WHEN LOWER(status) <> ''up'' THEN 1 ELSE 0 END) AS down_samples,
                AVG(cpu_percent) AS cpu_avg,
                MIN(cpu_percent) AS cpu_min,
                MAX(cpu_percent) AS cpu_max,
                AVG(memory_percent) AS memory_avg,
                MIN(memory_percent) AS memory_min,
                MAX(memory_percent) AS memory_max,
                AVG(sla_ms) AS sla_avg_ms,
                MIN(sla_ms) AS sla_min_ms,
                MAX(sla_ms) AS sla_max_ms,
                AVG(CONVERT(FLOAT, interfaces_down)) AS interfaces_down_avg
            FROM src
            GROUP BY device_name, bucket_date
        )
        MERGE dbo.monitoring_rollup_daily AS tgtd
        USING (
            SELECT
                device_name,
                bucket_date,
                sample_count,
                up_samples,
                down_samples,
                CASE WHEN sample_count = 0 THEN NULL ELSE (100.0 * up_samples) / sample_count END AS availability_pct,
                cpu_avg, cpu_min, cpu_max,
                memory_avg, memory_min, memory_max,
                sla_avg_ms, sla_min_ms, sla_max_ms,
                interfaces_down_avg
            FROM srcd
        ) AS srcmd
        ON tgtd.device_name = srcmd.device_name AND tgtd.bucket_date = srcmd.bucket_date
        WHEN MATCHED THEN
            UPDATE SET
                sample_count = srcmd.sample_count,
                up_samples = srcmd.up_samples,
                down_samples = srcmd.down_samples,
                availability_pct = srcmd.availability_pct,
                cpu_avg = srcmd.cpu_avg,
                cpu_min = srcmd.cpu_min,
                cpu_max = srcmd.cpu_max,
                memory_avg = srcmd.memory_avg,
                memory_min = srcmd.memory_min,
                memory_max = srcmd.memory_max,
                sla_avg_ms = srcmd.sla_avg_ms,
                sla_min_ms = srcmd.sla_min_ms,
                sla_max_ms = srcmd.sla_max_ms,
                interfaces_down_avg = srcmd.interfaces_down_avg,
                updated_at_utc = SYSUTCDATETIME()
        WHEN NOT MATCHED THEN
            INSERT (
                device_name, bucket_date, sample_count, up_samples, down_samples, availability_pct,
                cpu_avg, cpu_min, cpu_max, memory_avg, memory_min, memory_max,
                sla_avg_ms, sla_min_ms, sla_max_ms, interfaces_down_avg
            ) VALUES (
                srcmd.device_name, srcmd.bucket_date, srcmd.sample_count, srcmd.up_samples, srcmd.down_samples, srcmd.availability_pct,
                srcmd.cpu_avg, srcmd.cpu_min, srcmd.cpu_max, srcmd.memory_avg, srcmd.memory_min, srcmd.memory_max,
                srcmd.sla_avg_ms, srcmd.sla_min_ms, srcmd.sla_max_ms, srcmd.interfaces_down_avg
            );
    END
    ');

    /* 6) Retention procedure. */
    EXEC ('
    CREATE OR ALTER PROCEDURE dbo.sp_monitoring_retention_cleanup
        @raw_days INT = 18250,
        @hourly_days INT = 18250,
        @daily_days INT = 36500
    AS
    BEGIN
        SET NOCOUNT ON;

        DECLARE @raw_cutoff DATETIME2(0) = DATEADD(DAY, -@raw_days, SYSUTCDATETIME());
        DECLARE @hourly_cutoff DATETIME2(0) = DATEADD(DAY, -@hourly_days, SYSUTCDATETIME());
        DECLARE @daily_cutoff DATE = CAST(DATEADD(DAY, -@daily_days, SYSUTCDATETIME()) AS DATE);

        DELETE FROM dbo.monitoring_interface_metrics WHERE collected_at_utc < @raw_cutoff;
        DELETE FROM dbo.monitoring_metrics WHERE collected_at_utc < @raw_cutoff;
        DELETE FROM dbo.monitoring_rollup_hourly WHERE bucket_start_utc < @hourly_cutoff;
        DELETE FROM dbo.monitoring_rollup_daily WHERE bucket_date < @daily_cutoff;
    END
    ');

    COMMIT TRAN;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK TRAN;
    THROW;
END CATCH;
GO

/* Run once now (safe default window): */
EXEC dbo.sp_monitoring_build_rollups @from_utc = DATEADD(DAY, -30, SYSUTCDATETIME());
GO
