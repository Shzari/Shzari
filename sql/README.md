# Monitoring Time-Series Setup (SQL Server)

Run in this order:

1. `sql/monitoring_timeseries_setup.sql`
2. Optional: `sql/monitoring_timeseries_jobs.sql` (requires SQL Server Agent)

What it adds:
- `monitoring_metrics.collected_at_utc` normalization + trigger for future inserts.
- `monitoring_interface_metrics` append-only interface sample table.
- `monitoring_rollup_hourly` and `monitoring_rollup_daily` aggregate tables.
- `sp_monitoring_build_rollups` and `sp_monitoring_retention_cleanup` stored procedures.
- Performance indexes for dashboard/history queries.

Default retention policy:
- Raw (`monitoring_metrics`, `monitoring_interface_metrics`): 18250 days (50 years)
- Hourly rollup: 18250 days (50 years)
- Daily rollup: 36500 days (100 years)

You can tune retention by changing parameters in:
- `sp_monitoring_retention_cleanup`
- SQL Agent job command in `monitoring_timeseries_jobs.sql`
