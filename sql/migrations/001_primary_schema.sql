-- statement 001
IF OBJECT_ID(N'dbo.app_settings', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.app_settings (
        setting_key NVARCHAR(128) NOT NULL PRIMARY KEY,
        setting_json NVARCHAR(MAX) NOT NULL CONSTRAINT DF_app_settings_json DEFAULT '{}',
        updated_at NVARCHAR(64) NOT NULL CONSTRAINT DF_app_settings_updated DEFAULT ''
    );
END

GO

-- statement 002
IF OBJECT_ID(N'dbo.users', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.users (
        username NVARCHAR(255) NOT NULL PRIMARY KEY,
        role NVARCHAR(50) NOT NULL CONSTRAINT DF_users_role DEFAULT 'operator',
        auth_source NVARCHAR(32) NOT NULL CONSTRAINT DF_users_auth_source DEFAULT 'ldap',
        salt NVARCHAR(255) NOT NULL CONSTRAINT DF_users_salt DEFAULT '',
        password_hash NVARCHAR(255) NOT NULL CONSTRAINT DF_users_password_hash DEFAULT '',
        must_change_password BIT NOT NULL CONSTRAINT DF_users_mcp DEFAULT 1,
        allowed_categories NVARCHAR(MAX) NULL,
        admin_permissions NVARCHAR(MAX) NULL,
        category_panel_access NVARCHAR(MAX) NULL,
        account_privileges NVARCHAR(MAX) NULL
    );
END

GO

-- statement 003
IF COL_LENGTH('dbo.users', 'admin_permissions') IS NULL
    ALTER TABLE dbo.users ADD admin_permissions NVARCHAR(MAX) NULL;
IF COL_LENGTH('dbo.users', 'category_panel_access') IS NULL
    ALTER TABLE dbo.users ADD category_panel_access NVARCHAR(MAX) NULL;
IF COL_LENGTH('dbo.users', 'account_privileges') IS NULL
    ALTER TABLE dbo.users ADD account_privileges NVARCHAR(MAX) NULL;
IF COL_LENGTH('dbo.users', 'auth_source') IS NULL
    ALTER TABLE dbo.users ADD auth_source NVARCHAR(32) NOT NULL CONSTRAINT DF_users_auth_source_v2 DEFAULT 'ldap';

GO

-- statement 004
IF OBJECT_ID(N'dbo.devices', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.devices (
        hostname NVARCHAR(255) NOT NULL PRIMARY KEY,
        ip_address NVARCHAR(64) NOT NULL
    );
END

GO

-- statement 005
IF OBJECT_ID(N'dbo.device_groups', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.device_groups (
        hostname NVARCHAR(255) NOT NULL,
        group_name NVARCHAR(255) NOT NULL,
        CONSTRAINT PK_device_groups PRIMARY KEY(hostname, group_name)
    );
END

GO

-- statement 006
IF OBJECT_ID(N'dbo.ip_branches', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.ip_branches (
        branch_name NVARCHAR(255) NOT NULL PRIMARY KEY
    );
END

GO

-- statement 007
IF OBJECT_ID(N'dbo.ip_branch_details', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.ip_branch_details (
        branch_name NVARCHAR(255) NOT NULL PRIMARY KEY,
        site NVARCHAR(255) NOT NULL CONSTRAINT DF_ip_branch_details_site DEFAULT '',
        network_base NVARCHAR(64) NOT NULL CONSTRAINT DF_ip_branch_details_network_base DEFAULT '',
        cidr INT NOT NULL CONSTRAINT DF_ip_branch_details_cidr DEFAULT 27,
        subnet_mask NVARCHAR(64) NOT NULL CONSTRAINT DF_ip_branch_details_subnet_mask DEFAULT '',
        gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_ip_branch_details_gateway DEFAULT '',
        broadcast NVARCHAR(64) NOT NULL CONSTRAINT DF_ip_branch_details_broadcast DEFAULT '',
        created_at NVARCHAR(64) NOT NULL CONSTRAINT DF_ip_branch_details_created DEFAULT '',
        updated_at NVARCHAR(64) NOT NULL CONSTRAINT DF_ip_branch_details_updated DEFAULT ''
    );
END

GO

-- statement 008
IF OBJECT_ID(N'dbo.ip_branch_ips', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.ip_branch_ips (
        branch_name NVARCHAR(255) NOT NULL,
        ip_address NVARCHAR(64) NOT NULL,
        hostname NVARCHAR(255) NOT NULL CONSTRAINT DF_ip_branch_ips_hostname DEFAULT '',
        enduser_name NVARCHAR(255) NOT NULL CONSTRAINT DF_ip_branch_ips_enduser DEFAULT '',
        status NVARCHAR(32) NOT NULL CONSTRAINT DF_ip_branch_ips_status DEFAULT 'FREE',
        CONSTRAINT PK_ip_branch_ips PRIMARY KEY(branch_name, ip_address)
    );
END

GO

-- statement 009
IF OBJECT_ID(N'dbo.device_credentials', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.device_credentials (
        account_key NVARCHAR(255) NOT NULL PRIMARY KEY,
        username NVARCHAR(255) NOT NULL CONSTRAINT DF_device_credentials_username DEFAULT '',
        password_enc NVARCHAR(MAX) NOT NULL CONSTRAINT DF_device_credentials_pwd DEFAULT '',
        enable_password_enc NVARCHAR(MAX) NOT NULL CONSTRAINT DF_device_credentials_enable_pwd DEFAULT ''
    );
END

GO

-- statement 010
IF OBJECT_ID(N'dbo.super_admin', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.super_admin (
        id INT NOT NULL PRIMARY KEY,
        username NVARCHAR(255) NOT NULL CONSTRAINT DF_super_admin_username DEFAULT '',
        salt NVARCHAR(255) NOT NULL CONSTRAINT DF_super_admin_salt DEFAULT '',
        password_hash NVARCHAR(255) NOT NULL CONSTRAINT DF_super_admin_password_hash DEFAULT '',
        CONSTRAINT CK_super_admin_id CHECK (id = 1)
    );
END

GO

-- statement 011
IF OBJECT_ID(N'dbo.ise_settings', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.ise_settings (
        id INT NOT NULL PRIMARY KEY,
        primary_server NVARCHAR(255) NOT NULL CONSTRAINT DF_ise_settings_ps DEFAULT '',
        primary_port INT NOT NULL CONSTRAINT DF_ise_settings_pp DEFAULT 1812,
        primary_shared_secret NVARCHAR(MAX) NOT NULL CONSTRAINT DF_ise_settings_psecret DEFAULT '',
        secondary_server NVARCHAR(255) NOT NULL CONSTRAINT DF_ise_settings_ss DEFAULT '',
        secondary_port INT NOT NULL CONSTRAINT DF_ise_settings_sp DEFAULT 1812,
        secondary_shared_secret NVARCHAR(MAX) NOT NULL CONSTRAINT DF_ise_settings_ssecret DEFAULT '',
        timeout INT NOT NULL CONSTRAINT DF_ise_settings_timeout DEFAULT 5,
        nas_ip NVARCHAR(64) NOT NULL CONSTRAINT DF_ise_settings_nas DEFAULT '127.0.0.1',
        CONSTRAINT CK_ise_settings_id CHECK (id = 1)
    );
END

GO

-- statement 012
IF OBJECT_ID(N'dbo.ldap_settings', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.ldap_settings (
        id INT NOT NULL PRIMARY KEY,
        server NVARCHAR(255) NOT NULL CONSTRAINT DF_ldap_settings_server DEFAULT '',
        port INT NOT NULL CONSTRAINT DF_ldap_settings_port DEFAULT 389,
        use_ssl BIT NOT NULL CONSTRAINT DF_ldap_settings_use_ssl DEFAULT 0,
        start_tls BIT NOT NULL CONSTRAINT DF_ldap_settings_start_tls DEFAULT 0,
        timeout INT NOT NULL CONSTRAINT DF_ldap_settings_timeout DEFAULT 5,
        base_dn NVARCHAR(512) NOT NULL CONSTRAINT DF_ldap_settings_base_dn DEFAULT '',
        user_dn_template NVARCHAR(512) NOT NULL CONSTRAINT DF_ldap_settings_user_dn_template DEFAULT '',
        user_search_filter NVARCHAR(512) NOT NULL CONSTRAINT DF_ldap_settings_user_filter DEFAULT '(sAMAccountName={username})',
        bind_dn NVARCHAR(512) NOT NULL CONSTRAINT DF_ldap_settings_bind_dn DEFAULT '',
        bind_password NVARCHAR(MAX) NOT NULL CONSTRAINT DF_ldap_settings_bind_password DEFAULT '',
        CONSTRAINT CK_ldap_settings_id CHECK (id = 1)
    );
END

GO

-- statement 013
IF OBJECT_ID(N'dbo.sql_server_settings', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.sql_server_settings (
        id INT NOT NULL PRIMARY KEY,
        enabled BIT NOT NULL CONSTRAINT DF_sql_server_settings_enabled DEFAULT 0,
        driver NVARCHAR(128) NOT NULL CONSTRAINT DF_sql_server_settings_driver DEFAULT 'ODBC Driver 18 for SQL Server',
        server NVARCHAR(255) NOT NULL CONSTRAINT DF_sql_server_settings_server DEFAULT '',
        port INT NOT NULL CONSTRAINT DF_sql_server_settings_port DEFAULT 1433,
        database_name NVARCHAR(255) NOT NULL CONSTRAINT DF_sql_server_settings_database DEFAULT '',
        username NVARCHAR(255) NOT NULL CONSTRAINT DF_sql_server_settings_username DEFAULT '',
        password_enc NVARCHAR(MAX) NOT NULL CONSTRAINT DF_sql_server_settings_password DEFAULT '',
        encrypt BIT NOT NULL CONSTRAINT DF_sql_server_settings_encrypt DEFAULT 1,
        trust_server_certificate BIT NOT NULL CONSTRAINT DF_sql_server_settings_trust DEFAULT 1,
        timeout INT NOT NULL CONSTRAINT DF_sql_server_settings_timeout DEFAULT 5,
        table_name NVARCHAR(255) NOT NULL CONSTRAINT DF_sql_server_settings_table DEFAULT 'audit_logs',
        CONSTRAINT CK_sql_server_settings_id CHECK (id = 1)
    );
END

GO

-- statement 014
IF OBJECT_ID(N'dbo.pending_device_requests', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.pending_device_requests (
        id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        requester_username NVARCHAR(255) NOT NULL,
        requester_role NVARCHAR(50) NOT NULL,
        device_name NVARCHAR(255) NOT NULL,
        original_hostname NVARCHAR(255) NOT NULL,
        original_ip NVARCHAR(64) NOT NULL,
        original_categories NVARCHAR(MAX) NOT NULL,
        proposed_hostname NVARCHAR(255) NOT NULL,
        proposed_ip NVARCHAR(64) NOT NULL,
        proposed_categories NVARCHAR(MAX) NOT NULL,
        status NVARCHAR(50) NOT NULL CONSTRAINT DF_pending_device_requests_status DEFAULT 'pending',
        approver_username NVARCHAR(255) NOT NULL CONSTRAINT DF_pending_device_requests_approver DEFAULT '',
        created_at NVARCHAR(64) NOT NULL,
        decided_at NVARCHAR(64) NOT NULL CONSTRAINT DF_pending_device_requests_decided DEFAULT ''
    );
END

GO

-- statement 015
IF OBJECT_ID(N'dbo.pending_command_requests', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.pending_command_requests (
        id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        requester_username NVARCHAR(255) NOT NULL,
        requester_role NVARCHAR(50) NOT NULL,
        command_mode NVARCHAR(64) NOT NULL,
        command_text NVARCHAR(MAX) NOT NULL,
        target_devices NVARCHAR(MAX) NOT NULL,
        status NVARCHAR(50) NOT NULL CONSTRAINT DF_pending_command_requests_status DEFAULT 'pending',
        approver_username NVARCHAR(255) NOT NULL CONSTRAINT DF_pending_command_requests_approver DEFAULT '',
        created_at NVARCHAR(64) NOT NULL,
        decided_at NVARCHAR(64) NOT NULL CONSTRAINT DF_pending_command_requests_decided DEFAULT ''
    );
END

GO

-- statement 016
IF OBJECT_ID(N'dbo.user_notifications', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.user_notifications (
        id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        username NVARCHAR(255) NOT NULL,
        message NVARCHAR(MAX) NOT NULL,
        created_at NVARCHAR(64) NOT NULL,
        is_read BIT NOT NULL CONSTRAINT DF_user_notifications_is_read DEFAULT 0
    );
END

GO

-- statement 017
IF OBJECT_ID(N'dbo.audit_logs', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.audit_logs (
        id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        action NVARCHAR(128) NOT NULL,
        requester NVARCHAR(255) NOT NULL,
        approver NVARCHAR(255) NOT NULL,
        device_name NVARCHAR(255) NOT NULL,
        details_json NVARCHAR(MAX) NOT NULL,
        created_at NVARCHAR(64) NOT NULL
    );
END

GO

-- statement 018
IF OBJECT_ID(N'dbo.login_audit_logs', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.login_audit_logs (
        id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        username NVARCHAR(255) NOT NULL,
        auth_source NVARCHAR(32) NOT NULL,
        success BIT NOT NULL,
        reason NVARCHAR(512) NOT NULL,
        client_ip NVARCHAR(128) NOT NULL,
        user_agent NVARCHAR(512) NOT NULL,
        created_at NVARCHAR(64) NOT NULL
    );
END

GO

-- statement 019
IF OBJECT_ID(N'dbo.action_logs', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.action_logs (
        id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        username NVARCHAR(255) NOT NULL,
        role NVARCHAR(50) NOT NULL CONSTRAINT DF_action_logs_role DEFAULT 'unknown',
        action NVARCHAR(128) NOT NULL,
        device_name NVARCHAR(255) NOT NULL,
        interface_name NVARCHAR(128) NOT NULL,
        status NVARCHAR(64) NOT NULL,
        details_json NVARCHAR(MAX) NOT NULL,
        client_ip NVARCHAR(128) NOT NULL,
        user_agent NVARCHAR(512) NOT NULL,
        created_at NVARCHAR(64) NOT NULL
    );
END

GO

-- statement 020
IF COL_LENGTH('dbo.action_logs', 'role') IS NULL
    ALTER TABLE dbo.action_logs ADD role NVARCHAR(50) NOT NULL CONSTRAINT DF_action_logs_role_v2 DEFAULT 'unknown';
IF OBJECT_ID(N'dbo.action_logs', N'U') IS NOT NULL AND OBJECT_ID(N'dbo.helpdesk_action_logs', N'U') IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM dbo.action_logs)
BEGIN
    SET IDENTITY_INSERT dbo.action_logs ON;
    INSERT INTO dbo.action_logs(id, username, role, action, device_name, interface_name, status, details_json, client_ip, user_agent, created_at)
    SELECT id, username, COALESCE(role, 'unknown'), action, device_name, interface_name, status, details_json, client_ip, user_agent, created_at
    FROM dbo.helpdesk_action_logs;
    SET IDENTITY_INSERT dbo.action_logs OFF;
END

GO

-- statement 021
IF OBJECT_ID(N'dbo.monitoring_metrics', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.monitoring_metrics (
        id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        device_name NVARCHAR(255) NOT NULL,
        host NVARCHAR(64) NOT NULL,
        collection_mode NVARCHAR(32) NOT NULL,
        status NVARCHAR(32) NOT NULL,
        severity NVARCHAR(32) NOT NULL,
        cpu_percent FLOAT NULL,
        memory_percent FLOAT NULL,
        interfaces_up INT NULL,
        interfaces_down INT NULL,
        sla_ms FLOAT NULL,
        details_json NVARCHAR(MAX) NOT NULL,
        collected_at NVARCHAR(64) NOT NULL
    );
END

GO

-- statement 022
IF COL_LENGTH('dbo.monitoring_metrics', 'collected_at_utc') IS NULL
    ALTER TABLE dbo.monitoring_metrics ADD collected_at_utc NVARCHAR(64) NOT NULL CONSTRAINT DF_monitoring_metrics_collected_at_utc DEFAULT '';

GO

-- statement 023
IF COL_LENGTH('dbo.monitoring_metrics', 'collected_at_utc') IS NOT NULL
    UPDATE dbo.monitoring_metrics SET collected_at_utc = collected_at WHERE ISNULL(collected_at_utc, '') = '';

GO

-- statement 024
IF OBJECT_ID(N'dbo.monitoring_device_profiles', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.monitoring_device_profiles (
        device_name NVARCHAR(255) NOT NULL PRIMARY KEY,
        host NVARCHAR(64) NOT NULL,
        profile_json NVARCHAR(MAX) NOT NULL,
        created_at NVARCHAR(64) NOT NULL,
        updated_at NVARCHAR(64) NOT NULL
    );
END

GO

-- statement 025
IF OBJECT_ID(N'dbo.monitoring_interface_metrics', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.monitoring_interface_metrics (
        id BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        device_name NVARCHAR(255) NOT NULL,
        host NVARCHAR(64) NOT NULL CONSTRAINT DF_monitoring_interface_metrics_host DEFAULT '',
        interface_name NVARCHAR(128) NOT NULL,
        interface_description NVARCHAR(255) NOT NULL CONSTRAINT DF_monitoring_interface_metrics_desc DEFAULT '',
        oper_status NVARCHAR(32) NOT NULL CONSTRAINT DF_monitoring_interface_metrics_status DEFAULT 'unknown',
        tx_percent FLOAT NULL,
        rx_percent FLOAT NULL,
        collected_at_utc NVARCHAR(64) NOT NULL,
        details_json NVARCHAR(MAX) NOT NULL CONSTRAINT DF_monitoring_interface_metrics_details DEFAULT '{}'
    );
END

GO

-- statement 026
IF OBJECT_ID(N'dbo.monitoring_alerts', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.monitoring_alerts (
        id BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        device_name NVARCHAR(255) NOT NULL,
        host NVARCHAR(64) NOT NULL CONSTRAINT DF_monitoring_alerts_host DEFAULT '',
        alert_key NVARCHAR(128) NOT NULL,
        alert_type NVARCHAR(64) NOT NULL,
        severity NVARCHAR(32) NOT NULL CONSTRAINT DF_monitoring_alerts_severity DEFAULT 'warning',
        status NVARCHAR(32) NOT NULL CONSTRAINT DF_monitoring_alerts_status DEFAULT 'open',
        message NVARCHAR(512) NOT NULL CONSTRAINT DF_monitoring_alerts_message DEFAULT '',
        threshold_value FLOAT NULL,
        last_value FLOAT NULL,
        opened_at NVARCHAR(64) NOT NULL,
        updated_at NVARCHAR(64) NOT NULL,
        sample_collected_at NVARCHAR(64) NOT NULL CONSTRAINT DF_monitoring_alerts_sample_collected DEFAULT '',
        acked_by NVARCHAR(255) NOT NULL CONSTRAINT DF_monitoring_alerts_acked_by DEFAULT '',
        acked_at NVARCHAR(64) NOT NULL CONSTRAINT DF_monitoring_alerts_acked_at DEFAULT '',
        cleared_at NVARCHAR(64) NOT NULL CONSTRAINT DF_monitoring_alerts_cleared_at DEFAULT '',
        details_json NVARCHAR(MAX) NOT NULL CONSTRAINT DF_monitoring_alerts_details DEFAULT '{}'
    );
END

GO

-- statement 027
IF OBJECT_ID(N'dbo.network_isp_branch_rows', N'U') IS NULL
BEGIN
    BEGIN TRY
        CREATE TABLE dbo.network_isp_branch_rows (
            id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
            row_order INT NOT NULL CONSTRAINT DF_network_isp_branch_rows_order DEFAULT 0,
            branch_code NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_branch_code DEFAULT '',
            city NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_branch_rows_city DEFAULT '',
            primary_name NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_name DEFAULT '',
            primary_wan NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_wan DEFAULT '',
            primary_gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_gateway DEFAULT '',
            primary_cidr NVARCHAR(32) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_cidr DEFAULT '',
            primary_bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_bandwidth DEFAULT '',
            secondary_name NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_name DEFAULT '',
            secondary_wan NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_wan DEFAULT '',
            secondary_gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_gateway DEFAULT '',
            secondary_cidr NVARCHAR(32) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_cidr DEFAULT '',
            secondary_bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_bandwidth DEFAULT '',
            locked BIT NOT NULL CONSTRAINT DF_network_isp_branch_rows_locked DEFAULT 0
        );
    END TRY
    BEGIN CATCH
        IF ERROR_NUMBER() <> 2714
            THROW;
    END CATCH
END

GO

-- statement 028
IF COL_LENGTH('dbo.network_isp_branch_rows', 'row_order') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD row_order INT NOT NULL CONSTRAINT DF_network_isp_branch_rows_order_v2 DEFAULT 0;
IF COL_LENGTH('dbo.network_isp_branch_rows', 'branch_code') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD branch_code NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_branch_code_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'city') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD city NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_branch_rows_city_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'primary_name') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD primary_name NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_name_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'primary_wan') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD primary_wan NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_wan_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'primary_gateway') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD primary_gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_gateway_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'primary_cidr') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD primary_cidr NVARCHAR(32) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_cidr_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'primary_bandwidth') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD primary_bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_bandwidth_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'secondary_name') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD secondary_name NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_name_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'secondary_wan') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD secondary_wan NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_wan_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'secondary_gateway') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD secondary_gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_gateway_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'secondary_cidr') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD secondary_cidr NVARCHAR(32) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_cidr_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'secondary_bandwidth') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD secondary_bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_bandwidth_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'locked') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD locked BIT NOT NULL CONSTRAINT DF_network_isp_branch_rows_locked_v2 DEFAULT 0;

GO

-- statement 029
IF OBJECT_ID(N'dbo.network_isp_atm_rows', N'U') IS NULL
BEGIN
    BEGIN TRY
        CREATE TABLE dbo.network_isp_atm_rows (
            id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
            row_order INT NOT NULL CONSTRAINT DF_network_isp_atm_rows_order DEFAULT 0,
            atm NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_atm DEFAULT '',
            location NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_atm_rows_location DEFAULT '',
            primary_name NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_name DEFAULT '',
            primary_wan NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_wan DEFAULT '',
            primary_gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_gateway DEFAULT '',
            primary_cidr NVARCHAR(32) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_cidr DEFAULT '',
            primary_bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_bandwidth DEFAULT '',
            secondary_name NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_name DEFAULT '',
            secondary_wan NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_wan DEFAULT '',
            secondary_gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_gateway DEFAULT '',
            secondary_cidr NVARCHAR(32) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_cidr DEFAULT '',
            secondary_bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_bandwidth DEFAULT '',
            locked BIT NOT NULL CONSTRAINT DF_network_isp_atm_rows_locked DEFAULT 0
        );
    END TRY
    BEGIN CATCH
        IF ERROR_NUMBER() <> 2714
            THROW;
    END CATCH
END

GO

-- statement 030
IF COL_LENGTH('dbo.network_isp_atm_rows', 'row_order') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD row_order INT NOT NULL CONSTRAINT DF_network_isp_atm_rows_order_v2 DEFAULT 0;
IF COL_LENGTH('dbo.network_isp_atm_rows', 'atm') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD atm NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_atm_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'location') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD location NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_atm_rows_location_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'primary_name') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD primary_name NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_name_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'primary_wan') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD primary_wan NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_wan_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'primary_gateway') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD primary_gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_gateway_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'primary_cidr') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD primary_cidr NVARCHAR(32) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_cidr_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'primary_bandwidth') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD primary_bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_bandwidth_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'secondary_name') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD secondary_name NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_name_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'secondary_wan') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD secondary_wan NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_wan_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'secondary_gateway') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD secondary_gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_gateway_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'secondary_cidr') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD secondary_cidr NVARCHAR(32) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_cidr_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'secondary_bandwidth') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD secondary_bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_bandwidth_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'locked') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD locked BIT NOT NULL CONSTRAINT DF_network_isp_atm_rows_locked_v2 DEFAULT 0;

GO

-- statement 031
IF OBJECT_ID(N'dbo.network_isp_internet_rows', N'U') IS NULL
BEGIN
    BEGIN TRY
        CREATE TABLE dbo.network_isp_internet_rows (
            id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
            row_order INT NOT NULL CONSTRAINT DF_network_isp_internet_rows_order DEFAULT 0,
            site NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_internet_rows_site DEFAULT '',
            isp NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_isp DEFAULT '',
            public_ip NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_public_ip DEFAULT '',
            gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_gateway DEFAULT '',
            subnet NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_subnet DEFAULT '',
            bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_bandwidth DEFAULT '',
            locked BIT NOT NULL CONSTRAINT DF_network_isp_internet_rows_locked DEFAULT 0
        );
    END TRY
    BEGIN CATCH
        IF ERROR_NUMBER() <> 2714
            THROW;
    END CATCH
END

GO

-- statement 032
IF COL_LENGTH('dbo.network_isp_internet_rows', 'row_order') IS NULL
    ALTER TABLE dbo.network_isp_internet_rows ADD row_order INT NOT NULL CONSTRAINT DF_network_isp_internet_rows_order_v2 DEFAULT 0;
IF COL_LENGTH('dbo.network_isp_internet_rows', 'site') IS NULL
    ALTER TABLE dbo.network_isp_internet_rows ADD site NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_internet_rows_site_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_internet_rows', 'isp') IS NULL
    ALTER TABLE dbo.network_isp_internet_rows ADD isp NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_isp_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_internet_rows', 'public_ip') IS NULL
    ALTER TABLE dbo.network_isp_internet_rows ADD public_ip NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_public_ip_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_internet_rows', 'gateway') IS NULL
    ALTER TABLE dbo.network_isp_internet_rows ADD gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_gateway_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_internet_rows', 'subnet') IS NULL
    ALTER TABLE dbo.network_isp_internet_rows ADD subnet NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_subnet_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_internet_rows', 'bandwidth') IS NULL
    ALTER TABLE dbo.network_isp_internet_rows ADD bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_bandwidth_v2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_internet_rows', 'locked') IS NULL
    ALTER TABLE dbo.network_isp_internet_rows ADD locked BIT NOT NULL CONSTRAINT DF_network_isp_internet_rows_locked_v2 DEFAULT 0;

IF EXISTS (
    SELECT 1
    FROM sys.columns gateway_col
    INNER JOIN sys.columns subnet_col ON gateway_col.object_id = subnet_col.object_id
    WHERE gateway_col.object_id = OBJECT_ID(N'dbo.network_isp_internet_rows')
      AND gateway_col.name = 'gateway'
      AND subnet_col.name = 'subnet'
      AND gateway_col.column_id > subnet_col.column_id
)
BEGIN
    BEGIN TRY
        BEGIN TRANSACTION;

        IF OBJECT_ID(N'dbo.network_isp_internet_rows_rebuild', N'U') IS NOT NULL
            DROP TABLE dbo.network_isp_internet_rows_rebuild;

        CREATE TABLE dbo.network_isp_internet_rows_rebuild (
            id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
            row_order INT NOT NULL CONSTRAINT DF_network_isp_internet_rows_order_rebuild_v2 DEFAULT 0,
            site NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_internet_rows_site_rebuild_v2 DEFAULT '',
            isp NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_isp_rebuild_v2 DEFAULT '',
            public_ip NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_public_ip_rebuild_v2 DEFAULT '',
            gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_gateway_rebuild_v2 DEFAULT '',
            subnet NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_subnet_rebuild_v2 DEFAULT '',
            bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_bandwidth_rebuild_v2 DEFAULT '',
            locked BIT NOT NULL CONSTRAINT DF_network_isp_internet_rows_locked_rebuild_v2 DEFAULT 0
        );

        SET IDENTITY_INSERT dbo.network_isp_internet_rows_rebuild ON;
        INSERT INTO dbo.network_isp_internet_rows_rebuild (
            id, row_order, site, isp, public_ip, gateway, subnet, bandwidth, locked
        )
        SELECT
            id,
            row_order,
            site,
            isp,
            public_ip,
            ISNULL(gateway, ''),
            subnet,
            bandwidth,
            locked
        FROM dbo.network_isp_internet_rows
        ORDER BY id ASC;
        SET IDENTITY_INSERT dbo.network_isp_internet_rows_rebuild OFF;

        DROP TABLE dbo.network_isp_internet_rows;
        EXEC sp_rename N'dbo.network_isp_internet_rows_rebuild', N'network_isp_internet_rows';

        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF XACT_STATE() <> 0
            ROLLBACK TRANSACTION;
        THROW;
    END CATCH
END

GO

-- statement 033
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_monitoring_metrics_device_collected_at_utc' AND object_id = OBJECT_ID(N'dbo.monitoring_metrics'))
    CREATE INDEX IX_monitoring_metrics_device_collected_at_utc ON dbo.monitoring_metrics(device_name, collected_at_utc DESC);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_monitoring_interface_metrics_device_collected_at_utc' AND object_id = OBJECT_ID(N'dbo.monitoring_interface_metrics'))
    CREATE INDEX IX_monitoring_interface_metrics_device_collected_at_utc ON dbo.monitoring_interface_metrics(device_name, collected_at_utc DESC);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_monitoring_interface_metrics_device_interface_time' AND object_id = OBJECT_ID(N'dbo.monitoring_interface_metrics'))
    CREATE INDEX IX_monitoring_interface_metrics_device_interface_time ON dbo.monitoring_interface_metrics(device_name, interface_name, collected_at_utc DESC);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_monitoring_alerts_device_status' AND object_id = OBJECT_ID(N'dbo.monitoring_alerts'))
    CREATE INDEX IX_monitoring_alerts_device_status ON dbo.monitoring_alerts(device_name, status, updated_at DESC);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_monitoring_alerts_device_key_status' AND object_id = OBJECT_ID(N'dbo.monitoring_alerts'))
    CREATE INDEX IX_monitoring_alerts_device_key_status ON dbo.monitoring_alerts(device_name, alert_key, status);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_network_isp_branch_rows_order' AND object_id = OBJECT_ID(N'dbo.network_isp_branch_rows'))
BEGIN TRY
    CREATE INDEX IX_network_isp_branch_rows_order ON dbo.network_isp_branch_rows(row_order ASC, id ASC);
END TRY
BEGIN CATCH
    IF ERROR_NUMBER() NOT IN (1913, 2714)
        THROW;
END CATCH
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_network_isp_atm_rows_order' AND object_id = OBJECT_ID(N'dbo.network_isp_atm_rows'))
BEGIN TRY
    CREATE INDEX IX_network_isp_atm_rows_order ON dbo.network_isp_atm_rows(row_order ASC, id ASC);
END TRY
BEGIN CATCH
    IF ERROR_NUMBER() NOT IN (1913, 2714)
        THROW;
END CATCH
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_network_isp_internet_rows_order' AND object_id = OBJECT_ID(N'dbo.network_isp_internet_rows'))
BEGIN TRY
    CREATE INDEX IX_network_isp_internet_rows_order ON dbo.network_isp_internet_rows(row_order ASC, id ASC);
END TRY
BEGIN CATCH
    IF ERROR_NUMBER() NOT IN (1913, 2714)
        THROW;
END CATCH
