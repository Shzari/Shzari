-- statement 001
BEGIN TRY
    CREATE TABLE dbo.user_panel_permissions (
        username NVARCHAR(255) NOT NULL,
        panel_key NVARCHAR(128) NOT NULL,
        access_level NVARCHAR(16) NOT NULL CONSTRAINT DF_user_panel_permissions_access DEFAULT 'none',
        updated_at NVARCHAR(64) NOT NULL CONSTRAINT DF_user_panel_permissions_updated DEFAULT '',
        CONSTRAINT PK_user_panel_permissions PRIMARY KEY (username, panel_key)
    );
END TRY
BEGIN CATCH
    IF ERROR_NUMBER() <> 2714
        THROW;
END CATCH

GO

-- statement 002
BEGIN TRY
    CREATE TABLE dbo.user_menu_permissions (
        username NVARCHAR(255) NOT NULL,
        menu_key NVARCHAR(128) NOT NULL,
        access_level NVARCHAR(16) NOT NULL CONSTRAINT DF_user_menu_permissions_access DEFAULT 'none',
        updated_at NVARCHAR(64) NOT NULL CONSTRAINT DF_user_menu_permissions_updated DEFAULT '',
        CONSTRAINT PK_user_menu_permissions PRIMARY KEY (username, menu_key)
    );
END TRY
BEGIN CATCH
    IF ERROR_NUMBER() <> 2714
        THROW;
END CATCH

GO

-- statement 003
BEGIN TRY
    CREATE TABLE dbo.user_device_category_permissions (
        username NVARCHAR(255) NOT NULL,
        category_name NVARCHAR(255) NOT NULL,
        access_level NVARCHAR(16) NOT NULL CONSTRAINT DF_user_device_category_permissions_access DEFAULT 'none',
        updated_at NVARCHAR(64) NOT NULL CONSTRAINT DF_user_device_category_permissions_updated DEFAULT '',
        CONSTRAINT PK_user_device_category_permissions PRIMARY KEY (username, category_name)
    );
END TRY
BEGIN CATCH
    IF ERROR_NUMBER() <> 2714
        THROW;
END CATCH

GO

-- statement 004
BEGIN TRY
    CREATE INDEX IX_user_panel_permissions_username ON dbo.user_panel_permissions(username);
END TRY
BEGIN CATCH
    IF ERROR_NUMBER() <> 1913
        THROW;
END CATCH

GO

-- statement 005
BEGIN TRY
    CREATE INDEX IX_user_menu_permissions_username ON dbo.user_menu_permissions(username);
END TRY
BEGIN CATCH
    IF ERROR_NUMBER() <> 1913
        THROW;
END CATCH

GO

-- statement 006
BEGIN TRY
    CREATE INDEX IX_user_device_category_permissions_username ON dbo.user_device_category_permissions(username);
END TRY
BEGIN CATCH
    IF ERROR_NUMBER() <> 1913
        THROW;
END CATCH

GO
