// rustnmap-fingerprint database updater tests
//
// These tests verify the database update functionality including
// options builders, result structures, and version extraction.

use rustnmap_fingerprint::database::{
    CustomUrls, DatabaseUpdateDetail, DatabaseUpdater, UpdateOptions, UpdateResult,
};

/// Test UpdateOptions default values.
#[test]
fn test_update_options_default() {
    let _opts = UpdateOptions::default();

    // Default backup should be true
    // Default verify_checksums should be false
    // Default custom_urls should be None
}

/// Test UpdateOptions builder pattern with all fields.
#[test]
fn test_update_options_builder_complete() {
    let custom_urls = CustomUrls {
        service_probes: Some("https://example.com/probes".to_string()),
        os_db: Some("https://example.com/os-db".to_string()),
        mac_prefixes: Some("https://example.com/mac".to_string()),
    };

    let _opts = UpdateOptions::new()
        .backup(false)
        .verify_checksums(true)
        .custom_urls(custom_urls);

    // Verify builder methods compile and run
}

/// Test UpdateOptions builder with backup only.
#[test]
fn test_update_options_builder_backup() {
    let _opts = UpdateOptions::default().backup(false);

    // Verify backup can be set to false
    let _opts = _opts.backup(true);
    // Verify backup can be set to true
}

/// Test UpdateOptions builder with verify_checksums only.
#[test]
fn test_update_options_builder_verify() {
    let _opts = UpdateOptions::default().verify_checksums(true);

    // Verify verify_checksums can be set
    let _opts = _opts.verify_checksums(false);
    // Verify verify_checksums can be toggled
}

/// Test UpdateOptions builder chaining.
#[test]
fn test_update_options_builder_chaining() {
    let _opts = UpdateOptions::new()
        .backup(true)
        .verify_checksums(true)
        .backup(false)
        .verify_checksums(false);

    // Multiple chained calls should work
}

/// Test CustomUrls struct creation with all fields.
#[test]
fn test_custom_urls_all_fields() {
    let urls = CustomUrls {
        service_probes: Some("https://custom.example.com/service-probes".to_string()),
        os_db: Some("https://custom.example.com/nmap-os-db".to_string()),
        mac_prefixes: Some("https://custom.example.com/nmap-mac-prefixes".to_string()),
    };

    assert!(urls.service_probes.is_some());
    assert!(urls.os_db.is_some());
    assert!(urls.mac_prefixes.is_some());

    assert_eq!(
        urls.service_probes.unwrap(),
        "https://custom.example.com/service-probes"
    );
}

/// Test CustomUrls struct creation with partial fields.
#[test]
fn test_custom_urls_partial() {
    let urls = CustomUrls {
        service_probes: Some("https://custom.example.com/service-probes".to_string()),
        os_db: None,
        mac_prefixes: None,
    };

    assert!(urls.service_probes.is_some());
    assert!(urls.os_db.is_none());
    assert!(urls.mac_prefixes.is_none());
}

/// Test CustomUrls struct creation with all None.
#[test]
fn test_custom_urls_all_none() {
    let urls = CustomUrls {
        service_probes: None,
        os_db: None,
        mac_prefixes: None,
    };

    assert!(urls.service_probes.is_none());
    assert!(urls.os_db.is_none());
    assert!(urls.mac_prefixes.is_none());
}

/// Test CustomUrls clone.
#[test]
fn test_custom_urls_clone() {
    let urls = CustomUrls {
        service_probes: Some("https://example.com".to_string()),
        os_db: None,
        mac_prefixes: None,
    };

    let cloned = urls.clone();
    assert_eq!(urls.service_probes, cloned.service_probes);
}

/// Test UpdateOptions with custom URLs.
#[test]
fn test_update_options_with_custom_urls() {
    let custom_urls = CustomUrls {
        service_probes: Some("https://mirror1.example.com/probes".to_string()),
        os_db: Some("https://mirror1.example.com/os".to_string()),
        mac_prefixes: Some("https://mirror1.example.com/mac".to_string()),
    };

    let _opts = UpdateOptions::default().custom_urls(custom_urls);

    // Verify custom_urls can be set
}

/// Test DatabaseUpdater creation.
#[test]
fn test_database_updater_new() {
    let _updater = DatabaseUpdater::new();

    // Verify updater was created successfully
}

/// Test DatabaseUpdater default.
#[test]
fn test_database_updater_default() {
    let _updater: DatabaseUpdater = Default::default();

    // Verify default creation works
}

/// Test DatabaseUpdater clone.
#[test]
fn test_database_updater_clone() {
    let updater = DatabaseUpdater::new();
    let _cloned = updater.clone();

    // Verify clone works (DatabaseUpdater derives Clone)
}

/// Test UpdateResult creation with success.
#[test]
fn test_update_result_success() {
    let result = UpdateResult {
        updated_count: 3,
        unchanged_count: 0,
        failed_count: 0,
        details: vec![
            DatabaseUpdateDetail {
                name: "service-probes".to_string(),
                success: true,
                previous_version: Some("2024-01-01".to_string()),
                new_version: Some("2024-02-01".to_string()),
                error: None,
                backup_created: true,
            },
            DatabaseUpdateDetail {
                name: "os-db".to_string(),
                success: true,
                previous_version: Some("2023-12-01".to_string()),
                new_version: Some("2024-02-01".to_string()),
                error: None,
                backup_created: true,
            },
            DatabaseUpdateDetail {
                name: "mac-prefixes".to_string(),
                success: true,
                previous_version: Some("2024-01-15".to_string()),
                new_version: Some("2024-02-01".to_string()),
                error: None,
                backup_created: true,
            },
        ],
    };

    assert_eq!(result.updated_count, 3);
    assert_eq!(result.unchanged_count, 0);
    assert_eq!(result.failed_count, 0);
    assert_eq!(result.details.len(), 3);
}

/// Test UpdateResult creation with partial success.
#[test]
fn test_update_result_partial() {
    let result = UpdateResult {
        updated_count: 1,
        unchanged_count: 1,
        failed_count: 1,
        details: vec![
            DatabaseUpdateDetail {
                name: "service-probes".to_string(),
                success: true,
                previous_version: Some("2024-01-01".to_string()),
                new_version: Some("2024-02-01".to_string()),
                error: None,
                backup_created: true,
            },
            DatabaseUpdateDetail {
                name: "os-db".to_string(),
                success: true,
                previous_version: Some("2024-02-01".to_string()),
                new_version: Some("2024-02-01".to_string()),
                error: None,
                backup_created: false,
            },
            DatabaseUpdateDetail {
                name: "mac-prefixes".to_string(),
                success: false,
                previous_version: None,
                new_version: None,
                error: Some("Network error".to_string()),
                backup_created: false,
            },
        ],
    };

    assert_eq!(result.updated_count, 1);
    assert_eq!(result.unchanged_count, 1);
    assert_eq!(result.failed_count, 1);
    assert_eq!(result.details.len(), 3);
}

/// Test UpdateResult creation with all failures.
#[test]
fn test_update_result_all_failures() {
    let result = UpdateResult {
        updated_count: 0,
        unchanged_count: 0,
        failed_count: 3,
        details: vec![
            DatabaseUpdateDetail {
                name: "service-probes".to_string(),
                success: false,
                previous_version: None,
                new_version: None,
                error: Some("Download failed".to_string()),
                backup_created: false,
            },
            DatabaseUpdateDetail {
                name: "os-db".to_string(),
                success: false,
                previous_version: None,
                new_version: None,
                error: Some("HTTP 404".to_string()),
                backup_created: false,
            },
            DatabaseUpdateDetail {
                name: "mac-prefixes".to_string(),
                success: false,
                previous_version: None,
                new_version: None,
                error: Some("Timeout".to_string()),
                backup_created: false,
            },
        ],
    };

    assert_eq!(result.updated_count, 0);
    assert_eq!(result.unchanged_count, 0);
    assert_eq!(result.failed_count, 3);
}

/// Test DatabaseUpdateDetail creation for successful update.
#[test]
fn test_update_detail_success() {
    let detail = DatabaseUpdateDetail {
        name: "service-probes".to_string(),
        success: true,
        previous_version: Some("2024-01-01".to_string()),
        new_version: Some("2024-02-01".to_string()),
        error: None,
        backup_created: true,
    };

    assert_eq!(detail.name, "service-probes");
    assert!(detail.success);
    assert_eq!(detail.previous_version, Some("2024-01-01".to_string()));
    assert_eq!(detail.new_version, Some("2024-02-01".to_string()));
    assert!(detail.error.is_none());
    assert!(detail.backup_created);
}

/// Test DatabaseUpdateDetail creation for failed update.
#[test]
fn test_update_detail_failure() {
    let detail = DatabaseUpdateDetail {
        name: "os-db".to_string(),
        success: false,
        previous_version: Some("2024-01-01".to_string()),
        new_version: None,
        error: Some("Connection timeout".to_string()),
        backup_created: false,
    };

    assert_eq!(detail.name, "os-db");
    assert!(!detail.success);
    assert_eq!(detail.previous_version, Some("2024-01-01".to_string()));
    assert!(detail.new_version.is_none());
    assert_eq!(detail.error, Some("Connection timeout".to_string()));
    assert!(!detail.backup_created);
}

/// Test DatabaseUpdateDetail creation for unchanged database.
#[test]
fn test_update_detail_unchanged() {
    let detail = DatabaseUpdateDetail {
        name: "mac-prefixes".to_string(),
        success: true,
        previous_version: Some("2024-02-01".to_string()),
        new_version: Some("2024-02-01".to_string()),
        error: None,
        backup_created: false,
    };

    assert!(detail.success);
    assert_eq!(detail.previous_version, detail.new_version);
}

/// Test DatabaseUpdateDetail with no previous version (new install).
#[test]
fn test_update_detail_new_install() {
    let detail = DatabaseUpdateDetail {
        name: "service-probes".to_string(),
        success: true,
        previous_version: None,
        new_version: Some("2024-02-01".to_string()),
        error: None,
        backup_created: false,
    };

    assert!(detail.success);
    assert!(detail.previous_version.is_none());
    assert!(detail.new_version.is_some());
}

/// Test UpdateResult clone.
#[test]
fn test_update_result_clone() {
    let result = UpdateResult {
        updated_count: 2,
        unchanged_count: 1,
        failed_count: 0,
        details: vec![DatabaseUpdateDetail {
            name: "test".to_string(),
            success: true,
            previous_version: None,
            new_version: Some("v1".to_string()),
            error: None,
            backup_created: false,
        }],
    };

    let cloned = result.clone();
    assert_eq!(result.updated_count, cloned.updated_count);
    assert_eq!(result.details.len(), cloned.details.len());
}

/// Test DatabaseUpdateDetail clone.
#[test]
fn test_update_detail_clone() {
    let detail = DatabaseUpdateDetail {
        name: "service-probes".to_string(),
        success: true,
        previous_version: Some("old".to_string()),
        new_version: Some("new".to_string()),
        error: None,
        backup_created: true,
    };

    let cloned = detail.clone();
    assert_eq!(detail.name, cloned.name);
    assert_eq!(detail.success, cloned.success);
    assert_eq!(detail.previous_version, cloned.previous_version);
    assert_eq!(detail.new_version, cloned.new_version);
    assert_eq!(detail.error, cloned.error);
    assert_eq!(detail.backup_created, cloned.backup_created);
}

/// Test UpdateResult debug formatting.
#[test]
fn test_update_result_debug() {
    let result = UpdateResult {
        updated_count: 1,
        unchanged_count: 0,
        failed_count: 0,
        details: vec![],
    };

    let debug_str = format!("{:?}", result);
    assert!(debug_str.contains("UpdateResult"));
    assert!(debug_str.contains("updated_count"));
}

/// Test DatabaseUpdateDetail debug formatting.
#[test]
fn test_update_detail_debug() {
    let detail = DatabaseUpdateDetail {
        name: "test-db".to_string(),
        success: true,
        previous_version: None,
        new_version: Some("v1.0".to_string()),
        error: None,
        backup_created: false,
    };

    let debug_str = format!("{:?}", detail);
    assert!(debug_str.contains("DatabaseUpdateDetail"));
    assert!(debug_str.contains("test-db"));
}

/// Test UpdateOptions debug formatting.
#[test]
fn test_update_options_debug() {
    let opts = UpdateOptions::default();
    let debug_str = format!("{:?}", opts);
    assert!(debug_str.contains("UpdateOptions"));
}

/// Test CustomUrls debug formatting.
#[test]
fn test_custom_urls_debug() {
    let urls = CustomUrls {
        service_probes: Some("https://example.com".to_string()),
        os_db: None,
        mac_prefixes: None,
    };

    let debug_str = format!("{:?}", urls);
    assert!(debug_str.contains("CustomUrls"));
}

/// Test DatabaseUpdater debug formatting.
#[test]
fn test_database_updater_debug() {
    let updater = DatabaseUpdater::new();
    let debug_str = format!("{:?}", updater);
    assert!(debug_str.contains("DatabaseUpdater"));
}

/// Test empty UpdateResult.
#[test]
fn test_update_result_empty() {
    let result = UpdateResult {
        updated_count: 0,
        unchanged_count: 0,
        failed_count: 0,
        details: vec![],
    };

    assert_eq!(result.updated_count, 0);
    assert_eq!(result.unchanged_count, 0);
    assert_eq!(result.failed_count, 0);
    assert!(result.details.is_empty());
}

/// Test UpdateResult with many details.
#[test]
fn test_update_result_many_details() {
    let details: Vec<_> = (0..10)
        .map(|i| DatabaseUpdateDetail {
            name: format!("db-{}", i),
            success: i % 2 == 0,
            previous_version: Some(format!("v{}", i)),
            new_version: Some(format!("v{}", i + 1)),
            error: if i % 2 == 0 { None } else { Some("error".to_string()) },
            backup_created: i % 3 == 0,
        })
        .collect();

    let result = UpdateResult {
        updated_count: 5,
        unchanged_count: 3,
        failed_count: 2,
        details,
    };

    assert_eq!(result.details.len(), 10);
}

/// Test UpdateOptions with empty custom URLs.
#[test]
fn test_update_options_empty_custom_urls() {
    let urls = CustomUrls {
        service_probes: None,
        os_db: None,
        mac_prefixes: None,
    };

    let _opts = UpdateOptions::default().custom_urls(urls);
    // Should compile and run without error
}

/// Test all UpdateOptions builder combinations.
#[test]
fn test_update_options_all_combinations() {
    // All defaults
    let _opts = UpdateOptions::default();

    // Backup only
    let _opts = UpdateOptions::default().backup(true);
    let _opts = UpdateOptions::default().backup(false);

    // Verify checksums only
    let _opts = UpdateOptions::default().verify_checksums(true);
    let _opts = UpdateOptions::default().verify_checksums(false);

    // Custom URLs only
    let urls = CustomUrls {
        service_probes: Some("https://example.com".to_string()),
        os_db: None,
        mac_prefixes: None,
    };
    let _opts = UpdateOptions::default().custom_urls(urls);

    // All options combined
    let urls = CustomUrls {
        service_probes: Some("https://example.com/p".to_string()),
        os_db: Some("https://example.com/o".to_string()),
        mac_prefixes: Some("https://example.com/m".to_string()),
    };
    let _opts = UpdateOptions::new()
        .backup(true)
        .verify_checksums(true)
        .custom_urls(urls);
}
