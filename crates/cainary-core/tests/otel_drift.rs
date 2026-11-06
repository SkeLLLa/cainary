use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use cainary_core::rules::otel_catalog::{self, Attr, Export, Vendor};
use cainary_core::rules::otel_classify::{ClassifyError, classify};
use serde_json::Value;

// Add a documented exception only when a vendor intentionally exports a field
// that is not part of the checked catalog. Keys are record:<name>,
// <record-name>/<attribute-key>, or resource/<attribute-key>.
const IGNORE: &[(&str, &str, &str)] = &[];

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/otel-payloads")
}

fn vendor_dir_name(vendor: Vendor) -> &'static str {
    match vendor {
        Vendor::ClaudeCode => "claude-code-",
        Vendor::Codex => "codex-",
    }
}

fn vendor_label(vendor: Vendor) -> &'static str {
    match vendor {
        Vendor::ClaudeCode => "claude-code",
        Vendor::Codex => "codex",
    }
}

fn vendors() -> [Vendor; 2] {
    [Vendor::ClaudeCode, Vendor::Codex]
}

fn fixture_dirs() -> Vec<(Vendor, PathBuf, String)> {
    let root = fixture_root();
    let mut dirs = Vec::new();
    for entry in fs::read_dir(root).expect("OTel fixture directory exists") {
        let path = entry.expect("fixture directory entry").path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        for vendor in vendors() {
            if let Some(version) = name.strip_prefix(vendor_dir_name(vendor)) {
                dirs.push((vendor, path.clone(), version.to_owned()));
            }
        }
    }
    dirs
}

fn version_parts(version: &str) -> Vec<u64> {
    version
        .split('.')
        .map(|part| part.parse().expect("numeric fixture version component"))
        .collect()
}

fn export_for_file(file: &str) -> Option<Export> {
    match file {
        "logs.json" => Some(Export::Logs),
        "metrics.json" => Some(Export::Metrics),
        "traces.json" => Some(Export::Traces),
        _ => None,
    }
}

fn is_ignored(vendor: &str, key: &str) -> bool {
    IGNORE
        .iter()
        .any(|(ignored_vendor, ignored_key, _why)| *ignored_vendor == vendor && *ignored_key == key)
}

fn attr_accepts(attr: &Attr, export: Export) -> bool {
    match attr.only {
        None => true,
        Some(exports) => {
            exports.contains(&export)
                || (matches!(export, Export::Logs | Export::Traces)
                    && exports.contains(&Export::Beta))
        }
    }
}

fn key_pattern_matches(pattern: &str, key: &str) -> bool {
    if pattern == "*" {
        key == "*"
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        key.starts_with(prefix)
    } else if let Some(suffix) = pattern.strip_prefix('*') {
        key.ends_with(suffix)
    } else {
        pattern == key
    }
}

#[test]
fn catalog_versions_match_the_latest_fixture_directory() {
    let dirs = fixture_dirs();
    for vendor in vendors() {
        let latest = dirs
            .iter()
            .filter(|(dir_vendor, _, _)| *dir_vendor == vendor)
            .max_by_key(|(_, _, version)| version_parts(version))
            .unwrap_or_else(|| panic!("missing fixture directory for {}", vendor_label(vendor)));
        assert_eq!(
            otel_catalog::catalog(vendor).version,
            latest.2,
            "catalog version must match newest {} fixture directory",
            vendor_label(vendor)
        );
    }
}

#[test]
fn every_fixture_record_and_attribute_is_catalogued() {
    let mut unknown = BTreeSet::new();
    for (vendor, directory, _) in fixture_dirs() {
        let vendor_name = vendor_label(vendor);
        for entry in fs::read_dir(&directory).expect("fixture vendor directory exists") {
            let path = entry.expect("fixture file entry").path();
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(export) = export_for_file(file_name) else {
                continue;
            };
            let data = fs::read(&path).expect("read sanitized OTLP fixture");
            let doc: Value = serde_json::from_slice(&data).expect("sanitized OTLP fixture JSON");
            let classified = classify(export, &doc).unwrap_or_else(|error| {
                panic!(
                    "{} {} fixture did not classify: {error:?}",
                    vendor_name, file_name
                )
            });

            for resource in &classified.resources {
                for field in &resource.attrs {
                    if field.attr.is_none() {
                        let key = format!("resource/{}", field.key);
                        if !is_ignored(vendor_name, &key) {
                            unknown.insert(format!("{vendor_name} {file_name} {key}"));
                        }
                    }
                }
                for scope in &resource.scopes {
                    for record in &scope.records {
                        if record.item.is_none() {
                            let key = format!("record:{}", record.name);
                            if !is_ignored(vendor_name, &key) {
                                unknown.insert(format!("{vendor_name} {file_name} {key}"));
                            }
                        }
                        for field in &record.fields {
                            if field.attr.is_none() {
                                let key = format!("{}/{}", record.name, field.key);
                                if !is_ignored(vendor_name, &key) {
                                    unknown.insert(format!("{vendor_name} {file_name} {key}"));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(
        unknown.is_empty(),
        "OTel fixture drift:\n{}",
        unknown.into_iter().collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn every_observed_catalog_item_and_attribute_appears_in_its_fixture() {
    for (vendor, directory, _) in fixture_dirs() {
        let catalog = otel_catalog::catalog(vendor);
        let mut fixture_exports = Vec::new();
        let mut observed_items = Vec::new();
        let mut observed_global_keys = Vec::new();
        let mut observed_item_fields = Vec::new();

        for entry in fs::read_dir(&directory).expect("fixture vendor directory exists") {
            let path = entry.expect("fixture file entry").path();
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(export) = export_for_file(file_name) else {
                continue;
            };
            fixture_exports.push(export);
            let doc: Value =
                serde_json::from_slice(&fs::read(&path).expect("read sanitized OTLP fixture"))
                    .expect("sanitized OTLP fixture JSON");
            let classified = classify(export, &doc).expect("fixture classifies");
            for resource in &classified.resources {
                for field in &resource.attrs {
                    observed_global_keys.push((export, field.key.clone()));
                }
                for scope in &resource.scopes {
                    for record in &scope.records {
                        if let Some(item) = record.item {
                            observed_items.push((export, record.kind, item as *const _ as usize));
                        }
                        for field in &record.fields {
                            observed_global_keys.push((export, field.key.clone()));
                            if let Some(item) = record.item {
                                observed_item_fields.push((
                                    export,
                                    item as *const _ as usize,
                                    field.key.clone(),
                                ));
                            }
                        }
                    }
                }
            }
        }

        fixture_exports.sort_by_key(|export| match export {
            Export::Logs => 0,
            Export::Metrics => 1,
            Export::Traces => 2,
            Export::Beta => 3,
        });
        fixture_exports.dedup();

        for export in &fixture_exports {
            for item in catalog.items.iter().filter(|item| item.observed) {
                let Some(found) = catalog.item(item.name, *export) else {
                    continue;
                };
                if !std::ptr::eq(found, item) {
                    continue;
                }
                let appears =
                    observed_items.contains(&(*export, item.kind, item as *const _ as usize));
                assert!(
                    appears,
                    "{} observed item {:?} is absent from its {} fixture",
                    vendor_label(vendor),
                    item.name,
                    export_name(*export)
                );
            }

            let global_attrs = catalog
                .identity
                .iter()
                .chain(catalog.resource)
                .chain(catalog.common);
            for attr in global_attrs.filter(|attr| attr.observed && attr_accepts(attr, *export)) {
                assert!(
                    observed_global_keys
                        .iter()
                        .any(|(found_export, key)| *found_export == *export
                            && key_pattern_matches(attr.key, key)),
                    "{} observed {} attribute {:?} is absent from its version fixture",
                    vendor_label(vendor),
                    export_name(*export),
                    attr.key
                );
            }

            for item in catalog.items.iter().filter(|item| item.observed) {
                let Some(found) = catalog.item(item.name, *export) else {
                    continue;
                };
                if !std::ptr::eq(found, item) {
                    continue;
                }
                for attr in item
                    .attrs
                    .iter()
                    .filter(|attr| attr.observed && attr_accepts(attr, *export))
                {
                    assert!(
                        observed_item_fields
                            .iter()
                            .any(|(found_export, item_ptr, key)| {
                                *found_export == *export
                                    && *item_ptr == item as *const _ as usize
                                    && key_pattern_matches(attr.key, key)
                            }),
                        "{} observed {} attribute {:?} on {:?} is absent from its version fixture",
                        vendor_label(vendor),
                        export_name(*export),
                        attr.key,
                        item.name
                    );
                }
            }
        }
    }
}

fn export_name(export: Export) -> &'static str {
    match export {
        Export::Logs => "logs",
        Export::Metrics => "metrics",
        Export::Traces => "traces",
        Export::Beta => "beta",
    }
}

#[test]
fn classifier_errors_are_fixed_categories() {
    assert_eq!(
        classify(Export::Logs, &Value::Null).unwrap_err(),
        ClassifyError::NotObject
    );
    assert_eq!(
        classify(Export::Logs, &serde_json::json!({ "secret": "not echoed" })).unwrap_err(),
        ClassifyError::MissingRoot("resourceLogs")
    );
    assert_eq!(
        classify(
            Export::Logs,
            &serde_json::json!({ "resourceLogs": ["bad"] })
        )
        .unwrap_err(),
        ClassifyError::BadShape { index: Some(0) }
    );
}

#[test]
fn summaries_are_serializable_for_json_lines() {
    let doc = serde_json::json!({ "resourceLogs": [] });
    let classified = classify(Export::Logs, &doc).expect("valid empty OTLP logs");
    let summary = cainary_core::rules::otel_classify::summarize(&classified);
    let encoded = serde_json::to_value(summary).expect("summary serializes");
    assert_eq!(encoded["identity"], serde_json::json!([]));
    assert_eq!(encoded["resource"], serde_json::json!([]));
    assert_eq!(encoded["records"], serde_json::json!([]));
}
