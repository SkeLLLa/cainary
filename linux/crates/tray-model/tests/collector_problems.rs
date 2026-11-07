//! Specific settings problems and structured startup failures.

use cainary_tray_model::collector::{self, Line, Model, decode_line};
use cainary_tray_model::settings::CollectorSettings;

fn tls(hosts: &[&str]) -> CollectorSettings {
    CollectorSettings {
        tls: true,
        tls_hosts: hosts.iter().map(|host| (*host).into()).collect(),
        ..CollectorSettings::default()
    }
}

#[test]
fn problem_tls_no_host() {
    let settings = tls(&[]);
    let problem = settings.problem().unwrap();
    assert_eq!(problem.code, "tls-no-host");
    assert_eq!(
        problem.message,
        "HTTPS takeover needs at least one host name."
    );
    assert_eq!(
        collector::child_args(&settings),
        Err(problem.message.clone())
    );
    assert_eq!(collector::config_stdin(&settings), Err(problem.message));
}

#[test]
fn problem_tls_bad_host() {
    let problem = tls(&["otel.example.test", "*.example.com"])
        .problem()
        .unwrap();
    assert_eq!(problem.code, "tls-bad-host");
    assert!(
        problem.message.contains("*.example.com"),
        "{}",
        problem.message
    );
}

#[test]
fn problem_port_range() {
    let mut settings = CollectorSettings {
        port: 0,
        ..CollectorSettings::default()
    };
    assert_eq!(settings.problem().unwrap().code, "port-range");
    settings = tls(&["otel.example.test"]);
    settings.tls_port = 0;
    assert_eq!(settings.problem().unwrap().code, "port-range");
}

#[test]
fn low_ports_accepted() {
    for port in [1, 80, 443] {
        let mut settings = CollectorSettings {
            port,
            ..CollectorSettings::default()
        };
        assert_eq!(settings.problem(), None, "port {port}");
        settings = tls(&["otel.example.test"]);
        settings.tls_port = port;
        assert_eq!(settings.problem(), None, "tls port {port}");
        assert!(collector::child_args(&settings).is_ok());
    }
}

#[test]
fn valid_matches_problem() {
    let cases = [
        CollectorSettings::default(),
        tls(&[]),
        tls(&["otel.example.test"]),
        CollectorSettings {
            port: 0,
            ..CollectorSettings::default()
        },
    ];
    for settings in cases {
        assert_eq!(settings.valid(), settings.problem().is_none());
    }
}

const HELLO: &str =
    r#"{"v":1,"type":"hello","endpoint":"http://127.0.0.1:4318","mode":"debug","setup":{}}"#;

fn error_line(extra: &str) -> String {
    format!(
        r#"{{"v":1,"type":"error","ts":"2026-11-07T12:00:00Z","source":"listen","message":"Permission denied"{extra}}}"#
    )
}

#[test]
fn error_line_with_code_and_port() {
    let line = error_line(r#","code":"port-privileged","port":443"#);
    let Ok(Line::Error(error)) = decode_line(&line) else {
        panic!("not an error line");
    };
    assert_eq!(error.code.as_deref(), Some("port-privileged"));
    assert_eq!(error.port, Some(443));
}

#[test]
fn error_line_without_code_still_decodes() {
    let Ok(Line::Error(error)) = decode_line(&error_line("")) else {
        panic!("not an error line");
    };
    assert_eq!(error.code, None);
    assert_eq!(error.port, None);
    assert_eq!(error.message.as_deref(), Some("Permission denied"));
}

#[test]
fn pre_hello_error_becomes_failure() {
    let mut model = Model::default();
    model.starting();
    model.accept(error_line(r#","code":"port-privileged","port":443"#));
    model.exited(Some(1), "");
    let view = serde_json::to_value(model.view()).unwrap();
    assert_eq!(view["state"], "stopped");
    assert_eq!(view["message"], "Stopped: Permission denied");
    assert_eq!(
        view["failure"],
        serde_json::json!({"code": "port-privileged", "message": "Permission denied", "port": 443})
    );
}

#[test]
fn startup_error_beats_stderr() {
    let mut model = Model::default();
    model.starting();
    model.accept(error_line(r#","code":"port-in-use""#));
    model.exited(Some(1), "\nfirst stderr line\nsecond");
    let view = model.view();
    let failure = view.failure.unwrap();
    assert_eq!(failure.message, "Permission denied");
    assert_eq!(failure.code.as_deref(), Some("port-in-use"));
    assert_eq!(view.stderr_tail, "\nfirst stderr line\nsecond");

    // Without a startup error the first stderr line is used; an error after hello isn't one.
    let mut model = Model::default();
    model.starting();
    model.accept(HELLO.into());
    model.accept(error_line(""));
    model.exited(Some(1), "boom\nmore");
    let failure = model.view().failure.unwrap();
    assert_eq!((failure.code, failure.message.as_str()), (None, "boom"));
}
