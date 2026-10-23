mod app;
mod bridge;
mod controller;
mod diagnostics;
mod env_defaults;
mod placement;
mod selftest;
mod signals;
mod tray_icons;
mod ui;
mod wlprobe;

use std::process::ExitCode;

#[derive(Debug, Default, PartialEq, Eq)]
struct Options {
    /// Only the tray icon, whatever the settings say.
    background: bool,
    /// Launched at login: the "Start minimized" setting decides.
    autostart: bool,
    details: Option<Option<String>>,
    dev: bool,
    self_test: bool,
    verbose: bool,
}

pub fn run() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--version") {
        println!("cainary-tray {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    let options = match parse_args(&args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("cainary-tray: {error}");
            eprintln!(
                "usage: cainary-tray [--background | --autostart] [--details [entry]] [--self-test] [--dev] [--verbose]"
            );
            return ExitCode::from(2);
        }
    };

    diagnostics::set_verbose(options.verbose);
    let result = if options.self_test {
        selftest::run()
    } else {
        app::run(&options)
    };
    match result {
        Ok(code) => ExitCode::from(code as u8),
        Err(error) => {
            eprintln!("cainary-tray: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut options = Options::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--version" => {}
            "--background" => options.background = true,
            "--autostart" => options.autostart = true,
            "--dev" => options.dev = true,
            "--self-test" => options.self_test = true,
            "--verbose" => options.verbose = true,
            "--details" => {
                let entry = args
                    .get(index + 1)
                    .filter(|arg| !arg.starts_with('-'))
                    .cloned();
                if entry.is_some() {
                    index += 1;
                }
                options.details = Some(entry);
            }
            other => return Err(format!("unknown option {other}")),
        }
        index += 1;
    }
    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::{Options, parse_args};

    #[test]
    fn parses_background_and_dev() {
        assert_eq!(
            parse_args(&["--background".into(), "--dev".into()]).unwrap(),
            Options {
                background: true,
                dev: true,
                ..Options::default()
            }
        );
    }

    #[test]
    fn parses_autostart() {
        assert_eq!(
            parse_args(&["--autostart".into()]).unwrap(),
            Options {
                autostart: true,
                ..Options::default()
            }
        );
    }

    #[test]
    fn parses_optional_details_entry() {
        assert_eq!(
            parse_args(&["--details".into(), "finding-1".into()]).unwrap(),
            Options {
                details: Some(Some("finding-1".into())),
                ..Options::default()
            }
        );
        assert_eq!(
            parse_args(&["--details".into()]).unwrap(),
            Options {
                details: Some(None),
                ..Options::default()
            }
        );
    }
}
