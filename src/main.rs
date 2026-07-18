//! CLI entry point.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::process::ExitCode;

use intel_features::model::Detection;
use intel_features::probes::{self, Context, ContextOptions};
use intel_features::report::{Report, TextOptions};

const HELP: &str = "\
intel-features — detect Intel® processor and platform features

USAGE:
    intel-features [OPTIONS]

OPTIONS:
    -j, --json        Emit the report as JSON
    -v, --verbose     Show each probe's finding under every feature (text mode)
    -a, --all         Include features detected as absent (hidden by default)
        --load-msr-module
                      If root and /dev/cpu/0/msr is missing, run modprobe msr once
        --no-color    Disable ANSI colors
    -h, --help        Print this help
    -V, --version     Print version

EXIT CODES:
    0  ran successfully
    1  internal probe/report error
    2  bad arguments

TRADEMARKS:
    Intel and other Intel marks are trademarks of Intel Corporation or its subsidiaries.
    This independent project is not affiliated with or endorsed by Intel Corporation.
";

struct Args {
    json: bool,
    verbose: bool,
    show_absent: bool,
    color: Option<bool>,
    load_msr_module: bool,
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(code) => return code,
    };

    // Gather findings from every probe, aggregated per feature id.
    let ctx = Context::with_options(ContextOptions {
        load_msr_module: args.load_msr_module,
    });
    let mut results: HashMap<&'static str, Vec<Detection>> = HashMap::new();
    for probe in probes::all() {
        let source = probe.name();
        let covered = probe.feature_ids();
        let findings = match probe.detect(&ctx) {
            Ok(findings) => findings,
            Err(error) => {
                eprintln!("internal error: probe {} failed: {error}", probe.name());
                return ExitCode::from(1);
            }
        };
        for (id, det) in findings {
            if det.source != source || !covered.contains(&id) {
                eprintln!(
                    "internal error: probe {source} emitted undeclared or mismatched finding {id}"
                );
                return ExitCode::from(1);
            }
            results.entry(id).or_default().push(det);
        }
    }

    let identity = probes::cpuid::identity_with(&ctx);
    let system = probes::firmware::system_info_with(&ctx);
    let report = match Report::try_build(results, identity, system, ctx.privilege) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("internal error: {error}");
            return ExitCode::from(1);
        }
    };

    if args.json {
        println!("{}", report.to_json());
    } else {
        let color = args
            .color
            .unwrap_or_else(|| std::io::stdout().is_terminal());
        let opts = TextOptions {
            color,
            verbose: args.verbose,
            hide_absent: !args.show_absent,
        };
        print!("{}", report.render_text(opts));
    }

    ExitCode::SUCCESS
}

fn parse_args() -> Result<Args, ExitCode> {
    parse_args_from(std::env::args().skip(1))
}

fn parse_args_from(args_iter: impl IntoIterator<Item = String>) -> Result<Args, ExitCode> {
    let mut args = Args {
        json: false,
        verbose: false,
        show_absent: false,
        color: None,
        load_msr_module: false,
    };
    for arg in args_iter {
        match arg.as_str() {
            "-j" | "--json" => args.json = true,
            "-v" | "--verbose" => args.verbose = true,
            "-a" | "--all" => args.show_absent = true,
            "--no-color" => args.color = Some(false),
            "--color" => args.color = Some(true),
            "--load-msr-module" => args.load_msr_module = true,
            "-h" | "--help" => {
                print!("{HELP}");
                return Err(ExitCode::SUCCESS);
            }
            "-V" | "--version" => {
                println!("intel-features {}", env!("CARGO_PKG_VERSION"));
                return Err(ExitCode::SUCCESS);
            }
            other => {
                eprintln!("error: unknown argument '{other}'\n\n{HELP}");
                return Err(ExitCode::from(2));
            }
        }
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_module_loading_opt_in() {
        let args =
            parse_args_from(["--json".to_string(), "--load-msr-module".to_string()]).unwrap();
        assert!(args.json);
        assert!(args.load_msr_module);
    }

    #[test]
    fn module_loading_is_off_by_default() {
        let args = parse_args_from(Vec::<String>::new()).unwrap();
        assert!(!args.load_msr_module);
    }

    #[test]
    fn rejects_unknown_option() {
        assert!(parse_args_from(["--bogus".to_string()]).is_err());
    }
}
