//! CLI entry point.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::process::ExitCode;

use intel_features::model::Detection;
use intel_features::probes::{self, Context};
use intel_features::report::{Report, TextOptions};

const HELP: &str = "\
intel-features — detect Intel CPU and platform features

USAGE:
    intel-features [OPTIONS]

OPTIONS:
    -j, --json        Emit the report as JSON
    -v, --verbose     Show each probe's finding under every feature (text mode)
    -a, --all         Include features detected as absent (hidden by default)
        --no-color    Disable ANSI colors
    -h, --help        Print this help
    -V, --version     Print version

EXIT CODES:
    0  ran successfully
    2  bad arguments
";

struct Args {
    json: bool,
    verbose: bool,
    show_absent: bool,
    color: Option<bool>,
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(code) => return code,
    };

    // Gather findings from every probe, aggregated per feature id.
    let ctx = Context::detect();
    let mut results: HashMap<&'static str, Vec<Detection>> = HashMap::new();
    for probe in probes::all() {
        for (id, det) in probe.detect(&ctx) {
            results.entry(id).or_default().push(det);
        }
    }

    let identity = probes::cpuid::identity();
    let report = Report::build(results, identity, ctx.privilege);

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
    let mut args = Args {
        json: false,
        verbose: false,
        show_absent: false,
        color: None,
    };
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "-j" | "--json" => args.json = true,
            "-v" | "--verbose" => args.verbose = true,
            "-a" | "--all" => args.show_absent = true,
            "--no-color" => args.color = Some(false),
            "--color" => args.color = Some(true),
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
