use std::env;
use std::path::PathBuf;
use std::str::FromStr;

const INVALID_INPUT_ERROR: i32 = 1;
pub const DEFAULT_CHECK_PATH: &str = "/usr/libexec/cis-checks/bottlerocket";

#[derive(Clone, Debug)]
pub enum Format {
    Text,
    Json,
}

impl FromStr for Format {
    type Err = ();

    fn from_str(value: &str) -> Result<Format, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "text" => Ok(Format::Text),
            "json" => Ok(Format::Json),
            _ => Err(()),
        }
    }
}

/// Command line arguments for the bloodhound program.
#[derive(Debug)]
pub struct Arguments {
    /// Path to the directory containing checker binaries [default: {DEFAULT_CHECK_PATH}]
    pub check_dir: Option<PathBuf>,
    /// Format of the output
    pub format: Format,
    /// The CIS benchmark compliance level to check
    pub level: u8,
    /// Write output to a file at given path [default: stdout]
    pub output: Option<PathBuf>,
}

/// Prints a usage message in the event a bad arg is passed.
fn usage() -> ! {
    eprintln!(
        "Command line arguments for the bloodhound program

    Usage: bloodhound [OPTIONS]

    Options:
      -c, --checks <CHECK_DIR>  Path to the directory containing checker binaries [default: {}]
      -f, --format <FORMAT>     Format of the output [default: text] [possible values: text, json]
      -l, --level <LEVEL>       The CIS benchmark compliance level to check [default: 1]
      -o, --output <OUTPUT>     Write output to a file at given path [default: stdout]
      -h, --help                Print help",
        DEFAULT_CHECK_PATH
    );
    std::process::exit(INVALID_INPUT_ERROR);
}

/// Prints a more specific message before exiting through usage().
fn usage_msg(msg: &str) -> ! {
    eprintln!("{}\n", msg);
    usage();
}

/// Parses the command line arguments.
pub fn parse_args() -> Arguments {
    let mut arguments = Arguments {
        check_dir: Some(PathBuf::from(DEFAULT_CHECK_PATH)),
        format: Format::Text,
        level: 1,
        output: None,
    };

    let args = env::args();
    let mut iter = args.skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_ref() {
            "-c" | "--checks" => {
                arguments.check_dir = Some(
                    iter.next()
                        .unwrap_or_else(|| usage_msg("Did not give argument to --checks"))
                        .into(),
                );
            }
            "-f" | "--format" => {
                arguments.format = Format::from_str(
                    iter.next()
                        .unwrap_or_else(|| usage_msg("Did not give argument to --format"))
                        .as_str(),
                )
                .unwrap_or_else(|_| usage_msg("Valid format options are 'text' or 'json'"));
            }
            "-l" | "--level" => {
                let level = u8::from_str(
                    iter.next()
                        .unwrap_or_else(|| usage_msg("Did not give argument to --level"))
                        .as_str(),
                )
                .unwrap_or_else(|_| usage_msg("Valid levels are either 1 or 2"));
                if !(1..=2).contains(&level) {
                    usage_msg("Level must be either 1 or 2");
                }
                arguments.level = level;
            }
            "-o" | "--output" => {
                arguments.output = Some(
                    iter.next()
                        .unwrap_or_else(|| usage_msg("Did not give argument to --output"))
                        .into(),
                )
            }
            _ => usage(),
        }
    }

    arguments
}
