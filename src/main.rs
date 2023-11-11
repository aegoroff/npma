use clap::{command, ArgMatches, Command};
use clap_complete::{generate, Shell};
use color_eyre::eyre::Result;
use npma::{analyze, console, filter::Criteria, read_strings_from_file, read_strings_from_stdin};
use std::io;

#[macro_use]
extern crate clap;

const PATH: &str = "PATH";
const EXCLUDE_HELP: &str = "Exclude requests that match this pattern";
const INCLUDE_HELP: &str = "Include only requests that match this pattern";

struct ScanConfiguration {
    filter: Criteria,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let app = build_cli();
    let matches = app.get_matches();

    match matches.subcommand() {
        Some(("f", cmd)) => scan_file(cmd).await,
        Some(("i", cmd)) => scan_stdin(cmd).await,
        Some(("completion", cmd)) => {
            print_completions(cmd);
            Ok(())
        }
        _ => Ok(()),
    }
}

async fn scan_file(cmd: &ArgMatches) -> Result<()> {
    if let Some(path) = cmd.get_one::<String>(PATH) {
        let config = configure_scan(cmd);
        let entries = read_strings_from_file(path).await?;
        let analyzed = analyze(&entries, &config.filter);
        console::print(analyzed.into_iter());
    }
    Ok(())
}

async fn scan_stdin(cmd: &ArgMatches) -> Result<()> {
    let config = configure_scan(cmd);
    let entries = read_strings_from_stdin().await;
    let analyzed = analyze(&entries, &config.filter);
    console::print(analyzed.into_iter());
    Ok(())
}

/// Creates application configuration from parsed command line
fn configure_scan(cmd: &ArgMatches) -> ScanConfiguration {
    let include_pattern = cmd.get_one::<String>("include");
    let exclude_pattern = cmd.get_one::<String>("exclude");

    let filter = Criteria::new(include_pattern, exclude_pattern);
    ScanConfiguration { filter }
}

fn build_cli() -> Command {
    #![allow(non_upper_case_globals)]
    command!(crate_name!())
        .arg_required_else_help(true)
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        .subcommand(file_cmd())
        .subcommand(stdin_cmd())
        .subcommand(completion_cmd())
}

fn print_completions(matches: &ArgMatches) {
    let mut cmd = build_cli();
    let bin_name = cmd.get_name().to_string();
    if let Some(generator) = matches.get_one::<Shell>("generator") {
        generate(*generator, &mut cmd, bin_name, &mut io::stdout());
    }
}

fn file_cmd() -> Command {
    Command::new("f")
        .aliases(["file"])
        .about("Analyse file specified")
        .arg(
            arg!([PATH])
                .help("Sets file path to analyze")
                .required(true),
        )
        .arg(
            arg!(-e --exclude <PATTERN>)
                .required(false)
                .help(EXCLUDE_HELP),
        )
        .arg(
            arg!(-i --include <PATTERN>)
                .required(false)
                .help(INCLUDE_HELP),
        )
}

fn stdin_cmd() -> Command {
    Command::new("i")
        .aliases(["stdin"])
        .about("Analyse data from standard input")
        .arg(
            arg!(-e --exclude <PATTERN>)
                .required(false)
                .help(EXCLUDE_HELP),
        )
        .arg(
            arg!(-i --include <PATTERN>)
                .required(false)
                .help(INCLUDE_HELP),
        )
}

fn completion_cmd() -> Command {
    Command::new("completion")
        .about("Generate the autocompletion script for the specified shell")
        .arg(
            arg!([generator])
                .value_parser(value_parser!(Shell))
                .required(true)
                .index(1),
        )
}
