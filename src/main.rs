use clap::{command, ArgMatches, Command};
use clap_complete::{generate, Shell};
use color_eyre::eyre::Result;
use core::hash::Hash;
use indicatif::HumanBytes;
use itertools::Itertools;
use npma::{
    analyze,
    console::{self, print_groupped},
    filter::Criteria,
    read_strings_from_file, read_strings_from_stdin, GrouppedParameter, Groupping, LogEntry,
};
use std::{fmt::Display, io};

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
        print_analyzed(cmd, analyzed);
    }
    Ok(())
}

async fn scan_stdin(cmd: &ArgMatches) -> Result<()> {
    let config = configure_scan(cmd);
    let entries = read_strings_from_stdin().await;
    let analyzed = analyze(&entries, &config.filter);

    print_analyzed(cmd, analyzed);
    Ok(())
}

fn print_analyzed(cmd: &ArgMatches, analyzed: Vec<LogEntry>) {
    match cmd.subcommand() {
        Some(("g", cmd)) => {
            let limit = cmd.get_one::<usize>("top");
            if let Some(param) = cmd.get_one::<Groupping>("parameter") {
                match param {
                    Groupping::Time => group_by(*param, limit, &analyzed, |e| e.timestamp),
                    Groupping::Agent => group_by(*param, limit, &analyzed, |e| e.agent.clone()),
                    Groupping::ClientIp => {
                        group_by(*param, limit, &analyzed, |e| e.clientip.clone())
                    }
                    Groupping::Status => group_by(*param, limit, &analyzed, |e| e.status),
                    Groupping::Method => group_by(*param, limit, &analyzed, |e| e.method.clone()),
                    Groupping::Schema => group_by(*param, limit, &analyzed, |e| e.schema.clone()),
                    Groupping::Request => group_by(*param, limit, &analyzed, |e| e.request.clone()),
                    Groupping::Referrer => {
                        group_by(*param, limit, &analyzed, |e| e.referrer.clone())
                    }
                }
            }
        }
        Some(("t", _)) => {
            let total_bytes = analyzed.iter().fold(0, |acc, x| acc + x.length);
            let total_bytes = HumanBytes(total_bytes);
            println!("Total traffic: {total_bytes}");
        }
        _ => console::print(analyzed.into_iter()),
    }
}

fn group_by<T, F>(parameter: Groupping, limit: Option<&usize>, data: &[LogEntry], f: F)
where
    T: Default + Display + Hash + Eq,
    F: Fn(&LogEntry) -> T,
{
    let groupped = data
        .iter()
        .into_group_map_by(|e| f(e))
        .into_iter()
        .map(|(parameter, grp)| GrouppedParameter {
            parameter,
            count: grp.len(),
        })
        .collect();
    print_groupped(parameter, groupped, limit);
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
        .subcommand(groupping_cmd())
        .subcommand(traffic_cmd())
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
        .subcommand(groupping_cmd())
        .subcommand(traffic_cmd())
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

fn groupping_cmd() -> Command {
    Command::new("g")
        .aliases(["group"])
        .about("Groups log entries using parameter specified. After grouping the number of each group items will be displayed")
        .arg(
            arg!(-t --top <NUMBER>)
                .required(false)
                .value_parser(value_parser!(usize))
                .help("Output only specified number of groupped items"),
        )
        .arg(
            arg!([parameter])
                .value_parser(value_parser!(Groupping))
                .required(true)
                .index(1),
        )
}

fn traffic_cmd() -> Command {
    Command::new("t")
        .aliases(["traffic"])
        .about("Sums all log entries length to caclulate all data size passed through proxy")
}
