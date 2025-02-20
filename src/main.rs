use chrono::Datelike;
use clap::{Arg, ArgMatches, Command, command};
use clap_complete::{Shell, generate};
use color_eyre::eyre::Result;
use core::hash::Hash;
use indicatif::HumanBytes;
use itertools::Itertools;
use npma::{
    GroupedParameter, LogEntry, LogParameter,
    console::{self, print_grouped},
    convert,
    filter::Criteria,
    read_strings_from_file, read_strings_from_stdin,
};
use std::{fmt::Display, io};

#[macro_use]
extern crate clap;

#[cfg(target_os = "linux")]
use mimalloc::MiMalloc;

#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

const PATH: &str = "PATH";
const EXCLUDE_HELP: &str = "Exclude requests that match this pattern";
const INCLUDE_HELP: &str = "Include only requests that match this pattern";
const FILTER_PARAMETER_ARG: &str = "parameter";

struct ScanConfiguration {
    filter: Criteria,
    parameter: Option<LogParameter>,
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
        let converted = convert(entries, &config.filter, config.parameter).await;
        print_converted(cmd, converted);
    }
    Ok(())
}

async fn scan_stdin(cmd: &ArgMatches) -> Result<()> {
    let config = configure_scan(cmd);
    let entries = read_strings_from_stdin();
    let converted = convert(entries, &config.filter, config.parameter).await;

    print_converted(cmd, converted);
    Ok(())
}

fn print_converted(cmd: &ArgMatches, converted: Vec<LogEntry>) {
    match cmd.subcommand() {
        Some(("g", cmd)) => {
            let limit = cmd.get_one::<usize>("top");
            if let Some(param) = cmd.get_one::<LogParameter>(FILTER_PARAMETER_ARG) {
                match param {
                    LogParameter::Time => group_by(*param, limit, &converted, |e| e.timestamp),
                    LogParameter::Date => group_by(*param, limit, &converted, |e| {
                        format!(
                            "{}-{:02}-{:02}",
                            e.timestamp.year(),
                            e.timestamp.month(),
                            e.timestamp.day()
                        )
                    }),
                    LogParameter::Agent => group_by(*param, limit, &converted, |e| e.agent.clone()),
                    LogParameter::ClientIp => {
                        group_by(*param, limit, &converted, |e| e.clientip.clone());
                    }
                    LogParameter::Status => group_by(*param, limit, &converted, |e| e.status),
                    LogParameter::Method => {
                        group_by(*param, limit, &converted, |e| e.method.clone());
                    }
                    LogParameter::Schema => {
                        group_by(*param, limit, &converted, |e| e.schema.clone());
                    }
                    LogParameter::Request => {
                        group_by(*param, limit, &converted, |e| e.request.clone());
                    }
                    LogParameter::Referrer => {
                        group_by(*param, limit, &converted, |e| e.referrer.clone());
                    }
                }
            }
        }
        Some(("t", _)) => {
            let total_bytes = converted.iter().fold(0, |acc, x| acc + x.length);
            let total_bytes = HumanBytes(total_bytes);
            println!("Total traffic: {total_bytes}");
        }
        _ => console::print(converted.into_iter()),
    }
}

fn group_by<T, F>(parameter: LogParameter, limit: Option<&usize>, data: &[LogEntry], f: F)
where
    T: Default + Display + Hash + Eq,
    F: Fn(&LogEntry) -> T,
{
    let grouped = data
        .iter()
        .into_group_map_by(|e| f(e))
        .into_iter()
        .map(|(parameter, grp)| GroupedParameter {
            parameter,
            count: grp.len(),
        })
        .collect();
    print_grouped(parameter, grouped, limit);
}

/// Creates application configuration from parsed command line
fn configure_scan(cmd: &ArgMatches) -> ScanConfiguration {
    let include_pattern = cmd.get_one::<String>("include");
    let exclude_pattern = cmd.get_one::<String>("exclude");
    let parameter = cmd.get_one::<LogParameter>(FILTER_PARAMETER_ARG).copied();

    let filter = Criteria::new(include_pattern, exclude_pattern);
    ScanConfiguration { filter, parameter }
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
        .arg(exclude_arg())
        .arg(include_arg())
        .arg(parameter_arg())
        .subcommand(grouping_cmd())
        .subcommand(traffic_cmd())
}

fn stdin_cmd() -> Command {
    Command::new("i")
        .aliases(["stdin"])
        .about("Analyse data from standard input")
        .arg(exclude_arg())
        .arg(include_arg())
        .arg(parameter_arg())
        .subcommand(grouping_cmd())
        .subcommand(traffic_cmd())
}

fn exclude_arg() -> Arg {
    arg!(-e --exclude <PATTERN>)
        .required(false)
        .requires(FILTER_PARAMETER_ARG)
        .help(EXCLUDE_HELP)
}

fn include_arg() -> Arg {
    arg!(-i --include <PATTERN>)
        .required(false)
        .requires(FILTER_PARAMETER_ARG)
        .help(INCLUDE_HELP)
}

fn parameter_arg() -> Arg {
    arg!(-p --parameter <PARAMETER>)
        .value_parser(value_parser!(LogParameter))
        .help("Filter parameter")
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

fn grouping_cmd() -> Command {
    Command::new("g")
        .aliases(["group"])
        .about("Groups log entries using parameter specified. After grouping the number of each group items will be displayed")
        .arg(
            arg!(-t --top <NUMBER>)
                .required(false)
                .value_parser(value_parser!(usize))
                .help("Output only specified number of grouped items"),
        )
        .arg(
            arg!([parameter])
                .value_parser(value_parser!(LogParameter))
                .required(true)
                .index(1),
        )
}

fn traffic_cmd() -> Command {
    Command::new("t")
        .aliases(["traffic"])
        .about("Sums all log entries length to calculate all data size passed through proxy")
}
