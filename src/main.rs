use clap::{
    Arg, ArgMatches, Command, arg, command, crate_authors, crate_description, crate_name,
    crate_version, value_parser,
};
use clap_complete::{Shell, generate};
use color_eyre::eyre::Result;
use indicatif::HumanBytes;
use npma::{
    GroupedParameter, LogEntry, LogParameter,
    console::{self, print_grouped},
    convert,
    filter::Criteria,
    read_strings_from_file, read_strings_from_stdin,
};
use std::io;
use std::{borrow::Cow, collections::HashMap, pin::pin};
use tokio_stream::{self, Stream, StreamExt};

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
        let entries = read_strings_from_file(path).await?;
        scan(pin!(entries), cmd).await?;
    }
    Ok(())
}

async fn scan_stdin(cmd: &ArgMatches) -> Result<()> {
    let entries = read_strings_from_stdin();
    scan(entries, cmd).await
}

async fn scan(entries: impl Stream<Item = String> + Unpin, cmd: &ArgMatches) -> Result<()> {
    let config = configure_scan(cmd);
    let stream = convert(entries, &config.filter, config.parameter);
    let stream = pin!(stream);
    print_converted(cmd, stream).await;
    Ok(())
}

async fn print_converted(cmd: &ArgMatches, entries: impl Stream<Item = LogEntry> + Unpin) {
    match cmd.subcommand() {
        Some(("g", cmd)) => handle_group(cmd, entries).await,
        Some(("t", _)) => handle_traffic(entries).await,
        _ => console::print(entries).await,
    }
}

async fn handle_traffic(mut entries: impl Stream<Item = LogEntry> + Unpin) {
    let mut total_bytes: u64 = 0;
    while let Some(e) = entries.next().await {
        total_bytes += e.length;
    }
    println!("Total traffic: {}", HumanBytes(total_bytes));
}

async fn handle_group(cmd: &ArgMatches, stream: impl Stream<Item = LogEntry> + Unpin) {
    let collected: Vec<LogEntry> = stream.collect().await;
    let limit = cmd.get_one::<usize>("top");
    if let Some(param) = cmd.get_one::<LogParameter>(FILTER_PARAMETER_ARG) {
        group_by(*param, limit, &collected, |e| param.extract(e));
    }
}

fn group_by<F>(parameter: LogParameter, limit: Option<&usize>, data: &[LogEntry], f: F)
where
    F: Fn(&LogEntry) -> Cow<'_, str>,
{
    let mut counts: HashMap<Cow<'_, str>, u64> = HashMap::new();
    for entry in data {
        *counts.entry(f(entry)).or_insert(0) += 1;
    }

    let grouped = counts
        .into_iter()
        .map(|(parameter, count)| GroupedParameter { parameter, count });

    print_grouped(parameter, grouped, limit);
}
/// Creates application configuration from parsed command line
fn configure_scan(cmd: &ArgMatches) -> ScanConfiguration {
    let include_pattern = cmd.get_one::<String>("include");
    let exclude_pattern = cmd.get_one::<String>("exclude");
    let parameter = cmd.get_one::<LogParameter>(FILTER_PARAMETER_ARG).copied();

    let filter = Criteria::new(
        include_pattern.map(String::as_str),
        exclude_pattern.map(String::as_str),
    );
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
