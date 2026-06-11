use chrono::Datelike;
use chrono::{DateTime, FixedOffset};
use clap::ValueEnum;
use clap::builder::PossibleValue;

use core::hash::Hash;
use std::borrow::Cow;
use std::fmt::Display;

use async_stream::stream;
use filter::Criteria;
use tokio_stream::{Stream, StreamExt};

pub mod console;
pub mod filter;
mod io;

pub use io::read_strings_from_file;
pub use io::read_strings_from_stdin;

/// JSONL log entry structure matching the input format
#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
struct JsonlEntry {
    line: u64,
    matched: bool,
    pattern: String,
    properties: JsonlProperties,
}

/// Properties extracted from JSONL entry
#[derive(serde::Deserialize, Debug, Default)]
struct JsonlProperties {
    #[serde(default)]
    timestamp: String,
    #[serde(default)]
    clientip: String,
    #[serde(default)]
    schema: String,
    #[serde(default)]
    request: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    referrer: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    agent: String,
    #[serde(default)]
    gzip: String,
    #[serde(default)]
    serverhost: String,
    #[serde(default)]
    length: String,
}

/// Converts a stream of JSONL strings into stream of `LogEntry` instances, applying filtering and parameterization.
///
/// Each input line is expected to be a valid JSON object with the following structure:
/// {
///   "line": <number>,
///   "matched": <boolean>,
///   "pattern": <string>,
///   "text": <string>,
///   "properties": { ... }
/// }
///
/// The `properties` object contains the actual log data fields.
pub fn convert<'a, S>(
    input: S,
    filter: &'a Criteria,
    parameter: Option<LogParameter>,
) -> impl Stream<Item = LogEntry> + 'a
where
    S: Stream<Item = String> + 'a,
{
    stream! {
        let mut pinned = std::pin::pin!(input);

        while let Some(line) = pinned.next().await {
            if line.trim().is_empty() {
                continue;
            }

            if let Ok(jsonl_entry) = serde_json::from_str::<JsonlEntry>(&line) {
                let entry = LogEntry::from_jsonl(&jsonl_entry);
                if entry.allow(filter, parameter) {
                    yield entry;
                }
            }
        }
    }
}

#[must_use]
pub fn calculate_percent(value: u64, total: u64) -> f64 {
    if total == 0 {
        0_f64
    } else {
        (value as f64 / total as f64) * 100_f64
    }
}

#[derive(Default, Debug)]
pub struct LogEntry {
    pub agent: String,
    pub clientip: String,
    pub gzip: String,
    pub host: String,
    pub length: u64,
    pub method: String,
    pub request: String,
    pub referrer: String,
    pub schema: String,
    pub serverhost: String,
    pub status: u16,
    pub timestamp: DateTime<FixedOffset>,
    pub line: u64,
}

impl LogEntry {
    fn from_jsonl(entry: &JsonlEntry) -> Self {
        let props = &entry.properties;

        let timestamp =
            DateTime::parse_from_str(&props.timestamp, "%d/%b/%Y:%H:%M:%S %z").unwrap_or_default();

        let length = props.length.parse().unwrap_or_default();
        let status = props.status.parse().unwrap_or_default();

        // Remove surrounding quotes from agent if present
        let agent = props.agent.trim_matches('"').to_string();

        Self {
            agent,
            clientip: props.clientip.clone(),
            gzip: props.gzip.clone(),
            host: props.host.clone(),
            length,
            method: props.method.clone(),
            request: props.request.clone(),
            referrer: props.referrer.clone(),
            schema: props.schema.clone(),
            serverhost: props.serverhost.clone(),
            status,
            timestamp,
            line: entry.line,
        }
    }

    fn allow(&self, filter: &Criteria, parameter: Option<LogParameter>) -> bool {
        parameter.is_none_or(|p| filter.allow(&p.extract(self)))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Default)]
pub enum LogParameter {
    Time,
    Agent,
    ClientIp,
    Status,
    Method,
    Schema,
    #[default]
    Request,
    Referrer,
    Date,
}

impl LogParameter {
    #[must_use]
    pub fn extract<'a>(&self, entry: &'a LogEntry) -> Cow<'a, str> {
        match self {
            LogParameter::Agent => Cow::Borrowed(&entry.agent),
            LogParameter::ClientIp => Cow::Borrowed(&entry.clientip),
            LogParameter::Method => Cow::Borrowed(&entry.method),
            LogParameter::Schema => Cow::Borrowed(&entry.schema),
            LogParameter::Request => Cow::Borrowed(&entry.request),
            LogParameter::Referrer => Cow::Borrowed(&entry.referrer),
            LogParameter::Status => Cow::Owned(entry.status.to_string()),
            LogParameter::Time => Cow::Owned(entry.timestamp.to_string()),
            LogParameter::Date => Cow::Owned(format!(
                "{}-{:02}-{:02}",
                entry.timestamp.year(),
                entry.timestamp.month(),
                entry.timestamp.day()
            )),
        }
    }
}

#[derive(Debug)]
pub struct GroupedParameter<T: Display + Hash + Eq> {
    pub parameter: T,
    pub count: u64,
}

impl Display for LogParameter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_possible_value()
            .expect("no values are skipped")
            .get_name()
            .fmt(f)
    }
}

// Hand-rolled so it can work even when `derive` feature is disabled
impl ValueEnum for LogParameter {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            LogParameter::Time,
            LogParameter::Date,
            LogParameter::Agent,
            LogParameter::ClientIp,
            LogParameter::Status,
            LogParameter::Method,
            LogParameter::Schema,
            LogParameter::Request,
            LogParameter::Referrer,
        ]
    }

    fn to_possible_value<'a>(&self) -> Option<PossibleValue> {
        Some(match self {
            LogParameter::Time => PossibleValue::new("time"),
            LogParameter::Date => PossibleValue::new("date"),
            LogParameter::Agent => PossibleValue::new("agent"),
            LogParameter::ClientIp => PossibleValue::new("client"),
            LogParameter::Status => PossibleValue::new("status"),
            LogParameter::Method => PossibleValue::new("method"),
            LogParameter::Schema => PossibleValue::new("schema"),
            LogParameter::Request => PossibleValue::new("req"),
            LogParameter::Referrer => PossibleValue::new("ref"),
        })
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    #[test_case(1, 100, 1.0)]
    #[test_case(0, 100, 0.0)]
    #[test_case(100, 100, 100.0)]
    #[test_case(50, 100, 50.0)]
    #[test_case(20, 100, 20.0)]
    fn calculate_percent_tests(value: u64, total: u64, expected: f64) {
        // Arrange

        // Act
        let actual = calculate_percent(value, total);

        // Assert
        assert_eq!(actual, expected);
    }
}
