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

/// JSONL log entry structure matching the input format.
/// Strings are borrowed from the input line when possible (no escapes) to avoid allocations
#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
struct JsonlEntry<'a> {
    line: u64,
    matched: bool,
    #[serde(borrow)]
    pattern: Cow<'a, str>,
    #[serde(borrow)]
    properties: JsonlProperties<'a>,
}

/// Properties extracted from JSONL entry
#[derive(serde::Deserialize, Debug, Default)]
struct JsonlProperties<'a> {
    #[serde(default, borrow)]
    timestamp: Cow<'a, str>,
    #[serde(default, borrow)]
    clientip: Cow<'a, str>,
    #[serde(default, borrow)]
    schema: Cow<'a, str>,
    #[serde(default, borrow)]
    request: Cow<'a, str>,
    #[serde(default, borrow)]
    status: Cow<'a, str>,
    #[serde(default, borrow)]
    method: Cow<'a, str>,
    #[serde(default, borrow)]
    referrer: Cow<'a, str>,
    #[serde(default, borrow)]
    host: Cow<'a, str>,
    #[serde(default, borrow)]
    agent: Cow<'a, str>,
    #[serde(default, borrow)]
    gzip: Cow<'a, str>,
    #[serde(default, borrow)]
    serverhost: Cow<'a, str>,
    #[serde(default, borrow)]
    length: Cow<'a, str>,
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
            if let Ok(jsonl_entry) = serde_json::from_str::<JsonlEntry>(&line) {
                let entry = LogEntry::from_jsonl(jsonl_entry);
                if entry.allow(filter, parameter) {
                    yield entry;
                }
            }
        }
    }
}

#[must_use]
#[allow(clippy::cast_precision_loss)]
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
    fn from_jsonl(entry: JsonlEntry<'_>) -> Self {
        let props = entry.properties;

        let timestamp =
            DateTime::parse_from_str(&props.timestamp, "%d/%b/%Y:%H:%M:%S %z").unwrap_or_default();

        let length = props.length.parse().unwrap_or_default();
        let status = props.status.parse().unwrap_or_default();

        let agent = trim_quotes(props.agent);

        Self {
            agent,
            clientip: props.clientip.into_owned(),
            gzip: props.gzip.into_owned(),
            host: props.host.into_owned(),
            length,
            method: props.method.into_owned(),
            request: props.request.into_owned(),
            referrer: props.referrer.into_owned(),
            schema: props.schema.into_owned(),
            serverhost: props.serverhost.into_owned(),
            status,
            timestamp,
            line: entry.line,
        }
    }

    fn allow(&self, filter: &Criteria, parameter: Option<LogParameter>) -> bool {
        parameter.is_none_or(|p| filter.allow(&p.extract(self)))
    }
}

/// Removes surrounding quotes. Agent usually contains escaped quotes, so it is already
/// an owned string after deserialization and can be trimmed in place without reallocation
fn trim_quotes(value: Cow<'_, str>) -> String {
    match value {
        Cow::Borrowed(s) => s.trim_matches('"').to_owned(),
        Cow::Owned(mut s) => {
            let end = s.trim_end_matches('"').len();
            s.truncate(end);
            let start = s.len() - s.trim_start_matches('"').len();
            s.drain(..start);
            s
        }
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

    #[test_case("\"a b\"", "a b")]
    #[test_case("a b", "a b")]
    #[test_case("\"\"", "")]
    #[test_case("\"a", "a")]
    #[test_case("", "")]
    fn trim_quotes_tests(value: &str, expected: &str) {
        // Arrange

        // Act
        let borrowed = trim_quotes(Cow::Borrowed(value));
        let owned = trim_quotes(Cow::Owned(value.to_owned()));

        // Assert
        assert_eq!(borrowed, expected);
        assert_eq!(owned, expected);
    }

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
