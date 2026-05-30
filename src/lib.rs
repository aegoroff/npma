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

const VALUE_SEPARATOR: char = ':';
const TRIM_VALUE_PATTERN: &[char] = &[VALUE_SEPARATOR, ' '];

struct EntryParser {
    current: LogEntry,
    line: u64,
    started: bool,
}

impl EntryParser {
    fn new() -> Self {
        Self {
            current: LogEntry {
                line: 0,
                ..Default::default()
            },
            line: 0,
            started: false,
        }
    }

    fn push(&mut self, s: &str) -> Option<LogEntry> {
        if s.contains("pattern: NGINXPROXYACCESS") {
            let prev_started = self.started;
            self.started = true;
            self.line += 1;
            let entry = std::mem::replace(
                &mut self.current,
                LogEntry {
                    line: self.line,
                    ..Default::default()
                },
            );
            if prev_started { Some(entry) } else { None }
        } else if !s.ends_with(VALUE_SEPARATOR) {
            self.current.apply_line(s);
            None
        } else {
            None
        }
    }

    fn finish(self) -> Option<LogEntry> {
        if self.started && !self.current.request.is_empty() {
            Some(self.current)
        } else {
            None
        }
    }
}

/// Converts a stream of strings into stream of `LogEntry` instances, applying filtering and parameterization.
///
/// This function takes in a stream of log entries, a filter criteria, and an optional `LogParameter`.
/// It iterates through the stream, grouping lines together until it encounters a line that
/// starts with "pattern: NGINXPROXYACCESS".
/// When such a line is encountered, it adds the accumulated log entry to the result vector and resets the accumulator.
///
/// Finally, after processing all lines, it adds any remaining accumulated log entry to the result stream.
pub fn convert<'a, S>(
    input: S,
    filter: &'a Criteria,
    parameter: Option<LogParameter>,
) -> impl Stream<Item = LogEntry> + 'a
where
    S: Stream<Item = String> + 'a,
{
    stream! {
        let mut parser = EntryParser::new();
        let mut pinned = std::pin::pin!(input);

        while let Some(line) = pinned.next().await {
            if let Some(entry) = parser.push(&line)
                && entry.allow(filter, parameter) {
                    yield entry;
                }
        }
        // Last entry
        if let Some(entry) = parser.finish()
            && entry.allow(filter, parameter) {
                yield entry;
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
    fn apply_line(&mut self, s: &str) {
        let Some(sep_ix) = s.find(VALUE_SEPARATOR) else {
            return;
        };
        let key = s[..sep_ix].trim();
        let value = s[sep_ix..].trim_matches(TRIM_VALUE_PATTERN);
        match key {
            "request" => self.request = value.to_string(),
            "timestamp" => {
                self.timestamp =
                    DateTime::parse_from_str(value, "%d/%b/%Y:%H:%M:%S %z").unwrap_or_default();
            }
            "agent" => self.agent = value.trim_matches('"').to_string(),
            "clientip" => self.clientip = value.to_string(),
            "method" => self.method = value.to_string(),
            "schema" => self.schema = value.to_string(),
            "length" => self.length = value.parse().unwrap_or_default(),
            "status" => self.status = value.parse().unwrap_or_default(),
            "referrer" => self.referrer = value.to_string(),
            _ => {}
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
