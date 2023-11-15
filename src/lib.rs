use chrono::{DateTime, FixedOffset};
use clap::builder::PossibleValue;
use clap::ValueEnum;
use color_eyre::eyre::{Context, Result};
use core::hash::Hash;
use std::fmt::Display;
use std::path::Path;

use filter::Criteria;
use itertools::Itertools;
use tokio::fs::File;
use tokio::io::BufReader;
use tokio::io::{AsyncBufReadExt, AsyncRead};
use tokio_stream::wrappers::LinesStream;
use tokio_stream::StreamExt;

pub mod console;
pub mod filter;

#[must_use]
pub fn analyze(
    entries: &[String],
    filter: &Criteria,
    parameter: Option<LogParameter>,
) -> Vec<LogEntry> {
    let items = entries
        .iter()
        .group_by(|s| s.contains("pattern: NGINXPROXYACCESS"));
    items
        .into_iter()
        .filter_map(|(is_head, g)| if is_head { None } else { Some(g) })
        .enumerate()
        .filter_map(|(line, g)| {
            let strings = g.cloned().collect_vec();

            let request = read_parameter(&strings, "request");
            let timestamp = read_parameter(&strings, "timestamp");
            let agent = read_parameter(&strings, "agent")
                .trim_matches('"')
                .to_string();
            let clientip = read_parameter(&strings, "clientip");
            let method = read_parameter(&strings, "method");
            let schema = read_parameter(&strings, "schema");
            let length = read_parameter(&strings, "length");
            let status = read_parameter(&strings, "status");
            let referrer = read_parameter(&strings, "referrer");

            let allow = if let Some(parameter) = parameter {
                match parameter {
                    LogParameter::Time => filter.allow(&timestamp),
                    LogParameter::Agent => filter.allow(&agent),
                    LogParameter::ClientIp => filter.allow(&clientip),
                    LogParameter::Status => filter.allow(&status),
                    LogParameter::Method => filter.allow(&method),
                    LogParameter::Schema => filter.allow(&schema),
                    LogParameter::Request => filter.allow(&request),
                    LogParameter::Referrer => filter.allow(&referrer),
                }
            } else {
                true
            };

            if allow {
                Some(LogEntry {
                    line: line as u64 + 1,
                    request,
                    agent,
                    timestamp: DateTime::parse_from_str(&timestamp, "%d/%b/%Y:%H:%M:%S %z")
                        .unwrap_or_default(),
                    clientip,
                    method,
                    schema,
                    referrer,
                    length: length.parse().unwrap_or_default(),
                    status: status.parse().unwrap_or_default(),
                    ..Default::default()
                })
            } else {
                None
            }
        })
        .collect_vec()
}

fn read_parameter(strings: &[String], parameter: &str) -> String {
    let empty = String::new();
    let req = strings
        .iter()
        .find(|s| s.contains(parameter))
        .unwrap_or(&empty);
    let from = req.find(':').unwrap_or_default() + 2;
    if req.len() <= 2 {
        empty
    } else {
        req[from..].to_string()
    }
}

/// Reads strings from file specified using `path`.
///
/// # Errors
///
/// This function will return an error if file specified by `path` cannot be opened or not exist.
pub async fn read_strings_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let path = path.as_ref().to_str().unwrap_or_default();
    let file = File::open(path)
        .await
        .wrap_err_with(|| format!("Log file '{path}' cannot be opened"))?;
    Ok(read_not_empty_strings_from(file).await)
}

/// Reads strings from stdin.
pub async fn read_strings_from_stdin() -> Vec<String> {
    read_not_empty_strings_from(tokio::io::stdin()).await
}

async fn read_not_empty_strings_from<R: AsyncRead + Unpin>(reader: R) -> Vec<String> {
    read_strings_from(reader, |entry| !entry.is_empty()).await
}

async fn read_strings_from<R, F>(reader: R, filter: F) -> Vec<String>
where
    F: FnMut(&String) -> bool,
    R: AsyncRead + Unpin,
{
    let lines = BufReader::new(reader).lines();
    let stream = LinesStream::new(lines);
    stream
        .filter_map(std::result::Result::ok)
        .filter(filter)
        .collect()
        .await
}

#[must_use]
pub fn calculate_percent(value: i32, total: i32) -> f64 {
    if total == 0 {
        0_f64
    } else {
        (f64::from(value) / f64::from(total)) * 100_f64
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
}

#[derive(Default, Debug)]
pub struct GrouppedParameter<T: Default + Display + Hash + Eq> {
    pub parameter: T,
    pub count: usize,
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
    use rstest::rstest;
    use std::io::Cursor;

    use super::*;

    #[tokio::test]
    async fn read_strings_from_all_not_empty() {
        // Arrange
        let cursor = Cursor::new(b"a\nb\r\nc");

        // Act
        let result = read_strings_from(cursor, |_| true).await;

        // Assert
        assert_eq!(3, result.len());
        assert_eq!("a", result[0]);
        assert_eq!("b", result[1]);
        assert_eq!("c", result[2]);
    }

    #[tokio::test]
    async fn read_strings_from_some_empty() {
        // Arrange
        let cursor = Cursor::new(b"a\n\nb");

        // Act
        let result = read_strings_from(cursor, |_| true).await;

        // Assert
        assert_eq!(3, result.len());
        assert_eq!("a", result[0]);
        assert_eq!("", result[1]);
        assert_eq!("b", result[2]);
    }

    #[tokio::test]
    async fn read_strings_from_some_empty_windows_line_endings() {
        // Arrange
        let cursor = Cursor::new(b"a\r\n\r\nb");

        // Act
        let result = read_strings_from(cursor, |_| true).await;

        // Assert
        assert_eq!(3, result.len());
        assert_eq!("a", result[0]);
        assert_eq!("", result[1]);
        assert_eq!("b", result[2]);
    }

    #[tokio::test]
    async fn read_not_empty_strings_from_all_not_empty() {
        // Arrange
        let cursor = Cursor::new(b"a\nb\r\nc");

        // Act
        let result = read_not_empty_strings_from(cursor).await;

        // Assert
        assert_eq!(3, result.len());
        assert_eq!("a", result[0]);
        assert_eq!("b", result[1]);
        assert_eq!("c", result[2]);
    }

    #[tokio::test]
    async fn read_not_empty_strings_from_some_empty() {
        // Arrange
        let cursor = Cursor::new(b"a\n\nb");

        // Act
        let result = read_not_empty_strings_from(cursor).await;

        // Assert
        assert_eq!(2, result.len());
        assert_eq!("a", result[0]);
        assert_eq!("b", result[1]);
    }

    #[rstest]
    #[case(1, 100, 1.0)]
    #[case(0, 100, 0.0)]
    #[case(100, 100, 100.0)]
    #[case(50, 100, 50.0)]
    #[case(20, 100, 20.0)]
    #[trace]
    fn calculate_percent_tests(#[case] value: i32, #[case] total: i32, #[case] expected: f64) {
        // Arrange

        // Act
        let actual = calculate_percent(value, total);

        // Assert
        assert_eq!(actual, expected);
    }
}
