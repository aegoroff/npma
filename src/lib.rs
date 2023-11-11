use color_eyre::eyre::{Context, Result};
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
pub fn analyze(entries: &[String], filter: &Criteria) -> Vec<LogEntry> {
    let items = entries
        .iter()
        .group_by(|s| s.contains("pattern: NGINXPROXYACCESS"));
    items
        .into_iter()
        .filter_map(|(is_head, g)| if is_head { None } else { Some(g) })
        .enumerate()
        .map(|(line, g)| {
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
            LogEntry {
                line: line as u64 + 1,
                request,
                agent,
                timestamp,
                clientip,
                method,
                schema,
                referrer,
                length: length.parse().unwrap_or_default(),
                status: status.parse().unwrap_or_default(),
                ..Default::default()
            }
        })
        .filter(|e| filter.allow(e))
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
    pub timestamp: String,
    pub line: u64,
}

#[cfg(test)]
mod tests {
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
}
