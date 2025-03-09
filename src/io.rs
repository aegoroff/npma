use color_eyre::eyre::{Context, Result};
use std::path::Path;

use tokio::fs::File;
use tokio::io::BufReader;

use tokio::io::{AsyncBufReadExt, AsyncRead};
use tokio_stream::wrappers::LinesStream;

use tokio_stream::{Stream, StreamExt};

/// Reads strings from file specified using `path`.
///
/// # Errors
///
/// This function will return an error if file specified by `path` cannot be opened or not exist.
pub async fn read_strings_from_file<P: AsRef<Path>>(path: P) -> Result<impl Stream<Item = String>> {
    let path = path.as_ref().to_str().unwrap_or_default();
    let file = File::open(path)
        .await
        .wrap_err_with(|| format!("Log file '{path}' cannot be opened"))?;
    Ok(read_not_empty_strings_from(file))
}

/// Reads strings from stdin.
pub fn read_strings_from_stdin() -> impl Stream<Item = String> {
    read_not_empty_strings_from(tokio::io::stdin())
}

fn read_not_empty_strings_from<R: AsyncRead + Unpin>(reader: R) -> impl Stream<Item = String> {
    read_strings_from(reader, |entry| !entry.is_empty())
}

fn read_strings_from<R, F>(reader: R, filter: F) -> impl Stream<Item = String>
where
    F: FnMut(&String) -> bool,
    R: AsyncRead + Unpin,
{
    let lines = BufReader::new(reader).lines();
    let stream = LinesStream::new(lines);
    stream.filter_map(Result::ok).filter(filter)
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
        let mut result = read_strings_from(cursor, |_| true);

        // Assert
        assert_eq!("a", result.next().await.unwrap());
        assert_eq!("b", result.next().await.unwrap());
        assert_eq!("c", result.next().await.unwrap());
        assert!(result.next().await.is_none());
    }

    #[tokio::test]
    async fn read_strings_from_some_empty() {
        // Arrange
        let cursor = Cursor::new(b"a\n\nb");

        // Act
        let mut result = read_strings_from(cursor, |_| true);

        // Assert
        assert_eq!("a", result.next().await.unwrap());
        assert_eq!("", result.next().await.unwrap());
        assert_eq!("b", result.next().await.unwrap());
        assert!(result.next().await.is_none());
    }

    #[tokio::test]
    async fn read_strings_from_some_empty_windows_line_endings() {
        // Arrange
        let cursor = Cursor::new(b"a\r\n\r\nb");

        // Act
        let mut result = read_strings_from(cursor, |_| true);

        // Assert
        assert_eq!("a", result.next().await.unwrap());
        assert_eq!("", result.next().await.unwrap());
        assert_eq!("b", result.next().await.unwrap());
        assert!(result.next().await.is_none());
    }

    #[tokio::test]
    async fn read_not_empty_strings_from_all_not_empty() {
        // Arrange
        let cursor = Cursor::new(b"a\nb\r\nc");

        // Act
        let mut result = read_not_empty_strings_from(cursor);

        // Assert
        assert_eq!("a", result.next().await.unwrap());
        assert_eq!("b", result.next().await.unwrap());
        assert_eq!("c", result.next().await.unwrap());
        assert!(result.next().await.is_none());
    }

    #[tokio::test]
    async fn read_not_empty_strings_from_some_empty() {
        // Arrange
        let cursor = Cursor::new(b"a\n\nb");

        // Act
        let mut result = read_not_empty_strings_from(cursor);

        // Assert
        assert_eq!("a", result.next().await.unwrap());
        assert_eq!("b", result.next().await.unwrap());
        assert!(result.next().await.is_none());
    }
}
