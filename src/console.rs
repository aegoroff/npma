use comfy_table::presets::UTF8_HORIZONTAL_ONLY;
use comfy_table::{Attribute, Cell, ColumnConstraint, ContentArrangement, LineStyle, Table, Width};
use core::hash::Hash;
use std::fmt::Display;
use std::io::{self, Write};
use tokio_stream::Stream;
use tokio_stream::StreamExt;

use crate::{GroupedParameter, LogEntry, LogParameter, calculate_percent};

/// Number of rows rendered at once. Rendering the whole table requires memory many times
/// greater than its data, so the table is rendered in chunks with the same column widths
const PRINT_CHUNK_SIZE: usize = 1000;

/// Left + right cell padding used by comfy table by default
const CELL_PADDING: u16 = 2;

/// Columns which are narrowed (Agent, Request, Referrer) when the table doesn't fit terminal
const SHRINKABLE_COLUMNS: [usize; 3] = [2, 8, 9];

/// Narrowed column content width cannot be less than this
const MIN_SHRINKED_WIDTH: u16 = 10;

const ENTRIES_HEADER: [&str; 10] = [
    "#",
    "Time",
    "Agent",
    "Client IP",
    "Status",
    "Method",
    "Schema",
    "Length",
    "Request",
    "Referrer",
];

/// Prints results table
pub async fn print(data: impl Stream<Item = LogEntry>) {
    let entries: Vec<LogEntry> = data.collect().await;
    if entries.is_empty() {
        return;
    }

    // First pass: column widths over all rows so that every chunk looks the same
    let mut widths = vec![0u16; ENTRIES_HEADER.len()];
    for chunk in entries.chunks(PRINT_CHUNK_SIZE) {
        let table = new_entries_table(chunk, true);
        for (width, chunk_width) in widths.iter_mut().zip(table.column_max_content_widths()) {
            *width = (*width).max(chunk_width);
        }
    }
    if let Some(terminal_width) = Table::new().width() {
        fit_into_width(&mut widths, terminal_width);
    }
    let constraints: Vec<_> = widths
        .iter()
        .map(|w| ColumnConstraint::Absolute(Width::Fixed(w.saturating_add(CELL_PADDING))))
        .collect();

    // Second pass: render chunks one by one
    let mut out = io::stdout().lock();
    for (i, chunk) in entries.chunks(PRINT_CHUNK_SIZE).enumerate() {
        let first = i == 0;
        let mut table = new_entries_table(chunk, first);
        table.set_constraints(constraints.iter().copied());
        if !first {
            // previous chunk's bottom border already separates rows
            table.style_mut().top_border = LineStyle::none();
        }
        for line in table.lines() {
            if writeln!(out, "{line}").is_err() {
                // stdout closed (broken pipe for example) so there is no reason to render the rest
                return;
            }
        }
    }
    let _ = writeln!(out, "Total data: {}", entries.len());
}

fn new_entries_table(entries: &[LogEntry], with_header: bool) -> Table {
    let mut table = Table::new();
    table
        .load_style(UTF8_HORIZONTAL_ONLY)
        .set_content_arrangement(ContentArrangement::Dynamic);
    if with_header {
        table.set_header(ENTRIES_HEADER.map(|h| Cell::new(h).add_attribute(Attribute::Bold)));
    }

    for entry in entries {
        let status = if entry.status >= 400 {
            Cell::new(entry.status).fg(comfy_table::Color::DarkRed)
        } else if entry.status >= 300 && entry.status < 400 {
            Cell::new(entry.status).fg(comfy_table::Color::DarkYellow)
        } else {
            Cell::new(entry.status).fg(comfy_table::Color::DarkGreen)
        };

        table.add_row([
            Cell::new(entry.line),
            Cell::new(entry.timestamp),
            Cell::new(&entry.agent),
            Cell::new(&entry.clientip),
            status,
            Cell::new(&entry.method),
            Cell::new(&entry.schema),
            Cell::new(entry.length),
            Cell::new(&entry.request),
            Cell::new(&entry.referrer),
        ]);
    }
    table
}

/// Narrows shrinkable columns so that table fits into `available` width
fn fit_into_width(widths: &mut [u16], available: u16) {
    // style has junctions so there is one char vertical separator between columns
    let separators = u32::try_from(widths.len().saturating_sub(1)).unwrap_or(u32::MAX);
    let available = u32::from(available).saturating_sub(separators);
    let total: u32 = widths
        .iter()
        .map(|w| u32::from(*w) + u32::from(CELL_PADDING))
        .sum();
    if total <= available {
        return;
    }

    let fixed: u32 = widths
        .iter()
        .enumerate()
        .map(|(i, w)| {
            if SHRINKABLE_COLUMNS.contains(&i) {
                u32::from(CELL_PADDING)
            } else {
                u32::from(*w) + u32::from(CELL_PADDING)
            }
        })
        .sum();
    let mut room = available.saturating_sub(fixed);

    // Columns narrower than equal share keep their width, the rest share remaining space equally.
    // If even minimal width doesn't fit, table overflows terminal - nothing better can be done
    let mut shrinkable = SHRINKABLE_COLUMNS;
    shrinkable.sort_unstable_by_key(|i| widths[*i]);
    for (n, i) in shrinkable.iter().enumerate() {
        let left = u32::try_from(shrinkable.len() - n).unwrap_or(1);
        let share = (room / left).max(u32::from(MIN_SHRINKED_WIDTH));
        let width = u32::from(widths[*i]).min(share);
        room = room.saturating_sub(width);
        widths[*i] = u16::try_from(width).unwrap_or(u16::MAX);
    }
}

pub fn print_grouped<T: Display + Hash + Eq>(
    parameter: LogParameter,
    data: impl Iterator<Item = GroupedParameter<T>>,
    limit: Option<&usize>,
) {
    let parameter_name = match parameter {
        LogParameter::Time => "Time",
        LogParameter::Date => "Date",
        LogParameter::Agent => "User agent",
        LogParameter::ClientIp => "Client IP",
        LogParameter::Status => "HTTP Status",
        LogParameter::Method => "HTTP Method",
        LogParameter::Schema => "Schema",
        LogParameter::Request => "Request URI",
        LogParameter::Referrer => "Referrer",
    };

    let mut table = Table::new();
    table
        .load_style(UTF8_HORIZONTAL_ONLY)
        .set_header([
            Cell::new(parameter_name).add_attribute(Attribute::Bold),
            Cell::new("Count").add_attribute(Attribute::Bold),
            Cell::new("Proportion").add_attribute(Attribute::Bold),
        ])
        .set_content_arrangement(ContentArrangement::Dynamic);

    let mut data: Vec<_> = data.collect();
    data.sort_unstable_by(|a, b| Ord::cmp(&b.count, &a.count));

    let limited: Vec<_> = data
        .into_iter()
        .take(*limit.unwrap_or(&usize::MAX))
        .collect();

    let total_count: u64 = limited.iter().map(|e| e.count).sum();

    for entry in limited {
        table.add_row([
            Cell::new(entry.parameter),
            Cell::new(entry.count),
            Cell::new(format!(
                "{:.2}%",
                calculate_percent(entry.count, total_count)
            )),
        ]);
    }

    let total = table.row_count();
    if total > 0 {
        println!("{table}");
        let group = if parameter_name.chars().last().unwrap_or_default() == 's' {
            format!("{parameter_name}es")
        } else {
            format!("{parameter_name}s")
        };
        let spacer = " ".repeat(group.len() - 4); // 4 is data len
        println!("Total {group}:\t{total}");
        println!("Total data:{spacer}\t{total_count}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_into_width_fits_already() {
        // arrange
        let mut widths = [4, 26, 100, 15, 3, 4, 5, 6, 50, 20];
        let expected = widths;
        let total: u16 = widths.iter().map(|w| w + CELL_PADDING).sum::<u16>() + 9;

        // act
        fit_into_width(&mut widths, total);

        // assert
        assert_eq!(widths, expected);
    }

    fn table_width(widths: &[u16]) -> u16 {
        widths.iter().map(|w| w + CELL_PADDING).sum::<u16>() + 9
    }

    #[test]
    fn fit_into_width_shrinks_only_shrinkable() {
        // arrange
        let mut widths = [5, 26, 111, 11, 6, 6, 6, 10, 345, 58];

        // act
        fit_into_width(&mut widths, 150);

        // assert
        assert!(table_width(&widths) <= 150);
        assert_eq!(&widths[..2], &[5, 26]);
        assert_eq!(&widths[3..8], &[11, 6, 6, 6, 10]);
        assert_eq!([widths[2], widths[8], widths[9]], [17, 17, 17]);
    }

    #[test]
    fn fit_into_width_narrow_column_keeps_its_width() {
        // arrange
        let mut widths = [5, 26, 111, 11, 6, 6, 6, 10, 345, 12];

        // act
        fit_into_width(&mut widths, 160);

        // assert
        assert_eq!(table_width(&widths), 160);
        assert_eq!(widths[9], 12);
        assert!(widths[2].abs_diff(widths[8]) <= 1);
    }

    #[test]
    fn fit_into_width_narrow_terminal_uses_min_width() {
        // arrange
        let mut widths = [4, 26, 200, 15, 3, 4, 5, 6, 100, 100];

        // act
        fit_into_width(&mut widths, 40);

        // assert
        assert_eq!([widths[2], widths[8], widths[9]], [MIN_SHRINKED_WIDTH; 3]);
    }
}
