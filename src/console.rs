use comfy_table::presets::UTF8_HORIZONTAL_ONLY;
use comfy_table::{Attribute, Cell, ContentArrangement, Table};
use core::hash::Hash;
use itertools::Itertools;
use std::fmt::Display;

use crate::{GroupedParameter, LogEntry, LogParameter, calculate_percent};

/// Prints results table
pub fn print(data: impl Iterator<Item = LogEntry>) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_HORIZONTAL_ONLY)
        .set_header([
            Cell::new("#").add_attribute(Attribute::Bold),
            Cell::new("Time").add_attribute(Attribute::Bold),
            Cell::new("Agent").add_attribute(Attribute::Bold),
            Cell::new("Client IP").add_attribute(Attribute::Bold),
            Cell::new("Status").add_attribute(Attribute::Bold),
            Cell::new("Method").add_attribute(Attribute::Bold),
            Cell::new("Schema").add_attribute(Attribute::Bold),
            Cell::new("Length").add_attribute(Attribute::Bold),
            Cell::new("Request").add_attribute(Attribute::Bold),
            Cell::new("Referrer").add_attribute(Attribute::Bold),
        ])
        .set_content_arrangement(ContentArrangement::Dynamic);

    let rows = data.map(|entry| {
        [
            Cell::new(entry.line),
            Cell::new(entry.timestamp),
            Cell::new(entry.agent),
            Cell::new(entry.clientip),
            Cell::new(entry.status),
            Cell::new(entry.method),
            Cell::new(entry.schema),
            Cell::new(entry.length),
            Cell::new(entry.request),
            Cell::new(entry.referrer),
        ]
    });
    table.add_rows(rows);
    let total = table.row_count();
    if total > 0 {
        println!("{table}");
        println!("Total items: {total}");
    }
}

#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_possible_wrap)]
pub fn print_grouped<T: Default + Display + Hash + Eq>(
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
        .load_preset(UTF8_HORIZONTAL_ONLY)
        .set_header([
            Cell::new(parameter_name).add_attribute(Attribute::Bold),
            Cell::new("Count").add_attribute(Attribute::Bold),
            Cell::new("Proportion").add_attribute(Attribute::Bold),
        ])
        .set_content_arrangement(ContentArrangement::Dynamic);

    let mut total_count = 0;

    data.sorted_unstable_by(|a, b| Ord::cmp(&b.count, &a.count))
        .take(*limit.unwrap_or(&usize::MAX))
        .for_each(|entry| {
            total_count += entry.count;
            table.add_row([Cell::new(entry.parameter), Cell::new(entry.count)]);
        });

    for r in table.row_iter_mut() {
        if let Some(c) = r.cell_iter().nth(1) {
            if let Ok(count) = c.content().parse() {
                let percent = calculate_percent(count, total_count as i32);
                r.add_cell(Cell::new(format!("{percent:.2}%")));
            }
        }
    }
    let total = table.row_count();
    if total > 0 {
        println!("{table}");
        println!("Total items: {total}");
    }
}
