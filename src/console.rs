use comfy_table::presets::UTF8_HORIZONTAL_ONLY;
use comfy_table::{Attribute, Cell, ContentArrangement, Table};
use core::hash::Hash;
use itertools::Itertools;
use std::fmt::Display;

use crate::{calculate_percent, GrouppedParameter, LogEntry, LogParameter};

/// Prints results table
pub fn print(data: impl Iterator<Item=LogEntry>) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_HORIZONTAL_ONLY)
        .set_header(vec![
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

    data.for_each(|entry| {
        table.add_row(vec![
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
        ]);
    });
    let total = table.row_iter().count();
    if total > 0 {
        println!("{table}");
        println!("Total items: {total}");
    }
}

#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_possible_wrap)]
pub fn print_groupped<T: Default + Display + Hash + Eq>(
    parameter: LogParameter,
    data: Vec<GrouppedParameter<T>>,
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
        .set_header(vec![
            Cell::new(parameter_name).add_attribute(Attribute::Bold),
            Cell::new("Count").add_attribute(Attribute::Bold),
            Cell::new("Proportion").add_attribute(Attribute::Bold),
        ])
        .set_content_arrangement(ContentArrangement::Dynamic);

    let total_count = data.iter().fold(0, |acc, x| acc + x.count);

    data.into_iter()
        .sorted_unstable_by(|a, b| Ord::cmp(&b.count, &a.count))
        .enumerate()
        .take_while(|(count, _)| {
            if let Some(limit) = limit {
                *limit > *count
            } else {
                true
            }
        })
        .map(|(_, entry)| entry)
        .for_each(|entry| {
            let percent = calculate_percent(entry.count as i32, total_count as i32);
            table.add_row(vec![
                Cell::new(entry.parameter),
                Cell::new(entry.count),
                Cell::new(format!("{percent:.2}%")),
            ]);
        });
    let total = table.row_iter().count();
    if total > 0 {
        println!("{table}");
        println!("Total items: {total}");
    }
}
