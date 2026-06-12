use comfy_table::presets::UTF8_HORIZONTAL_ONLY;
use comfy_table::{Attribute, Cell, ContentArrangement, Table};
use core::hash::Hash;
use std::fmt::Display;
use std::pin::pin;
use tokio_stream::Stream;
use tokio_stream::StreamExt;

use crate::{GroupedParameter, LogEntry, LogParameter, calculate_percent};

/// Prints results table
pub async fn print(data: impl Stream<Item = LogEntry>) {
    let mut data = pin!(data);
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

    let mut total = 0u64;
    while let Some(entry) = data.next().await {
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
            Cell::new(entry.agent),
            Cell::new(entry.clientip),
            status,
            Cell::new(entry.method),
            Cell::new(entry.schema),
            Cell::new(entry.length),
            Cell::new(entry.request),
            Cell::new(entry.referrer),
        ]);
        total += 1;
    }
    if total > 0 {
        println!("{table}");
        println!("Total data: {total}");
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
        .load_preset(UTF8_HORIZONTAL_ONLY)
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
