use comfy_table::presets::UTF8_HORIZONTAL_ONLY;
use comfy_table::{Attribute, Cell, ContentArrangement, Table};

use crate::LogEntry;

/// Prints results table
pub fn print(data: impl Iterator<Item = LogEntry>) {
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
