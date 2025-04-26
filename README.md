[![Lines of Code](https://tokei.rs/b1/github/aegoroff/npma?category=code)](https://github.com/XAMPPRocky/tokei)
[![Crates.io](https://img.shields.io/crates/v/npma)](https://crates.io/crates/npma)
[![Documentation](https://docs.rs/npma/badge.svg)](https://docs.rs/npma)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# Nginx Proxy Manager Access Log Analyzer

A powerful command-line tool for analyzing Nginx Proxy Manager access logs. This tool processes the output from the [grok](https://github.com/aegoroff/grok) tool, which parses raw Nginx Proxy Manager access logs and extracts all properties of each log entry.

## Features

- Analyze access logs with detailed statistics
- Filter logs by various parameters (time, date, agent, client IP, status, method, etc.)
- Group and count entries by different parameters
- Calculate percentages and statistics
- Interactive console output with progress indicators
- Support for both file and stdin input

## Installation

### Prerequisites

- Rust toolchain (stable or nightly)
- [grok](https://github.com/aegoroff/grok) tool for log parsing

### From Source

1. Clone the repository:
```shell
git clone https://github.com/aegoroff/npma.git
cd npma
```

2. Install the tool:
```shell
cargo install --path .
```

### From Crates.io

```shell
cargo install npma
```

## Usage

### Basic Usage

The most common usage pattern is to pipe the output from grok into npma:

```shell
grok -i -m NGINXPROXYACCESS -f ~/access.log | npma i
```

### Command Line Options

```
npma [OPTIONS] [COMMAND]

Commands:
  i, interactive  Interactive mode
  h, help        Print help
  V, version     Print version

Options:
  -f, --file <FILE>    Input file path
  -p, --param <PARAM>  Parameter to analyze [possible values: time, date, agent, client, status, method, schema, req, ref]
  -i, --include <INCLUDE>  Include pattern
  -e, --exclude <EXCLUDE>  Exclude pattern
  -h, --help           Print help
  -V, --version        Print version
```

### Examples

1. Analyze logs from a file:
```shell
npma -f access.log
```

2. Filter by specific parameter:
```shell
grok -i -m NGINXPROXYACCESS -f access.log | npma -p status
```

3. Include only specific patterns:
```shell
grok -i -m NGINXPROXYACCESS -f access.log | npma -i "200" -p status
```

4. Exclude specific patterns:
```shell
grok -i -m NGINXPROXYACCESS -f access.log | npma -e "404" -p status
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Nginx Proxy Manager](https://nginxproxymanager.com/) for the access log format
- [grok](https://github.com/aegoroff/grok) for log parsing capabilities
