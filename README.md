# Nginx Proxy Manager Access Log Analyzer

[![Lines of Code](https://tokei.rs/b1/github/aegoroff/npma?category=code)](https://github.com/XAMPPRocky/tokei)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A powerful command-line tool for analyzing Nginx Proxy Manager access logs. This tool processes JSON-formatted log entries (typically from the [grok](https://github.com/aegoroff/grok) tool) and provides detailed statistics, filtering, and grouping capabilities.

## Features

- **Real-time analysis** - Process logs from stdin or analyze existing files
- **Advanced filtering** - Filter by time, date, user agent, client IP, status code, HTTP method, and more
- **Grouping and statistics** - Group log entries by any parameter with top-N support
- **Traffic calculation** - Calculate total data size transferred through proxy
- **Interactive console output** - Progress indicators and formatted tables
- **Shell completions** - Built-in support for bash, zsh, fish, and powershell

## Installation

### Prerequisites

- Rust toolchain (stable or nightly)
- [grok](https://github.com/aegoroff/grok) tool for log parsing (optional, for stdin mode)

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

### Generate Shell Completions

```shell
# Bash
npma completion bash > ~/.bash_completion

# Zsh
npma completion zsh > ~/.zshrc

# Fish
npma completion fish > ~/.config/fish/completions/npma.fish

# PowerShell
npma completion powershell > $PROFILE
```

## Usage

### Basic Usage

The most common usage pattern is to pipe the output from grok into npma:

```shell
# Analyze logs from stdin (piped from grok)
grok file -j -m NGINXPROXYACCESS ~/access.log | npma i

# Analyze logs from a file directly
npma f access.log
```

### Commands

| Command | Aliases | Description |
|---------|---------|-------------|
| `f` | `file` | Analyze log file |
| `i` | `stdin` | Analyze data from standard input |
| `completion` | - | Generate shell completion script |

### Subcommands

Both `f` and `i` commands support the following subcommands:

| Subcommand | Aliases | Description |
|------------|---------|-------------|
| `g` | `group` | Group log entries by parameter |
| `t` | `traffic` | Calculate total traffic size |

### Options

| Option | Description |
|--------|-------------|
| `-p, --parameter <PARAM>` | Filter parameter [possible values: `time`, `date`, `agent`, `client`, `status`, `method`, `schema`, `req`, `ref`] |
| `-i, --include <PATTERN>` | Include only entries matching this pattern (requires `-p`) |
| `-e, --exclude <PATTERN>` | Exclude entries matching this pattern (requires `-p`) |

### Examples

#### 1. Basic Analysis

```shell
# From file
npma f access.log

# From stdin
grok file -j -m NGINXPROXYACCESS access.log | npma i
```

#### 2. Filter by Status Code

```shell
# Show only successful requests (200)
npma f access.log -p status -i "200"

# Exclude 404 errors
npma f access.log -p status -e "404"
```

#### 3. Group by Parameter

```shell
# Top 10 clients by request count
npma f access.log g client -t 10

# Group by HTTP method
npma i -p method < logs.json g method

# Group by date
npma f access.log g date
```

#### 4. Calculate Traffic

```shell
# Total traffic from file
npma f access.log t

# Total traffic from stdin
grok file -j -m NGINXPROXYACCESS access.log | npma i t
```

#### 5. Combined Usage

```shell
# Analyze only POST requests, grouped by client
npma f access.log -p method -i "POST" g client -t 5

# Exclude specific user agents and group by status
npma i -p agent -e "curl" g status
```

## Log Entry Parameters

The following parameters can be used for filtering and grouping:

| Parameter | Description |
|-----------|-------------|
| `time` | Request timestamp |
| `date` | Request date |
| `agent` | User agent string |
| `client` | Client IP address |
| `status` | HTTP status code |
| `method` | HTTP method (GET, POST, etc.) |
| `schema` | Request scheme (http/https) |
| `req` | Request path |
| `ref` | Referrer URL |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Nginx Proxy Manager](https://nginxproxymanager.com/) for the access log format
- [grok](https://github.com/aegoroff/grok) for log parsing capabilities