[![](https://tokei.rs/b1/github/aegoroff/npma?category=code)](https://github.com/XAMPPRocky/tokei)

# Nginx Proxy Manager access log analyzer
Nginx Proxy Manager access log analyzer can be used to analyze [grok](https://github.com/aegoroff/grok) tool output that parses 
raw Nginx Proxy Manager access log and outputs all found properties of each log entry. These propertes are input for this tool.

# Installation
Install Rust, then go to sources root and then run:
```shell
cargo install --path .
```
# Usage
```
grok -i -m NGINXPROXYACCESS -f ~/access.log | npma i
```
