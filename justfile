check: build test

build:
  cargo build --workspace

test:
  cargo nextest run --workspace --all-features

install:
  cargo install --path .
