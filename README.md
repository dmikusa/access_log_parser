# Access Log Parser

This is a pure Rust library for parsing access log entries. It currently support common, combined, Cloud Controller Nginx and Gorouter log formats.

## Usage

Add the following to your `Cargo.toml`:

```toml
[dependencies]
access_log_parser = "0.10"
```

See [examples/](examples/) for example code.

## Features

* Read access log entries, parse them to Rust structs and process the data in your programs
* Supported log formats:
  - Common
  - Combined
  - Cloud Controller Nginx
  - Gorouter

## License

This software is released under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
