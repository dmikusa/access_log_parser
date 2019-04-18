# Access Log Parser

This is a pure Rust library for parsing access log entries. It currently support common, combined, Cloud Controller Nginx and Gorouter log formats.

## Usage

Add the following to your `Cargo.toml`:

```toml
[dependencies]
access_log_parser = "0.1"
```

Parse a log line:

```
    let entry = parse(
        LogType::CommonLog,
        r#"127.0.0.1 - - [15/Mar/2019:03:17:05 +0000] "GET / HTTP/1.1" 200 612"#,
    );
    if let Ok(LogEntry::CommonLog(entry)) = entry {
        assert_eq!(entry.ip, Ipv4Addr::new(127, 0, 0, 1));
        assert!(entry.identd_user.is_none());
        assert!(entry.user.is_none());
        assert_eq!(
            entry.timestamp,
            FixedOffset::west(0).ymd(2019, 3, 15).and_hms(3, 17, 5)
        );
        assert_eq!(entry.request.method(), http::Method::GET);
        assert_eq!(entry.request.uri(), "/");
        assert_eq!(entry.request.version(), http::Version::HTTP_11);
        assert_eq!(entry.status_code, http::StatusCode::OK);
        assert_eq!(entry.bytes, 612);
    }
```

## Features

* Read access log entries, parse them to rust structs and process the data in your programs
* Supported log formats:
  - Common
  - Combined
  - Cloud Controller Nginx
  - Gorouter

## License

This software is released under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
