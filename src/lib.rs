use chrono::prelude::*;
use std::net::IpAddr;
use std::str::FromStr;

mod parsers;

#[derive(Debug)]
pub struct CommonLogEntry<'a> {
    pub ip: IpAddr,
    pub identd_user: Option<&'a str>,
    pub user: Option<&'a str>,
    pub timestamp: DateTime<FixedOffset>,
    pub request: http::Request<()>,
    pub status_code: http::StatusCode,
    pub bytes: u32,
}

#[derive(Debug)]
pub struct CombinedLogEntry<'a> {
    pub ip: IpAddr,
    pub identd_user: Option<&'a str>,
    pub user: Option<&'a str>,
    pub timestamp: DateTime<FixedOffset>,
    pub request: http::Request<()>,
    pub status_code: http::StatusCode,
    pub bytes: u32,
    pub referrer: Option<http::Uri>,
    pub user_agent: &'a str,
}

#[derive(Debug)]
pub struct GorouterLogEntry<'a> {
    pub request_host: &'a str,
    pub timestamp: DateTime<FixedOffset>,
    pub request: http::Request<()>,
    pub status_code: http::StatusCode,
    pub bytes_received: u32,
    pub bytes_sent: u32,
    pub referrer: Option<http::Uri>,
    pub user_agent: &'a str,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub backend_addr: IpAddr,
    pub backend_port: u16,
    pub x_forwarded_for: Vec<IpAddr>,
    pub x_forwarded_proto: XForwardedProto,
    pub vcap_request_id: &'a str,
    pub response_time: f32,
    pub app_id: Option<&'a str>,
    pub app_index: Option<u16>,
    pub trace_id: Option<&'a str>,
    pub span_id: Option<&'a str>,
    pub parent_span_id: Option<&'a str>,
}

#[derive(Debug)]
pub enum LogEntry<'a> {
    CommonLog(CommonLogEntry<'a>),
    CombinedLog(CombinedLogEntry<'a>),
}

#[derive(Debug)]
pub enum LogType {
    CommonLog,
    CombinedLog,
    GorouterLog,
    CloudControllerLog,
}

impl FromStr for LogType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "common" => Ok(LogType::CommonLog),
            "combined" => Ok(LogType::CombinedLog),
            "gorouter" | "router" => Ok(LogType::GorouterLog),
            "cloud_controller" | "cc" | "capi" => Ok(LogType::CloudControllerLog),
            _ => Err("invalid log type"),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum XForwardedProto {
    HTTP,
    HTTPS,
}

impl Default for XForwardedProto {
    fn default() -> Self {
        XForwardedProto::HTTP
    }
}

pub fn parse(log_type: LogType, line: &str) -> Result<LogEntry, nom::Err<&str>> {
    match log_type {
        LogType::CommonLog => match parsers::parse_common_log(line) {
            Ok((_remaining, log)) => Ok(LogEntry::CommonLog(log)),
            Err(err) => Err(err),
        },
        LogType::CombinedLog => match parsers::parse_combined_log(line) {
            Ok((_remaining, log)) => Ok(LogEntry::CombinedLog(log)),
            Err(err) => Err(err),
        },
        _ => {
            unimplemented!();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::Context::Code;
    use nom::Err::Error;
    use nom::Err::Incomplete;
    use nom::ErrorKind::Tag;
    use nom::Needed::Size;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_log_type() {
        let entry = parse(
            LogType::CommonLog,
            r#"127.0.0.1 - - [15/Mar/2019:03:17:05 +0000] "GET / HTTP/1.1" 200 612"#,
        );
        assert!(entry.is_ok());
        if let LogEntry::CommonLog(entry) = entry.unwrap() {
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
    }

    #[test]
    fn test_parse_log_type_incomplete() {
        let entry = parse(LogType::CommonLog, r#"lskdjflkjsdf"#);
        assert!(entry.is_err());
        assert_eq!(entry.unwrap_err(), Incomplete(Size(1)));
    }

    #[test]
    fn test_parse_log_type_fails() {
        // it's missing the leading `[`
        let entry = parse(
            LogType::CommonLog,
            r#"127.0.0.1 - - 15/Mar/2019:03:17:05 +0000] "GET / HTTP/1.1" 200 612"#,
        );
        assert!(entry.is_err());
        assert_eq!(
            entry.unwrap_err(),
            Error(Code(
                "15/Mar/2019:03:17:05 +0000] \"GET / HTTP/1.1\" 200 612",
                Tag
            ))
        );
    }
}

// TODO: try using parse in the actual code
// TODO: add support for gorouter & cloud controller
