// Copyright 2019 Daniel Mikusa

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
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
    pub user_agent: Option<&'a str>,
}

#[derive(Debug)]
pub struct CloudControllerLogEntry<'a> {
    pub request_host: &'a str,
    pub timestamp: DateTime<FixedOffset>,
    pub request: http::Request<()>,
    pub status_code: http::StatusCode,
    pub bytes: u32,
    pub referrer: Option<http::Uri>,
    pub user_agent: Option<&'a str>,
    pub x_forwarded_for: Vec<IpAddr>,
    pub vcap_request_id: &'a str,
    pub response_time: f32,
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
    pub user_agent: Option<&'a str>,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub backend_addr: Option<IpAddr>,
    pub backend_port: Option<u16>,
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
    GorouterLog(GorouterLogEntry<'a>),
    CloudControllerLog(CloudControllerLogEntry<'a>),
}

#[derive(Debug, Copy, Clone)]
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
        LogType::CloudControllerLog => match parsers::parse_cloud_controller_log(line) {
            Ok((_remaining, log)) => Ok(LogEntry::CloudControllerLog(log)),
            Err(err) => Err(err),
        },
        LogType::GorouterLog => match parsers::parse_gorouter_log(line) {
            Ok((_remaining, log)) => Ok(LogEntry::GorouterLog(log)),
            Err(err) => Err(err),
        },
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

    #[test]
    fn test_parse_cloud_controller() {
        let entry = parse(LogType::CloudControllerLog, r#"api.system_domain.local - [01/Feb/2019:20:45:02 +0000] "GET /v2/spaces/a91c3fa8-e67d-40dd-9d6b-d01aefe5062a/summary HTTP/1.1" 200 53188 "-" "cf_exporter/" 172.26.28.115, 172.26.31.254, 172.26.30.2 vcap_request_id:49d47ebe-a54f-4f84-66a7-f1262800588b::67ee0d7f-08bd-401f-a46c-24d7501a5f92 response_time:0.252"#);
        println!("{:#?}", entry);
        assert!(entry.is_ok());
    }

    #[test]
    fn test_parse_gorouter() {
        let entry = parse(
            LogType::GorouterLog,
            r#"test.app_domain.example.com - [2019-01-28T22:15:08.622+0000] "PUT /eureka/apps/SERVICE-REGISTRY/service-registry:-1532850760?status=UP&lastDirtyTimestamp=1547950465746 HTTP/1.1" 404 0 116 "-" "Java-EurekaClient/v1.7.0" "10.224.20.205:23150" "-" x_forwarded_for:"10.179.113.63" x_forwarded_proto:"https" vcap_request_id:"762147e9-ecb8-41b2-4acd-2adc68122486" response_time:0.000119524 app_id:"-" app_index:"-" x_b3_traceid:"59ece3a70be6b6db" x_b3_spanid:"59ece3a70be6b6db" x_b3_parentspanid:"-""#,
        );
        println!("{:#?}", entry);
        assert!(entry.is_ok());
    }
}

// TODO: add support for cloud controller
