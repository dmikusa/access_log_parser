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
use super::XForwardedProto;
use chrono::prelude::*;
use http;
use nom::*;
use std::net::IpAddr;

named!(parse_ip <&str, IpAddr>,
    flat_map!(take_until_and_consume!(" "), parse_to!(IpAddr))
);

named!(parse_date <&str, DateTime<FixedOffset>>,
    map_res!(
        delimited!(
            tag!("["),
            take_until!("]"),
            tag!("]")
        ),
        |s| {
            DateTime::parse_from_str(s, "%d/%h/%Y:%H:%M:%S %z")
                .or_else(|_e| DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%z"))
                .or_else(|_e| DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%z"))
                .or_else(|_e| DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f%z"))
                .or_else(|_e| DateTime::parse_from_rfc2822(s))
                .or_else(|_e| DateTime::parse_from_rfc3339(s))
        }
    )
);

named!(parse_identd_user <&str, Option<&str>>,
    alt!(
        tag!("- ") => { |_| None } |
        opt!(
            take_until_and_consume!(" ")
        )
    )
);

named!(parse_user <&str, Option<&str>>,
    alt!(
        tag!("- ") => { |_| None } |
        opt!(
            take_until_and_consume!(" ")
        )
    )
);

named!(parse_request <&str, super::LogFormatValid>,
    alt_complete!(
        delimited!(
            tag!(r#"""#),
            do_parse!(
                method: take_until_and_consume!(" ") >>
                path: take_until_and_consume!(" ") >>
                proto_ver: alt!(
                    tag!("HTTP/1.0") => { |_| http::Version::HTTP_10 } |
                    tag!("HTTP/1.1") => { |_| http::Version::HTTP_11 } |
                    tag!("HTTP/2.0") => { |_| http::Version::HTTP_2 }
                ) >>
                (match http::Request::builder().method(method).uri(path).version(proto_ver).body(()) {
                    Ok(req) => super::LogFormatValid::Valid(req),
                    Err(err) => super::LogFormatValid::InvalidPath(path, err),
                })
            ),
            tag!(r#"""#)
        ) |
        delimited!(
            tag!(r#"""#),
            take_until!(r#"""#),
            tag!(r#"""#)
        ) => { |path| super::LogFormatValid::InvalidRequest(path) }
    )
);

named!(parse_http_status <&str, http::StatusCode>,
    alt!(
        tag!(r#""-" "#) => { |_| http::StatusCode::IM_A_TEAPOT } |
        flat_map!(take_until_and_consume!(" "), parse_to!(http::StatusCode))
    )
);

named!(parse_bytes <&str, u32>,
    flat_map!(alt_complete!(take_until_and_consume!(" ") | rest), parse_to!(u32))
);

named!(parse_referrer <&str, Option<http::Uri>>,
    map_res!(
        delimited!(
            tag!(r#"""#),
            take_until!(r#"""#),
            tag!(r#"""#)
        ),
        |s: &str| {
            if s.trim() == "-" {
                return Ok(None)
            } else {
                match s.parse() {
                    Ok(uri) => Ok(Some(uri)),
                    Err(e) => Err(e),
                }
            }
        }
    )
);

named!(parse_user_agent <&str, Option<&str>>,
    alt!(
        tag!(r#""-""#) => {|_tag| None } |
        opt!(
            delimited!(
                tag!(r#"""#),
                take_until!(r#"""#),
                tag!(r#"""#)
            )
        )
    )
);

named!(parse_ip_and_port <&str, (Option<IpAddr>, Option<u16>)>,
    alt!(
        tag!("-") => {|_tag| (None, None) } |
        do_parse!(
            ip: opt!(flat_map!(take_until_and_consume!(":"), parse_to!(IpAddr))) >>
            port: opt!(flat_map!(take_until!(r#"""#), parse_to!(u16))) >>
            ((ip, port))
        )
    )
);

named!(parse_ip_list <&str, Vec<IpAddr>>,
    separated_list_complete!(
        tag!(", "),
        flat_map!(
            alt_complete!(
                take_until!(",") |
                take_until!(r#"""#) |
                take_until!(" ")
            ),
            parse_to!(IpAddr)
        )
    )
);

named!(parse_x_forwarded_for <&str, Vec<IpAddr>>,
    alt!(
        tag!("x_forwarded_for:-") => {|_time| Vec::new() } |
        tag!(r#"x_forwarded_for:"-""#) => {|_tag| Vec::new() } |
        do_parse!(
            tag!("x_forwarded_for:") >>
            ips: delimited!(
                tag!(r#"""#),
                parse_ip_list,
                tag!(r#"""#)
            ) >>
            (ips)
        )
    )
);

named!(parse_x_forwarded_proto <&str, XForwardedProto>,
    alt!(
        tag!("x_forwarded_proto:-") => {|_time| XForwardedProto::UNSPECIFIED } |
        tag!(r#"x_forwarded_proto:"-""#) => {|_tag| XForwardedProto::UNSPECIFIED } |
        do_parse!(
            tag!("x_forwarded_proto:") >>
            x_forwarded_for: delimited!(
                tag!(r#"""#),
                alt!(
                    tag!("https") => { |_proto| XForwardedProto::HTTPS } |
                    tag!("http") => { |_proto| XForwardedProto::HTTP }
                ),
                tag!(r#"""#)
            ) >>
            (x_forwarded_for)
        )
    )
);

named!(parse_vcap_request_id <&str, Option<&str>>,
    alt!(
        tag!("vcap_request_id:-") => {|_time| None } |
        tag!(r#"vcap_request_id:"-""#) => {|_time| None } |
        opt!(
            do_parse!(
                tag!("vcap_request_id:") >>
                vcap_request_id: alt!(
                    delimited!(
                        tag!(r#"""#),
                        take_until!(r#"""#),
                        tag!(r#"""#)
                    ) |
                    take_until!(" ")
                ) >>
                (vcap_request_id)
            )
        )
    )
);

named!(parse_response_time <&str, Option<f32>>,
    alt!(
        tag!("response_time:-") => {|_time| None } |
        opt!(
            do_parse!(
                tag!("response_time:") >>
                response_time: flat_map!(alt_complete!(recognize_float | rest), parse_to!(f32)) >>
                (response_time)
            )
        )
    )
);

named!(parse_gorouter_time <&str, Option<f32>>,
    alt!(
        peek!(tag!(r#"app_id"#)) => {|_tag| None } |
        tag!("gorouter_time:-") => {|_time| None } |
        opt!(
            do_parse!(
                tag!("gorouter_time:") >>
                gorouter_time: flat_map!(alt_complete!(recognize_float | rest), parse_to!(f32)) >>
                (gorouter_time)
            )
        )
    )
);

named!(parse_app_id <&str, Option<&str>>,
    alt!(
        tag!(r#"app_id:"-""#) => {|_tag| None } |
        opt!(
            do_parse!(
                tag!("app_id:") >>
                vcap_request_id: delimited!(
                    tag!(r#"""#),
                    take_until!(r#"""#),
                    tag!(r#"""#)
                ) >>
                (vcap_request_id)
            )
        )
    )
);

named!(parse_app_index <&str, Option<u16>>,
    alt!(
        tag!(r#"app_index:"-""#) => {|_tag| None } |
        opt!(
            do_parse!(
                tag!("app_index:") >>
                vcap_request_id: delimited!(
                    tag!(r#"""#),
                    flat_map!(take_until!(r#"""#), parse_to!(u16)),
                    tag!(r#"""#)
                ) >>
                (vcap_request_id)
            )
        )
    )
);

named!(parse_x_cf_routererror <&str, Option<&str>>,
    alt!(
        not!(complete!(non_empty)) => {|_tag| None} |
        peek!(tag!(r#"x_b3_traceid"#)) => {|_tag| None } |
        tag!(r#"x_cf_routererror:"-""#) => {|_tag| None } |
        opt!(
            do_parse!(
                tag!("x_cf_routererror:") >>
                x_cf_routererror: delimited!(
                    tag!(r#"""#),
                    take_until!(r#"""#),
                    tag!(r#"""#)
                ) >>
                (x_cf_routererror)
            )
        )
    )
);

named!(parse_trace_id <&str, Option<&str>>,
    alt!(
        not!(complete!(non_empty)) => {|_tag| None} |
        tag!(r#"x_b3_traceid:"-""#) => {|_tag| None} |
        opt!(
            do_parse!(
                tag!("x_b3_traceid:") >>
                trace_id: delimited!(
                    tag!(r#"""#),
                    take_until!(r#"""#),
                    tag!(r#"""#)
                ) >>
                (trace_id)
            )
        )
    )
);

named!(parse_span_id <&str, Option<&str>>,
    alt!(
        not!(complete!(non_empty)) => {|_tag| None} |
        tag!(r#"x_b3_spanid:"-""#) => {|_tag| None } |
        opt!(
            do_parse!(
                tag!("x_b3_spanid:") >>
                span_id: delimited!(
                    tag!(r#"""#),
                    take_until!(r#"""#),
                    tag!(r#"""#)
                ) >>
                (span_id)
            )
        )
    )
);

named!(parse_parent_span_id <&str, Option<&str>>,
    alt!(
        not!(complete!(non_empty)) => {|_tag| None} |
        tag!(r#"x_b3_parentspanid:"-""#) => {|_tag| None} |
        opt!(
            do_parse!(
                tag!("x_b3_parentspanid:") >>
                parent_span_id: delimited!(
                    tag!(r#"""#),
                    take_until!(r#"""#),
                    tag!(r#"""#)
                ) >>
                (parent_span_id)
            )
        )
    )
);

named!(pub(crate) parse_common_log <&str, super::CommonLogEntry>,
    do_parse!(
        ip: parse_ip >>
        identd_user: parse_identd_user >>
        user: parse_user >>
        timestamp: parse_date >>
        tag!(" ") >>
        request: parse_request >>
        tag!(" ") >>
        status_code: parse_http_status >>
        bytes: parse_bytes >>
        (super::CommonLogEntry { ip, identd_user, user, timestamp, request, status_code, bytes })
    )
);

named!(pub(crate) parse_combined_log <&str, super::CombinedLogEntry>,
    do_parse!(
        ip: parse_ip >>
        identd_user: parse_identd_user >>
        user: parse_user >>
        timestamp: parse_date >>
        tag!(" ") >>
        request: parse_request >>
        tag!(" ") >>
        status_code: parse_http_status >>
        bytes: parse_bytes >>
        referrer: parse_referrer >>
        tag!(" ") >>
        user_agent: parse_user_agent >>
        (super::CombinedLogEntry { ip, identd_user, user, timestamp, request, status_code, bytes, referrer, user_agent })
    )
);

named!(pub(crate) parse_cloud_controller_log <&str, super::CloudControllerLogEntry>,
    do_parse!(
        request_host: take_until_and_consume!(" ") >>
        tag!("- ") >>
        timestamp: parse_date >>
        tag!(" ") >>
        request: parse_request >>
        tag!(" ") >>
        status_code: parse_http_status >>
        bytes: parse_bytes >>
        referrer: parse_referrer >>
        tag!(" ") >>
        user_agent: parse_user_agent >>
        tag!(" ") >>
        x_forwarded_for: parse_ip_list >>
        tag!(" ") >>
        vcap_request_id: parse_vcap_request_id >>
        tag!(" ") >>
        response_time: parse_response_time >>
        (super::CloudControllerLogEntry{
            request_host,
            timestamp,
            request,
            status_code,
            bytes,
            referrer,
            user_agent,
            x_forwarded_for,
            vcap_request_id,
            response_time,
        })
    )
);

named!(pub(crate) parse_gorouter_log <&str, super::GorouterLogEntry>,
    do_parse!(
        request_host: take_until_and_consume!(" ") >>
        tag!("- ") >>
        timestamp: parse_date >>
        tag!(" ") >>
        request: parse_request >>
        tag!(" ") >>
        status_code: parse_http_status >>
        bytes_received: parse_bytes >>
        bytes_sent: parse_bytes >>
        referrer: parse_referrer >>
        tag!(" ") >>
        user_agent: parse_user_agent >>
        tag!(" ") >>
        remote_addr: delimited!(tag!(r#"""#), parse_ip_and_port, tag!(r#"""#)) >>
        tag!(" ") >>
        backend_addr: delimited!(tag!(r#"""#), parse_ip_and_port, tag!(r#"""#)) >>
        tag!(" ") >>
        x_forwarded_for: parse_x_forwarded_for >>
        tag!(" ") >>
        x_forwarded_proto: parse_x_forwarded_proto >>
        tag!(" ") >>
        vcap_request_id: parse_vcap_request_id >>
        tag!(" ") >>
        response_time: parse_response_time >>
        tag!(" ") >>
        gorouter_time: parse_gorouter_time >>
        alt!(peek!(tag!(r#"app_id"#)) => {|_tag| ""} |tag!(" ")) >>
        app_id: parse_app_id >>
        tag!(" ") >>
        app_index: parse_app_index >>
        alt!(not!(complete!(non_empty)) => {|_tag| ""} | tag!(" ")) >>
        x_cf_routererror: parse_x_cf_routererror >>
        alt!(not!(complete!(non_empty)) => {|_tag| ""} | peek!(tag!(r#"x_b3_traceid"#)) => {|_tag| ""} |  tag!(" ")) >>
        trace_id: parse_trace_id >>
        alt!(not!(complete!(non_empty)) => {|_tag| ""} | tag!(" ")) >>
        span_id: parse_span_id >>
        alt!(not!(complete!(non_empty)) => {|_tag| ""} | tag!(" ")) >>
        parent_span_id: parse_parent_span_id >>
        ({
            super::GorouterLogEntry {
                request_host,
                timestamp,
                request,
                status_code,
                bytes_received,
                bytes_sent,
                referrer,
                user_agent,
                remote_addr: remote_addr.0.unwrap(), // should always be there
                remote_port: remote_addr.1.unwrap(), // should always be there
                backend_addr: backend_addr.0,
                backend_port: backend_addr.1,
                x_forwarded_for,
                x_forwarded_proto,
                vcap_request_id,
                response_time,
                gorouter_time,
                app_id,
                app_index,
                x_cf_routererror,
                trace_id,
                span_id,
                parent_span_id,
            }
        })
    )
);

#[cfg(test)]
mod tests {
    use super::*;
    use nom::Context::Code;
    use nom::Err::Error;
    use nom::ErrorKind::{Alt, MapRes, ParseTo};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_parse_date() {
        let expected = FixedOffset::west(7 * 3600)
            .ymd(2000, 7, 25)
            .and_hms(13, 55, 36);

        assert_eq!(
            parse_date("[25/Jul/2000:13:55:36 -0700]"),
            Ok(("", expected))
        );

        assert_eq!(parse_date("[2000-07-25 13:55:36-0700]"), Ok(("", expected)));
        assert_eq!(
            parse_date("[2000-07-25T13:55:36-07:00]"),
            Ok(("", expected))
        );

        assert_eq!(
            parse_date("[Tue, 25 Jul 2000 13:55:36 -0700]"),
            Ok(("", expected))
        );

        let expected = FixedOffset::west(7 * 3600)
            .ymd(2000, 7, 25)
            .and_hms_milli(13, 55, 36, 499);

        assert_eq!(
            parse_date("[2000-07-25T13:55:36.499-0700]"),
            Ok(("", expected))
        );

        assert_eq!(
            parse_date("[10/Oct/2000:13:55:36]"),
            Err(Error(Code("[10/Oct/2000:13:55:36]", MapRes)))
        );
    }

    #[test]
    fn test_parse_ip() {
        assert_eq!(
            parse_ip("127.0.0.1 "),
            Ok(("", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))))
        );

        assert_eq!(
            parse_ip("::1 "),
            Ok(("", IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))))
        );
    }

    #[test]
    fn test_parse_identd_user() {
        // https://tools.ietf.org/html/rfc1413
        assert_eq!(parse_identd_user("- "), Ok(("", None)));
        assert_eq!(
            parse_identd_user("user-identifier "),
            Ok(("", Some("user-identifier")))
        );
    }

    #[test]
    fn test_parse_user() {
        assert_eq!(parse_user("- "), Ok(("", None)));
        assert_eq!(parse_user("daniel "), Ok(("", Some("daniel"))));
    }

    #[test]
    fn test_parse_request() {
        let res = parse_request(r#""GET /apache_pb.gif HTTP/1.0""#);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.0, ""); // nothing left in buffer
        match res.1 {
            super::super::LogFormatValid::Valid(req) => {
                assert_eq!(req.method(), http::Method::GET);
                assert_eq!(req.uri(), "/apache_pb.gif");
                assert_eq!(req.version(), http::Version::HTTP_10);
            }
            super::super::LogFormatValid::InvalidRequest(path) => panic!("invalid path [{}]", path),
            super::super::LogFormatValid::InvalidPath(path, err) => {
                panic!("invalid request [{}], err: {:?}", path, err)
            }
        }
    }

    #[test]
    fn test_parse_request_invalid_1() {
        let res = parse_request(
            r#""H\x00\x00\x00tj\xA8\x9E#D\x98+\xCA\xF0\xA7\xBBl\xC5\x19\xD7\x8D\xB6\x18\xEDJ\x1En\xC1\xF9xu[l\xF0E\x1D-j\xEC\xD4xL\xC9r\xC9\x15\x10u\xE0%\x86Rtg\x05fv\x86]%\xCC\x80\x0C\xE8\xCF\xAE\x00\xB5\xC0f\xC8\x8DD\xC5\x09\xF4""#,
        );
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.0, ""); // nothing left in buffer
        match res.1 {
            super::super::LogFormatValid::Valid(_) => panic!("should be InalidRequest"),
            super::super::LogFormatValid::InvalidRequest(path) => {
                assert_eq!(
                    path,
                    r#"H\x00\x00\x00tj\xA8\x9E#D\x98+\xCA\xF0\xA7\xBBl\xC5\x19\xD7\x8D\xB6\x18\xEDJ\x1En\xC1\xF9xu[l\xF0E\x1D-j\xEC\xD4xL\xC9r\xC9\x15\x10u\xE0%\x86Rtg\x05fv\x86]%\xCC\x80\x0C\xE8\xCF\xAE\x00\xB5\xC0f\xC8\x8DD\xC5\x09\xF4"#
                );
            }
            super::super::LogFormatValid::InvalidPath(path, err) => {
                panic!("invalid request [{}], err: {:?}", path, err)
            }
        }
    }

    #[test]
    fn test_parse_request_invalid_2() {
        let res = parse_request(
            r#""238\x00ll|'|'|SGFjS2VkX0Q3NUU2QUFB|'|'|WIN-QZN7FJ7D1O|'|'|Administrator|'|'|18-11-28|'|'||'|'|Win 7 Ultimate SP1 x64|'|'|No|'|'|S17|'|'|..|'|'|SW5ib3ggLSBPdXRsb29rIERhdGEgRmlsZSAtIE1pY3Jvc29mdCBPdXRsb29rAA==|'|'|""#,
        );
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.0, ""); // nothing left in buffer
        match res.1 {
            super::super::LogFormatValid::Valid(_) => panic!("should be InalidRequest"),
            super::super::LogFormatValid::InvalidRequest(path) => {
                assert_eq!(
                    path,
                    r#"238\x00ll|'|'|SGFjS2VkX0Q3NUU2QUFB|'|'|WIN-QZN7FJ7D1O|'|'|Administrator|'|'|18-11-28|'|'||'|'|Win 7 Ultimate SP1 x64|'|'|No|'|'|S17|'|'|..|'|'|SW5ib3ggLSBPdXRsb29rIERhdGEgRmlsZSAtIE1pY3Jvc29mdCBPdXRsb29rAA==|'|'|"#
                );
            }
            super::super::LogFormatValid::InvalidPath(path, err) => {
                panic!("invalid request [{}], err: {:?}", path, err)
            }
        }
    }

    #[test]
    fn test_parse_request_empty() {
        let res = parse_request(r#""""#);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.0, ""); // nothing left in buffer
        match res.1 {
            super::super::LogFormatValid::Valid(_) => panic!("should be InalidRequest"),
            super::super::LogFormatValid::InvalidRequest(path) => {
                assert_eq!(path, "");
            }
            super::super::LogFormatValid::InvalidPath(path, err) => {
                panic!("invalid request [{}], err: {:?}", path, err)
            }
        }
    }

    #[test]
    fn test_parse_invalid_request_gh_issue_2() {
        let res = parse_request(
            r#""GET /?a=fetch&content=<php>die(@md5(HelloThinkCMF))</php> HTTP/1.1""#,
        );
        assert!(res.is_ok(), "err: {:?}", res.err());
        let res = res.unwrap();
        assert_eq!(res.0, ""); // nothing left in buffer
        match res.1 {
            super::super::LogFormatValid::Valid(_) => panic!("should be InvalidPath"),
            super::super::LogFormatValid::InvalidRequest(path) => panic!("invalid path [{}]", path),
            super::super::LogFormatValid::InvalidPath(path, err) => {
                assert_eq!(
                    path,
                    "/?a=fetch&content=<php>die(@md5(HelloThinkCMF))</php>"
                );
                assert_eq!(err.to_string(), "invalid uri character");
            }
        }
    }

    #[test]
    fn test_parse_bytes() {
        assert_eq!(parse_bytes("1234"), Ok(("", 1234)));
        assert_eq!(parse_bytes("1234 "), Ok(("", 1234)));
        assert_eq!(parse_bytes(""), Err(Error(Code("", ParseTo))));
    }

    #[test]
    fn test_parse_http_status() {
        assert_eq!(
            parse_http_status("404 "),
            Ok(("", http::StatusCode::NOT_FOUND))
        );
        assert_eq!(
            parse_http_status("418 "),
            Ok(("", http::StatusCode::IM_A_TEAPOT))
        );
        assert_eq!(
            parse_http_status(r#""-" "#),
            Ok(("", http::StatusCode::IM_A_TEAPOT))
        );
        assert_eq!(parse_http_status(" "), Err(Error(Code(" ", Alt))));
    }

    #[test]
    fn test_parse_referrer() {
        let uri = parse_referrer(r#""http://www.example.com/query""#);
        assert!(uri.is_ok());
        let uri = uri.unwrap().1;
        assert!(uri.is_some());
        let uri = uri.unwrap();
        assert_eq!("/query", uri.path());
        assert_eq!("www.example.com", uri.host().unwrap());

        assert!(parse_referrer(r#""-""#).unwrap().1.is_none());
    }

    #[test]
    fn test_parse_user_agent() {
        let agent = parse_user_agent(r#""Mozilla/4.08 [en] (Win98; I ;Nav)""#);
        assert!(agent.is_ok());
        let agent = agent.unwrap().1;
        assert!(agent.is_some());
        let agent = agent.unwrap();
        assert_eq!(agent, "Mozilla/4.08 [en] (Win98; I ;Nav)");

        let agent = parse_user_agent(r#""-""#);
        assert!(agent.is_ok());
        let agent = agent.unwrap().1;
        assert!(agent.is_none());
    }

    #[test]
    fn test_parse_x_forwarded_for() {
        let x_forwarded_for = parse_x_forwarded_for(r#"x_forwarded_for:"10.10.10.1, 10.10.10.2""#);
        assert!(x_forwarded_for.is_ok());
        let x_forwarded_for = x_forwarded_for.unwrap().1;
        assert_eq!(
            x_forwarded_for,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 10, 10, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 10, 10, 2))
            ]
        );
    }

    #[test]
    fn test_parse_x_forwarded_proto() {
        let x_forwarded_proto = parse_x_forwarded_proto(r#"x_forwarded_proto:"https""#);
        assert!(x_forwarded_proto.is_ok());
        let x_forwarded_proto = x_forwarded_proto.unwrap().1;
        assert_eq!(x_forwarded_proto, XForwardedProto::HTTPS);

        let x_forwarded_proto = parse_x_forwarded_proto(r#"x_forwarded_proto:"https""#);
        assert!(x_forwarded_proto.is_ok());
        let x_forwarded_proto = x_forwarded_proto.unwrap().1;
        assert_eq!(x_forwarded_proto, XForwardedProto::HTTPS);
    }

    #[test]
    fn test_parse_vcap_request_id() {
        let vcap_request_id =
            parse_vcap_request_id(r#"vcap_request_id:"e1604ad1-002c-48ff-6c44-f360e3096911""#);
        assert!(vcap_request_id.is_ok());
        let vcap_request_id = vcap_request_id.unwrap().1;
        assert!(vcap_request_id.is_some());
        assert_eq!(
            vcap_request_id.unwrap(),
            "e1604ad1-002c-48ff-6c44-f360e3096911"
        );

        let vcap_request_id = parse_vcap_request_id(
            r#"vcap_request_id:49d47ebe-a54f-4f84-66a7-f1262800588b::67ee0d7f-08bd-401f-a46c-24d7501a5f92 "#,
        );
        assert!(vcap_request_id.is_ok());
        let vcap_request_id = vcap_request_id.unwrap().1;
        assert!(vcap_request_id.is_some());
        assert_eq!(
            vcap_request_id.unwrap(),
            "49d47ebe-a54f-4f84-66a7-f1262800588b::67ee0d7f-08bd-401f-a46c-24d7501a5f92"
        );

        let vcap_request_id = parse_vcap_request_id(r#"vcap_request_id:"-""#);
        assert!(vcap_request_id.is_ok());
        let vcap_request_id = vcap_request_id.unwrap().1;
        assert!(vcap_request_id.is_none());

        let vcap_request_id = parse_vcap_request_id("vcap_request_id:-");
        assert!(vcap_request_id.is_ok());
        let vcap_request_id = vcap_request_id.unwrap().1;
        assert!(vcap_request_id.is_none());
    }

    #[test]
    fn test_parse_response_time() {
        let response_time = parse_response_time(r#"response_time:0.007799583"#);
        assert!(response_time.is_ok());
        let response_time = response_time.unwrap().1;
        assert!(response_time.is_some());
        assert_eq!(response_time.unwrap(), 0.007799583);

        let response_time = parse_response_time(r#"response_time:-"#);
        assert!(response_time.is_ok());
        let response_time = response_time.unwrap().1;
        assert!(response_time.is_none());
    }

    #[test]
    fn test_parse_gorouter_time() {
        let gorouter_time = parse_gorouter_time(r#"gorouter_time:0.000104"#);
        assert!(gorouter_time.is_ok());
        let gorouter_time = gorouter_time.unwrap().1;
        assert!(gorouter_time.is_some());
        assert_eq!(gorouter_time.unwrap(), 0.000104);

        let gorouter_time = parse_gorouter_time(r#"gorouter_time:-"#);
        assert!(gorouter_time.is_ok());
        let gorouter_time = gorouter_time.unwrap().1;
        assert!(gorouter_time.is_none());
    }

    #[test]
    fn test_parse_app_id() {
        let app_id = parse_app_id(r#"app_id:"2c3f3955-d0cd-444c-9350-3fc47bd44eaa""#);
        assert!(app_id.is_ok());
        let app_id = app_id.unwrap().1;
        assert!(app_id.is_some());
        let app_id = app_id.unwrap();
        assert_eq!(app_id, "2c3f3955-d0cd-444c-9350-3fc47bd44eaa");

        let app_id = parse_app_id(r#"app_id:"-""#);
        assert!(app_id.is_ok());
        let app_id = app_id.unwrap().1;
        assert!(app_id.is_none());
    }

    #[test]
    fn test_parse_app_index() {
        let app_index = parse_app_index(r#"app_index:"0""#);
        assert!(app_index.is_ok());
        let app_index = app_index.unwrap().1;
        assert!(app_index.is_some());
        let app_index = app_index.unwrap();
        assert_eq!(app_index, 0);

        let app_index = parse_app_index(r#"app_index:"-""#);
        assert!(app_index.is_ok());
        let app_index = app_index.unwrap().1;
        assert!(app_index.is_none());
    }

    #[test]
    fn test_parse_x_cf_routererror() {
        let x_cf_routererror = parse_x_cf_routererror(r#"x_cf_routererror:"unknown_route""#);
        assert!(x_cf_routererror.is_ok());
        let x_cf_routererror = x_cf_routererror.unwrap().1;
        assert!(x_cf_routererror.is_some());
        let x_cf_routererror = x_cf_routererror.unwrap();
        assert_eq!(x_cf_routererror, "unknown_route");

        let x_cf_routererror = parse_x_cf_routererror(r#"x_cf_routererror:"-""#);
        assert!(x_cf_routererror.is_ok());
        let x_cf_routererror = x_cf_routererror.unwrap().1;
        assert!(x_cf_routererror.is_none());
    }

    #[test]
    fn test_parse_trace_id() {
        let trace_id = parse_trace_id(r#"x_b3_traceid:"f7a79a16ab5c8383""#);
        assert!(trace_id.is_ok());
        let trace_id = trace_id.unwrap().1;
        assert!(trace_id.is_some());
        let trace_id = trace_id.unwrap();
        assert_eq!(trace_id, "f7a79a16ab5c8383");

        let trace_id = parse_trace_id(r#"x_b3_traceid:"-""#);
        assert!(trace_id.is_ok());
        let trace_id = trace_id.unwrap().1;
        assert!(trace_id.is_none());

        let trace_id = parse_trace_id(r#""#);
        assert!(trace_id.is_ok());
        let trace_id = trace_id.unwrap().1;
        assert!(trace_id.is_none());
    }

    #[test]
    fn test_parse_span_id() {
        let span_id = parse_span_id(r#"x_b3_spanid:"f7a79a16ab5c8383""#);
        assert!(span_id.is_ok());
        let span_id = span_id.unwrap().1;
        assert!(span_id.is_some());
        let span_id = span_id.unwrap();
        assert_eq!(span_id, "f7a79a16ab5c8383");

        let span_id = parse_span_id(r#"x_b3_spanid:"-""#);
        assert!(span_id.is_ok());
        let span_id = span_id.unwrap().1;
        assert!(span_id.is_none());

        let span_id = parse_span_id(r#""#);
        assert!(span_id.is_ok());
        let span_id = span_id.unwrap().1;
        assert!(span_id.is_none());
    }

    #[test]
    fn test_parse_parent_span_id() {
        let parent_span_id = parse_parent_span_id(r#"x_b3_parentspanid:"f7a79a16ab5c8383""#);
        assert!(parent_span_id.is_ok());
        let parent_span_id = parent_span_id.unwrap().1;
        assert!(parent_span_id.is_some());
        let parent_span_id = parent_span_id.unwrap();
        assert_eq!(parent_span_id, "f7a79a16ab5c8383");

        let parent_span_id = parse_parent_span_id(r#"x_b3_parentspanid:"-""#);
        assert!(parent_span_id.is_ok());
        let parent_span_id = parent_span_id.unwrap().1;
        assert!(parent_span_id.is_none());

        let parent_span_id = parse_parent_span_id(r#""#);
        assert!(parent_span_id.is_ok());
        let parent_span_id = parent_span_id.unwrap().1;
        assert!(parent_span_id.is_none());
    }

    #[test]
    fn test_parse_common_log_entry() {
        let entry = parse_common_log(
            r#"127.0.0.1 user-identifier frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326"#,
        );
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(entry.ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(entry.identd_user.is_some());
        assert_eq!(entry.identd_user.unwrap(), "user-identifier");
        assert!(entry.user.is_some());
        assert_eq!(entry.user.unwrap(), "frank");
        assert_eq!(
            entry.timestamp,
            FixedOffset::west(7 * 3600)
                .ymd(2000, 10, 10)
                .and_hms(13, 55, 36)
        );
        match entry.request {
            super::super::LogFormatValid::Valid(req) => {
                assert_eq!(req.method(), http::Method::GET);
                assert_eq!(req.uri(), "/apache_pb.gif");
                assert_eq!(req.version(), http::Version::HTTP_10);
            }
            super::super::LogFormatValid::InvalidRequest(path) => panic!("invalid path [{}]", path),
            super::super::LogFormatValid::InvalidPath(path, err) => {
                panic!("invalid request [{}], err: {:?}", path, err)
            }
        }
        assert_eq!(entry.status_code, http::StatusCode::OK);
        assert_eq!(entry.bytes, 2326);
    }

    #[test]
    fn test_parse_common_log_ipv6() {
        let entry = parse_common_log(
            r#"2001:8a0:fa0d:ba01:5db0:ae0f:8444:161c - - [02/Mar/2019:17:39:56 +0000] "GET / HTTP/1.1" 200 66503"#,
        );
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(
            entry.ip,
            IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x8a0, 0xfa0d, 0xba01, 0x5db0, 0xae0f, 0x8444, 0x161c
            ))
        );
        assert!(entry.identd_user.is_none());
        assert!(entry.user.is_none());
        assert_eq!(
            entry.timestamp,
            FixedOffset::west(0).ymd(2019, 3, 2).and_hms(17, 39, 56)
        );
        match entry.request {
            super::super::LogFormatValid::Valid(req) => {
                assert_eq!(req.method(), http::Method::GET);
                assert_eq!(req.uri(), "/");
                assert_eq!(req.version(), http::Version::HTTP_11);
            }
            super::super::LogFormatValid::InvalidRequest(path) => panic!("invalid path [{}]", path),
            super::super::LogFormatValid::InvalidPath(path, err) => {
                panic!("invalid request [{}], err: {:?}", path, err)
            }
        }
        assert_eq!(entry.status_code, http::StatusCode::OK);
        assert_eq!(entry.bytes, 66503);
    }

    #[test]
    fn test_parse_common_log_entry_more() {
        let entry = parse_common_log(
            r#"127.0.0.1 - - [15/Mar/2019:03:17:05 +0000] "GET / HTTP/1.1" 200 612"#,
        );
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(entry.ip, Ipv4Addr::new(127, 0, 0, 1));
        assert!(entry.identd_user.is_none());
        assert!(entry.user.is_none());
        assert_eq!(
            entry.timestamp,
            FixedOffset::west(0).ymd(2019, 3, 15).and_hms(3, 17, 5)
        );
        match entry.request {
            super::super::LogFormatValid::Valid(req) => {
                assert_eq!(req.method(), http::Method::GET);
                assert_eq!(req.uri(), "/");
                assert_eq!(req.version(), http::Version::HTTP_11);
            }
            super::super::LogFormatValid::InvalidRequest(path) => panic!("invalid path [{}]", path),
            super::super::LogFormatValid::InvalidPath(path, err) => {
                panic!("invalid request [{}], err: {:?}", path, err)
            }
        }
        assert_eq!(entry.status_code, http::StatusCode::OK);
        assert_eq!(entry.bytes, 612);
    }

    #[test]
    fn test_parse_combined_log_entry() {
        let entry = parse_combined_log(
            r#"127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)""#,
        );
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(entry.ip, Ipv4Addr::new(127, 0, 0, 1));
        assert!(entry.identd_user.is_none());
        assert!(entry.user.is_some());
        assert_eq!(entry.user.unwrap(), "frank");
        assert_eq!(
            entry.timestamp,
            FixedOffset::west(7 * 3600)
                .ymd(2000, 10, 10)
                .and_hms(13, 55, 36)
        );
        match entry.request {
            super::super::LogFormatValid::Valid(req) => {
                assert_eq!(req.method(), http::Method::GET);
                assert_eq!(req.uri(), "/apache_pb.gif");
                assert_eq!(req.version(), http::Version::HTTP_10);
            }
            super::super::LogFormatValid::InvalidRequest(path) => panic!("invalid path [{}]", path),
            super::super::LogFormatValid::InvalidPath(path, err) => {
                panic!("invalid request [{}], err: {:?}", path, err)
            }
        }
        assert_eq!(entry.status_code, http::StatusCode::OK);
        assert_eq!(entry.bytes, 2326);
        assert!(entry.referrer.is_some());
        let referrer = entry.referrer.unwrap();
        assert_eq!(referrer.path(), "/start.html");
        assert_eq!(referrer.host().unwrap(), "www.example.com");
        assert!(entry.user_agent.is_some());
        assert_eq!(
            entry.user_agent.unwrap(),
            "Mozilla/4.08 [en] (Win98; I ;Nav)"
        );
    }

    #[test]
    fn test_parse_combined_log_entry_more() {
        let entry = parse_combined_log(
            r#"127.0.0.1 - - [15/Mar/2019:03:17:05 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.52.1""#,
        );
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(entry.ip, Ipv4Addr::new(127, 0, 0, 1));
        assert!(entry.identd_user.is_none());
        assert!(entry.user.is_none());
        assert_eq!(
            entry.timestamp,
            FixedOffset::west(0).ymd(2019, 3, 15).and_hms(3, 17, 5)
        );
        match entry.request {
            super::super::LogFormatValid::Valid(req) => {
                assert_eq!(req.method(), http::Method::GET);
                assert_eq!(req.uri(), "/");
                assert_eq!(req.version(), http::Version::HTTP_11);
            }
            super::super::LogFormatValid::InvalidRequest(path) => panic!("invalid path [{}]", path),
            super::super::LogFormatValid::InvalidPath(path, err) => {
                panic!("invalid request [{}], err: {:?}", path, err)
            }
        }
        assert_eq!(entry.status_code, http::StatusCode::OK);
        assert_eq!(entry.bytes, 612);
        assert!(entry.referrer.is_none());
        assert!(entry.user_agent.is_some());
        assert_eq!(entry.user_agent.unwrap(), "curl/7.52.1");
    }

    #[test]
    fn test_parse_cloud_controller_access_log() {
        let entry = parse_cloud_controller_log(
            r#"api.system_domain.local - [01/Feb/2019:20:45:02 +0000] "GET /v2/spaces/a91c3fa8-e67d-40dd-9d6b-d01aefe5062a/summary HTTP/1.1" 200 53188 "-" "cf_exporter/" 172.26.28.115, 172.26.31.254, 172.26.30.2 vcap_request_id:49d47ebe-a54f-4f84-66a7-f1262800588b::67ee0d7f-08bd-401f-a46c-24d7501a5f92 response_time:0.252"#,
        );
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(entry.request_host, "api.system_domain.local");
        assert_eq!(
            entry.timestamp,
            FixedOffset::west(0).ymd(2019, 2, 1).and_hms(20, 45, 2)
        );
        match entry.request {
            super::super::LogFormatValid::Valid(req) => {
                assert_eq!(req.method(), http::Method::GET);
                assert_eq!(
                    req.uri(),
                    "/v2/spaces/a91c3fa8-e67d-40dd-9d6b-d01aefe5062a/summary"
                );
                assert_eq!(req.version(), http::Version::HTTP_11);
            }
            super::super::LogFormatValid::InvalidRequest(path) => panic!("invalid path [{}]", path),
            super::super::LogFormatValid::InvalidPath(path, err) => {
                panic!("invalid request [{}], err: {:?}", path, err)
            }
        }
        assert_eq!(entry.status_code, http::StatusCode::OK);
        assert_eq!(entry.bytes, 53188);
        assert!(entry.referrer.is_none());
        assert!(entry.user_agent.is_some());
        assert_eq!(entry.user_agent.unwrap(), "cf_exporter/");
        assert_eq!(entry.x_forwarded_for.len(), 3);
        assert_eq!(
            entry.x_forwarded_for[0],
            IpAddr::V4(Ipv4Addr::new(172, 26, 28, 115))
        );
        assert_eq!(
            entry.x_forwarded_for[1],
            IpAddr::V4(Ipv4Addr::new(172, 26, 31, 254))
        );
        assert_eq!(
            entry.x_forwarded_for[2],
            IpAddr::V4(Ipv4Addr::new(172, 26, 30, 2))
        );
        assert!(entry.vcap_request_id.is_some());
        assert_eq!(
            entry.vcap_request_id.unwrap(),
            "49d47ebe-a54f-4f84-66a7-f1262800588b::67ee0d7f-08bd-401f-a46c-24d7501a5f92"
        );
        assert!(entry.response_time.is_some());
        assert_eq!(entry.response_time.unwrap(), 0.252);
    }

    #[test]
    fn test_parse_cloud_controller_access_log_with_no_response_time() {
        let entry = parse_cloud_controller_log(
            r#"api.system_domain.local - [01/Feb/2019:15:26:42 +0000] "GET /v2/organizations?page=1&results-per-page=1&order-direction=asc HTTP/1.1" 499 0 "-" "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36" 10.1.43.82, 172.26.31.254, 172.26.28.40, 172.26.31.254, 172.26.30.1 vcap_request_id:- response_time:-"#,
        );
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(entry.request_host, "api.system_domain.local");
        assert_eq!(
            entry.timestamp,
            FixedOffset::west(0).ymd(2019, 2, 1).and_hms(15, 26, 42)
        );
        match entry.request {
            super::super::LogFormatValid::Valid(req) => {
                assert_eq!(req.method(), http::Method::GET);
                assert_eq!(
                    req.uri(),
                    "/v2/organizations?page=1&results-per-page=1&order-direction=asc"
                );
                assert_eq!(req.version(), http::Version::HTTP_11);
            }
            super::super::LogFormatValid::InvalidRequest(path) => panic!("invalid path [{}]", path),
            super::super::LogFormatValid::InvalidPath(path, err) => {
                panic!("invalid request [{}], err: {:?}", path, err)
            }
        }
        assert_eq!(entry.status_code, http::StatusCode::from_u16(499).unwrap());
        assert_eq!(entry.bytes, 0);
        assert!(entry.referrer.is_none());
        assert!(entry.user_agent.is_some());
        assert_eq!(entry.user_agent.unwrap(), "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36");
        assert_eq!(entry.x_forwarded_for.len(), 5);
        assert_eq!(
            entry.x_forwarded_for[0],
            IpAddr::V4(Ipv4Addr::new(10, 1, 43, 82))
        );
        assert_eq!(
            entry.x_forwarded_for[1],
            IpAddr::V4(Ipv4Addr::new(172, 26, 31, 254))
        );
        assert_eq!(
            entry.x_forwarded_for[2],
            IpAddr::V4(Ipv4Addr::new(172, 26, 28, 40))
        );
        assert_eq!(
            entry.x_forwarded_for[3],
            IpAddr::V4(Ipv4Addr::new(172, 26, 31, 254))
        );
        assert_eq!(
            entry.x_forwarded_for[4],
            IpAddr::V4(Ipv4Addr::new(172, 26, 30, 1))
        );
        assert!(entry.vcap_request_id.is_none());
        assert!(entry.response_time.is_none());
    }

    #[test]
    fn test_parse_gorouter_access_log() {
        let entry = parse_gorouter_log(
            r#"service.apps-domain.example.com - [2019-01-28T22:15:02.499+0000] "GET /v1/some/resource HTTP/1.1" 200 0 16409 "-" "Apache-HttpClient/4.3.3 (java 1.5)" "10.224.16.182:63326" "10.224.28.75:61022" x_forwarded_for:"10.178.177.71, 10.179.113.67, 10.224.16.182" x_forwarded_proto:"https" vcap_request_id:"e1604ad1-002c-48ff-6c44-f360e3096911" response_time:0.007799583 app_id:"2c3f3955-d0cd-444c-9350-3fc47bd44eaa" app_index:"0" x_b3_traceid:"f7a79a16ab5c8383" x_b3_spanid:"f7a79a16ab5c8383" x_b3_parentspanid:"-""#,
        );
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(entry.request_host, "service.apps-domain.example.com");
        assert_eq!(
            entry.timestamp,
            FixedOffset::west(0)
                .ymd(2019, 1, 28)
                .and_hms_milli(22, 15, 2, 499)
        );
        match entry.request {
            super::super::LogFormatValid::Valid(req) => {
                assert_eq!(req.method(), http::Method::GET);
                assert_eq!(req.uri(), "/v1/some/resource");
                assert_eq!(req.version(), http::Version::HTTP_11);
            }
            super::super::LogFormatValid::InvalidRequest(path) => panic!("invalid path [{}]", path),
            super::super::LogFormatValid::InvalidPath(path, err) => {
                panic!("invalid request [{}], err: {:?}", path, err)
            }
        }
        assert_eq!(entry.status_code, http::StatusCode::OK);
        assert_eq!(entry.bytes_received, 0);
        assert_eq!(entry.bytes_sent, 16409);
        assert!(entry.referrer.is_none());
        assert!(entry.user_agent.is_some());
        assert_eq!(
            entry.user_agent.unwrap(),
            "Apache-HttpClient/4.3.3 (java 1.5)"
        );
        assert_eq!(
            entry.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 224, 16, 182))
        );
        assert_eq!(entry.remote_port, 63326);
        assert_eq!(
            entry.backend_addr,
            Some(IpAddr::V4(Ipv4Addr::new(10, 224, 28, 75)))
        );
        assert_eq!(entry.backend_port, Some(61022));
        assert_eq!(entry.x_forwarded_for.len(), 3);
        assert_eq!(
            entry.x_forwarded_for[0],
            IpAddr::V4(Ipv4Addr::new(10, 178, 177, 71))
        );
        assert_eq!(
            entry.x_forwarded_for[1],
            IpAddr::V4(Ipv4Addr::new(10, 179, 113, 67))
        );
        assert_eq!(
            entry.x_forwarded_for[2],
            IpAddr::V4(Ipv4Addr::new(10, 224, 16, 182))
        );
        assert_eq!(entry.x_forwarded_proto, XForwardedProto::HTTPS);
        assert!(entry.vcap_request_id.is_some());
        assert_eq!(
            entry.vcap_request_id.unwrap(),
            "e1604ad1-002c-48ff-6c44-f360e3096911"
        );
        assert!(entry.response_time.is_some());
        assert_eq!(entry.response_time.unwrap(), 0.007799583);
        assert!(entry.app_id.is_some());
        assert_eq!(
            entry.app_id.unwrap(),
            "2c3f3955-d0cd-444c-9350-3fc47bd44eaa"
        );
        assert!(entry.app_index.is_some());
        assert_eq!(entry.app_index.unwrap(), 0);
        assert!(entry.trace_id.is_some());
        assert_eq!(entry.trace_id.unwrap(), "f7a79a16ab5c8383");
        assert!(entry.span_id.is_some());
        assert_eq!(entry.span_id.unwrap(), "f7a79a16ab5c8383");
        assert!(entry.parent_span_id.is_none());
    }

    #[test]
    fn test_parse_gorouter_access_log_without_zipkin_info() {
        let entry = parse_gorouter_log(
            r#"service.apps-domain.example.com - [2019-01-28T22:15:02.499+0000] "GET /v1/some/resource HTTP/1.1" 200 0 16409 "-" "Apache-HttpClient/4.3.3 (java 1.5)" "10.224.16.182:63326" "10.224.28.75:61022" x_forwarded_for:"10.178.177.71, 10.179.113.67, 10.224.16.182" x_forwarded_proto:"https" vcap_request_id:"e1604ad1-002c-48ff-6c44-f360e3096911" response_time:0.007799583 app_id:"2c3f3955-d0cd-444c-9350-3fc47bd44eaa" app_index:"0""#,
        );
        print!("--> {:?}", entry);
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(entry.request_host, "service.apps-domain.example.com");
        assert_eq!(
            entry.timestamp,
            FixedOffset::west(0)
                .ymd(2019, 1, 28)
                .and_hms_milli(22, 15, 2, 499)
        );
        match entry.request {
            super::super::LogFormatValid::Valid(req) => {
                assert_eq!(req.method(), http::Method::GET);
                assert_eq!(req.uri(), "/v1/some/resource");
                assert_eq!(req.version(), http::Version::HTTP_11);
            }
            super::super::LogFormatValid::InvalidRequest(path) => panic!("invalid path [{}]", path),
            super::super::LogFormatValid::InvalidPath(path, err) => {
                panic!("invalid request [{}], err: {:?}", path, err)
            }
        }
        assert_eq!(entry.status_code, http::StatusCode::OK);
        assert_eq!(entry.bytes_received, 0);
        assert_eq!(entry.bytes_sent, 16409);
        assert!(entry.referrer.is_none());
        assert!(entry.user_agent.is_some());
        assert_eq!(
            entry.user_agent.unwrap(),
            "Apache-HttpClient/4.3.3 (java 1.5)"
        );
        assert_eq!(
            entry.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 224, 16, 182))
        );
        assert_eq!(entry.remote_port, 63326);
        assert_eq!(
            entry.backend_addr,
            Some(IpAddr::V4(Ipv4Addr::new(10, 224, 28, 75)))
        );
        assert_eq!(entry.backend_port, Some(61022));
        assert_eq!(entry.x_forwarded_for.len(), 3);
        assert_eq!(
            entry.x_forwarded_for[0],
            IpAddr::V4(Ipv4Addr::new(10, 178, 177, 71))
        );
        assert_eq!(
            entry.x_forwarded_for[1],
            IpAddr::V4(Ipv4Addr::new(10, 179, 113, 67))
        );
        assert_eq!(
            entry.x_forwarded_for[2],
            IpAddr::V4(Ipv4Addr::new(10, 224, 16, 182))
        );
        assert_eq!(entry.x_forwarded_proto, XForwardedProto::HTTPS);
        assert!(entry.vcap_request_id.is_some());
        assert_eq!(
            entry.vcap_request_id.unwrap(),
            "e1604ad1-002c-48ff-6c44-f360e3096911"
        );
        assert!(entry.response_time.is_some());
        assert_eq!(entry.response_time.unwrap(), 0.007799583);
        assert!(entry.app_id.is_some());
        assert_eq!(
            entry.app_id.unwrap(),
            "2c3f3955-d0cd-444c-9350-3fc47bd44eaa"
        );
        assert!(entry.app_index.is_some());
        assert_eq!(entry.app_index.unwrap(), 0);
        assert!(entry.trace_id.is_none());
        assert!(entry.span_id.is_none());
        assert!(entry.parent_span_id.is_none());
    }

    #[test]
    fn test_parse_gorouter_access_log_with_invalid_http_status() {
        let entry = parse_gorouter_log(
            r#"doppler.example.com:4443 - [2019-01-28T18:35:38.720+0000] "GET /apps/5f13e1d2-1aa7-41d7-80d1-8df4cfd279c9/stream HTTP/1.1" "-" 0 0 "-" "CloudFoundryJavaClient/unknown (Java; Oracle Corporation/1.8.0_162) ReactorNetty/unknown (Netty/unknown)" "10.224.16.82:44768" "10.224.24.29:8081" x_forwarded_for:"10.224.16.82" x_forwarded_proto:"https" vcap_request_id:"a038e75b-581f-457d-7a49-c46b69d56aac" response_time:5.001585426 app_id:"-" app_index:"-" x_b3_traceid:"d8b747e82ff5c572" x_b3_spanid:"d8b747e82ff5c572" x_b3_parentspanid:"-""#,
        );
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(entry.status_code, http::StatusCode::IM_A_TEAPOT);
    }

    #[test]
    fn test_parse_gorouter_access_log_with_gorouter_time() {
        let entry = parse_gorouter_log(
            r#"php-info.cfapps.io - [2020-07-23T19:46:59.042378510Z] "GET / HTTP/1.1" 200 0 399 "-" "curl/7.64.1" "10.10.66.179:28634" "10.10.148.45:61300" x_forwarded_for:"50.4.153.215, 10.10.66.179" x_forwarded_proto:"https" vcap_request_id:"c5794050-ac30-4911-5118-c5a8a4e8d09f" response_time:0.101468 gorouter_time:0.000104 app_id:"5f362051-e2bc-4abc-ab8e-adbdf688ae64" app_index:"0" x_b3_traceid:"e3e4a237210114ef" x_b3_spanid:"e3e4a237210114ef" x_b3_parentspanid:"-" b3:"e3e4a237210114ef-e3e4a237210114ef""#,
        );
        print!("{:?}", entry);
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(entry.gorouter_time.unwrap(), 0.000104);
        assert_eq!(entry.x_cf_routererror, None);
    }

    #[test]
    fn test_parse_gorouter_access_log_with_gorouter_time_and_x_cf_routererror() {
        let entry = parse_gorouter_log(
            r#"php-info.cfapps.io - [2020-07-23T19:46:59.042378510Z] "GET / HTTP/1.1" 200 0 399 "-" "curl/7.64.1" "10.10.66.179:28634" "10.10.148.45:61300" x_forwarded_for:"50.4.153.215, 10.10.66.179" x_forwarded_proto:"https" vcap_request_id:"c5794050-ac30-4911-5118-c5a8a4e8d09f" response_time:0.101468 gorouter_time:0.000104 app_id:"5f362051-e2bc-4abc-ab8e-adbdf688ae64" app_index:"0" x_cf_routererror:"-" x_b3_traceid:"e3e4a237210114ef" x_b3_spanid:"e3e4a237210114ef" x_b3_parentspanid:"-" b3:"e3e4a237210114ef-e3e4a237210114ef""#,
        );
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(entry.gorouter_time.unwrap(), 0.000104);
        assert_eq!(entry.x_cf_routererror, None);
    }

    #[test]
    fn test_parse_x_forwarded_with_dash_gh_issue_1() {
        let entry = parse_gorouter_log(
            r#"35.243.162.217:80 - [2019-10-31T00:11:09.329+0000] "GET / HTTP/1.1" 404 0 69 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36" "185.89.158.86:36539" "-" x_forwarded_for:"-" x_forwarded_proto:"-" vcap_request_id:"eb922abf-0f2d-4042-4a84-9161e6ee17a1" response_time:0.000108962 app_id:"-" app_index:"-" x_b3_traceid:"81aa595b268bbe68" x_b3_spanid:"81aa595b268bbe68" x_b3_parentspanid:"-" b3:"81aa595b268bbe68-81aa595b268bbe68""#,
        );
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(entry.x_forwarded_proto, XForwardedProto::UNSPECIFIED);
        assert_eq!(entry.x_forwarded_for.len(), 0);
    }
}
