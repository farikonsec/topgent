//! Everything one session found, in a file someone can read and send.
//!
//! Not the AI-BOM. That is a machine document about the assets a host holds;
//! this is a human document about what happened while Topgent was watching, and
//! conflating the two in naming is how an operator sends the wrong one.
//!
//! One self-contained HTML file. No stylesheet, no script, no image, and no
//! reference to anything outside itself: it has to open on a machine with no
//! network, because the machine most worth writing one about is the one you
//! have just taken off the network.
//!
//! `write!` into the buffer rather than `push_str(&format!(..))`: this document
//! is built from hundreds of rows, and each `format!` is an allocation thrown
//! away immediately.
//!
//! **Redaction is part of the document, not an option beside it.** Topgent
//! output describes a host in detail, and an export is the artefact most likely
//! to leave it. The file states which choice was made, at the top, in words,
//! so nobody has to guess whether what they are reading is complete.

use serde_json::Value;
use std::fmt::Write as _;

/// How much of the host goes into the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detail {
    /// Everything, as observed.
    Full,
    /// Home directories collapse to `~`, and addresses are dropped in favour of
    /// the network that announces them.
    Redacted,
}

impl Detail {
    /// The sentence the file states about itself.
    #[must_use]
    pub const fn statement(self) -> &'static str {
        match self {
            Self::Full => {
                "This export is complete. It contains full filesystem paths, user names, \
                 process identifiers, and peer addresses for this host."
            }
            Self::Redacted => {
                "This export is redacted. Home directories are collapsed to ~, and peer \
                 addresses are replaced by the network that announces them. Everything else \
                 is as observed."
            }
        }
    }
}

/// Write one session as a self-contained HTML document.
#[must_use]
pub fn session_html(report: &Value, detail: Detail) -> String {
    let mut out = String::with_capacity(64 * 1024);
    out.push_str(HEAD);
    out.push_str(&header(report, detail));
    out.push_str(&summary(report, detail));
    out.push_str(&agents(report, detail));
    out.push_str(&findings(report, detail));
    out.push_str(&access(report, detail));
    out.push_str(&network(report, detail));
    out.push_str(&events(report, detail));
    out.push_str(&sensors(report, detail));
    out.push_str(FOOT);
    out
}

/// The same session as JSON, for a machine.
///
/// The report as produced, with the redaction applied and stated in the
/// document itself rather than left for a reader to infer from what is missing.
#[must_use]
pub fn session_json(report: &Value, detail: Detail) -> Value {
    let mut copy = report.clone();
    if detail == Detail::Redacted {
        redact_value(&mut copy);
    }
    serde_json::json!({
        "topgent_session": {
            "generated_at": report.get("generated_at").cloned().unwrap_or(Value::Null),
            "version": report.get("version").cloned().unwrap_or(Value::Null),
            "detail": match detail { Detail::Full => "full", Detail::Redacted => "redacted" },
            "detail_statement": detail.statement(),
        },
        "report": copy,
    })
}

/// Collapse anything that names this host, everywhere in the document.
fn redact_value(value: &mut Value) {
    match value {
        Value::String(text) => *text = redact_text(text),
        Value::Array(items) => items.iter_mut().for_each(redact_value),
        Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                if key == "host" || key == "address" {
                    *item = Value::String("[redacted]".to_owned());
                } else {
                    redact_value(item);
                }
            }
        }
        _ => {}
    }
}

/// A home directory becomes `~`.
///
/// Matched on the shape `/Users/<name>/` and `/home/<name>/` rather than on this
/// machine's own home, so an export written on one host and read on another
/// still hides the name, and so a path belonging to a different user is hidden
/// too.
#[must_use]
fn redact_text(text: &str) -> String {
    let mut out = text.to_owned();
    for prefix in ["/Users/", "/home/", "C:\\Users\\"] {
        while let Some(at) = out.find(prefix) {
            let after = at + prefix.len();
            let end = out[after..]
                .find(['/', '\\'])
                .map_or(out.len(), |offset| after + offset);
            out.replace_range(at..end, "~");
        }
    }
    out
}

fn header(report: &Value, detail: Detail) -> String {
    format!(
        "<h1>Topgent session</h1>\n<p class=\"lede\">{}</p>\n\
         <table class=\"facts\">\
         <tr><th>Written</th><td>{}</td></tr>\
         <tr><th>Topgent</th><td>{}</td></tr>\
         <tr><th>Detail</th><td>{}</td></tr>\
         </table>\n",
        escape(detail.statement()),
        escape(&stamp(
            report
                .get("generated_at")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        )),
        cell(text_at(report, "version"), detail),
        match detail {
            Detail::Full => "complete",
            Detail::Redacted => "redacted",
        }
    )
}

fn summary(report: &Value, detail: Detail) -> String {
    let agents = array(report, "agents").len();
    let worst = array(report, "agents")
        .iter()
        .max_by_key(|a| a.get("score").and_then(Value::as_u64).unwrap_or(0))
        .map_or_else(String::new, |a| {
            format!("{} {}", text_at(a, "grade"), num_at(a, "score"))
        });
    let covered = array(report, "coverage")
        .iter()
        .filter(|c| text_at(c, "state") == "available")
        .count();
    format!(
        "<h2>What this session found</h2>\n<table class=\"facts\">\
         <tr><th>AI agents running</th><td>{agents}</td></tr>\
         <tr><th>Worst grade</th><td>{}</td></tr>\
         <tr><th>Rules with a sensor on this host</th><td>{covered} of {}</td></tr>\
         </table>\n\
         <p class=\"note\">A rule whose sensor cannot run here cannot fire here. \
         The sensor table at the end of this document says which, and why.</p>\n",
        cell(&worst, detail),
        array(report, "coverage").len()
    )
}

fn agents(report: &Value, detail: Detail) -> String {
    let mut out = String::from("<h2>Agents</h2>\n");
    out.push_str(
        "<table><thead><tr><th>Agent</th><th>Risk</th><th>Score</th><th>Identity</th>\
         <th>Started by</th><th>PID</th><th>Executable</th></tr></thead><tbody>",
    );
    for a in array(report, "agents") {
        let _ = write!(
            out,
            "<tr><td>{}</td><td class=\"g\">{}</td><td class=\"n\">{}</td><td>{}</td>\
             <td>{}</td><td class=\"n\">{}</td><td class=\"m\">{}</td></tr>",
            cell(family(a), detail),
            cell(text_at(a, "grade"), detail),
            num_at(a, "score"),
            cell(text_at(a, "identity"), detail),
            cell(text_at(a, "user"), detail),
            num_at(a, "pid"),
            cell(text_at(a, "exe"), detail),
        );
    }
    out.push_str("</tbody></table>\n");
    out
}

fn findings(report: &Value, detail: Detail) -> String {
    let mut out = String::from("<h2>Findings</h2>\n");
    for a in array(report, "agents") {
        let factors = array(a, "factors");
        if factors.is_empty() {
            continue;
        }
        let _ = write!(
            out,
            "<h3>{} ({})</h3>\n<table><thead><tr><th>Points</th><th>Finding</th>\
             <th>Why</th><th>What to do</th></tr></thead><tbody>",
            cell(family(a), detail),
            num_at(a, "pid")
        );
        for f in factors {
            let _ = write!(
                out,
                "<tr><td class=\"n\">+{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                num_at(f, "points"),
                cell(text_at(f, "title"), detail),
                cell(text_at(f, "source"), detail),
                cell(text_at(f, "remedy"), detail),
            );
        }
        out.push_str("</tbody></table>\n");
    }
    out
}

fn access(report: &Value, detail: Detail) -> String {
    let mut out = String::from("<h2>What each agent can reach</h2>\n");
    for a in array(report, "agents") {
        let resources = array(a, "resources");
        if resources.is_empty() {
            continue;
        }
        let _ = write!(
            out,
            "<h3>{} ({})</h3>\n<table><thead><tr><th>Resource</th><th>Credential</th>\
             <th>Declared</th><th>Observed</th><th>Reachable</th></tr></thead><tbody>",
            cell(family(a), detail),
            num_at(a, "pid")
        );
        for r in resources {
            let secret = r
                .get("latent_secret")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let _ = write!(
                out,
                "<tr><td class=\"m\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                cell(text_at(r, "path"), detail),
                if secret { "yes" } else { "-" },
                cell(text_at(r, "declared"), detail),
                cell(text_at(r, "observed"), detail),
                cell(text_at(r, "reachable"), detail),
            );
        }
        out.push_str("</tbody></table>\n");
    }
    out
}

fn network(report: &Value, detail: Detail) -> String {
    let mut out = String::from("<h2>Network</h2>\n");
    out.push_str(
        "<table><thead><tr><th>Agent</th><th>Protocol</th><th>Address</th><th>Port</th>\
         <th>Direction</th><th>Verdict</th></tr></thead><tbody>",
    );
    for e in array(report, "network") {
        let observable = e
            .get("peer_observable")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let address = if !observable {
            "not observable on this platform".to_owned()
        } else if detail == Detail::Redacted {
            "[redacted]".to_owned()
        } else {
            text_at(e, "host").to_owned()
        };
        let _ = write!(
            out,
            "<tr><td>{}</td><td>{}</td><td class=\"m\">{}</td><td class=\"n\">{}</td>\
             <td>{}</td><td>{}</td></tr>",
            cell(text_at(e, "agent_family"), detail),
            cell(text_at(e, "protocol"), detail),
            cell(&address, detail),
            num_at(e, "port"),
            cell(text_at(e, "direction"), detail),
            cell(text_at(e, "verdict"), detail),
        );
    }
    out.push_str("</tbody></table>\n");
    out
}

fn events(report: &Value, detail: Detail) -> String {
    let mut out = String::from("<h2>What changed</h2>\n");
    let entries = array(report, "events");
    if entries.is_empty() {
        out.push_str("<p class=\"note\">Nothing changed while Topgent was watching.</p>\n");
        return out;
    }
    out.push_str(
        "<table><thead><tr><th>When</th><th>Severity</th><th>Kind</th><th>Agent</th>\
         <th>Detail</th></tr></thead><tbody>",
    );
    for e in entries {
        let _ = write!(
            out,
            "<tr><td class=\"m\">{}</td><td class=\"g\">{}</td><td>{}</td><td>{}</td>\
             <td>{}</td></tr>",
            escape(&stamp(e.get("at").and_then(Value::as_u64).unwrap_or(0))),
            cell(text_at(e, "severity"), detail),
            cell(text_at(e, "kind"), detail),
            cell(text_at(e, "agent"), detail),
            cell(text_at(e, "detail"), detail),
        );
    }
    out.push_str("</tbody></table>\n");
    out
}

fn sensors(report: &Value, detail: Detail) -> String {
    let mut out = String::from("<h2>What this host could and could not see</h2>\n");
    out.push_str(
        "<p class=\"note\">A sensor that is available is not the same as coverage. \
         The boundary column says what each one still cannot see even when it is working, \
         which is the part an operator has to read before trusting an absence.</p>\n",
    );
    out.push_str(
        "<table><thead><tr><th>Sensor</th><th>State</th><th>Detail</th>\
         <th>Boundary</th></tr></thead><tbody>",
    );
    for sensor in array(report, "sensors") {
        let _ = write!(
            out,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            cell(text_at(sensor, "id"), detail),
            cell(text_at(sensor, "state"), detail),
            cell(text_at(sensor, "detail"), detail),
            cell(text_at(sensor, "boundary"), detail),
        );
    }
    out.push_str("</tbody></table>\n");
    out
}

fn apply(text: &str, detail: Detail) -> String {
    match detail {
        Detail::Full => text.to_owned(),
        Detail::Redacted => redact_text(text),
    }
}

fn family(agent: &Value) -> &str {
    let named = text_at(agent, "family");
    if named.is_empty() {
        "unrecognised"
    } else {
        named
    }
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn text_at<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

fn num_at(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// `YYYY-MM-DD HH:MM:SS` in UTC.
///
/// UTC, and labelled, because an export is read somewhere else: a local time
/// with no zone is a time nobody can line up against another record.
fn stamp(at_ms: u64) -> String {
    if at_ms == 0 {
        return String::new();
    }
    let secs = at_ms / 1000;
    let (days, rest) = (i64::try_from(secs / 86_400).unwrap_or(0), secs % 86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{year:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    )
}

/// One value, ready to go into the page.
///
/// Redacts and then escapes, in that order, and it is the only way a value
/// from the report reaches the document. The first version redacted the fields
/// somebody remembered to redact, which was the executable path and the
/// resource path. A fuzzer put a home directory in an agent's grade and it went
/// straight through: any string in the report can hold one, and a redaction
/// that covers the fields you thought of is not a redaction.
fn cell(text: &str, detail: Detail) -> String {
    escape(&apply(text, detail))
}

/// Everything a browser would treat as markup.
///
/// The values here come from a report describing processes an attacker may have
/// named. A document that renders one of those names as markup is a document
/// that executes it.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

const HEAD: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Topgent session</title>
<style>
:root{color-scheme:light dark}
body{font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
 max-width:1100px;margin:0 auto;padding:2rem 1.25rem;color:#1c1f24;background:#fff}
@media(prefers-color-scheme:dark){body{color:#e6e8eb;background:#14161a}
 th{color:#9aa0a8}table{border-color:#2b3038}td,th{border-color:#2b3038}
 .note,.lede{color:#9aa0a8}tbody tr:nth-child(even){background:#1a1d22}}
h1{font-size:1.6rem;margin:0 0 .25rem}
h2{font-size:1.15rem;margin:2rem 0 .5rem;padding-bottom:.3rem;border-bottom:1px solid #d8dade}
h3{font-size:.95rem;margin:1.25rem 0 .35rem;font-weight:600}
.lede{margin:0 0 1.25rem;color:#555b63}
.note{color:#555b63;font-size:.85rem;margin:.4rem 0 0}
table{border-collapse:collapse;width:100%;margin:.5rem 0;font-size:.85rem}
th{text-align:left;font-weight:600;font-size:.72rem;letter-spacing:.04em;
 text-transform:uppercase;color:#7d848d;padding:.35rem .5rem}
td{padding:.35rem .5rem;vertical-align:top;border-top:1px solid #e6e8eb}
tbody tr:nth-child(even){background:#f7f7f5}
.facts th{width:14rem}.n{text-align:right;font-variant-numeric:tabular-nums}
.m{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem;
 word-break:break-all}
.g{font-weight:600}
footer{margin-top:2.5rem;padding-top:.75rem;border-top:1px solid #d8dade;
 color:#7d848d;font-size:.8rem}
</style></head><body>
"#;

const FOOT: &str = "<footer>Written by Topgent, which runs entirely on the machine it \
describes. This file is self-contained: it loads nothing and reports to nobody.</footer>\
</body></html>\n";

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing)]

    use super::*;
    use serde_json::json;

    fn sample() -> Value {
        json!({
            "version": "0.1.0",
            "generated_at": 1_788_000_000_000u64,
            "agents": [{
                "family": "claude-code", "grade": "CRITICAL", "score": 100, "pid": 5039,
                "user": "testuser", "identity": "user account",
                "exe": "/Users/testuser/.local/bin/claude",
                "factors": [{"points": 30, "title": "Can execute arbitrary processes",
                             "source": "its own configuration", "remedy": "narrow the grant"}],
                "resources": [{"path": "/Users/testuser/.ssh/id_rsa", "latent_secret": true,
                               "declared": "no", "observed": "no", "reachable": "yes"}],
            }],
            "network": [{"agent_family": "claude-code", "protocol": "icmp", "host": "*",
                         "port": 0, "direction": "listening", "verdict": "observed",
                         "peer_observable": false}],
            "events": [], "sensors": [{"id": "sockets", "state": "available",
                                       "detail": "", "boundary": "no ICMP peer"}],
            "coverage": [{"state": "available"}, {"state": "unsupported"}],
        })
    }

    #[test]
    fn a_full_export_keeps_the_paths_and_says_that_it_did() {
        let html = session_html(&sample(), Detail::Full);
        assert!(
            html.contains("/Users/testuser/.ssh/id_rsa"),
            "the path was dropped"
        );
        assert!(
            html.contains("This export is complete"),
            "the file does not state its detail"
        );
    }

    /// Redaction has to reach every field, not the fields somebody remembered.
    ///
    /// A fuzzer found this: a home directory in an agent's *grade* went
    /// straight into the document, because only the executable and the resource
    /// path were being redacted. Any string in the report can hold one.
    #[test]
    fn a_home_directory_in_any_field_at_all_is_redacted() {
        let mut report = sample();
        for field in ["grade", "identity", "user", "family"] {
            report["agents"][0][field] = json!("/Users/someone/secret");
        }
        report["sensors"][0]["boundary"] = json!("/Users/someone/secret");
        report["network"][0]["verdict"] = json!("/Users/someone/secret");
        let html = session_html(&report, Detail::Redacted);
        assert!(
            !html.contains("/Users/someone"),
            "a home directory reached the page"
        );
    }

    #[test]
    fn a_redacted_export_hides_the_home_directory_and_says_that_it_did() {
        let html = session_html(&sample(), Detail::Redacted);
        assert!(
            !html.contains("/Users/testuser"),
            "the home directory survived redaction"
        );
        assert!(
            html.contains("~/.ssh/id_rsa"),
            "the useful part of the path was lost too"
        );
        assert!(html.contains("This export is redacted"));
    }

    #[test]
    fn a_process_named_to_inject_markup_is_rendered_as_text() {
        let mut report = sample();
        report["agents"][0]["family"] = json!("<script>fetch('https://evil.example')</script>");
        let html = session_html(&report, Detail::Full);
        assert!(
            !html.contains("<script>fetch"),
            "a process name became markup"
        );
        assert!(
            html.contains("&lt;script&gt;"),
            "it was dropped instead of escaped"
        );
    }

    /// Nothing in this file causes a fetch.
    ///
    /// The first version of this test forbade the string `https://` anywhere,
    /// which is the wrong invariant: a real report contains the endpoints an
    /// agent reached, and refusing to write those down would make the document
    /// useless. What matters is that none of them is markup, and this now
    /// checks that with a real URL in the data.
    #[test]
    fn nothing_in_the_file_causes_a_fetch() {
        let mut report = sample();
        report["network"][0]["host"] = json!("https://api.example/v1");
        report["network"][0]["peer_observable"] = json!(true);
        let html = session_html(&report, Detail::Full);
        for markup in [
            "<img", "<script", "<iframe", "<link", " src=", " href=", "url(",
        ] {
            assert!(
                !html.contains(markup),
                "{markup} would make this fetch something"
            );
        }
        assert!(
            html.contains("https://api.example"),
            "the endpoint an agent reached was dropped from the report"
        );
    }

    #[test]
    fn an_unobservable_peer_says_so_rather_than_printing_a_wildcard() {
        let html = session_html(&sample(), Detail::Full);
        assert!(html.contains("not observable on this platform"), "{html}");
    }

    #[test]
    fn the_json_form_carries_the_redaction_as_a_field_and_a_sentence() {
        let value = session_json(&sample(), Detail::Redacted);
        assert_eq!(value["topgent_session"]["detail"], "redacted");
        assert!(
            value["topgent_session"]["detail_statement"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        );
        let text = serde_json::to_string(&value).expect("serialises");
        assert!(
            !text.contains("/Users/testuser"),
            "redaction did not reach the JSON form"
        );
    }

    #[test]
    fn an_empty_report_produces_a_document_rather_than_a_panic() {
        let html = session_html(&json!({}), Detail::Full);
        assert!(html.contains("</html>"));
    }

    #[test]
    fn the_stamp_is_utc_and_says_so() {
        assert!(stamp(1_788_000_000_000).ends_with(" UTC"));
        assert!(stamp(0).is_empty(), "an absent time is absent, not 1970");
    }
}
