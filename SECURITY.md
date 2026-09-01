# Security policy

Topgent monitors AI agent processes running under the invoking user's privileges. Defects in Topgent affect software installed for security purposes. Private disclosure is required.

## Reporting a vulnerability

Use GitHub private vulnerability reporting. Open the **Security** tab on this repository and select **Report a vulnerability**. Reports are visible only to maintainers.

Do not open a public issue for a suspected vulnerability. Do not disclose publicly before a fix is available.

Reports should include the action performed, the expected result, and the observed result, with sufficient detail to reproduce. A proof of concept is sufficient. A working exploit is not required. Do not test against systems owned by others.

## Response targets

| Stage | Target |
|---|---|
| Acknowledgement | 3 working days |
| Assessment and reasoning | 10 working days |
| Credit in release notes | on request |

Topgent is maintained by a small team. These are targets, not contractual guarantees. Delays are communicated with a reason.

Disclosure is coordinated. Publication is unrestricted after a fix is released or ninety days elapse, whichever occurs first.

## Supported versions

Topgent is pre-1.0. Security fixes are applied to the latest release only. No long-term support branch exists.

## In scope

- Detection evasion, finding suppression, or reported risk lower than the evidence supports.
- Activity attributed to the wrong process, or bypass of the `(PID, process start time)` identity check.
- Privilege escalation through Topgent, its optional sensors, or the guarded response path, including termination of a process other than the verified target.
- Disclosure of data Topgent states it does not retain: prompts, file contents, credential values, or packet payloads.
- Fabricated telemetry accepted from an unprivileged local process and reported as confirmed.

## Out of scope

The following are documented design boundaries. Reports describing them will be closed with a reference to this section.

- A sensor reporting `unsupported`, `permission_required`, or `degraded` on a platform that does not supply the required evidence.
- Shared-host attribution. Multiple agent extensions in one editor process are reported against that process, and not against an individual extension.
- Telemetry requiring a privileged Tier 2 sensor that is not implemented, such as completed-connection duration on Windows.
- A recognised agent installed at a path absent from the signature catalogue reporting as `unrecognised`. This is a feature request.
- Findings that are non-scoring while their detectors are under evaluation.

Disagreement with the placement of a boundary is a valid issue. Use the normal issue tracker.

## Data in reports

Reports reach maintainers only. Redact hostnames, paths, usernames, and credentials before submitting logs or reports. Topgent output describes the host in detail and that detail is not required to reproduce a defect.
