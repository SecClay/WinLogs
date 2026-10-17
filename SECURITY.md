# Security

WinLogs runs with administrator or root rights and changes how a system records activity. Please report anything that could cause harm.

## Reporting a problem

Use GitHub's private reporting: open the **Security** tab of this repository and choose **Report a
vulnerability**. Only the maintainer can see the report. Do not open a public issue for a security
problem, and leave details of your own systems (hostnames, usernames, tokens, logs) out of any
report.

You should get a first answer within a week. This is a one-person project, so a fix may take longer.

## What counts

- A setting applied that is not logging, or that weakens the system's security.
- `-Revert` or `--revert` failing to restore what was there before.
- Code or downloads fetched from a source the documentation does not name, or without a check.
- A way for an unprivileged user to influence what the installer runs as administrator or root.
- Logs or configuration written somewhere readable by users who should not see them.

## Before you run it

WinLogs is built for disposable lab VMs and is provided as is, without warranty (see [LICENSE](LICENSE)). Do not run it on production systems.
