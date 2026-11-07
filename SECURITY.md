# Security

Skyveda Scan is built to be read-only: it calls only read, list and get APIs, and runs with the
built-in Reader role. A way to make it change, create or delete anything in a cloud account is
the most serious kind of report we can receive.

## Reporting a vulnerability

Email **skyvedahq@gmail.com** with "Security" in the subject. Please do not open a public issue.

Include the version (`skyveda --version`), what you did, and what happened. Do not send real
subscription IDs, tenant IDs, resource names, keys or customer data; describe them or replace
them with placeholders.

You will get a reply within 5 working days. We will agree a fix and a disclosure date with you,
and credit you in the release notes unless you prefer not to be named.

## In scope

- any path by which the scanner writes to, or calls a non-read API on, a cloud account
- leaks of credentials, tokens or scan output
- the Cloud Shell bundle and its install script
- injection through scan data into the HTML or PDF report

## Supported versions

Only the latest release receives fixes.
