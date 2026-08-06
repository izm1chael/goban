# Rule support policy

GoBan intentionally ships a small **core-supported** set and a larger
**available/experimental** library. Being present in `rules-available` does not
mean a parser is guaranteed across every upstream application version.

## Core-supported for 1.0

- `sshd`
- `nginx-http-auth`
- `apache-auth`

A core-supported rule must have, at minimum:

- a positive IPv4 fixture;
- a positive IPv6 fixture;
- a legitimate negative fixture;
- malformed-input coverage;
- source/application compatibility notes;
- an operator example showing direct-client versus trusted-proxy attribution;
- production-pipeline verification with `goban-client rule test`.

The machine-readable fixture corpus is in `testdata/rules/`; compatibility and
proxy notes are in `docs/CORE_RULES.md`. CI prevents a core rule from losing
its positive or negative coverage.

## Available/experimental

Other bundles are reviewed starting points. They remain disabled by default and
must be tested against the exact local log format before activation. Moving a
rule into the core set requires fixtures and a documented maintainer/review
owner, not merely a successful regex match on one sample.
