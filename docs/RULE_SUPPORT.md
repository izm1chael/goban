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

The compact core fixtures remain in `testdata/rules/`, while the broader production-pipeline corpus and pinned external-source metadata live in `testdata/corpus/`. CI prevents a core rule from losing positive or negative coverage and runs all curated corpus cases. Compatibility and proxy notes are in `docs/CORE_RULES.md`; corpus policy is in `docs/CORPUS_TESTING.md`.

## Available/experimental

Other bundles are reviewed starting points. They remain disabled by default and
must be tested against the exact local log format before activation. Moving a
rule into the core set requires fixtures and a documented maintainer/review
owner, not merely a successful regex match on one sample.
