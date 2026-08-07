# Core rule compatibility notes

The 1.0 core set is deliberately small. “Supported” means the bundled parser
has IPv4, IPv6, legitimate-negative, malformed-record, and production-pipeline
fixtures. Operators must still test the exact log format emitted by their
service before enabling enforcement.

## OpenSSH: `sshd`

Expected format is the conventional OpenSSH authentication message:

```text
Failed password for [invalid user] USER from ADDRESS port PORT ssh2
```

It works with file or journald sources because the parser keys on the OpenSSH
message body rather than a syslog prefix. The captured address is the direct
SSH peer; reverse-proxy attribution does not apply to ordinary SSH.

```bash
goban-client rule test --rule sshd --config /etc/goban/goban.yaml /var/log/auth.log
```

## Nginx: `nginx-http-auth`

Expected format is a combined-style access line whose first field is the true
client address and whose response status is `401`.

The stock rule must **not** be used against a log format where the first field
is an untrusted `X-Forwarded-For` value. Behind a proxy, use a custom format
that records both the socket peer and candidate client address, capture each
separately, and configure `trusted_proxy_capture` plus `trusted_proxies` so a
forwarded address is accepted only from an approved peer.

```yaml
regex: '^peer=(?P<peer>\S+) client=(?P<ip>\S+) .* status=401'
trusted_proxy_capture: peer
trusted_proxies: [10.0.0.0/8, 2001:db8:100::/48]
```

## Apache HTTPD: `apache-auth`

Expected format is an Apache error-log authentication message containing a
`[client ADDRESS]` field followed by an authentication failure, unknown user,
or password mismatch. Both `ADDRESS:PORT` and `[IPv6]:PORT` forms are covered.

The captured value is the peer Apache reports in the error log. Deployments
that replace it from forwarded headers need the same explicit trusted-proxy
model described for Nginx.

## Promotion and regression policy

Changes to any core parser require updates to `testdata/rules/core-fixtures.yaml` and `testdata/corpus/manifest.yaml`, plus passing `TestCoreRuleFixtures` and `TestRepositoryCorpus` gates. Application or log-format changes must be represented by positive and hard-negative cases before the compatibility claim is expanded. Optional upstream differential tests are documented in `docs/CORPUS_TESTING.md`.
