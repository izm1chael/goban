#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
CACHE=${GOBAN_CORPUS_CACHE:-.cache/goban-corpus}

if [[ "${ACCEPT_THIRD_PARTY_CORPUS_LICENSES:-}" != "yes" ]]; then
  cat >&2 <<'MSG'
External corpus testing is opt-in. Review:
  go run ./cmd/goban-corpus sources
Then run:
  ACCEPT_THIRD_PARTY_CORPUS_LICENSES=yes test/corpus/external.sh
The files are cached locally and are not added to the repository.
MSG
  exit 2
fi

go run ./cmd/goban-corpus fetch --accept-third-party-licenses --root "$CACHE"

# False positives are a hard gate. Recall is reported, not treated as parity:
# GoBan deliberately counts terminal security failures rather than every event
# that Fail2Ban's aggressive filters may count.
# Each row is file:rule:min-recall. Precision remains the universal hard gate.
# Recall floors are only set where GoBan intentionally claims compatibility with
# a terminal authentication-failure family; mode-dependent/aggressive upstream
# filters remain advisory rather than forcing broader, riskier matching.
for spec in \
  'fail2ban-sshd.log:sshd:0' \
  'fail2ban-apache-auth.log:apache-auth:0' \
  'fail2ban-nginx-http-auth.log:nginx-http-auth:0' \
  'fail2ban-postfix.log:postfix-sasl:0' \
  'fail2ban-dovecot.log:dovecot:0.50' \
  'fail2ban-vsftpd.log:vsftpd:1.0' \
  'fail2ban-traefik-auth.log:traefik-auth:0'; do
  IFS=: read -r file rule min_recall <<<"$spec"
  path="$CACHE/$file"
  [[ -f "$path" ]] || { echo "missing fetched source at $path" >&2; exit 1; }
  args=(compat-fail2ban --rule "$rule" --file "$path" --max-false-positive 0)
  if [[ "$min_recall" != "0" ]]; then
    args+=(--min-recall "$min_recall")
  fi
  go run ./cmd/goban-corpus "${args[@]}"
done

go run ./cmd/goban-corpus scan --rule sshd --file "$CACHE/loghub-openssh-2k.log"
go run ./cmd/goban-corpus scan --rule apache-auth --file "$CACHE/loghub-apache-2k.log"
