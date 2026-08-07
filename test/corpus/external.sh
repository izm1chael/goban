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
for spec in \
  'fail2ban-sshd.log:sshd' \
  'fail2ban-apache-auth.log:apache-auth' \
  'fail2ban-nginx-http-auth.log:nginx-http-auth' \
  'fail2ban-postfix.log:postfix-sasl' \
  'fail2ban-dovecot.log:dovecot' \
  'fail2ban-vsftpd.log:vsftpd' \
  'fail2ban-traefik-auth.log:traefik-auth'; do
  IFS=: read -r file rule <<<"$spec"
  path="$CACHE/$file"
  [[ -f "$path" ]] || { echo "missing fetched source at $path" >&2; exit 1; }
  go run ./cmd/goban-corpus compat-fail2ban --rule "$rule" --file "$path" --max-false-positive 0
done

go run ./cmd/goban-corpus scan --rule sshd --file "$CACHE/loghub-openssh-2k.log"
go run ./cmd/goban-corpus scan --rule apache-auth --file "$CACHE/loghub-apache-2k.log"
