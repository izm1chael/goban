#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
OUT=${1:-.cache/goban-corpus/generated-million.log}
LINES=${LINES:-1000000}
SEED=${SEED:-20260806}
mkdir -p "$(dirname "$OUT")"
go run ./cmd/goban-corpus generate --out "$OUT" --lines "$LINES" --seed "$SEED" --profile mixed --verify
for rule in sshd nginx-http-auth apache-auth postfix-sasl dovecot traefik-auth; do
  go run ./cmd/goban-corpus scan --rule "$rule" --file "$OUT" --sample 0
done
