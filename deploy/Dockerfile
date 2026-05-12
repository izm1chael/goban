# Multi-stage Dockerfile for the CGO-free (no journald) build.
# Final image is alpine because we need the iptables and ipset binaries at
# runtime to manipulate the host firewall.

# ---- builder ----
FROM golang:1.26-alpine AS builder

WORKDIR /src

# Cache module deps first so source changes don't bust the layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ENV CGO_ENABLED=0

RUN go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/goban-daemon ./cmd/goban-daemon \
 && go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/goban-client ./cmd/goban-client

# ---- runtime ----
FROM alpine:3.20

# iptables for INPUT-chain rule management, ipset for the O(1) ban-set
# storage, ip6tables for the ipv6 path.
RUN apk add --no-cache \
      iptables \
      ip6tables \
      ipset \
      ca-certificates \
      tzdata \
 && addgroup -S goban \
 && adduser -S -G goban goban

COPY --from=builder /out/goban-daemon /usr/local/bin/goban-daemon
COPY --from=builder /out/goban-client /usr/local/bin/goban-client
COPY examples/goban.yaml      /etc/goban/goban.yaml
COPY examples/rules.d         /etc/goban/rules.d

# /run/goban holds the unix control socket.
RUN mkdir -p /run/goban && chown goban:goban /run/goban

# The daemon must run as root because it shells out to iptables, ip6tables
# and ipset to manipulate kernel netfilter state. This is an unavoidable
# architectural requirement shared with fail2ban and every other firewall-
# management daemon — there is no userspace path to managing iptables rules.
#
# Mitigations layered on top of this privilege footprint:
#   - allowlist auto-loads local interfaces + RFC1918 so the daemon cannot
#     accidentally ban its own host;
#   - the exec runner in internal/banner/iptables.go restricts subprocesses
#     to a literal-only switch over {ipset, iptables, ip6tables};
#   - log lines are capped at 16 KiB before regex matching;
#   - the control socket defaults to mode 0660 with a dedicated goban group.
#
# When running inside a container, also add NET_ADMIN+NET_RAW capabilities
# and use --network host so the rules reach the host kernel:
#
#   docker run --rm --network host \
#     --cap-add NET_ADMIN --cap-add NET_RAW \
#     -v /var/log:/var/log:ro \
#     -v /var/run/docker.sock:/var/run/docker.sock:ro \
#     -v /etc/goban:/etc/goban:ro \
#     -v /run/goban:/run/goban \
#     goban:latest

# nosemgrep: dockerfile.security.last-user-is-root.last-user-is-root
USER root

ENTRYPOINT ["/usr/local/bin/goban-daemon"]
CMD ["--config", "/etc/goban/goban.yaml"]
