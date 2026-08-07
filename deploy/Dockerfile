# Multi-stage Dockerfile for the CGO-free (no journald) build.
# Final image is alpine. The default backend needs iptables/ip6tables only
# for one-time hook management; ban-set hot-path operations use netlink directly.

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

# iptables/ip6tables are used only to install and verify INPUT/FORWARD hooks.
# The ban sets themselves are managed directly over netlink.
RUN apk add --no-cache \
      iptables \
      ip6tables \
      ca-certificates \
      tzdata \
 && addgroup -S goban \
 && adduser -S -G goban goban

COPY --from=builder /out/goban-daemon /usr/local/bin/goban-daemon
COPY --from=builder /out/goban-client /usr/local/bin/goban-client
COPY examples/goban.yaml      /etc/goban/goban.yaml
COPY examples/rules.d         /usr/share/goban/rules-available
RUN mkdir -p /etc/goban/rules.d \
 && cp /usr/share/goban/rules-available/sshd.yaml /etc/goban/rules.d/ \
 && cp /usr/share/goban/rules-available/recidive.yaml /etc/goban/rules.d/

# /run/goban holds the unix control socket.
RUN mkdir -p /run/goban /var/lib/goban /var/log/goban \
 && chown goban:goban /run/goban

# This single-container image intentionally uses GoBan's direct compatibility
# mode: one process both parses logs and manages host netfilter state. Native
# systemd packages use the stronger split architecture, where goban-daemon is
# unprivileged and goban-enforcer alone retains firewall capability. Keeping
# the container single-process avoids requiring a second host-namespace helper
# and a shared privileged socket merely to run the image.
#
# Direct mode therefore still requires NET_ADMIN+NET_RAW and host networking:
#
#   docker run --rm --network host \
#     --cap-add NET_ADMIN --cap-add NET_RAW \
#     -v /var/log:/var/log:ro \
#     -v /var/run/docker.sock:/var/run/docker.sock:ro \
#     -v /etc/goban:/etc/goban:ro \
#     -v /run/goban:/run/goban \
#     goban:latest
#
# Mount docker.sock only when Docker log sources are required; access to that
# socket is itself effectively root-equivalent. For the smallest privilege
# footprint on a native Linux host, prefer the packaged systemd split mode.

# nosemgrep: dockerfile.security.last-user-is-root.last-user-is-root
USER root

ENTRYPOINT ["/usr/local/bin/goban-daemon"]
CMD ["--config", "/etc/goban/goban.yaml"]
