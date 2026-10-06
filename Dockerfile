# ─── Stage 1: Builder ─────────────────────────────────────────────────────────
# Use the official Go image on Alpine. Alpine keeps the image small (~300MB vs
# ~800MB for the debian-based golang image) while still having a C toolchain
# available if CGO is ever needed.
FROM golang:1.23-alpine AS builder

# Install git for module fetching (go get may need it for VCS metadata).
# ca-certificates is needed for HTTPS module downloads.
RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Copy dependency manifests first so Docker can cache the `go mod download`
# layer. This layer is only invalidated when go.mod or go.sum change — not on
# every source code change. Significant speedup in CI where deps rarely change.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source.
COPY . .

# Build the binary with:
#   CGO_ENABLED=0  — pure Go, no C dependencies → static binary (no libc needed)
#   GOOS=linux     — target Linux (even when building on macOS/Windows)
#   -ldflags       — inject version and git SHA at build time for traceability
#   -trimpath      — remove local file paths from the binary (reproducible build)
#
# The ARGs allow CI to pass in the real version and git SHA:
#   docker build --build-arg VERSION=v1.0.0 --build-arg GIT_SHA=$(git rev-parse HEAD) .
ARG VERSION=dev
ARG GIT_SHA=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-X main.Version=${VERSION} -X main.GitSHA=${GIT_SHA}" \
    -o /ats \
    ./cmd/ats

# ─── Stage 2: Runtime ─────────────────────────────────────────────────────────
# Use a minimal base image. We have two options:
#
#   scratch        — absolute minimum, ~0MB overhead. No shell, no libc, nothing.
#                    Requires CGO_ENABLED=0 (pure Go). Best for security.
#
#   alpine:3.19    — ~8MB. Has a shell (ash) for debugging and ps/ls tools.
#                    Use this in development; consider scratch for production.
#
# We use alpine for developer convenience. Switch FROM to `scratch` for a
# hardened production image (also remove the RUN apk command and the ca-certs COPY).
FROM alpine:3.19

# ca-certificates: needed for HTTPS outbound connections (e.g. future webhook calls).
# If the binary never makes TLS outbound calls, this can be removed.
RUN apk add --no-cache ca-certificates tzdata

# Run as a non-root user. Container escapes are less damaging when the process
# is not root. The user/group 65534 is the "nobody" user on Alpine.
RUN addgroup -S ats && adduser -S -G ats ats
USER ats

WORKDIR /app

# Copy the binary from the builder stage.
COPY --from=builder /ats /app/ats

# Copy the migrations directory. RunMigrations looks for migrations/ relative
# to the binary's directory. We place them at /app/migrations.
COPY --from=builder /src/migrations /app/migrations

# Expose the HTTP port. This is documentation only — the actual port is set
# by SERVER_ADDR env var. 8080 is the default.
EXPOSE 8080

# Run the binary. Use the JSON array form (exec form) so signals (SIGTERM) are
# delivered directly to the process, not to a shell wrapper. This enables
# graceful shutdown.
ENTRYPOINT ["/app/ats"]
