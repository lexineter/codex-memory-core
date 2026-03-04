FROM rust:slim AS builder
WORKDIR /workspace
COPY . .
RUN cargo build --release -p codex_cli --bin codex_cli

FROM rust:slim AS shipper
WORKDIR /workspace
COPY . .

FROM debian:trixie-slim
COPY --from=builder /workspace/target/release/codex_cli /usr/local/bin/codex_cli
ENTRYPOINT ["codex_cli"]
