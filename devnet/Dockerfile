FROM rust:1.88-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --locked --package btc-node

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/btc-node /usr/local/bin/
ENTRYPOINT ["btc-node"]
