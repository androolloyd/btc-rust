FROM rust:1.82 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/btc-node /usr/local/bin/
ENTRYPOINT ["btc-node"]
