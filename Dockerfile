FROM rust:1.85.1-slim-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --create-home rustmq
WORKDIR /app
COPY --from=builder /build/target/release/rustmq /usr/local/bin/rustmq
COPY config/rustmq.toml /app/config/rustmq.toml
USER rustmq
EXPOSE 1883 8083 8883 18083 14567/udp
ENTRYPOINT ["rustmq"]
CMD ["--config", "/app/config/rustmq.toml"]
