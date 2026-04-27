FROM rust:1.93@sha256:ecbe59a8408895edd02d9ef422504b8501dd9fa1526de27a45b73406d734d659 AS builder
WORKDIR /usr/src/app
COPY . .
RUN cargo build --release --locked

FROM debian:trixie-slim@sha256:cedb1ef40439206b673ee8b33a46a03a0c9fa90bf3732f54704f99cb061d2c5a
RUN apt-get update && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/app/target/release/kernelci-storage /usr/local/bin/kernelci-storage
# install ssl certificates
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
RUN mkdir /workdir
WORKDIR /workdir
CMD ["kernelci-storage"]
