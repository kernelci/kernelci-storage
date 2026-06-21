FROM rust:1.96@sha256:c6811167278337db5f3b0234964ced5f538f154a2a20f09ec03721d7411c933d AS builder
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
