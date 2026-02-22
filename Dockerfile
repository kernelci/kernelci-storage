FROM rust:1.93 AS builder
WORKDIR /usr/src/app
COPY . .
RUN cargo install --path .

FROM debian:trixie-slim
RUN apt-get update && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/kernelci-storage /usr/local/bin/kernelci-storage
# install ssl certificates
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
RUN mkdir /workdir
WORKDIR /workdir
CMD ["kernelci-storage"]
