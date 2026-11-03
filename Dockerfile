# syntax = docker/dockerfile:1-experimental

ARG GO_VERSION
ARG TRIVY_VERSION
ARG VERSION
# Digests pin the base images; the tags above stay for readability. When
# changing GO_VERSION or TRIVY_VERSION, update the matching digest here and in
# the Makefile (crane digest <image>:<tag>).
ARG GO_DIGEST=sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b
ARG TRIVY_DIGEST=sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c
ARG DEBIAN_DIGEST=sha256:d74df7598108a173a621eda4d58a2adbf850b2d9a9d81bc2cca1a6c21174a880
# Base image registry. Defaults to docker.io so upstream builds are unchanged,
# but allows pointing at a pull-through cache (e.g. a Harbor proxy project) so
# repeated builds do not hit Docker Hub rate limits.
ARG BASE_REGISTRY=docker.io

FROM ${BASE_REGISTRY}/aquasec/trivy:${TRIVY_VERSION}@${TRIVY_DIGEST} as trivy

# ----

FROM ${BASE_REGISTRY}/library/golang:${GO_VERSION}@${GO_DIGEST} as builder

WORKDIR /src
COPY . /src

RUN useradd -u 10001 image-inquisitor

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    go build \
    -ldflags "-s -w -extldflags \"-static\"  -X 'main.version=${VERSION}'" \
    -o /image-inquisitor \
    ./cmd

RUN mkdir -p /data/tmp

# ----

FROM ${BASE_REGISTRY}/library/debian:bookworm@${DEBIAN_DIGEST} AS certs

RUN apt-get update \
	&& apt-get install -y ca-certificates \
	&& update-ca-certificates

# ----

FROM scratch

WORKDIR /

COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# This brings over our non-root user
COPY --from=builder /etc/passwd /etc/passwd

# This craziness is required so we can make a /tmp directory with the right
# permissions so the application can write to it.
# This is mounting temporary files from busybox so we have the correct binaries + libs
# to run mkdir and chown.
# I tried everything else in my power to make this work but got to this point and I'm movin on
RUN --mount=from=busybox:latest,src=/bin/,dst=/bin/ \
    --mount=from=busybox:latest,src=/lib64,dst=/lib64 \
    --mount=from=busybox:latest,src=/lib,dst=/lib \
    mkdir -m 1755 /tmp && chown 10001:10001 /tmp && \
    mkdir -m 1755 /home && chown 10001:10001 /home

COPY --from=trivy /usr/local/bin/trivy /bin/trivy
COPY --from=builder /image-inquisitor /bin/image-inquisitor
ENV PATH=/bin

# This needs to be the UID (vs. the user name) because Kubernetes will check to ensure this is not a root user
# It can only do this if the UID is used so it can ensure that it is != 0 (root)
USER 10001

ENTRYPOINT ["image-inquisitor"]
