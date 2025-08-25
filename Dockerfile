# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.25.0 AS go-builder

ARG TARGETARCH
WORKDIR /workspace

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -a -ldflags="$(/workspace/hack/get-build-ld-flags.sh)" -o diki cmd/diki/main.go

FROM gcr.io/distroless/static-debian12:nonroot AS diki
WORKDIR /
COPY --from=go-builder /workspace/diki .

ENTRYPOINT ["/diki"]

FROM alpine:3.22.1 AS diki-ops-builder

ARG TARGETARCH

RUN apk --no-cache add curl &&\
    curl -sLf https://github.com/containerd/nerdctl/releases/download/v2.1.3/nerdctl-2.1.3-linux-${TARGETARCH}.tar.gz -o /nerdctl.tar.gz &&\
    tar -C /usr/local/bin -xzvf nerdctl.tar.gz

WORKDIR /volume

RUN mkdir -p ./bin ./usr/local/bin ./sbin ./lib ./tmp \
    && cp -d /bin/busybox ./bin                      && echo "package busybox" \
    && cp -d /lib/ld-musl-* ./lib                    && echo "package musl" \
    && cp -d /usr/sbin/chroot ./sbin                 && echo "package chroot" \
    && cp -d /usr/local/bin/nerdctl ./usr/local/bin  && echo "package nerdctl"

FROM scratch AS diki-ops
WORKDIR /
COPY --from=diki-ops-builder /volume .
