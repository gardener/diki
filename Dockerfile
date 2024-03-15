# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.22.1 AS builder

ARG TARGETARCH
WORKDIR /workspace

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -a -ldflags="$(/workspace/hack/get-build-ld-flags.sh)" -o diki cmd/diki/main.go

FROM gcr.io/distroless/static-debian12:nonroot AS diki
WORKDIR /
COPY --from=builder /workspace/diki .

ENTRYPOINT ["/diki"]

FROM alpine:3.19.1 AS diki-ops

ARG TARGETARCH

RUN apk --no-cache add curl &&\
    curl -sLf https://github.com/containerd/nerdctl/releases/download/v1.7.4/nerdctl-1.7.4-linux-${TARGETARCH}.tar.gz -o /nerdctl.tar.gz &&\
    tar -C /usr/local/bin -xzvf nerdctl.tar.gz &&\
    rm -f nerdctl.tar.gz &&\
    mkdir /etc/nerdctl &&\
    echo address = "\"unix:///host/run/containerd/containerd.sock\"" >> /etc/nerdctl/nerdctl.toml &&\
    echo namespace = "\"k8s.io\"" >> /etc/nerdctl/nerdctl.toml
