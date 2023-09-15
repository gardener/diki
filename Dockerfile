# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.21.0 AS builder

ARG TARGETARCH
WORKDIR /workspace

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -a -ldflags="$(/workspace/hack/get-build-ld-flags.sh)" -o diki cmd/diki/main.go

FROM gcr.io/distroless/static-debian11:nonroot AS diki
WORKDIR /
COPY --from=builder /workspace/diki .

ENTRYPOINT ["/diki"]
