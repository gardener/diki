# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

# Build the manager binary
FROM golang:1.21.0 AS builder

ARG TARGETARCH
WORKDIR /workspace

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# Copy the go source
COPY cmd/ cmd/
COPY imagevector/ imagevector/
COPY pkg/ pkg/
COPY vendor/ vendor/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -a -o diki cmd/diki/main.go

FROM gcr.io/distroless/static-debian11:nonroot
WORKDIR /
COPY --from=builder /workspace/diki .

ENTRYPOINT ["/diki"]
