# Builds the demo binaries: the mock cluster issuer (cmd/zeroid-mockidp, from
# ZeroID's module) and the demo agent, resource and setup (this module). The
# build context is the repository root: this module replaces ZeroID with
# ../.. and needs it present.
FROM golang:1.27.0-alpine3.23 AS build
ENV CGO_ENABLED=0 GOWORK=off
WORKDIR /src
COPY . .
RUN go build -trimpath -o /out/zeroid-mockidp ./cmd/zeroid-mockidp \
 && cd examples/aauth \
 && go build -trimpath -o /out/demo-agent ./cmd/demo-agent \
 && go build -trimpath -o /out/demo-resource ./cmd/demo-resource \
 && go build -trimpath -o /out/demo-setup ./cmd/demo-setup

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /out/ /usr/local/bin/
