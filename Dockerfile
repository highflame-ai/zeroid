FROM golang:1.27.0-alpine3.23 AS build-stage
LABEL maintainer="Highflame Team"

ENV CGO_ENABLED=0
ENV GOOS=linux
RUN apk add --no-cache git ca-certificates

WORKDIR /app
# go.mod's replace directives point every nested module at ./pkg/<name>,
# so `go mod download` resolves them from disk rather than the network.
# EVERY nested module must be copied here: a replace target that is not
# present fails the download outright, and because lockstep pins name the
# version being released NEXT, the proxy has not indexed those tags yet
# and cannot serve as a fallback.
#
# Adding a nested module? This COPY is one of the five places that need
# it — see "Adding a new nested module" in RELEASING.md.
COPY go.mod go.sum ./
COPY pkg/authjwt/go.mod pkg/authjwt/go.sum ./pkg/authjwt/
COPY pkg/dpop/go.mod pkg/dpop/go.sum ./pkg/dpop/
COPY pkg/jwks/go.mod pkg/jwks/go.sum ./pkg/jwks/
RUN go mod download

COPY . .
RUN go build -ldflags="-s -w" -trimpath -o /app/zeroid ./cmd/zeroid

FROM alpine:3.22 AS run-stage
LABEL maintainer="Highflame Team"

ARG APP_USER="highflame"
ARG APP_ID="10000"

WORKDIR /app
COPY --from=build-stage /app/zeroid /app/zeroid
COPY --from=build-stage /app/migrations /app/migrations

RUN apk add --no-cache ca-certificates tzdata tini curl \
    && addgroup -g ${APP_ID} ${APP_USER} \
    && adduser -u ${APP_ID} -G ${APP_USER} -D -s /bin/sh ${APP_USER} \
    && chown -R ${APP_USER}:${APP_USER} /app

EXPOSE 8899

CMD [ "/app/zeroid" ]
ENTRYPOINT [ "tini", "--" ]
