FROM golang:1.26.0-alpine3.22 AS build-stage
LABEL maintainer="Highflame Team"

ENV CGO_ENABLED=0
ENV GOOS=linux
# jwx v4 needs the encoding/json/v2 experiment (Go 1.26+). Set on the build
# stage so go mod download / go build both compile against the right stdlib
# variants.
ENV GOEXPERIMENT=jsonv2

RUN apk add --no-cache git ca-certificates

WORKDIR /app
COPY go.mod go.sum ./
COPY pkg/authjwt/go.mod pkg/authjwt/go.sum ./pkg/authjwt/
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
