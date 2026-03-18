FROM golang:1.25.8-alpine3.22 AS build-stage
LABEL maintainer="Highflame Team"

ENV CGO_ENABLED=0
ENV GOOS=linux

RUN apk add --no-cache git ca-certificates

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -ldflags="-s -w" -o /app/zeroid ./cmd/zeroid

FROM alpine:3.22 AS run-stage
LABEL maintainer="Highflame Team"

ARG APP_USER="highflame"
ARG APP_ID="10000"

WORKDIR /app
COPY --from=build-stage /app/zeroid /app/zeroid
COPY --from=build-stage /app/migrations /app/migrations

RUN apk add --no-cache ca-certificates tzdata tini \
    && addgroup -g ${APP_ID} ${APP_USER} \
    && adduser -u ${APP_ID} -G ${APP_USER} -D -s /bin/sh ${APP_USER} \
    && chown -R ${APP_USER}:${APP_USER} /app

EXPOSE 8899

CMD [ "/app/zeroid" ]
ENTRYPOINT [ "tini", "--" ]