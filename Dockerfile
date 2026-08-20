FROM golang:1.27.0-alpine3.24 AS build-stage
LABEL maintainer="Highflame Team"

ENV CGO_ENABLED=0
ENV GOOS=linux

RUN apk add --no-cache git ca-certificates

WORKDIR /app
# go.mod replaces point nested modules at ./pkg/{authjwt,dpop}; copy
# their go.mod/go.sum so `go mod download` does not try to fetch the
# pinned pkg/dpop tag from the network (needed on release-dpop PRs and
# whenever the proxy has not indexed a brand-new tag yet).
COPY go.mod go.sum ./
COPY pkg/authjwt/go.mod pkg/authjwt/go.sum ./pkg/authjwt/
COPY pkg/dpop/go.mod pkg/dpop/go.sum ./pkg/dpop/
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
