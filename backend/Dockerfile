
# ---- build stage ----------------------------------------------------------
FROM golang:1.24-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/app .

# ---- runtime stage --------------------------------------------------------
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -u 10001 app \
 && mkdir -p /data/uploads \
 && chown -R app:app /data

COPY --from=build /out/app /usr/local/bin/app
COPY run-both.sh /usr/local/bin/run-both.sh
RUN chmod +x /usr/local/bin/run-both.sh

USER app
WORKDIR /home/app

ENV APP_MODE=api \
    HTTP_ADDR=:8080 \
    UPLOAD_DIR=/data/uploads

EXPOSE 8080

# One process tree: worker in background + HTTP API in foreground (see run-both.sh).
# For API-only or worker-only, override: docker run ... /usr/local/bin/app api   (or worker)
ENTRYPOINT ["/usr/local/bin/run-both.sh"]
