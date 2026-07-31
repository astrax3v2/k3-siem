FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/server ./cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/analyzer-cli ./cmd/analyzer-cli

FROM alpine:3.20
RUN apk add --no-cache wget ca-certificates && adduser -D -u 1000 appuser
WORKDIR /app
COPY --from=build /out/server ./server
COPY --from=build /out/analyzer-cli ./analyzer-cli
RUN mkdir -p /app/data && chown -R appuser:appuser /app
USER appuser
EXPOSE 8090
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=10 \
  CMD wget -q -O- http://localhost:8090/healthz || exit 1
ENTRYPOINT ["./server"]
