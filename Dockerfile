### build golang
FROM registry.kharita.ai/baselibrary/golang:1.19-buster as golang-builder

USER 0

RUN apt-get update && \
    apt-get install -y \
       libpcap0.8-dev
USER 1000

#ENV GOPROXY=https://goproxy.io,direct \
ENV GO111MODULE=on \
    CGO_ENABLED=1

COPY --chown=1000:1000 ./handler/ /app/handler/
COPY --chown=1000:1000 ./test/ /app/test/
COPY --chown=1000:1000 ./utils/ /app/utils/
COPY --chown=1000:1000 ./main.go /app/main.go
COPY --chown=1000:1000 ./go.mod /app/go.mod
COPY --chown=1000:1000 ./go.sum /app/go.sum
RUN go mod tidy && go build -o /app/netcap  main.go


FROM registry.kharita.ai/baselibrary/ubuntu:22.04

USER 0

LABEL maintainer="@sherwinwangs" \
      maintainer="sherwinwangs@hotmail.com" \
      version=1.0 \
      description="Openconnect server with radius authentication"

COPY --from=golang-builder /app/netcap /netcap

CMD ["/netcap"]
