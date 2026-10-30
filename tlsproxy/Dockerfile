FROM golang:1.26.9-alpine3.24 AS build
WORKDIR /src
COPY go.mod *.go bypass.txt ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /tlsproxy .

FROM alpine:3.24.3
RUN apk add --no-cache ca-certificates
COPY --from=build /tlsproxy /usr/local/bin/tlsproxy
USER root
ENTRYPOINT ["/usr/local/bin/tlsproxy"]
