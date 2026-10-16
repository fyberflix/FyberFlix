# Build context is the REPO ROOT (because this service uses libs/authz):
#   docker build -f services/content/Dockerfile --target api    -t fyberflix-content-api .
#   docker build -f services/content/Dockerfile --target worker -t fyberflix-content-worker .
FROM golang:1.24-alpine3.22 AS build
WORKDIR /src
COPY libs/authz/ libs/authz/
COPY services/content/ services/content/
WORKDIR /src/services/content
RUN go mod download
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/content ./cmd/content \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/worker ./cmd/worker

FROM gcr.io/distroless/static-debian12:nonroot AS api
COPY --from=build /out/content /content
USER nonroot
EXPOSE 8082
ENTRYPOINT ["/content"]

FROM alpine:3.22 AS worker
RUN apk add --no-cache ffmpeg ca-certificates && adduser -D -u 10001 app
COPY --from=build /out/worker /worker
USER app
ENTRYPOINT ["/worker"]
