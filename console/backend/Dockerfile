# AriGuard Console backend: Go API + SQLite, one static binary.
FROM golang:1.27-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 go build -o /console .

FROM alpine:3.20
RUN mkdir -p /data
COPY --from=build /console /usr/local/bin/console
EXPOSE 8080
ENTRYPOINT ["console"]
CMD ["--addr", ":8080", "--db", "/data/ariguard-console.db"]
