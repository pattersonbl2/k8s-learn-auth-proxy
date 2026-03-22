FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /auth-proxy .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /auth-proxy /auth-proxy
ENTRYPOINT ["/auth-proxy"]
