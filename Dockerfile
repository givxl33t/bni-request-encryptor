FROM golang:1.24-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/bni-request-encryptor .

FROM scratch
COPY --from=build /out/bni-request-encryptor /bni-request-encryptor
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/bni-request-encryptor"]