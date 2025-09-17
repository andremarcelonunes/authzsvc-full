FROM golang:1.22 as builder
WORKDIR /src
COPY go.mod .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/authz ./cmd/authzsvc

FROM gcr.io/distroless/base-debian12
COPY --from=builder /bin/authz /bin/authz
COPY casbin/model.conf /app/casbin/model.conf
COPY seed /app/seed
ENV CASBIN_MODEL=/app/casbin/model.conf
ENTRYPOINT ["/bin/authz"]
