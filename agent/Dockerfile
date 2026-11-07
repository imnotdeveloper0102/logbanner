FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /agent ./cmd/agent

FROM alpine:3.20
# The firewall tools the agent shells out to in live mode. Dry-run
# never calls them, but the image ships them so flipping dry_run off
# does not need a rebuild.
RUN apk add --no-cache nftables ipset iptables
COPY --from=build /agent /usr/local/bin/agent
ENTRYPOINT ["/usr/local/bin/agent"]
