# witnessd Docker image
# Multi-stage build for minimal image size

FROM alpine:3.19 AS base
RUN apk add --no-cache ca-certificates tzdata

FROM scratch
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=base /usr/share/zoneinfo /usr/share/zoneinfo
COPY witnessd /usr/bin/witnessd
COPY witnessctl /usr/bin/witnessctl

ENTRYPOINT ["/usr/bin/witnessd"]
CMD ["help"]
