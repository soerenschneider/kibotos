# Keep in sync with the toolchain in go.mod, otherwise the build downloads that toolchain.
# The build stage runs on the build host and cross-compiles, so no emulation is needed.
FROM --platform=$BUILDPLATFORM golang:1.27.4 AS build

ARG VERSION=dev
ARG COMMIT_HASH=unknown
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY . .
# Same flags as the release binaries built with the Makefile.
RUN GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    make compile VERSION="${VERSION}" COMMIT_HASH="${COMMIT_HASH}" OUTPUT=/kibotos


FROM gcr.io/distroless/static:nonroot

LABEL maintainer="soerenschneider"
COPY --from=build /kibotos /kibotos
USER nonroot:nonroot

ENTRYPOINT ["/kibotos"]
CMD ["-config", "/config.json"]
