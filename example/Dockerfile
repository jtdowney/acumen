ARG GLEAM_VERSION=v1.15.2

FROM ghcr.io/gleam-lang/gleam:${GLEAM_VERSION}-erlang AS builder

WORKDIR /usr/src

COPY gleam.toml manifest.toml ./
COPY src src

COPY example/gleam.toml example/manifest.toml example/

WORKDIR /usr/src/example

RUN gleam deps download

COPY example/ .

RUN gleam export erlang-shipment

FROM erlang:28-slim AS runner

RUN apt-get install --update -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/example/build/erlang-shipment /app

WORKDIR /app

ENTRYPOINT [ "/app/entrypoint.sh" ]
CMD ["run"]
