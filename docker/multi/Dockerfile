# Same build as Dockerfile.buildcheck + meson install + runtime tools. Context = repo root.
FROM debian:bookworm
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    build-essential pkg-config \
    libssl-dev libjson-c-dev libbsd-dev gengetopt patch perl \
    meson ninja-build git ca-certificates \
    iptables ipset iproute2 procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/bstring-build
RUN git clone --depth 1 --branch v1.1.0 https://github.com/msteinert/bstring.git . \
    && meson setup build --prefix=/usr/local -Ddefault_library=shared \
    && meson compile -C build \
    && meson install -C build \
    && ldconfig

ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/lib/x86_64-linux-gnu/pkgconfig:/usr/local/lib/aarch64-linux-gnu/pkgconfig:/usr/local/share/pkgconfig

WORKDIR /src
COPY . .
RUN meson setup build --prefix=/usr/local && meson compile -C build -j$(nproc) \
    && meson install -C build && ldconfig
COPY docker/multi/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
