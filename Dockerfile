FROM nginx:1.27-alpine

LABEL org.opencontainers.image.title="RawrXD TLS gateway" \
      org.opencontainers.image.description="Same-origin edge for Windows RawrXD and private inference" \
      io.rawrxd.hexmag.capability="disabled-linux-container" \
      io.rawrxd.native-runtime="external-windows-x64"

# This Linux image is only the TLS/static reverse proxy. HexMag and the native
# engine are Windows x64/MSVC/MASM artifacts and are intentionally not copied
# into, emulated by, or represented as available in this image.
ENV RAWRXD_HEXMAG_CAPABILITY=disabled-linux-container

# Ship the same static tree that screenpilot.tech publishes. The edge can
# therefore embed /gui without depending on a second, divergent web bundle.
COPY sites/screenpilot.tech/ /usr/share/nginx/html/
COPY docker/nginx.conf /etc/nginx/nginx.conf

EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1/healthz >/dev/null || exit 1
