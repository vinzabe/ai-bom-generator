# =============================================================================
# Post-Quantum Cloudflared (Open Source)
# =============================================================================
# MIT License - Full source code
# Enterprise support: grant@abejar.net
# =============================================================================

FROM cloudflare/cloudflared:latest

LABEL maintainer="Abejar <grant@abejar.net>"
LABEL description="Cloudflare Tunnel with Post-Quantum TLS Support (Open Source)"
LABEL license="MIT"

# Cloudflared supports post-quantum key agreement natively via CLI flags
# Post-quantum is enabled by default in recent cloudflared versions

ENV TUNNEL_LOGLEVEL=info

# cloudflared image is minimal - just use the built-in entrypoint
# Post-quantum is configured via environment variable
ENTRYPOINT ["cloudflared", "--post-quantum"]
CMD ["tunnel", "run"]
