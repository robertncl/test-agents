# Sandbox target image for the Group 2 (containment/isolation/egress) test agents.
#
# This stands in for the Copilot *local sandbox*: a minimal, non-root environment
# whose only writable area is the project dir (/workspace). The launch wrapper
# (launch.sh) applies the OS-level restrictions (read-only rootfs, dropped
# capabilities, no-new-privileges, default-deny network) that the SC-07/SC-08/SC-11
# probes verify. Keeping bash + curl present makes the egress/isolation probes
# meaningful (a *blocked* curl is evidence; a *missing* curl is not).
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash curl ca-certificates iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Non-root sandbox user; project dir owned by it.
RUN useradd --create-home --uid 1000 sandbox \
    && mkdir -p /workspace \
    && chown sandbox:sandbox /workspace

# Centrally-managed policy marker: root-owned, world-readable, NOT user-writable.
# SC-08 verifies the non-root user cannot disable/relax it.
COPY policy/sandbox-policy.json /etc/itest/sandbox-policy.json
RUN chown root:root /etc/itest/sandbox-policy.json \
    && chmod 0444 /etc/itest/sandbox-policy.json

USER sandbox
WORKDIR /workspace

# Stay alive so the harness can `docker exec` probes into the session.
CMD ["sleep", "infinity"]
