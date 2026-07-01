# ExploitLink Orchestration Engine — reproducible deployment image
#
# Built on Kali Rolling so the five scanner CLIs the app shells out to
# (nmap, whatweb, gobuster, nuclei, searchsploit) are available via apt
# at pinned versions.
#
# Hardening (chapter 6.4 controls):
#   - Runs as a non-root `exploitlink` user (CONT-1)
#   - Nuclei + Exploit-DB baked into the image for reproducibility
#   - apt cache cleaned in the same layer (smaller image, no stale package
#     metadata if the image is later inspected)
#
# Use docker-compose for the runtime — it sets the auth password env var
# and (optionally) host networking for LAN target scanning.

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.title="ExploitLink Orchestration Engine"
LABEL org.opencontainers.image.description="Web-based vulnerability assessment & exploit correlation"
LABEL org.opencontainers.image.source="https://github.com/beef1016/FYP"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLASK_APP=run.py

# Layer 1 — system packages (Python toolchain + 5 scanner CLIs + dirb)
# libcap2-bin provides `setcap`, used below to grant nmap raw-socket caps to
# the non-root user (the Kali base image does not ship it).
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        ca-certificates \
        libcap2-bin \
        nmap \
        whatweb \
        gobuster \
        nuclei \
        exploitdb \
        dirb \
    && rm -rf /var/lib/apt/lists/*

# Layer 2 — Nuclei templates baked at build time for reproducibility.
# Templates land at /root/.local/nuclei-templates (Nuclei v3+ default).
RUN nuclei -update-templates -silent

# Layer 3 — non-root runtime user (chapter 6.4 control CONT-1).
# Created BEFORE Python deps so the install layer is owned by the right user.
# Nmap's privileged features (SYN scan, OS detection) need CAP_NET_RAW which
# we grant via setcap on the binary so the unprivileged user can still use them.
RUN groupadd --system exploitlink && \
    useradd  --system --gid exploitlink --create-home --shell /usr/sbin/nologin \
             --uid 1001 exploitlink && \
    setcap 'cap_net_raw,cap_net_admin,cap_net_bind_service+eip' /usr/bin/nmap

WORKDIR /app

# Layer 4 — Python deps.
# Separate from app source so this layer reuses its cache on source edits.
COPY requirements.txt ./
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Layer 5 — application source (respects .dockerignore)
COPY . ./

# Make /app and the instance dir writable by the non-root user
RUN mkdir -p /app/instance && \
    chown -R exploitlink:exploitlink /app /home/exploitlink

USER exploitlink

EXPOSE 5000

# Run pending Alembic migrations on every container start (idempotent),
# then launch the Flask dev server. EXPLOITLINK_AUTH_PASSWORD MUST be set
# in the container environment (see docker-compose.yml) or run.py exits.
CMD ["sh", "-c", "flask db upgrade && python3 run.py"]
