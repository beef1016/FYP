# VulnFlow Orchestration Engine — reproducible deployment image
#
# Built on Kali Rolling so the five scanner CLIs the app shells out to
# (nmap, whatweb, gobuster, nuclei, searchsploit) are available via apt at
# pinned versions. The image is intentionally fat (~2.5 GB) because that's
# the price of including the Exploit-DB mirror + Nuclei templates baked in.
#
# Use docker-compose for the runtime — it sets host networking (required for
# LAN target scanning) and the instance/ volume (SQLite DB persistence).

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.title="VulnFlow Orchestration Engine"
LABEL org.opencontainers.image.description="Web-based vulnerability assessment & exploit correlation"
LABEL org.opencontainers.image.source="https://github.com/beef1016/FYP"

# Quiet apt + sane Python defaults
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLASK_APP=run.py

# ---------------------------------------------------------------------------
# Layer 1 — system packages
# Python toolchain + the five scanner CLIs + dirb for Gobuster's wordlist.
# Bundled into one RUN so the apt cache is cleaned in the same layer (smaller image).
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        python3 \
        python3-pip \
        python3-venv \
        ca-certificates \
        nmap \
        whatweb \
        gobuster \
        nuclei \
        exploitdb \
        dirb \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Layer 2 — Nuclei templates
# Baked into the image at build time so CVE coverage is reproducible. To
# refresh after release, rebuild with `docker compose build --no-cache`.
# ---------------------------------------------------------------------------
RUN nuclei -update-templates -silent

WORKDIR /app

# ---------------------------------------------------------------------------
# Layer 3 — Python dependencies
# Separate COPY for requirements.txt means this layer only invalidates when
# the deps actually change, not on every source edit.
#
# `--break-system-packages`: required on Debian/Kali since PEP 668. We don't
# need a venv inside the container — the container itself is the isolation.
# ---------------------------------------------------------------------------
COPY requirements.txt ./
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# ---------------------------------------------------------------------------
# Layer 4 — application source (respects .dockerignore)
# ---------------------------------------------------------------------------
COPY . ./

EXPOSE 5000

# Run pending Alembic migrations on every container start (idempotent — a no-op
# when the DB is already at head), then launch the Flask dev server.
CMD ["sh", "-c", "flask db upgrade && python3 run.py"]
