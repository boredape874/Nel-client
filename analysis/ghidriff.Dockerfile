# Reproducible Ghidriff environment: Ghidra base is pinned by OCI index digest.
FROM ghcr.io/clearbluejar/ghidra-python@sha256:e3eb539dbf56dd616dac96ce0a36b6deb759c2f83993db5501328a3c52cca3a6
USER root
RUN python3 -m venv /opt/ghidriff-venv \
    && /opt/ghidriff-venv/bin/pip install --no-cache-dir "ghidriff==1.0.0"
ENV PATH="/opt/ghidriff-venv/bin:${PATH}"
ENTRYPOINT ["ghidriff"]
