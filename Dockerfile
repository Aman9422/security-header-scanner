# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/home/scanner

WORKDIR /app

# Install the exact application/test dependency set from the repository's
# hash-locked file. The image build fails if a downloaded artifact hash differs.
COPY requirements.lock ./requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock \
    && groupadd --system --gid 10001 scanner \
    && useradd --system --uid 10001 --gid scanner --create-home \
        --home-dir /home/scanner --shell /usr/sbin/nologin scanner \
    && mkdir -p /app/data \
    && chown -R scanner:scanner /app /home/scanner

COPY --chown=scanner:scanner . /app

USER scanner

# The scanner is primarily a CLI. The API can be run with `serve --host 0.0.0.0`
# when deliberately deployed behind a protected reverse proxy.
EXPOSE 5000

ENTRYPOINT ["python", "/app/main.py"]
CMD ["--help"]
