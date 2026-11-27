# Governance portal: API + the single-page app. Everything from Debian 13's own packages.
FROM debian:trixie-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 python3-fastapi python3-uvicorn python3-pymysql ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin portal \
 && mkdir -p /app/static
COPY server/app.py server/users.py server/automox.py server/qualys.py server/eol.py server/redhat.py server/epss.py server/relational.py server/rules.py server/kev.py /app/
COPY server/login.html /app/static/login.html
COPY index.html app.js /app/static/
COPY new/index.html /app/static/new/index.html
USER portal
WORKDIR /app
ENV STATIC_DIR=/app/static PYTHONUNBUFFERED=1
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=4 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if b'\"ok\":true' in urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=4).read().replace(b' ', b'') else 1)"
CMD ["python3", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
