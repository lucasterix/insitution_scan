FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    # WeasyPrint runtime deps for PDF rendering
    libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libharfbuzz-subset0 \
    fonts-dejavu-core \
    # Pillow runtime deps for image EXIF parsing
    libjpeg62-turbo zlib1g \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

# Install nuclei binary (projectdiscovery.io) for active vulnerability scanning.
# Uses the GitHub Releases API to always pull the latest stable version.
RUN NUCLEI_URL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | \
        python3 -c "import sys,json; [print(a['browser_download_url']) for a in json.load(sys.stdin).get('assets',[]) if 'linux_amd64.zip' in a['name']]" | head -1) && \
    if [ -n "$NUCLEI_URL" ]; then \
        curl -sLo /tmp/nuclei.zip "$NUCLEI_URL" && \
        python3 -c "import zipfile; zipfile.ZipFile('/tmp/nuclei.zip').extract('nuclei', '/usr/local/bin')" && \
        chmod +x /usr/local/bin/nuclei && \
        rm /tmp/nuclei.zip; \
    fi

COPY app ./app

RUN useradd --create-home --shell /bin/bash appuser && chown -R appuser:appuser /app

# Pre-download nuclei templates so the first scan doesn't need to wait.
USER appuser
RUN nuclei -update-templates -disable-update-check 2>/dev/null || true

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
