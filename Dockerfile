FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
# GCC enables the optional native FortiGate lexer; ingestion retains a fallback.
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY pyproject.toml README.md ./
COPY src ./src
COPY configs ./configs
COPY rules ./rules
COPY web ./web
COPY data/sample ./data/sample
RUN pip install --no-deps -e . \
 && useradd --create-home --uid 10001 trace \
 && mkdir -p /app/out /app/work /app/spill \
 && chown -R trace:trace /app
USER trace
EXPOSE 8000
ENTRYPOINT ["tracekc"]
CMD ["--help"]
