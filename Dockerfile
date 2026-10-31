# Pin by digest before shipping to judges: docker pull python:3.12-slim && docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY pyproject.toml README.md ./
COPY src ./src
COPY configs ./configs
COPY rules ./rules
COPY web ./web
COPY data/sample ./data/sample
RUN pip install -e ".[graph]" \
 && useradd --create-home --uid 10001 trace \
 && mkdir -p /app/out /app/work \
 && chown -R trace:trace /app
USER trace
EXPOSE 8000
ENTRYPOINT ["tracekc"]
CMD ["--help"]
