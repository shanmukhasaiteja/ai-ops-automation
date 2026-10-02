FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY config ./config
COPY samples ./samples
RUN pip install --no-cache-dir . \
    && useradd --create-home app && mkdir /data && chown app /data
ENV OPS_DB=/data/ops.db
USER app
EXPOSE 8000
CMD ["ops-triage", "serve", "--host", "0.0.0.0", "--port", "8000"]
