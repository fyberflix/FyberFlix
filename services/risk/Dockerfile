FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv
COPY pyproject.toml ./
COPY app ./app
RUN pip install .
COPY rules ./rules
RUN useradd -r -u 10002 risk && chown -R risk /srv
USER risk
EXPOSE 8091
# One worker on purpose: Prism keeps rate counters in process memory.
CMD ["uvicorn", "--factory", "app.main:app_factory", "--host", "0.0.0.0", "--port", "8091", "--workers", "1"]
