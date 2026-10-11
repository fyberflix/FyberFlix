FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv
COPY pyproject.toml ./
COPY app ./app
RUN pip install .
COPY scripts ./scripts
COPY models ./models
RUN python scripts/fetch_models.py
RUN useradd -r -u 10001 face && chown -R face /srv
USER face
EXPOSE 8090
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090"]
