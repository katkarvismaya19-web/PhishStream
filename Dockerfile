# API + dashboard image (also used by the producer). Spark jobs use Dockerfile.spark.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt requirements-bigdata.txt ./
RUN pip install --no-cache-dir -r requirements-bigdata.txt
COPY . .
RUN python -m phishstream.pipeline
EXPOSE 8000
CMD ["uvicorn", "phishstream.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
