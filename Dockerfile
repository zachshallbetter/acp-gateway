FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --disable-pip-version-check -r /app/requirements.txt
COPY gateway.py postgres_store.py db_migrations.py client_releases.json /app/
COPY migrations /app/migrations
ENV PYTHONUNBUFFERED=1
CMD ["python3", "/app/gateway.py"]
