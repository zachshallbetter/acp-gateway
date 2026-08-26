FROM python:3.12-slim
WORKDIR /app
COPY gateway.py /app/gateway.py
ENV PYTHONUNBUFFERED=1
CMD ["python3", "/app/gateway.py"]
