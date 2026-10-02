FROM python:3.12-slim

WORKDIR /app

COPY monitor-railway.py /app/monitor-railway.py

CMD ["python", "-u", "/app/monitor-railway.py"]
