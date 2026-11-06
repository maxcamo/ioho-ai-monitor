FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/ioho
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --system --create-home --uid 1101 ioho
COPY app ./app
COPY manage.py worker.py ./
USER ioho
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
