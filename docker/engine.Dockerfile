FROM python:3.11-slim

WORKDIR /app

# Least-privileged runtime user.
RUN groupadd -r ide && useradd -r -g ide ide

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY mock_backend.py .

USER ide

CMD ["python", "mock_backend.py"]
