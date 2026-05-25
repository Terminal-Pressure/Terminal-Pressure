FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY terminal_pressure.py .

ENTRYPOINT ["python", "terminal_pressure.py"]
