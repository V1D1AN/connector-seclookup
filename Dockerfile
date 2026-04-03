FROM python:3.11-slim

COPY requirements.txt /opt/connector/
WORKDIR /opt/connector
RUN pip install --no-cache-dir -r requirements.txt

COPY src /opt/connector/src

ENTRYPOINT ["python", "-m", "src.main"]
