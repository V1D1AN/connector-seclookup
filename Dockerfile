FROM python:3.11-slim
 
RUN apt-get update && \
    apt-get install -y --no-install-recommends libmagic1 && \
    rm -rf /var/lib/apt/lists/*
 
COPY requirements.txt /opt/connector/
WORKDIR /opt/connector
RUN pip install --no-cache-dir -r requirements.txt
 
COPY src /opt/connector/src
 
ENTRYPOINT ["python", "-m", "src.main"]