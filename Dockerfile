FROM python:3.10-slim

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y \
    tshark \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY ./README.md ./README.md
COPY ./karton ./karton
COPY ./setup.py ./setup.py

RUN pip install .
ENTRYPOINT karton-pcap-miner