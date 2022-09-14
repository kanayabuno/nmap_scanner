FROM python:3.9.14-bullseye

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y nmap

COPY requirements.txt requirements.txt
RUN pip3 install wheel
RUN pip3 install -r requirements.txt

COPY . .
ENTRYPOINT ["python3", "nmap_scanner/nmap_scanner.py"]