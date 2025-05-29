FROM ghcr.io/identicum/python-flask:latest

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY ./app/ /app
