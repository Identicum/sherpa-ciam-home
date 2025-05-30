FROM ghcr.io/identicum/python-flask:latest

RUN apk add --no-cache openldap-dev && \
    pip install --upgrade pip && \
    python3 -m pip install --no-cache git+https://github.com/Identicum/sherpa-py-utils.git@main && \
    python3 -m pip install --no-cache git+https://github.com/Identicum/sherpa-py-keycloak.git@main

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY ./app/ /app
