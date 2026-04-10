FROM ghcr.io/identicum/python-flask:latest

RUN python3 -m pip install --upgrade --no-cache git+https://github.com/Identicum/sherpa-py-utils.git@main && \
    python3 -m pip install --upgrade --no-cache git+https://github.com/Identicum/sherpa-py-keycloak.git@main && \
    python3 -m pip install --upgrade --no-cache elasticsearch flask-oidc

ENV APP_BASE_URL="http://localhost:5000" \
    SMTP_HOST="localhost" \
    SMTP_PORT="25" \
    SMTP_FROM_ADDR="sherpa@localhost"

COPY ./app/ /app
