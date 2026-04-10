FROM ghcr.io/identicum/python-flask:latest

RUN python3 -m pip install --upgrade --no-cache git+https://github.com/Identicum/sherpa-py-utils.git@main && \
    python3 -m pip install --upgrade --no-cache git+https://github.com/Identicum/sherpa-py-keycloak.git@main && \
    python3 -m pip install --upgrade --no-cache elasticsearch flask-oidc

ENV TERRAFORM_VERSION="1.14.7"
ARG BUILDARCH
RUN curl https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${BUILDARCH}.zip > terraform.zip && \
    unzip terraform.zip -d /bin && \
    rm -f terraform.zip

ENV LOG_LEVEL="DEBUG" \
    APP_BASE_URL="http://localhost:5000" \
    SMTP_HOST="localhost" \
    SMTP_PORT="25" \
    SMTP_FROM_ADDR="sherpa@localhost"

COPY ./app/ /app
