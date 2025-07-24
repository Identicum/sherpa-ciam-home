FROM ghcr.io/identicum/python-flask:latest

RUN apk add --no-cache openldap-dev && \
    pip install --upgrade pip && \
    python3 -m pip install --upgrade --no-cache git+https://github.com/Identicum/sherpa-py-utils.git@main && \
    python3 -m pip install --upgrade --no-cache git+https://github.com/Identicum/sherpa-py-keycloak.git@main && \
    python3 -m pip install elasticsearch

ENV LOG_LEVEL="DEBUG"
ENV TERRAFORM_VERSION="1.9.8"
ARG BUILDARCH
RUN curl https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${BUILDARCH}.zip > terraform.zip && \
    unzip terraform.zip -d /bin && \
    rm -f terraform.zip

ENV SMTP_HOST="localhost"
ENV SMTP_PORT="25"
ENV SMTP_FROM_ADDR="sherpa@localhost"

COPY ./app/ /app
