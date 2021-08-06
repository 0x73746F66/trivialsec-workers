FROM registry.gitlab.com/trivialsec/containers-common/python
LABEL org.opencontainers.image.authors="Christopher Langton"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.source="https://gitlab.com/trivialsec/workers"

ARG COMMON_VERSION
ARG BUILD_ENV
ARG GITLAB_USER
ARG GITLAB_PASSWORD
ARG OPENSSL_PKG
ARG TESTSSL_INSTALL_DIR

ENV PYTHONPATH ${PYTHONPATH}
ENV APP_ENV ${APP_ENV}
ENV APP_NAME ${APP_NAME}
ENV AWS_REGION ap-southeast-2
ENV AWS_ACCESS_KEY_ID ${AWS_ACCESS_KEY_ID}
ENV AWS_SECRET_ACCESS_KEY ${AWS_SECRET_ACCESS_KEY}
ENV CONFIG_FILE ${CONFIG_FILE}
ENV LOG_LEVEL ${LOG_LEVEL}
ENV TESTSSL_INSTALL_DIR ${TESTSSL_INSTALL_DIR:-/testssl}
ENV PATH ${PATH}:/srv/app/lib/bin:/testssl

RUN touch /tmp/application.log \
    && echo "Cloning python-libs from Gitlab" \
    && git clone --depth 1 --branch ${COMMON_VERSION} --single-branch https://${GITLAB_USER}:${GITLAB_PASSWORD}@gitlab.com/trivialsec/python-common.git /tmp/trivialsec/python-libs \
    && cd /tmp/trivialsec/python-libs \
    && echo "Installing python-libs" \
    && make install \
    && echo "Clean up..." \
    && rm -rf /tmp/trivialsec

USER root
COPY build/openssl.tar.gz /tmp/trivialsec/openssl.tar.gz
COPY build/testssl.tar.gz /tmp/trivialsec/testssl.tar.gz
RUN mkdir -p /openssl /tmp/testssl /testssl/etc \
    && echo "Installing openssl" \
    && tar -xzvf /tmp/trivialsec/openssl.tar.gz -C /openssl \
    && mv -f /openssl/bin/openssl /usr/bin/openssl \
    && echo "Installing testssl.sh" \
    && apt-get update \
    && apt-get install -qy --no-install-recommends bsdmainutils procps \
    && tar -xzvf /tmp/trivialsec/testssl.tar.gz -C /tmp/testssl \
    && mv -f /tmp/testssl/* ${TESTSSL_INSTALL_DIR}/ \
    && echo "Clean up..." \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /tmp/* /var/lib/apt/lists/* \
    && chown -R trivialsec:trivialsec ${TESTSSL_INSTALL_DIR}/etc /openssl

USER trivialsec
COPY --chown=trivialsec:trivialsec docker/circusd-logger.yaml circusd-logger.yaml
COPY --chown=trivialsec:trivialsec docker/config-${BUILD_ENV}.yaml config.yaml
COPY --chown=trivialsec:trivialsec docker/testssl/circus-${BUILD_ENV}.ini circus.ini
COPY --chown=trivialsec:trivialsec docker/testssl/bin lib/bin
COPY --chown=trivialsec:trivialsec requirements.txt .
RUN mkdir -p lib \
    && echo "Installing from requirements.txt" \
    && python3 -m pip install -q -U --no-cache-dir -r requirements.txt
COPY --chown=trivialsec:trivialsec src/worker worker
COPY --chown=trivialsec:trivialsec src/testssl testssl
COPY --chown=trivialsec:trivialsec src/main.py main.py
COPY --chown=trivialsec:trivialsec src/s3_upload.py s3_upload.py

CMD ["circusd", "--logger-config", "circusd-logger.yaml", "--log-level", "INFO", "circus.ini"]
