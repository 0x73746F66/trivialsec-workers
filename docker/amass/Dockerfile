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
ENV LOG_LEVEL ${LOG_LEVEL}
ENV PATH ${PATH}:/srv/app/lib/bin

RUN touch /tmp/application.log \
    && echo "Cloning python-libs from Gitlab" \
    && git clone -q -c advice.detachedHead=false --depth 1 --branch ${COMMON_VERSION} --single-branch https://${GITLAB_USER}:${GITLAB_PASSWORD}@gitlab.com/trivialsec/python-common.git /tmp/trivialsec/python-libs \
    && cd /tmp/trivialsec/python-libs \
    && echo "Installing python-libs" \
    && make install \
    && echo "Clean up..." \
    && rm -rf /tmp/trivialsec

USER root
COPY build/amass.tar.gz /tmp/trivialsec/amass.tar.gz
RUN mkdir -p /amass \
    && echo "Installing Amass" \
    && tar -xzvf /tmp/trivialsec/amass.tar.gz -C /amass \
    && chmod a+x /amass/amass_linux_amd64/amass \
    && cp -nr /amass/amass_linux_amd64/examples/wordlists /srv/app/lib \
    && cp -nr /amass/amass_linux_amd64/amass /usr/local/bin/amass \
    && chown -R trivialsec:trivialsec /amass

USER trivialsec
COPY --chown=trivialsec:trivialsec docker/circusd-logger.yaml circusd-logger.yaml
COPY --chown=trivialsec:trivialsec docker/amass/circus-${BUILD_ENV}.ini circus.ini
COPY --chown=trivialsec:trivialsec docker/amass/bin lib/bin
COPY --chown=trivialsec:trivialsec requirements.txt .
RUN mkdir -p lib \
    && echo "Installing from requirements.txt" \
    && python3 -m pip install -q -U --no-cache-dir -r requirements.txt
COPY --chown=trivialsec:trivialsec src/worker worker
COPY --chown=trivialsec:trivialsec src/amass amass
COPY --chown=trivialsec:trivialsec src/main.py main.py
COPY --chown=trivialsec:trivialsec src/s3_upload.py s3_upload.py

CMD ["circusd", "--logger-config", "circusd-logger.yaml", "--log-level", "INFO", "circus.ini"]
