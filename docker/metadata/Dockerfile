FROM registry.gitlab.com/trivialsec/containers-common/python
LABEL org.opencontainers.image.authors="Christopher Langton"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.source="https://gitlab.com/trivialsec/workers"

ARG TRIVIALSEC_PY_LIB_VER
ARG BUILD_ENV
ARG GITLAB_USER
ARG GITLAB_PASSWORD

ENV PYTHONPATH ${PYTHONPATH}
ENV APP_ENV ${APP_ENV}
ENV APP_NAME ${APP_NAME}
ENV AWS_REGION ap-southeast-2
ENV AWS_ACCESS_KEY_ID ${AWS_ACCESS_KEY_ID}
ENV AWS_SECRET_ACCESS_KEY ${AWS_SECRET_ACCESS_KEY}
ENV LOG_LEVEL ${LOG_LEVEL}

USER root
RUN echo "Installing whois" \
    && apt-get update -q \
    && apt-get install -qy --no-install-recommends whois \
    && echo "Clean up..." \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /tmp/* /var/lib/apt/lists/*

USER trivialsec
RUN touch /tmp/application.log \
    && echo "Cloning python-libs from Gitlab" \
    && git clone -q -c advice.detachedHead=false --depth 1 --branch ${TRIVIALSEC_PY_LIB_VER} --single-branch https://${GITLAB_USER}:${GITLAB_PASSWORD}@gitlab.com/trivialsec/python-common.git /tmp/trivialsec/python-libs \
    && cd /tmp/trivialsec/python-libs \
    && echo "Installing python-libs" \
    && make install \
    && echo "Clean up..." \
    && rm -rf /tmp/trivialsec

COPY --chown=trivialsec:trivialsec docker/circusd-logger.yaml circusd-logger.yaml
COPY --chown=trivialsec:trivialsec docker/metadata/circus-${BUILD_ENV}.ini circus.ini
COPY --chown=trivialsec:trivialsec requirements.txt .
RUN echo "Installing from requirements.txt" \
    && python3 -m pip install -q -U --no-cache-dir -r requirements.txt
COPY --chown=trivialsec:trivialsec src/worker worker
COPY --chown=trivialsec:trivialsec src/metadata metadata
COPY --chown=trivialsec:trivialsec src/main.py main.py
COPY --chown=trivialsec:trivialsec src/s3_upload.py s3_upload.py

CMD ["circusd", "--logger-config", "circusd-logger.yaml", "--log-level", "INFO", "circus.ini"]
