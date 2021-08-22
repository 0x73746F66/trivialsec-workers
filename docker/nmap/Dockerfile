FROM registry.gitlab.com/trivialsec/containers-common/python
LABEL org.opencontainers.image.authors="Christopher Langton"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.source="https://gitlab.com/trivialsec/workers"

ARG COMMON_VERSION
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
RUN touch /tmp/application.log \
    && echo "Cloning python-libs from Gitlab" \
    && git clone --depth 1 --branch ${COMMON_VERSION} --single-branch https://${GITLAB_USER}:${GITLAB_PASSWORD}@gitlab.com/trivialsec/python-common.git /tmp/trivialsec/python-libs \
    && cd /tmp/trivialsec/python-libs \
    && echo "Installing python-libs" \
    && make install \
    && echo "Clean up..." \
    && rm -rf /tmp/trivialsec

COPY build/scipag_vulscan.tar.gz /tmp/trivialsec/scipag_vulscan.tar.gz
RUN mkdir -p /nse \
    && echo "Installing nmap" \
    && apt-get update -q \
    && apt-get install -qy --no-install-recommends nmap libcap2-bin \
    && echo "configure capabilities" \
    && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap \
    && echo "update script db" \
    && tar -xzvf /tmp/trivialsec/scipag_vulscan.tar.gz -C /nse \
    && ln -s /nse/scipag_vulscan /usr/share/nmap/scripts/vulscan \
    && nmap --script-updatedb \
    && echo "Clean up..." \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /tmp/* /var/lib/apt/lists/*

COPY docker/circusd-logger.yaml circusd-logger.yaml
COPY docker/nmap/circus-${BUILD_ENV}.ini circus.ini
COPY docker/nmap/bin lib/bin
COPY requirements.txt .
RUN mkdir -p lib \
    && echo "Installing from requirements.txt" \
    && python3 -m pip install -q -U --no-cache-dir -r requirements.txt
COPY src/worker worker
COPY src/nmap nmap
COPY src/main.py main.py
COPY src/s3_upload.py s3_upload.py

CMD ["circusd", "--logger-config", "circusd-logger.yaml", "--log-level", "INFO", "circus.ini"]
