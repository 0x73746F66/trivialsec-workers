FROM registry.gitlab.com/trivialsec/containers-common/python
LABEL org.opencontainers.image.authors="Christopher Langton"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.source="https://gitlab.com/trivialsec/workers"

ARG COMMON_VERSION
ARG BUILD_ENV
ARG GITLAB_USER
ARG GITLAB_PASSWORD
ARG OPENSSL_PKG

ENV PYTHONPATH ${PYTHONPATH}
ENV APP_ENV ${APP_ENV}
ENV APP_NAME ${APP_NAME}
ENV AWS_REGION ap-southeast-2
ENV AWS_ACCESS_KEY_ID ${AWS_ACCESS_KEY_ID}
ENV AWS_SECRET_ACCESS_KEY ${AWS_SECRET_ACCESS_KEY}
ENV CONFIG_FILE ${CONFIG_FILE}
ENV LOG_LEVEL ${LOG_LEVEL}
ENV PATH ${PATH}:/home/trivialsec/.local/bin

RUN echo "Cloning Python Libs Package from Gitlab" \
    && git clone --depth 1 --branch ${COMMON_VERSION} --single-branch https://${GITLAB_USER}:${GITLAB_PASSWORD}@gitlab.com/trivialsec/python-common.git /tmp/trivialsec/python-libs \
    && cd /tmp/trivialsec/python-libs \
    && echo "Installing python-libs" \
    && make install \
    && echo "Clean up..." \
    && rm -rf /tmp/trivialsec

COPY --chown=trivialsec:trivialsec docker/conf/circusd-logger.yaml circusd-logger.yaml
COPY --chown=trivialsec:trivialsec docker/conf/circus-${BUILD_ENV}.ini circus.ini
COPY --chown=trivialsec:trivialsec docker/conf/config-${BUILD_ENV}.yaml config.yaml
COPY --chown=trivialsec:trivialsec requirements.txt .
RUN python3 -m pip install -q -U --no-cache-dir -r /srv/app/requirements.txt




RUN mkdir -p /srv/app/lib /amass /openssl /tmp/testssl /testssl/etc && \
    touch /tmp/application.log
RUN aws s3 cp --only-show-errors s3://tfplans-trivialsec/deploy-packages/${COMMON_VERSION}/amass.tar.gz /tmp/trivialsec/amass.tar.gz
RUN aws s3 cp --only-show-errors s3://tfplans-trivialsec/deploy-packages/${COMMON_VERSION}/openssl.tar.gz /tmp/trivialsec/openssl.tar.gz
RUN aws s3 cp --only-show-errors s3://tfplans-trivialsec/deploy-packages/${COMMON_VERSION}/testssl.tar.gz /tmp/trivialsec/testssl.tar.gz
RUN aws s3 cp --only-show-errors s3://tfplans-trivialsec/deploy-packages/${COMMON_VERSION}/worker.tar.gz /tmp/trivialsec/worker.tar.gz
RUN aws s3 cp --only-show-errors s3://tfplans-trivialsec/deploy-packages/trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl \
        /srv/app/trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl
RUN aws s3 cp --only-show-errors s3://tfplans-trivialsec/deploy-packages/${COMMON_VERSION}/build.tgz /tmp/trivialsec/build.tgz
RUN tar -xzvf /tmp/trivialsec/build.tgz -C /srv/app
RUN tar -xzvf /tmp/trivialsec/amass.tar.gz -C /amass
RUN tar -xzvf /tmp/trivialsec/openssl.tar.gz -C /openssl
RUN tar -xzvf /tmp/trivialsec/testssl.tar.gz -C /tmp/testssl
RUN tar -xzvf /tmp/trivialsec/worker.tar.gz -C /tmp/trivialsec
RUN cp -nr /tmp/trivialsec/src/* /srv/app/ && \
    cp -nr /tmp/trivialsec/bin /srv/app/lib/ && \
    cp -n /tmp/trivialsec/circusd-logger.yaml /srv/app/circusd-logger.yaml
RUN chmod a+x /amass/amass_linux_amd64/amass && \
    cp -nr /amass/amass_linux_amd64/examples/wordlists /srv/app/lib && \
    mv -f /openssl/bin/openssl /usr/bin/openssl && \
    mv -f /tmp/testssl/testssl /testssl/testssl && \
    mv -f /tmp/testssl/* /testssl/etc/
RUN chown -R trivialsec: \
        /usr/bin/openssl \
        /testssl \
        /amass \
        /srv/app \
        /tmp/trivialsec \
        /tmp/application.log && \
    rm -rf /tmp/trivialsec

USER trivialsec
COPY docker/requirements.txt /srv/app/requirements.txt
COPY docker/circus.ini /srv/app/circus.ini
RUN python3 -m pip install -q --user --no-cache-dir --find-links=/srv/app/build/wheel --no-index /srv/app/trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl
RUN python3 -m pip install -U --user --no-cache-dir --isolated -r /srv/app/requirements.txt

USER root
RUN cp -nr /amass/amass_linux_amd64/amass /usr/local/bin/amass
RUN nmap --script-updatedb
RUN rm -rf \
        /tmp/trivialsec \
        /openssl \
        /amass

USER trivialsec
ENTRYPOINT [ "/home/trivialsec/.local/bin/circusd" ]
CMD [ "--logger-config", "circusd-logger.yaml", "--log-level", "DEBUG", "circus.ini" ]
