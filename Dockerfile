FROM registry.gitlab.com/trivialsec/containers-common/python

ARG COMMON_VERSION
ARG PYTHONUNBUFFERED
ARG PYTHONUTF8
ARG PYTHONDEBUG
ARG PYTHONCOERCECLOCALE
ARG CFLAGS
ARG STATICBUILD
ARG LC_ALL
ARG LANG
ARG AWS_ACCOUNT
ARG AWS_REGION
ARG AWS_ACCESS_KEY_ID
ARG AWS_SECRET_ACCESS_KEY
ARG OPENSSL_PKG
ENV PYTHONUNBUFFERED ${PYTHONUNBUFFERED}
ENV PYTHONUTF8 ${PYTHONUTF8}
ENV PYTHONDEBUG ${PYTHONDEBUG}
ENV PYTHONCOERCECLOCALE ${PYTHONCOERCECLOCALE}
ENV LC_ALL ${LC_ALL}
ENV LANG ${LANG}
ENV CONFIG_FILE ${CONFIG_FILE}
ENV AWS_REGION ap-southeast-2
ENV AWS_ACCESS_KEY_ID ${AWS_ACCESS_KEY_ID}
ENV AWS_SECRET_ACCESS_KEY ${AWS_SECRET_ACCESS_KEY}
ENV PATH ${PATH}:/home/trivialsec/.local/bin

USER root
WORKDIR /srv/app

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
RUN python3.8 -m pip install -q --user --no-cache-dir --find-links=/srv/app/build/wheel --no-index /srv/app/trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl
RUN python3.8 -m pip install -U --user --no-cache-dir --isolated -r /srv/app/requirements.txt

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
