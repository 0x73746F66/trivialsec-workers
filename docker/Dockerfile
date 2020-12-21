FROM trivialsec/python-base

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
ARG AWS_DEFAULT_REGION
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
ENV AWS_ACCOUNT ${AWS_ACCOUNT}
ENV AWS_REGION ${AWS_REGION}
ENV AWS_DEFAULT_REGION ${AWS_DEFAULT_REGION}
ENV AWS_ACCESS_KEY_ID ${AWS_ACCESS_KEY_ID}
ENV AWS_SECRET_ACCESS_KEY ${AWS_SECRET_ACCESS_KEY}
ENV PATH ${PATH}:/home/ec2-user/.local/bin

USER root
WORKDIR /srv/app

RUN mkdir -p /srv/app/lib /amass /openssl /tmp/testssl /testssl/etc && \
    touch /tmp/application.log && \
    yum install -q -y \
        openjdk-11-jdk \
        ldns && \
    yum clean metadata && \
    yum -q -y clean all && \
    rpm --quiet -U https://nmap.org/dist/nmap-7.91-1.x86_64.rpm && \
    aws s3 cp --only-show-errors s3://cloudformation-trivialsec/deploy-packages/amass_linux_amd64-${COMMON_VERSION}.zip /tmp/trivialsec/amass_linux_amd64.zip && \
    aws s3 cp --only-show-errors s3://cloudformation-trivialsec/deploy-packages/openssl-${COMMON_VERSION}.zip /tmp/trivialsec/openssl.zip && \
    aws s3 cp --only-show-errors s3://cloudformation-trivialsec/deploy-packages/testssl-${COMMON_VERSION}.zip /tmp/trivialsec/testssl.zip && \
    aws s3 cp --only-show-errors s3://cloudformation-trivialsec/deploy-packages/worker-dev-${COMMON_VERSION}.zip /tmp/trivialsec/worker.zip && \
    aws s3 cp --only-show-errors s3://cloudformation-trivialsec/deploy-packages/trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl \
        /srv/app/trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl && \
    aws s3 cp --only-show-errors s3://cloudformation-trivialsec/deploy-packages/build-${COMMON_VERSION}.zip /tmp/trivialsec/build.zip && \
    unzip -qo /tmp/trivialsec/build.zip -d /srv/app && \
    unzip -qo /tmp/trivialsec/amass_linux_amd64.zip -d /amass && \
    unzip -qo /tmp/trivialsec/openssl.zip -d /openssl && \
    unzip -qo /tmp/trivialsec/testssl.zip -d /tmp/testssl && \
    unzip -qo /tmp/trivialsec/worker.zip -d /tmp/trivialsec && \
    cp -nr /tmp/trivialsec/src/* /srv/app/ && \
    cp -nr /tmp/trivialsec/bin /srv/app/lib/ && \
    cp -n /tmp/trivialsec/circus.ini /srv/app/circus.ini && \
    cp -n /tmp/trivialsec/circusd-logger.yaml /srv/app/circusd-logger.yaml && \
    chmod a+x /amass/amass_linux_amd64/amass && \
    cp -nr /amass/amass_linux_amd64/examples/wordlists /srv/app/lib && \
    mv -f /openssl/bin/openssl /usr/bin/openssl && \
    mv -f /tmp/testssl/testssl /testssl/testssl && \
    mv -f /tmp/testssl/* /testssl/etc/ && \
    chown -R ec2-user: \
        /usr/bin/openssl \
        /testssl \
        /amass \
        /srv/app \
        /tmp/trivialsec \
        /tmp/application.log && \
    rm -rf /tmp/trivialsec

USER ec2-user
COPY docker/requirements.txt /srv/app/requirements.txt
RUN python3.8 -m pip install -q --user --no-cache-dir --find-links=/srv/app/build/wheel --no-index /srv/app/trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl && \
    python3.8 -m pip install -U --user --no-cache-dir --isolated -r /srv/app/requirements.txt

USER root
RUN cp -nr /amass/amass_linux_amd64/amass /usr/local/bin/amass && \
    nmap --script-updatedb && \
    rm -rf \
        /tmp/trivialsec \
        /openssl \
        /amass

USER ec2-user
ENTRYPOINT [ "/home/ec2-user/.local/bin/circusd" ]
CMD [ "--logger-config", "circusd-logger.yaml", "--log-level", "DEBUG", "circus.ini" ]
