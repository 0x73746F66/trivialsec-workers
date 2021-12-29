FROM trivialsec/worker-base

ARG AWS_ACCESS_KEY_ID
ENV AWS_ACCESS_KEY_ID ${AWS_ACCESS_KEY_ID}
ARG AWS_SECRET_ACCESS_KEY
ENV AWS_SECRET_ACCESS_KEY ${AWS_SECRET_ACCESS_KEY}
ARG VERSION
ENV VERSION=${VERSION}
ENV PATH "$PATH:/nikto2"
RUN mkdir -p /nikto2

WORKDIR /tmp
RUN apt-get update && \
    apt-get install -y \
    perl \
    libnet-ssleay-perl && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    echo https://github.com/sullo/nikto/archive/${VERSION}.tar.gz && \
    wget -s https://github.com/sullo/nikto/archive/${VERSION}.tar.gz -O nikto2.tar.gz && \
    tar -xzf nikto2.tar.gz && \
    cp -r /tmp/nikto-${VERSION}/program/* /nikto2 && \
    rm -rf /tmp/*

# nmap -sS www.langton.cloud/32 -oG - | nikto.pl -evasion A -Format csv -nointeractive -output nikto_www.langton.cloud.csv -Plugins @@ALL -C all -ssl 443 -port 80,443 -useragent 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/600.3.18 (KHTML, like Gecko) Version/8.0.3 Safari/600.3.18' -ask no -host -

WORKDIR /srv/app

COPY docker/nikto2/requirements.txt requirements.txt
COPY src/worker/nikto2/lib lib
RUN python3 -m pip install -U pip setuptools && \
    CFLAGS="-O0" STATICBUILD=true python3 -m pip install -q --user -r requirements.txt

VOLUME ["/srv/app", "/tmp", "/var/log/nikto2"]

ENTRYPOINT ["python3"]
CMD ["main.py", "--service", "nikto2"]
