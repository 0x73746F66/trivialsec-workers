FROM trivialsec/worker-base

ARG AWS_ACCESS_KEY_ID
ENV AWS_ACCESS_KEY_ID ${AWS_ACCESS_KEY_ID}
ARG AWS_SECRET_ACCESS_KEY
ENV AWS_SECRET_ACCESS_KEY ${AWS_SECRET_ACCESS_KEY}

RUN mkdir -p lib/bin
COPY docker/shodan_crawl/requirements.txt requirements.txt
COPY src/worker/shodan_crawl/lib lib
RUN python3 -m pip install -U pip setuptools && \
    CFLAGS="-O0" STATICBUILD=true python3 -m pip install -q --no-cache-dir --isolated -r requirements.txt

ENTRYPOINT ["python3"]
CMD ["main.py", "--service", "shodan_crawl"]
