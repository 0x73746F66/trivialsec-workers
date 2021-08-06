SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)
REPO_ORG = registry.gitlab.com/trivialsec/workers
TESTSSL_URL = https://testssl.sh
BUCKET = tfplans-trivialsec
.ONESHELL:
.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

ifndef CI_BUILD_REF
	CI_BUILD_REF = local
endif

prep: ## Cleanup tmp files
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	find . -type d -name '__pycache__' -delete 2>/dev/null || true
	find . -type f -name '*.DS_Store' -delete 2>/dev/null || true
	@rm -f **/*.zip **/*.tar **/*.tgz **/*.gz
	@rm -rf build python-libs

python-libs: prep ## download and install the trivialsec python libs locally (for IDE completions)
	yes | pip uninstall -q trivialsec-common
	@$(shell git clone --depth 1 --branch ${COMMON_VERSION} --single-branch https://${DOCKER_USER}:${DOCKER_PASSWORD}@gitlab.com/trivialsec/python-common.git python-libs)
	cd python-libs
	make install
install-deps: python-libs ## Just the minimal local deps for IDE completions
	pip install -q -U pip setuptools wheel semgrep pylint
	pip install -q -U -r requirements.txt

test-local: ## Prettier test outputs
	pylint --exit-zero -f colorized --persistent=y -r y --jobs=0 src/**/*.py
	semgrep -q --strict --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

pylint-ci: ## run pylint for CI
	pylint --exit-zero --persistent=n -f json -r n --jobs=0 --errors-only src/**/*.py > pylint.json

semgrep-sast-ci: ## run core semgrep rules for CI
	semgrep --disable-version-check -q --strict --error -o semgrep-ci.json --json --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

test-all: semgrep-sast-ci pylint-ci ## Run all CI tests

build-metadata: ## Builds metadata image using docker cli directly for CI
	@docker build --compress $(BUILD_ARGS) \
		-t $(REPO_ORG)/metadata:$(CI_BUILD_REF) \
		--cache-from $(REPO_ORG)/metadata:latest \
        --build-arg COMMON_VERSION=$(COMMON_VERSION) \
        --build-arg BUILD_ENV=$(BUILD_ENV) \
        --build-arg GITLAB_USER=$(DOCKER_USER) \
        --build-arg GITLAB_PASSWORD=$(DOCKER_PASSWORD) \
		-f docker/metadata/Dockerfile .

build: build-metadata ## Builds all images

push-metadata-tagged: ## Push tagged metadata image
	docker push -q $(REPO_ORG)/metadata:${CI_BUILD_REF}

push-tagged: push-metadata-tagged ## Push tagged images

push-metadata-ci: ## Push latest metadata image using docker cli directly for CI
	docker tag $(REPO_ORG)/metadata:${CI_BUILD_REF} $(REPO_ORG)/metadata:latest
	docker push -q $(REPO_ORG)/metadata:latest

push-ci: push-metadata-ci ## Push latest images

pull-base: ## pulls latest base image
	docker pull -q registry.gitlab.com/trivialsec/containers-common/python:latest

build-ci: pull pull-base build ## Builds from latest base image

pull: ## pulls latest image
	docker pull -q $(REPO_ORG)/metadata:latest || true

rebuild: down build-ci ## Brings down the stack and builds it anew

docker-login: ## login to docker cli using $DOCKER_USER and $DOCKER_PASSWORD
	@echo $(shell [ -z "${DOCKER_PASSWORD}" ] && echo "DOCKER_PASSWORD missing" )
	@echo ${DOCKER_PASSWORD} | docker login -u ${DOCKER_USER} --password-stdin registry.gitlab.com

up: prep ## Start the app
	docker-compose up -d metadata

down: ## Stop the app
	@docker-compose down --remove-orphans

restart: down up ## restarts the app

dep-openssl:
	[ -f build/$(OPENSSL_PKG) ] || wget -q $(TESTSSL_URL)/$(OPENSSL_PKG) -O build/$(OPENSSL_PKG)
	tar xvzf build/$(OPENSSL_PKG)
	mv bin/openssl.Linux.x86_64.static bin/openssl
	tar --exclude '*.DS_Store' -cf build/openssl.tar bin/openssl
	gzip -f9 build/openssl.tar
	ls -l --block-size=M build/openssl.tar.gz
	rm -f bin/openssl*

dep-amass:
	[ -f build/amass_linux_amd64.zip ] || wget -q https://github.com/OWASP/Amass/releases/download/v$(AMASS_VERSION)/amass_linux_amd64.zip -O build/amass_linux_amd64.zip
	unzip -qo build/amass_linux_amd64.zip -d build/
	tar --exclude '*.DS_Store' --exclude 'doc' --exclude 'LICENSE' --exclude 'README.md' -cf build/amass.tar -C build amass_linux_amd64
	gzip -f9 build/amass.tar
	ls -l --block-size=M build/amass.tar.gz

dep-testssl:
	[ -f build/testssl ] || wget -q https://raw.githubusercontent.com/drwetter/testssl.sh/3.1dev/testssl.sh -O build/testssl
	chmod a+x build/testssl
	mkdir -p build/etc
	[ -f build/etc/Apple.pem ] || wget -q $(TESTSSL_URL)/etc/Apple.pem -O build/etc/Apple.pem
	[ -f build/etc/Java.pem ] || wget -q $(TESTSSL_URL)/etc/Java.pem -O build/etc/Java.pem
	[ -f build/etc/Linux.pem ] || wget -q $(TESTSSL_URL)/etc/Linux.pem -O build/etc/Linux.pem
	[ -f build/etc/Microsoft.pem ] || wget -q $(TESTSSL_URL)/etc/Microsoft.pem -O build/etc/Microsoft.pem
	[ -f build/etc/Mozilla.pem ] || wget -q $(TESTSSL_URL)/etc/Mozilla.pem -O build/etc/Mozilla.pem
	[ -f build/etc/ca_hashes.txt ] || wget -q $(TESTSSL_URL)/etc/ca_hashes.txt -O build/etc/ca_hashes.txt
	[ -f build/etc/cipher-mapping.txt ] || wget -q $(TESTSSL_URL)/etc/cipher-mapping.txt -O build/etc/cipher-mapping.txt
	[ -f build/etc/client-simulation.txt ] || wget -q $(TESTSSL_URL)/etc/client-simulation.txt -O build/etc/client-simulation.txt
	[ -f build/etc/client-simulation.wiresharked.txt ] || wget -q $(TESTSSL_URL)/etc/client-simulation.wiresharked.txt -O build/etc/client-simulation.wiresharked.txt
	[ -f build/etc/common-primes.txt ] || wget -q $(TESTSSL_URL)/etc/common-primes.txt -O build/etc/common-primes.txt
	[ -f build/etc/curves.txt ] || wget -q $(TESTSSL_URL)/etc/curves.txt -O build/etc/curves.txt
	[ -f build/etc/tls_data.txt ] || wget -q $(TESTSSL_URL)/etc/tls_data.txt -O build/etc/tls_data.txt
	tar --exclude '*.DS_Store' -cf build/testssl.tar -C build etc
	tar --exclude '*.DS_Store' -rf build/testssl.tar -C build testssl
	gzip -f9 build/testssl.tar
	ls -l --block-size=M build/testssl.tar.gz
