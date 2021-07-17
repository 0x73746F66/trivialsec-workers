SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)

TESTSSL_URL = https://testssl.sh
BUCKET = tfplans-trivialsec

.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

prep:
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	find . -type d -name '__pycache__' -delete 2>/dev/null || true
	find . -type f -name '*.DS_Store' -delete 2>/dev/null || true
	@rm *.zip *.whl || true
	@rm -rf build || true
	@rm -f bin/openssl* || true

python-libs: prep
	yes | pip uninstall -q trivialsec-common
	aws --profile $(AWS_PROFILE) s3 cp --only-show-errors s3://$(BUCKET)/deploy-packages/trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl
	aws --profile $(AWS_PROFILE) s3 cp --only-show-errors s3://$(BUCKET)/deploy-packages/$(COMMON_VERSION)/build.tgz build.tgz
	tar -xzvf build.tgz
	pip install -q --no-cache-dir --find-links=build/wheel --no-index trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl

install-dev: python-libs
	pip install -q -U pip setuptools wheel
	pip install -q -U --no-cache-dir --isolated -r ./docker/requirements.txt

lint:
	pylint --jobs=0 --persistent=y --errors-only src/**/*.py
	semgrep -q --strict --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

build: ## Build compressed container
	docker-compose build --compress

buildnc: package ## Clean build docker
	docker-compose build --no-cache --compress

rebuild: down build

up: prep ## Start the app
	docker-compose up -d

down: ## Stop the app
	@docker-compose down --remove-orphans

restart: down run

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

package-upload: ## uploads distribution to s3
	aws --profile $(AWS_PROFILE) s3 cp build/openssl.tar.gz s3://$(BUCKET)/deploy-packages/$(COMMON_VERSION)/openssl.tar.gz
	aws --profile $(AWS_PROFILE) s3 cp build/testssl.tar.gz s3://$(BUCKET)/deploy-packages/$(COMMON_VERSION)/testssl.tar.gz
	aws --profile $(AWS_PROFILE) s3 cp build/amass.tar.gz s3://$(BUCKET)/deploy-packages/$(COMMON_VERSION)/amass.tar.gz
