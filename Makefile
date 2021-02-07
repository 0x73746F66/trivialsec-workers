SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)
APP_NAME = worker
LOCAL_CACHE = /tmp/trivialsec

.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

CMD_AWS := aws
ifdef AWS_PROFILE
CMD_AWS += --profile $(AWS_PROFILE)
endif
ifdef AWS_REGION
CMD_AWS += --region $(AWS_REGION)
endif

prep:
	mkdir -p worker_datadir
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	find . -type d -name '__pycache__' -delete 2>/dev/null || true
	find . -type f -name '*.DS_Store' -delete 2>/dev/null || true
	@rm *.zip *.whl || true
	@rm -rf build || true
	@rm -f bin/openssl* || true

common: prep
	yes | pip uninstall -q trivialsec-common
	aws s3 cp --only-show-errors s3://trivialsec-assets/deploy-packages/trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl
	aws s3 cp --only-show-errors s3://trivialsec-assets/deploy-packages/$(COMMON_VERSION)/build.zip build.zip
	unzip -qo build.zip
	pip install -q --no-cache-dir --find-links=build/wheel --no-index trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl

common-dev: ## Install trivialsec_common lib from local build
	yes | pip uninstall -q trivialsec-common
	cp -fu $(LOCAL_CACHE)/build.zip build.zip
	cp -fu $(LOCAL_CACHE)/trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl
	unzip -qo build.zip
	pip install -q --no-cache-dir --find-links=build/wheel --no-index trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl

install-dev: common
	pip install -q -U pip setuptools pylint wheel awscli
	pip install -q -U --no-cache-dir --isolated -r ./docker/requirements.txt

lint:
	pylint --jobs=0 --persistent=y --errors-only src/**/*.py

build: package-dev ## Build compressed container
	docker-compose build --compress

buildnc: package-dev ## Clean build docker
	docker-compose build --no-cache --compress

rebuild: down build

docker-clean: ## Fixes some issues with docker
	docker rmi $(docker images -qaf "dangling=true")
	yes | docker system prune
	sudo service docker restart

docker-purge: ## tries to compeltely remove all docker files and start clean
	docker rmi $(docker images -qa)
	yes | docker system prune
	sudo service docker stop
	sudo rm -rf /tmp/docker.backup/
	sudo cp -Pfr /var/lib/docker /tmp/docker.backup
	sudo rm -rf /var/lib/docker
	sudo service docker start

up: prep ## Start the app
	docker-compose up -d $(APP_NAME)

down: ## Stop the app
	@docker-compose down

restart: down run

package:
	mkdir -p build
	@rm **/*.zip || true
	zip -9rq build/$(APP_NAME).zip src bin -x '*.pyc' -x '__pycache__' -x '*.DS_Store'
	zip -uj9q build/$(APP_NAME).zip docker/circus.ini docker/circusd-logger.yaml docker/requirements.txt
	[ -f build/amass_linux_amd64.zip ] || wget -q https://github.com/OWASP/Amass/releases/download/v$(AMASS_VERSION)/amass_linux_amd64.zip -O build/amass_linux_amd64.zip
	[ -f build/$(OPENSSL_PKG) ] || wget -q https://testssl.sh/$(OPENSSL_PKG) -O build/$(OPENSSL_PKG)
	tar xvzf build/$(OPENSSL_PKG)
	mv bin/openssl.Linux.x86_64.static bin/openssl
	[ -f build/testssl ] || wget -q https://raw.githubusercontent.com/drwetter/testssl.sh/3.1dev/testssl.sh -O build/testssl
	chmod a+x build/testssl
	mkdir -p build/etc
	[ -f build/etc/Apple.pem ] || wget -q https://testssl.sh/etc/Apple.pem -O build/etc/Apple.pem
	[ -f build/etc/Java.pem ] || wget -q https://testssl.sh/etc/Java.pem -O build/etc/Java.pem
	[ -f build/etc/Linux.pem ] || wget -q https://testssl.sh/etc/Linux.pem -O build/etc/Linux.pem
	[ -f build/etc/Microsoft.pem ] || wget -q https://testssl.sh/etc/Microsoft.pem -O build/etc/Microsoft.pem
	[ -f build/etc/Mozilla.pem ] || wget -q https://testssl.sh/etc/Mozilla.pem -O build/etc/Mozilla.pem
	[ -f build/etc/ca_hashes.txt ] || wget -q https://testssl.sh/etc/ca_hashes.txt -O build/etc/ca_hashes.txt
	[ -f build/etc/cipher-mapping.txt ] || wget -q https://testssl.sh/etc/cipher-mapping.txt -O build/etc/cipher-mapping.txt
	[ -f build/etc/client-simulation.txt ] || wget -q https://testssl.sh/etc/client-simulation.txt -O build/etc/client-simulation.txt
	[ -f build/etc/client-simulation.wiresharked.txt ] || wget -q https://testssl.sh/etc/client-simulation.wiresharked.txt -O build/etc/client-simulation.wiresharked.txt
	[ -f build/etc/common-primes.txt ] || wget -q https://testssl.sh/etc/common-primes.txt -O build/etc/common-primes.txt
	[ -f build/etc/curves.txt ] || wget -q https://testssl.sh/etc/curves.txt -O build/etc/curves.txt
	[ -f build/etc/tls_data.txt ] || wget -q https://testssl.sh/etc/tls_data.txt -O build/etc/tls_data.txt
	zip -9rq build/openssl.zip bin/openssl
	zip -9jrq build/testssl.zip build/etc
	zip -uj9q build/testssl.zip build/testssl
	rm -f bin/openssl*

package-upload: prep package ## uploads distribution to s3
	$(CMD_AWS) s3 cp build/$(APP_NAME).zip s3://trivialsec-assets/deploy-packages/$(COMMON_VERSION)/$(APP_NAME).zip
	$(CMD_AWS) s3 cp build/openssl.zip s3://trivialsec-assets/deploy-packages/$(COMMON_VERSION)/openssl.zip
	$(CMD_AWS) s3 cp build/testssl.zip s3://trivialsec-assets/deploy-packages/$(COMMON_VERSION)/testssl.zip
	$(CMD_AWS) s3 cp build/amass_linux_amd64.zip s3://trivialsec-assets/deploy-packages/$(COMMON_VERSION)/amass_linux_amd64.zip

package-dev-deps: package ## uploads distribution deps to s3
	$(CMD_AWS) s3 cp build/$(APP_NAME).zip s3://trivialsec-assets/dev/$(COMMON_VERSION)/$(APP_NAME).zip
	$(CMD_AWS) s3 cp build/openssl.zip s3://trivialsec-assets/dev/$(COMMON_VERSION)/openssl.zip
	$(CMD_AWS) s3 cp build/testssl.zip s3://trivialsec-assets/dev/$(COMMON_VERSION)/testssl.zip
	$(CMD_AWS) s3 cp build/amass_linux_amd64.zip s3://trivialsec-assets/dev/$(COMMON_VERSION)/amass_linux_amd64.zip

package-dev: common-dev package
	$(CMD_AWS) s3 cp --only-show-errors build/$(APP_NAME).zip s3://trivialsec-assets/dev/$(COMMON_VERSION)/$(APP_NAME).zip
