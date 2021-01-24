#!/bin/bash -xe
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
export COMMON_VERSION=0.3.5

function proxy_on() {
    local proxyPrivateAddr=proxy.trivialsec.local
    export http_proxy=http://${proxyPrivateAddr}:3128/
    export https_proxy=http://${proxyPrivateAddr}:3128/
    export no_proxy=169.254.169.254,cloudformation-trivialsec.s3.amazonaws.com,s3.ap-southeast-2.amazonaws.com,ssm.ap-southeast-2.amazonaws.com,logs.ap-southeast-2.amazonaws.com,sts.amazonaws.com
}
function proxy_off() {
    unset http_proxy
    unset https_proxy
    unset no_proxy
}
function echo_proxy() {
    echo $http_proxy
    echo $https_proxy
    echo $no_proxy
}
function proxy_persist() {
    local proxyPrivateAddr=proxy.trivialsec.local
    proxy_on
    cat > /etc/profile.d/http_proxy.sh << EOF
export http_proxy=${http_proxy}
export https_proxy=${https_proxy}
export no_proxy=${no_proxy}

EOF
    cat >> /etc/environment << EOF
export http_proxy=${http_proxy}
export https_proxy=${https_proxy}
export no_proxy=${no_proxy}

EOF
}
function setup_centos() {
    sysctl -w net.core.somaxconn=1024
    echo 'net.core.somaxconn=1024' >> /etc/sysctl.conf
    mkdir -p /usr/share/man/man1mkdir /usr/share/man/man1
    proxy_on
    amazon-linux-extras enable epel
    yum update -q -y
    yum install -q -y deltarpm
    yum groupinstall -q -y "Development Tools"
    yum install -q -y pcre-devel ca-certificates curl epel-release
    update-ca-trust force-enable
    proxy_off
}
function setup_logging() {
    proxy_on
    yum install -q -y https://s3.us-east-1.amazonaws.com/amazoncloudwatch-agent-us-east-1/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm || true
    proxy_off
    /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c ssm:AmazonCloudWatch-trivialsec-prod
}
function install_python() {
    proxy_on
    amazon-linux-extras enable python3.8
    yum clean metadata
    yum install -q -y python38 python38-devel python38-pip
    proxy_off
}
function install_worker_deps() {
    proxy_on
    yum install -q -y jq PyYAML openjdk-11-jdk fakeroot wine-stable ldns
    rpm --quiet -U https://nmap.org/dist/nmap-7.91-1.x86_64.rpm
    proxy_off
}
function install_mysql_client() {
    proxy_on
    yum install -q -y https://repo.mysql.com/mysql80-community-release-el7-1.noarch.rpm || true
    wget -q http://repo.mysql.com/RPM-GPG-KEY-mysql -O /tmp/mysql.key
    rpm --import /tmp/mysql.key
    yum install -q -y mysql-connector-python
    proxy_off
}
function deploy_worker() {
    mkdir -p /srv/app/lib/bin
    aws s3 cp --only-show-errors s3://cloudformation-trivialsec/deploy-packages/worker-${COMMON_VERSION}.zip /tmp/trivialsec/worker.zip
    aws s3 cp --only-show-errors s3://cloudformation-trivialsec/deploy-packages/trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl \
        /srv/app/trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl
    aws s3 cp --only-show-errors s3://cloudformation-trivialsec/deploy-packages/build-${COMMON_VERSION}.zip /tmp/trivialsec/build.zip
    unzip -qo /tmp/trivialsec/worker.zip -d /tmp/trivialsec
    unzip -qo /tmp/trivialsec/build.zip -d /srv/app
    cp -nr /tmp/trivialsec/src/* /srv/app/
    cp -nr /tmp/trivialsec/bin/* /srv/app/lib/bin/
    cp -n /tmp/trivialsec/circus.ini /srv/app/circus.ini
    cp -n /tmp/trivialsec/circusd-logger.yaml /srv/app/circusd-logger.yaml
    cp -n /tmp/trivialsec/requirements.txt /srv/app/requirements.txt
}
function install_amass() {
    mkdir -p /amass
    aws s3 cp --only-show-errors s3://cloudformation-trivialsec/deploy-packages/amass_linux_amd64-${COMMON_VERSION}.zip /amass/amass_linux_amd64.zip
    unzip -qo /amass/amass_linux_amd64.zip -d /amass
    chmod a+x /amass/amass_linux_amd64/amass
    cp -nr /amass/amass_linux_amd64/amass /usr/local/bin/amass
    cp -nr /amass/amass_linux_amd64/examples/wordlists /srv/app/lib
    chown -R ec2-user: /amass
}
function install_testssl() {
    mkdir -p /testssl/etc
    aws s3 cp --only-show-errors s3://cloudformation-trivialsec/deploy-packages/openssl-${COMMON_VERSION}.zip /tmp/trivialsec/openssl.zip
    unzip -qo /tmp/trivialsec/openssl.zip -d /tmp/trivialsec/openssl
    mv -f /tmp/trivialsec/openssl/bin/openssl /usr/bin/openssl
    aws s3 cp --only-show-errors s3://cloudformation-trivialsec/deploy-packages/testssl-${COMMON_VERSION}.zip /tmp/trivialsec/testssl.zip
    unzip -qo /tmp/trivialsec/testssl.zip -d /tmp/trivialsec/testssl
    mv -nf /tmp/trivialsec/testssl/testssl /testssl/testssl
    mv -nf /tmp/trivialsec/testssl/* /testssl/etc/
    chown -R ec2-user: \
        /usr/bin/openssl \
        /testssl
    chmod a+x /testssl/testssl
}
function configure_worker() {
    touch /tmp/application.log
    cat > /srv/app/.env << EOF
CONFIG_FILE=config.yaml
AWS_ACCOUNT=$(TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" --stderr /dev/null) && curl -s -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/iam/info --stderr /dev/null | jq -r '.InstanceProfileArn' | cut -d ":" -f 5)
AWS_REGION=ap-southeast-2

EOF
    chown -R ec2-user: /srv/app
    proxy_persist
    runuser -l ec2-user -c 'python3.8 -m pip install -U --user pip setuptools wheel'
    runuser -l ec2-user -c "CFLAGS='-O0' STATICBUILD=true python3.8 -m pip install -q --user --no-cache-dir --find-links=/srv/app/build/wheel --no-index /srv/app/trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl"
    runuser -l ec2-user -c 'CFLAGS="-O0" STATICBUILD=true python3.8 -m pip install -q -U --user --no-cache-dir --isolated -r /srv/app/requirements.txt'
}
function cleanup() {
    chown -R ec2-user: /srv/app /tmp/application.log /var/log/user-data.log
    yum groupremove -q -y "Development Tools"
    yum -y clean all
    echo '' > /etc/environment
    rm -rf /var/cache/yum /amass /nmap /tmp/trivialsec /etc/profile.d/http_proxy.sh
}
function do_release() {
    setup_logging
    setup_centos
    install_python
    install_mysql_client
    install_testssl
    install_worker_deps
    deploy_worker
    install_amass
    configure_worker
    cleanup
}

time do_release
echo $(date +'%F') > /home/ec2-user/.deployed
