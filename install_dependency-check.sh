#!/usr/bin/env bash
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}x${NC} This script must be run as root" 
   exit 1
fi
if [[ ! -d scripts ]]; then
    echo -e "${RED}x${NC} Run this from the project root directory"
    exit 0
fi

OWNER=chris
TARGET=$(pwd)/src/lib
PIP_INSTALL_BIN=/home/${OWNER}/.local/bin/dependency-check
DEPENDENCY_CHECK_VERSION=0.2.0

mkdir -p ${TARGET}/bin && echo -e "${GREEN}✔${NC} Created directory ${TARGET}/bin"

chown -R ${OWNER}: /home/${OWNER}/.gnupg
find /home/${OWNER}/.gnupg -type f -exec chmod 600 {} \;
find /home/${OWNER}/.gnupg -type d -exec chmod 700 {} \;
echo -e "${GREEN}✔${NC} Prepared GPG"
runuser ${OWNER} -c 'gpg --keyserver hkp://keys.gnupg.net --recv-keys F9514E84AE3708288374BBBE097586CFEA37F9A6' && echo -e "${GREEN}✔${NC} Added keys"
echo -e "Installing dependency-check version ${DEPENDENCY_CHECK_VERSION}"
runuser ${OWNER} -c "python3 -m pip -q install --user -U dependency-check==${DEPENDENCY_CHECK_VERSION}" && echo -e "${GREEN}✔${NC} Installed dependency-check"

if [[ ! -f ${TARGET}/bin/dependency-check ]]; then
    runuser ${OWNER} -c "cp ${PIP_INSTALL_BIN} ${TARGET}/bin/dependency-check"
    echo -e "${GREEN}✔${NC} Vendored to ${TARGET}/bin/dependency-check"
fi

if [[ -d /etc/cron.hourly ]] && [[ ! -f /etc/cron.hourly/dependency-check-update.sh ]]; then
  cat << EOF > /etc/cron.hourly/dependency-check-update.sh
#!/usr/bin/env bash

dependency-check --updateonly
EOF
  echo -e "${GREEN}✔${NC} Added hourly database update cron job"
fi
rm -rf ${TARGET}/dependency_check* && echo -e "${GREEN}✔${NC} Cleaned up"

# dependency-check \
#   --enableExperimental \
#   -f CSV \
#   --noupdate \
#   --project $(basename -s .git `git config --get remote.origin.url` || basename $(pwd)) \
#   --scan .
