#!/bin/bash
HEAD_LEN=17
PACKAGE_NAME=pmd
INSTALL_ROOT_DIR=/tmp/ikpkg
export INSTALL_DIR=${INSTALL_ROOT_DIR}/${PACKAGE_NAME}

[ ! -f ${INSTALL_DIR}/uninstall.sh ] && HAS_OLD_UNINSTALL=no
[ -f ${INSTALL_DIR}/uninstall.sh ] && bash ${INSTALL_DIR}/uninstall.sh
rm -rf ${INSTALL_DIR}
if [ "$1" = "install" ] ; then
    mkdir -p ${INSTALL_DIR}
    tail -n +$HEAD_LEN $0 | tar zx -C ${INSTALL_DIR}/
    [ "x${HAS_OLD_UNINSTALL}" == "xno" -a -f ${INSTALL_DIR}/uninstall.sh ] && bash ${INSTALL_DIR}/uninstall.sh "$@"
    [ -f ${INSTALL_DIR}/install.sh ] &&  bash ${INSTALL_DIR}/install.sh "$@"
fi
exit $?