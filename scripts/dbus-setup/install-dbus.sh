#!/bin/bash
source ./install-setting
cp ./mbusd.conf ${OUTPUT_DIR}${bindir}
install -m 0755 ./mbusd ${OUTPUT_DIR}${bindir}
#install -m 0755 ./mbusctl  ${OUTPUT_DIR}${bindir}

if [ ${DBUS_SERVICE_ENABLE} = "true" ]; then
    mkdir -p ${OUTPUT_DIR}/${service_dir}/
    cp ./*.service ${OUTPUT_DIR}/${service_dir}/
fi

sed -i 's:CONFIG_MBUS_UNIX_PATH:'${CONFIG_MBUS_UNIX_PATH}':1' ${OUTPUT_DIR}${bindir}/mbusd.conf
sed -i 's:CONFIG_MBUS_SERVICE_DIR:'${CONFIG_MBUS_SERVICE_DIR}':1' ${OUTPUT_DIR}${bindir}/mbusd.conf
sed -i 's:CONFIG_MBUS_PID_FILE:'${CONFIG_MBUS_PID_FILE}':g' ${OUTPUT_DIR}${bindir}/mbusd
sed -i 's:CONFIG_MBUS_TMP_PATH:'${CONFIG_MBUS_TMP_PATH}':g' ${OUTPUT_DIR}${bindir}/mbusd
sed -i 's:CONFIG_MBUS_PID_FILE:'${CONFIG_MBUS_PID_FILE}':g' ${OUTPUT_DIR}${bindir}/mbusd.conf 
sed -i 's:CONFIG_MBUS_SERVICE_DIR:'${CONFIG_MBUS_SERVICE_DIR}':g' ${OUTPUT_DIR}${bindir}/mbusd
#sed -i 's:CONFIG_MBUS_UNIX_PATH:'${CONFIG_MBUS_UNIX_PATH}':1' ${OUTPUT_DIR}${bindir}/mbusctl

if [ ${DBUS_SERVICE_ENABLE} = "true" ]; then
    find ${OUTPUT_DIR}/${service_dir} -name '*.service' -exec sed -i 's:CONFIG_MBUS_SERVICE_BIN_DIR:'${CONFIG_MBUS_SERVICE_BIN_DIR}':g' {} \;

    install -m 0755 ./dbus_start.sh ${OUTPUT_DIR}${bindir}
    sed -i 's:CONFIG_MBUS_UNIX_PATH:'${CONFIG_MBUS_UNIX_PATH}':1' ${OUTPUT_DIR}${bindir}/dbus_start.sh
    sed -i 's:CONFIG_MBUS_PID_FILE:'${CONFIG_MBUS_PID_FILE}':g' ${OUTPUT_DIR}${bindir}/dbus_start.sh

    sed -i 's:CONFIG_MBUS_SERVICE_DIR:'${CONFIG_MBUS_SERVICE_DIR}':g' ${OUTPUT_DIR}${bindir}/dbus_start.sh
    sed -i 's:service_dir:'${service_dir}':g' ${OUTPUT_DIR}${bindir}/dbus_start.sh
fi

source ./install-unsetting
