#!/bin/sh
#mkdir -p CONFIG_MBUS_UNIX_PATH
#mkdir -p CONFIG_MBUS_PID_FILE
mkdir -p CONFIG_MBUS_SERVICE_DIR
cp service_dir/*.service CONFIG_MBUS_SERVICE_DIR
mbusd
