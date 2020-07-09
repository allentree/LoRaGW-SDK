#!/bin/bash

source ./make.settings

MAKEJOB=-j4

SCRIPT_NAME=$(basename $0)

mkdir -p ${BUILDROOT}/${BUILDTMP}

mkdir -p ${BUILDROOT}/${BUILDOUTPUT}
mkdir -p ${BUILDROOT}/${BUILDOUTPUT}/include/
mkdir -p ${BUILDROOT}/${BUILDOUTPUT}/lib/
mkdir -p ${BUILDROOT}/${BUILDOUTPUT}/bin/

mkdir -p ${BUILDROOT}/${BUILDOUT}
mkdir -p ${BUILDROOT}/${BUILDOUT}/bin/
mkdir -p ${BUILDROOT}/${BUILDOUT}/lib/
mkdir -p ${BUILDROOT}/${BUILDOUT}/etc/

FP_TYPE=softfp

function get_toolchain_property()
{
    ${BUILDHOST}-gcc -v 2> ./gcc.info
    if [ `grep -c "with-float=hard" ./gcc.info` != '0' ]; then
        FP_TYPE=hardfp
    elif [ `grep -c "with-float=soft" ./gcc.info` !=  '0' ]; then
        FP_TYPE=softfp
    else
        FP_TYPE=softfp
    fi
    rm -f ./gcc.info
    echo $FP_TYPE
}

function build_libexpact()
{
    cd ${BUILDROOT}/external
    #start build libexpact
    if [ ! -d "./expat-2.2.3" ]; then
        tar -jxvf libexpat-*
    fi
    cd ./expat-2.2.3/
    #./buildconf.sh
    ./configure --host=${BUILDHOST} --prefix=${BUILDROOT}/${BUILDTMP}
    make clean
    make ${MAKEJOB}
    make install
    if [ ! -f ${BUILDROOT}/${BUILDTMP}/lib/libexpat.a ]; then
        echo
        echo "compile libexpat failed, exit" >&2
        echo
        exit 1
    fi
    cp ${BUILDROOT}/${BUILDTMP}/include/expat* ${BUILDROOT}/${BUILDOUTPUT}/include/
    cp ${BUILDROOT}/${BUILDTMP}/lib/libexpat.* ${BUILDROOT}/${BUILDOUTPUT}/lib/

    cp ${BUILDROOT}/${BUILDOUTPUT}/lib/libexpat.so* ${BUILDROOT}/${BUILDOUT}/lib/
}

function build_dbus()
{
    #start build dbus
    cd ${BUILDROOT}/external
    if [ ! -d "./dbus-1.10.18" ]; then
        tar -zxf dbus-1*
    fi
    cd dbus-1.10.18/
    ./configure --host=${BUILDHOST} CPPFLAGS=-I${BUILDROOT}/${BUILDTMP}/include LDFLAGS=-L${BUILDROOT}/${BUILDTMP}/lib --prefix=${BUILDROOT}/${BUILDTMP} --enable-verbose-mode --disable-modular-tests --disable-systemd --disable-inotify --disable-doxygen-docs
    make clean
    make ${MAKEJOB}
    make install
    if [ ! -f ${BUILDROOT}/${BUILDTMP}/lib/libdbus-1.a ]; then
        echo
        echo "compile dbus-1 failed, exit" >&2
        echo
        exit 1
    fi
    mkdir -p ${BUILDROOT}/${BUILDOUTPUT}/include/dbus
    cp ${BUILDROOT}/${BUILDTMP}/include/dbus-1.0/dbus/dbus* ${BUILDROOT}/${BUILDOUTPUT}/include/dbus
    cp ${BUILDROOT}/${BUILDTMP}/lib/dbus-1.0/include/dbus/* ${BUILDROOT}/${BUILDOUTPUT}/include/dbus/
    cp ${BUILDROOT}/${BUILDTMP}/lib/libdbus-* ${BUILDROOT}/${BUILDOUTPUT}/lib/
    cp ${BUILDROOT}/${BUILDTMP}/bin/dbus-* ${BUILDROOT}/${BUILDOUTPUT}/bin/

    cp ${BUILDROOT}/${BUILDOUTPUT}/bin/dbus-daemon ${BUILDROOT}/${BUILDOUT}/bin/
    cp ${BUILDROOT}/${BUILDOUTPUT}/lib/libdbus-1.so* ${BUILDROOT}/${BUILDOUT}/lib/
}

function build_libopenssl()
{
    cd ${BUILDROOT}/external
    if [ ! -d "./openssl-1.0.2" ]; then
        tar -zxvf openssl-*
    fi
    cd ./openssl-1.0.2/
    unset CROSS_COMPILE
    if [ -z ${TOOLCHAIN_SYSROOT} ]; then
        export CC="${BUILDHOST}-gcc -fPIC"
    else
        export CC="${BUILDHOST}-gcc --sysroot=${TOOLCHAIN_SYSROOT} -fPIC"
    fi
    #todo : configure other arch while building openssl
    ./Configure linux-generic32 --prefix=${BUILDROOT}/${BUILDTMP}
    make clean
    make
    make install
    
    if [ ! -f ${BUILDROOT}/${BUILDTMP}/lib/libssl.a ]; then
        echo
        echo "compile openssl failed, exit" >&2
        echo
        exit 1
    fi

    cp -rf ${BUILDROOT}/${BUILDTMP}/include/openssl/ ${BUILDROOT}/${BUILDOUTPUT}/include/
    cp ${BUILDROOT}/${BUILDTMP}/lib/libssl.a ${BUILDROOT}/${BUILDOUTPUT}/lib/
    cp ${BUILDROOT}/${BUILDTMP}/lib/libcrypto.a ${BUILDROOT}/${BUILDOUTPUT}/lib/
}

function build_libnopoll()
{
    cd ${BUILDROOT}/external
    if [ ! -d "./nopoll-0.4.4" ]; then
        tar -zxvf nopoll-*
    fi
    cd ./nopoll-0.4.4/
    ./autogen.sh
    ./configure CFLAGS="-DNOPOLL_HAVE_TLSv11_ENABLED -DNOPOLL_HAVE_TLSv12_ENABLED -DNOPOLL_HAVE_TLSv10_ENABLED" --host=${BUILDHOST} --prefix=${BUILDROOT}/${BUILDTMP} LDFLAGS=-L${BUILDROOT}/${BUILDOUTPUT}/lib CPPFLAGS=-I${BUILDROOT}/${BUILDOUTPUT}/include LIBS="-ldl -lrt"
    make clean
    make ${MAKEJOB}
    make install
    if [ ! -f ${BUILDROOT}/${BUILDTMP}/lib/libnopoll.a ]; then 
        echo
        echo "compile libnopoll failed, exit" >&2
        echo
        exit 1
    fi
    cp -rf ${BUILDROOT}/${BUILDTMP}/include/nopoll/ ${BUILDROOT}/${BUILDOUTPUT}/include/
    cp ${BUILDROOT}/${BUILDTMP}/lib/libnopoll.* ${BUILDROOT}/${BUILDOUTPUT}/lib/
}

function build_libhiredis()
{
    cd ${BUILDROOT}/external
    if [ ! -d "./hiredis-0.13.3" ]; then
        tar -zxf hiredis-*
    fi
    cd ./hiredis-0.13.3/
    export PREFIX=${BUILDROOT}/${BUILDTMP}
    make clean
    if [ -z ${TOOLCHAIN_SYSROOT} ]; then
        export CC="${BUILDHOST}-gcc"
    else
        export CC="${BUILDHOST}-gcc --sysroot=${TOOLCHAIN_SYSROOT}"
    fi
    make ${MAKEJOB}
    make install
    unset PREFIX
    if [ ! -f ${BUILDROOT}/${BUILDTMP}/lib/libhiredis.a ]; then
        echo
        echo "compile libhiredis failed, exit" >&2
        echo
        exit 1
    fi
    cp -rf ${BUILDROOT}/${BUILDTMP}/include/hiredis ${BUILDROOT}/${BUILDOUTPUT}/include/
    cp ${BUILDROOT}/${BUILDTMP}/lib/libhiredis.a ${BUILDROOT}/${BUILDOUTPUT}/lib/
}

function build_cjson()
{
    cd ${BUILDROOT}/external
    if [ ! -d "./cJSON-1.5.5" ]; then
        tar -zxf cJSON-*
    fi
    cd ./cJSON-1.5.5/
    if [ -z "${TOOLCHAIN_SYSROOT}" ]; then
        export CC="${BUILDHOST}-gcc"
    else
        export CC="${BUILDHOST}-gcc --sysroot=${TOOLCHAIN_SYSROOT}"
    fi
    export PREFIX=${BUILDROOT}/${BUILDTMP}
    make clean
    make ${MAKEJOB}
    make install
    unset PREFIX
    if [ ! -f ${BUILDROOT}/${BUILDTMP}/lib/libcjson.so ]; then
        echo
        echo "compile cJSON failed, exit" >&2
        echo
        exit 1
    fi
    cp ${BUILDROOT}/${BUILDTMP}/include/cjson/cJSON* ${BUILDROOT}/${BUILDOUTPUT}/include/
    cp ${BUILDROOT}/${BUILDTMP}/lib/libcjson* ${BUILDROOT}/${BUILDOUTPUT}/lib/

    cp ${BUILDROOT}/${BUILDOUTPUT}/lib/libcjson.so* ${BUILDROOT}/${BUILDOUT}/lib/
}

function build_ipcbus()
{
    cd ${BUILDROOT}/libraries/
    cd ./ipc-bus/

    sed -i 's/ENABLE_ALILOG_SUPPORT=.*/ENABLE_ALILOG_SUPPORT='${ENABLE_ALILOG}'/' Makefile

    make clean
    make ${MAKEJOB}
    if [ ! -f ./libipcbus.a ]; then
        echo
        echo "compile libipcbus failed, exit" >&2
        echo
        exit 1
    fi
    cp ./libipcbus.a ${BUILDROOT}/${BUILDOUTPUT}/lib
    cp ./include/*.h ${BUILDROOT}/${BUILDOUTPUT}/include/
    cp ${BUILDROOT}/modules/update-deamon/include/update_interface_export.h ${BUILDROOT}/${BUILDOUTPUT}/include/
    cp ${BUILDROOT}/modules/pktfwd/packet_forwarder/lora_pkt_fwd/inc/pktfwd_interface_export.h ${BUILDROOT}/${BUILDOUTPUT}/include/
}

function build_libalilog()
{
    cd ${BUILDROOT}/libraries/
    cd libalilog/
    export ALILOG_LIB_PATH=${BUILDROOT}/${BUILDOUTPUT}/lib
    export ALILOG_CFLAGS="-I${BUILDROOT}/${BUILDOUTPUT}/include"
    #export PREFIX=${BUILDROOT}/${BUILDTMP}
    make clean
    make ${MAKEJOB}
    #make install
    unset ALILOG_CFLAGS
    unset ALILOG_LIB_PATH
    if [ ! -f ./libalilog.so ]; then
        echo
        echo "compile libalilog failed, exit" >&2
        echo
        exit 1
    fi
    cp ./libalilog.so ${BUILDROOT}/${BUILDOUTPUT}/lib
    cp ./md5.h ${BUILDROOT}/${BUILDOUTPUT}/include/
    cp ./log.h ${BUILDROOT}/${BUILDOUTPUT}/include/

    cp ${BUILDROOT}/${BUILDOUTPUT}/lib/libalilog.so ${BUILDROOT}/${BUILDOUT}/lib/
}

function build_iotkit()
{
    cd ${BUILDROOT}/libraries/
    cd iotkit-embedded/
    #sed -i 's/PLATFORM_CC.*/PLATFORM_CC='${BUILDHOST}'-gcc/' make.settings
    #sed -i 's/PLATFORM_AR.*/PLATFORM_AR='${BUILDHOST}'-ar/' make.settings
    if [ ${ENABLE_ALILOG} = "true" ]; then 
        sed -i 's/FEATURE_REMOTE_LOG_ENABLED.*/FEATURE_REMOTE_LOG_ENABLED  = y/' make.settings
    else
        sed -i 's/FEATURE_REMOTE_LOG_ENABLED.*/FEATURE_REMOTE_LOG_ENABLED  = n/' make.settings
    fi
    make distclean
    make config
    make
    if [ ! -f ./output/release/lib/libiot_sdk.a ]; then
        echo
        echo "compile iotkit failed, exit" >&2
        echo
        exit 1
    fi
    cp ./output/release/lib/*.a ${BUILDROOT}/${BUILDOUTPUT}/lib
    mkdir -p ${BUILDROOT}/${BUILDOUTPUT}/include/iotkit/
    cp -rf ./output/release/include/* ${BUILDROOT}/${BUILDOUTPUT}/include/iotkit/
}

function build_watchdog()
{
    cd ${BUILDROOT}/modules/watchdog/ 
    make clean
    
    sed -i 's/ENABLE_ALILOG_SUPPORT=.*/ENABLE_ALILOG_SUPPORT='${ENABLE_ALILOG}'/' Makefile
    
    #make clean
    make ${MAKEJOB}
    if [ ! -f ./watchdog ]; then
        echo
        echo "compile watchdog failed, exit" >&2
        echo
        exit 1
    fi
    cp -rf ./watchdog ${BUILDROOT}/${BUILDOUTPUT}/bin/watch_dog
    cp ./lora_watchdog ${BUILDROOT}/${BUILDOUTPUT}/bin/
    cp ./libwatchdog.so ${BUILDROOT}/${BUILDOUTPUT}/lib/
    #cp ./src/api/libwatchdog.a ${BUILDROOT}/${BUILDOUTPUT}/lib/
    cp ./src/api/watch_dog_simple_export.h ${BUILDROOT}/${BUILDOUTPUT}/include/watch_dog_export.h
    install -m 755 ./src/cron_watchdog.sh ${BUILDROOT}/${BUILDOUTPUT}/bin/

    cd ${BUILDROOT}/scripts/dbus-setup/
    ./install-dbus.sh

    cp ${BUILDROOT}/${BUILDOUTPUT}/bin/mbus* ${BUILDROOT}/${BUILDOUT}/bin/
    cp ${BUILDROOT}/${BUILDOUTPUT}/bin/watch_dog ${BUILDROOT}/${BUILDOUT}/bin/
    cp ${BUILDROOT}/${BUILDOUTPUT}/bin/cron_watchdog.sh ${BUILDROOT}/${BUILDOUT}/bin/
    cp ${BUILDROOT}/${BUILDOUTPUT}/lib/libwatchdog.so ${BUILDROOT}/${BUILDOUT}/lib/
}

function build_gwiotapi()
{
    cd ${BUILDROOT}/modules/mqtt/sample_libgwiotapi/
    make clean
    make
    if [ ! -f ./libgwiotapi.so ]; then
        echo
        echo "compile libgwiotapi failed, exit" >&2
        echo
        exit 1
    fi
    cp ./libgwiotapi.* ${BUILDROOT}/${BUILDOUTPUT}/lib/
    cp ../include/gwiotapi.h ${BUILDROOT}/${BUILDOUTPUT}/include/
    cp ./auth_key.json ${BUILDROOT}/${BUILDOUTPUT}/bin/
    cp ./dev_info.json ${BUILDROOT}/${BUILDOUTPUT}/bin/

    cp ${BUILDROOT}/${BUILDOUTPUT}/lib/libgwiotapi.so ${BUILDROOT}/${BUILDOUT}/lib/
    cp ${BUILDROOT}/${BUILDOUTPUT}/bin/auth_key.json ${BUILDROOT}/${BUILDOUT}/bin/
    cp ${BUILDROOT}/${BUILDOUTPUT}/bin/dev_info.json ${BUILDROOT}/${BUILDOUT}/bin/
}

function build_mqtt()
{
    build_gwiotapi

    if [ ! -f ${BUILDROOT}/${BUILDOUTPUT}/lib/libiot_sdk.a ]; then
        build_iotkit
    fi

    cd ${BUILDROOT}/modules/mqtt/
    sed -i 's/ENABLE_WATCHDOG_SUPPORT=.*/ENABLE_WATCHDOG_SUPPORT='${ENABLE_WATCHDOG}'/' makefile
    sed -i 's/ENABLE_ALILOG_SUPPORT=.*/ENABLE_ALILOG_SUPPORT='${ENABLE_ALILOG}'/' makefile
    sed -i 's/ENABLE_MONITOR_SUPPORT=.*/ENABLE_MONITOR_SUPPORT='${ENABLE_MONITOR}'/' makefile
    sed -i 's/ENABLE_ADVANCED_OTA_SUPPORT=.*/ENABLE_ADVANCED_OTA_SUPPORT='${ENABLE_ADVANCED_OTA}'/' makefile
    sed -i 's/ENABLE_ADVANCED_SECURITY_SUPPORT=.*/ENABLE_ADVANCED_SECURITY_SUPPORT='${ENABLE_ADVANCED_SECURITY}'/' makefile

    make clean
    make ${MAKEJOB}
    if [ ! -f ./mqtt ]; then
        echo
        echo "compile mqtt failed, exit" >&2
        echo
        exit 1
    fi
    cp ./mqtt ${BUILDROOT}/${BUILDOUTPUT}/bin/
    cp ./include/mqtt_interface_export.h ${BUILDROOT}/${BUILDOUTPUT}/include/

    cp ${BUILDROOT}/${BUILDOUTPUT}/bin/mqtt ${BUILDROOT}/${BUILDOUT}/bin/
}

function build_security()
{
    get_toolchain_property

    cd ${BUILDROOT}/modules/security/
    cp ./lib/${board_arch}/libalicrypto_${FP_TYPE}.a ./lib/${board_arch}/libalicrypto.a
    cp ./lib/${board_arch}/libkm_${FP_TYPE}.a ./lib/${board_arch}/libkm.a
    cp ./lib/${board_arch}/libmbedcrypto_${FP_TYPE}.a ./lib/${board_arch}/libmbedcrypto.a
    cp ./lib/${board_arch}/libplat_gen_${FP_TYPE}.a ./lib/${board_arch}/libplat_gen.a

    cd ./irot/src
    make clean
    if [ -z "${TOOLCHAIN_SYSROOT}" ]; then
        make CC="${BUILDHOST}-gcc"
    else
        make CC="${BUILDHOST}-gcc --sysroot=${TOOLCHAIN_SYSROOT}"
    fi
    if [ ! -f ./irot_service ]; then
        echo
        echo "compile irot failed, exit" >&2
        echo
        exit 1
    fi
    make install
        
    cp ${BUILDROOT}/${BUILDOUTPUT}/bin/irot_service ${BUILDROOT}/${BUILDOUT}/bin/
    
    cd ${BUILDROOT}/modules/security/irot/test/
    make clean
    if [ -z "${TOOLCHAIN_SYSROOT}" ]; then
        make CC="${BUILDHOST}-gcc"
    else
        make CC="${BUILDHOST}-gcc --sysroot=${TOOLCHAIN_SYSROOT}"
    fi
    
    if [ ! -f ./km_test ]; then
        echo
        echo "compile km_test failed, exit" >&2
        echo
        exit 1
    fi
    make install
    
    cd ${BUILDROOT}/modules/security/keychain/sst/src/
    make clean 
    if [ -z "${TOOLCHAIN_SYSROOT}" ]; then
        make CC="${BUILDHOST}-gcc"
    else
        make CC="${BUILDHOST}-gcc --sysroot=${TOOLCHAIN_SYSROOT}"
    fi
    if [ ! -f ./libsst.a ]; then
        echo
        echo "compile sst failed, exit" >&2
        echo
        exit 1
    fi
    make install
    cp ${BUILDROOT}/${BUILDOUTPUT}/lib/libsst.a ${BUILDROOT}/${BUILDOUT}/lib/
    
    cd ${BUILDROOT}/modules/security/keychain/sst/test/
    make clean
    if [ -z "${TOOLCHAIN_SYSROOT}" ]; then
        make CC="${BUILDHOST}-gcc"
    else
        make CC="${BUILDHOST}-gcc --sysroot=${TOOLCHAIN_SYSROOT}"
    fi
    if [ ! -f ./sst_test ]; then
        echo
        echo "compile sst_test failed, exit" >&2
        echo
        exit 1
    fi
    make install

    cd ${BUILDROOT}/modules/security/keychain/deploy/
    make clean
    if [ -z "${TOOLCHAIN_SYSROOT}" ]; then
        make CC="${BUILDHOST}-gcc"
    else
        make CC="${BUILDHOST}-gcc --sysroot=${TOOLCHAIN_SYSROOT}"
    fi
    if [ ! -f ./deploy_sst ]; then
        echo
        echo "compile deploy_sst failed, exit" >&2
        echo
        exit 1
    fi
    make install
    cp ${BUILDROOT}/${BUILDOUTPUT}/bin/deploy_sst ${BUILDROOT}/${BUILDOUT}/bin/
    
    cd ${BUILDROOT}/modules/security/keychain/src/
    make clean 
    if [ -z "${TOOLCHAIN_SYSROOT}" ]; then
        make CC="${BUILDHOST}-gcc"
    else
        make CC="${BUILDHOST}-gcc --sysroot=${TOOLCHAIN_SYSROOT}"
    fi
    if [ ! -f ./keychain_service ]; then
        echo
        echo "compile keychain failed, exit" >&2
        echo
        exit 1
    fi
    make install
    cp ${BUILDROOT}/${BUILDOUTPUT}/bin/keychain_service ${BUILDROOT}/${BUILDOUT}/bin/
    cp ${BUILDROOT}/${BUILDOUTPUT}/lib/libkeychain.a ${BUILDROOT}/${BUILDOUT}/lib/

    cd ${BUILDROOT}/modules/security/keychain/test/
    make clean
    if [ -z "${TOOLCHAIN_SYSROOT}" ]; then
        make CC="${BUILDHOST}-gcc"
    else
        make CC="${BUILDHOST}-gcc --sysroot=${TOOLCHAIN_SYSROOT}"
    fi
    if [ ! -f ./sec_sst_test_basic ]; then
        echo
        echo "compile keychain test failed, exit" >&2
        echo
        exit 1
    fi    
    make install
    cp ${BUILDROOT}/modules/security/include/* ${BUILDROOT}/${BUILDOUTPUT}/include/
}

function build_monitor()
{
    cd ${BUILDROOT}/modules/monitor
    sed -i 's/ENABLE_WATCHDOG_SUPPORT.*/ENABLE_WATCHDOG_SUPPORT='${ENABLE_WATCHDOG}'/' make.settings
    sed -i 's/ENABLE_ALILOG_SUPPORT.*/ENABLE_ALILOG_SUPPORT='${ENABLE_ALILOG}'/' make.settings
    sed -i 's/ENABLE_ADVANCED_OTA_SUPPORT=.*/ENABLE_ADVANCED_OTA_SUPPORT='${ENABLE_ADVANCED_OTA}'/' make.settings
    
    make clean
    make ${MAKEJOB}
    if [ ! -f ./monitor ]; then
        echo
        echo "compile monitor failed, exit" >&2
        echo
        exit 1
    fi

    cp ./monitor ${BUILDROOT}/${BUILDOUTPUT}/bin/
    cp ./include/monitor_interface_export.h ${BUILDROOT}/${BUILDOUTPUT}/include/

    cp ${BUILDROOT}/${BUILDOUTPUT}/bin/monitor ${BUILDROOT}/${BUILDOUT}/bin/
}

function build_update()
{
    if [ ! -f ${BUILDROOT}/${BUILDOUTPUT}/lib/libgwiotapi.so ]; then
        build_gwiotapi
    fi

    cd ${BUILDROOT}/modules/update-deamon/
    sed -i 's/ENABLE_WATCHDOG_SUPPORT=.*/ENABLE_WATCHDOG_SUPPORT='${ENABLE_WATCHDOG}'/' Makefile
    sed -i 's/ENABLE_ALILOG_SUPPORT=.*/ENABLE_ALILOG_SUPPORT='${ENABLE_ALILOG}'/' Makefile
    sed -i 's/ENABLE_MONITOR_SUPPORT=.*/ENABLE_MONITOR_SUPPORT='${ENABLE_MONITOR}'/' Makefile
    make clean
    make ${MAKEJOB}
    if [ ! -f ./update-deamon ]; then
        echo
        echo "compile update-deamon failed, exit" >&2
        echo
        exit 1
    fi
    cp ./update-deamon ${BUILDROOT}/${BUILDOUTPUT}/bin/

    cp ./lora_sign ${BUILDROOT}/${BUILDOUTPUT}/bin/
    cp ./include/update_interface_export.h ${BUILDROOT}/${BUILDOUTPUT}/include/
    
    cp ./*.pem ${BUILDROOT}/${BUILDOUTPUT}/bin/
 
    cp ./publicKey.pem ${BUILDROOT}/${BUILDOUT}/bin/

    cp ${BUILDROOT}/${BUILDOUTPUT}/bin/update-deamon ${BUILDROOT}/${BUILDOUT}/bin/
}

function build_pktfwd()
{
    if [ ${BUILD_PKTFWD_BIN} = "true" ]; then
        cd ${BUILDROOT}/modules/pktfwd/lora_gateway/
        unset CFLAGS
        unset LDFLAGS
        make clean
        sed -i 's/CROSS_COMPILE.*/CROSS_COMPILE='${BUILDHOST}'-/' Makefile
        make ${MAKEJOB}
        if [ ! -f ./libloragw/libloragw.a ]; then
            echo
            echo "compile libloragw failed, exit" >&2
            echo
            exit 1
        fi
        cp ./libloragw/libloragw.* ${BUILDROOT}/${BUILDOUTPUT}/lib/
        cp ./reset_lgw.sh ${BUILDROOT}/${BUILDOUTPUT}/bin/

        cp ${BUILDROOT}/${BUILDOUTPUT}/bin/reset_lgw.sh ${BUILDROOT}/${BUILDOUT}/bin/

        cd ${BUILDROOT}/modules/pktfwd/packet_forwarder/
        sed -i 's/CROSS_COMPILE.*/CROSS_COMPILE='${BUILDHOST}'-/' Makefile
        sed -i 's/ENABLE_WATCHDOG_SUPPORT=.*/ENABLE_WATCHDOG_SUPPORT='${ENABLE_WATCHDOG}'/' ./lora_pkt_fwd/Makefile
        sed -i 's/ENABLE_ALILOG_SUPPORT=.*/ENABLE_ALILOG_SUPPORT='${ENABLE_ALILOG}'/' ./lora_pkt_fwd/Makefile
        sed -i 's/ENABLE_MONITOR_SUPPORT=.*/ENABLE_MONITOR_SUPPORT='${ENABLE_MONITOR}'/' ./lora_pkt_fwd/Makefile
        sed -i 's/ENABLE_ADVANCED_OTA_SUPPORT=.*/ENABLE_ADVANCED_OTA_SUPPORT='${ENABLE_ADVANCED_OTA}'/' ./lora_pkt_fwd/Makefile

        make clean
        make ${MAKEJOB}
        if [ ! -f ./lora_pkt_fwd/lora_pkt_fwd ]; then
            echo
            echo "compile lora_pkt_fwd failed, exit" >&2
            echo
            exit 1
        fi
        install -m 0755 ./lora_pkt_fwd/lora_pkt_fwd ${BUILDROOT}/${BUILDOUTPUT}/bin/
        cp ./lora_pkt_fwd/global_conf.json ${BUILDROOT}/${BUILDOUTPUT}/bin/
        cp ./lora_pkt_fwd/local_conf.json ${BUILDROOT}/${BUILDOUTPUT}/bin/
        cp ./lora_pkt_fwd/filter_conf.json ${BUILDROOT}/${BUILDOUTPUT}/bin/
        cp ./lora_pkt_fwd/inc/pktfwd_interface_export.h ${BUILDROOT}/${BUILDOUTPUT}/include/

        cp ${BUILDROOT}/${BUILDOUTPUT}/bin/lora_pkt_fwd ${BUILDROOT}/${BUILDOUT}/bin/
        cp ${BUILDROOT}/${BUILDOUTPUT}/bin/global_conf.json ${BUILDROOT}/${BUILDOUT}/bin/
        cp ${BUILDROOT}/${BUILDOUTPUT}/bin/local_conf.json ${BUILDROOT}/${BUILDOUT}/bin/
        cp ${BUILDROOT}/${BUILDOUTPUT}/bin/filter_conf.json ${BUILDROOT}/${BUILDOUT}/bin/
    fi
}

function build_remote_debug()
{
    cd ${BUILDROOT}/modules/remote_debug/sshd_agent/
    sed -i 's/ENABLE_LOG_SUPPORT=.*/ENABLE_LOG_SUPPORT='${ENABLE_ALILOG}'/' ./Makefile
    make clean
    if [ -z ${TOOLCHAIN_SYSROOT} ]; then
        export CC="${BUILDHOST}-gcc"
    else
        export CC="${BUILDHOST}-gcc --sysroot=${TOOLCHAIN_SYSROOT}"
    fi
    make ${MAKEJOB}
    if [ ! -f ./sshd_agent ]; then
        echo
        echo "compile sshd_agent failed, exit" >&2
        echo
        exit 1
    fi
    install -m 0755 ./sshd_agent ${BUILDROOT}/${BUILDOUTPUT}/bin/
    cp ./remote_debug.ini ${BUILDROOT}/${BUILDOUTPUT}/bin/
    cp ./root.pem ${BUILDROOT}/${BUILDOUTPUT}/bin/

    cp ${BUILDROOT}/${BUILDOUTPUT}/bin/sshd_agent ${BUILDROOT}/${BUILDOUT}/bin/
    cp ${BUILDROOT}/${BUILDOUTPUT}/bin/remote_debug.ini ${BUILDROOT}/${BUILDOUT}/bin/
    cp ${BUILDROOT}/${BUILDOUTPUT}/bin/root.pem ${BUILDROOT}/${BUILDOUT}/bin/
}

function check_libs()
{
    build_trd_lib

    if [ ${ENABLE_ALILOG} = "true" ]; then
        if [ ! -f ${BUILDROOT}/${BUILDOUTPUT}/lib/libalilog.so ]; then
            build_libalilog
        fi
    fi

    if [ ! -f ${BUILDROOT}/${BUILDOUTPUT}/lib/libipcbus.a ]; then
        build_ipcbus
    fi

    return 1
}

function check_watchdog()
{
    if [ ! -f ${BUILDROOT}/${BUILDOUTPUT}/lib/libwatchdog.so  ]; then
        build_watchdog
    fi
}

function save_toolchain_info()
{
    cd ${BUILDROOT}
    rm -f .toolchain.info
    echo ${PATH}${BUILDHOST} > .toolchain.info
}

#start build external
function build_trd_lib()
{
    if [  -f ${BUILDROOT}/.thirdLib.tar.gz ]; then
        cd ${BUILDROOT}/
        var=$(cat .toolchain.info)
        if [ ${PATH}${BUILDHOST} = ${var} ]; then
            tar -zxvf .thirdLib.tar.gz
            return
        fi
    fi
    var=$(cat .toolchain.info)    
    if [ ${PATH}${BUILDHOST} != ${var} ]; then
        rm -rf ${BUILDROOT}/${BUILDOUTPUT}/lib/*
        rm -f ${BUILDROOT}/.thirdLib.tar.gz
    fi
    
    if [ ! -f ${BUILDROOT}/${BUILDOUTPUT}/lib/libexpat.a ]; then
        build_libexpact
    fi

    if [ ! -f ${BUILDROOT}/${BUILDOUTPUT}/lib/libdbus-1.so ]; then
        build_dbus
    fi

    if [ ! -f ${BUILDROOT}/${BUILDOUTPUT}/lib/libssl.a ]; then
        build_libopenssl
    fi

    if [ ! -f ${BUILDROOT}/${BUILDOUTPUT}/lib/libnopoll.a ]; then
        build_libnopoll
    fi

    if [ ! -f ${BUILDROOT}/${BUILDOUTPUT}/lib/libhiredis.a ]; then
        build_libhiredis
    fi
    
    if [ ! -f ${BUILDROOT}/${BUILDOUTPUT}/lib/libcjson.so ]; then
        build_cjson
    fi

    cd ${BUILDROOT}
    tar -zcf ./.thirdLib.tar.gz build/
    save_toolchain_info
}

function check_security()
{
    if [ ! -f ${BUILDROOT}/${BUILDOUTPUT}/lib/libkeychain.a  ]; then
        build_module "security"
    fi
}

function build_library()
{
    case "$1" in
        "third" )
            build_trd_lib
            ;;

        "libalilog" )
            build_libalilog
            ;;

        "iotkit" )
            if [ ${ENABLE_ALILOG} = "true" ]; then
                build_library "libalilog"
            fi
            build_iotkit
            ;;

        "ipc-bus" )
            if [ ! -f ${BUILDROOT}/${BUILDOUTPUT}/lib/libexpat.so  ]; then
                build_libexpact
            fi
            if [ ! -f ${BUILDROOT}/${BUILDOUTPUT}/lib/libdbus-1.so  ]; then
                build_dbus
            fi
            if [ ${ENABLE_ALILOG} = "true" ]; then
                build_library "libalilog"
            fi
            build_ipcbus
            ;;

        "all" )
            build_trd_lib
            if [ ${ENABLE_ALILOG} = "true" ]; then
                build_library "libalilog"
            fi
            build_iotkit
            build_ipcbus
            ;;

        * )
            echo "Invalid command: $1"
            printusage
            exit 1
            ;;
    esac
}

function build_module()
{
    case "$1" in
        "watchdog" )
            check_libs
            build_watchdog
            ;;
		
        "remote_debug" )
            check_libs
            if [ ! -f ${BUILDROOT}/${BUILDOUTPUT}/lib/libgwiotapi.so ]; then
                build_gwiotapi
            fi
            build_remote_debug
            ;;

        "mqtt" )
            check_libs
            if [ ${ENABLE_WATCHDOG} = "true" ]; then
                check_watchdog
            fi
            build_mqtt
            ;;

        "update" )
            check_libs
            if [ ${ENABLE_WATCHDOG} = "true" ]; then
                check_watchdog
            fi
            build_update
            ;;

        "pktfwd" )
            check_libs
            if [ ${ENABLE_WATCHDOG} = "true" ]; then     
                check_watchdog
            fi
            build_pktfwd
            ;;

        "monitor" )
            check_libs
            if [ ${ENABLE_WATCHDOG} = "true" ]; then    
                check_watchdog
            fi
            build_monitor
            ;;

        "security" )
            check_libs
            if [ ${ENALBE_WATCHDOG} = "true" ]; then
                check_watchdog
            fi
            build_security
            ;;

        "all" )
            check_libs
            if [ ${ENABLE_WATCHDOG} = "true" ]; then
                build_watchdog
            fi
            if [ ${ENABLE_MONITOR} = "true" ]; then
                build_monitor
            fi
            build_security
            build_mqtt
            build_update
            build_pktfwd
            build_remote_debug
            ;;

        * )
            echo "Invalid command: $1"
            printusage
            exit 1
            ;;

    esac
}

function clean_tmp()
{
    rm -rf ${BUILDROOT}/${BUILDTMP}
}

function clean_build()
{
    rm -rf ${BUILDROOT}/${BUILDOUTPUT}
    rm -rf ${BUILDROOT}/${BUILDOUT}
    rm -rf ${BUILDROOT}/${BUILDTMP}
    
    cd ${BUILDROOT}/libraries/iotkit-embedded/
    make distclean

    cd ${BUILDROOT}/libraries/ipc-bus/
    make clean

    cd ${BUILDROOT}/libraries/libalilog/
    make clean

    cd ${BUILDROOT}/modules/mqtt/sample_libgwiotapi/
    make clean
    cd ${BUILDROOT}/modules/mqtt/
    make clean

    cd ${BUILDROOT}/modules/pktfwd/lora_gateway/
    make clean
    cd ${BUILDROOT}/modules/pktfwd/packet_forwarder/
    make clean

    cd ${BUILDROOT}/modules/watchdog/
    make clean

    cd ${BUILDROOT}/modules/remote_debug/sshd_agent/
    make clean

    cd ${BUILDROOT}/modules/monitor/
    make clean

    cd ${BUILDROOT}/modules/update-deamon/
    make clean
   
    cd ${BUILDROOT}/modules/security/irot/src
    make clean
    
    cd ${BUILDROOT}/modules/security/irot/test/
    make clean
    
    cd ${BUILDROOT}/modules/security/keychain/sst/src/
    make clean

    cd ${BUILDROOT}/modules/security/keychain/sst/test/
    make clean

    cd ${BUILDROOT}/modules/security/keychain/deploy/
    make clean

    cd ${BUILDROOT}/modules/security/keychain/src/
    make clean

    cd ${BUILDROOT}/modules/security/keychain/test/
    make clean

}

function printusage() {
    echo "Usage:"
    echo "${SCRIPT_NAME} lib [third libalilog iotkit ipc-bus]"
    echo "${SCRIPT_NAME} libraries"
    echo "${SCRIPT_NAME} module [watchdog mqtt pktfwd monitor remote_debug update security]"
    echo "${SCRIPT_NAME} modules"
    echo "${SCRIPT_NAME} all"
    echo "${SCRIPT_NAME} clean"
}

case "$1" in
    "lib" )
        build_library "$2"
        ;;

    "libraries" )
        build_library "all"
        ;;

    "module" )
        build_module "$2"
        ;;

    "modules" )
        build_module "all"
        ;;

    "all" )
        build_module "all"
        ;;

    "clean" )
        clean_build
        ;;

    "help" )
        printusage
        ;;

    * )
        echo "Invalid command: $1"
        printusage
        exit 1
        ;;
esac
