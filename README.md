Link WAN ����SDK����˵��

һ�� Ŀ¼�ṹ

build.sh      ������ű�

docs          : SDK�ĵ�

external      �����������ⲿ��������

libraries     ��������ʹ�õ�ģ��⣬����iotkit��

make.settings : SDK������ص�����

modules       : �����ϵĹ���ģ�����

README.md     ��ReadMe�ĵ�

scripts       : ����ģ����ؽű��ļ�

tools         : OTA��ȫ���������ǩ�����������


���� toolchain�����뻷������

����ǰ����������toolchain�ͱ��뻷������make.settings�ļ���


1) toolchain���ã�

�����Լ�ʵ�ʵ�toolchain·��������host�޸�����2������

setup vendor platform toolchain's path and host

export PATH=$(pwd)/toolchain/gcc-linaro-arm-linux-gnueabihf-4.9-2014.09_linux/bin:$PATH

export BUILDHOST=arm-linux-gnueabihf


2) ��������


�Ƿ�ʹ��libalilog���ܣ�����Ϊtrue��false

setup enable or disable use libalilog feature

export ENABLE_ALILOG=true


�Ƿ�ʹ��watchdog���ܣ�����Ϊtrue��false

setup enable or disable watchdog feature

export ENABLE_WATCHDOG=true


�Ƿ�ʹ��monitor���ܣ�����Ϊtrue��false

setup enable or disable monitor feature

export ENABLE_MONITOR=true


�Ƿ����OTA��ȫ��ǿģ��

setup enable or disable advanced ota module

export ENABLE_ADVANCED_OTA=false


�Ƿ���밲ȫ�洢ģ��

setup advanced security module

export ENABLE_ADVANCED_SECURITY=false


�Ƿ����pktfwdģ��

setup build pktfwd module

export BUILD_PKTFWD_BIN=true


3) ����Ŀ¼������ã�һ�㲻��Ҫ�޸�

setup build dir, general vendor no need modify

export BUILDROOT=$(pwd)

export BUILDTMP=tmp          //��������в�������ʱ�ļ�

export BUILDOUT=out          //������Ҫ�����豸������ʱ���ļ� 

export BUILDOUTPUT=build     //����ģ�����������ļ�������ͷ�ļ�����̬��


3. ����˵��


1) ��������

./build.sh all


2) ��ģ�����

build.sh lib [third libalilog iotkit ipc-bus]

build.sh libraries

build.sh module [watchdog mqtt pktfwd monitor remote_debug update security]

build.sh modules

build.sh all

build.sh clean

������ɺ�������Ҫ�����豸������ʱ���ļ�����${BUILDOUT}Ŀ¼�¡�


4. Changelog

v2.3.0 2018-11-30

�޸�˵����

1) ʹ���µ�SDKĿ¼�ṹ��

2) ����watchdog���ܣ�

3) ����monitor���ܣ�

4) ����dbus ipcͨ�Žӿڣ�

5����������ǿOTA���ܣ��ṩǩ�����쳣�ع�����

6�������������ݰ�ȫ�洢���ܣ�

7������gwiotapi�Ĳο�ʵ��


v2.4.0 2019-03-28

�޸�˵����

1) mqttģ�飬����ABP�ڵ����/����/ɾ�����ܣ�

2) monitorģ�飬���ӱ���NS����״̬�ϱ���

3) pktfwdģ�飬�Ƿ��ڵ���˹��ܵ�����֧�����ع��˵���LaRaWANЭ���׼�Ľڵ����а���

4) iotkitģ�飬����iotkit�׼��汾(v2.30); 

5) libalilog/watchdog/monitor/remote_debug/update-deamonģ�飬��ΪԴ�뿪�ţ�

6) SDK��������޸����Ż���

