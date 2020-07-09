Link WAN 网关SDK编译说明

一、 目录结构

build.sh      ：编译脚本

docs          : SDK文档

external      ：所依赖的外部第三方库

libraries     ：网关上使用的模块库，例如iotkit等

make.settings : SDK编译相关的设置

modules       : 网关上的功能模块代码

README.md     ：ReadMe文档

scripts       : 功能模块相关脚本文件

tools         : OTA安全升级所需的签名、打包工具


二、 toolchain及编译环境设置

编译前首先请设置toolchain和编译环境，见make.settings文件：


1) toolchain设置：

根据自己实际的toolchain路径、编译host修改以下2个变量

setup vendor platform toolchain's path and host

export PATH=$(pwd)/toolchain/gcc-linaro-arm-linux-gnueabihf-4.9-2014.09_linux/bin:$PATH

export BUILDHOST=arm-linux-gnueabihf


2) 编译配置


是否使能libalilog功能，参数为true或false

setup enable or disable use libalilog feature

export ENABLE_ALILOG=true


是否使能watchdog功能，参数为true或false

setup enable or disable watchdog feature

export ENABLE_WATCHDOG=true


是否使能monitor功能，参数为true或false

setup enable or disable monitor feature

export ENABLE_MONITOR=true


是否编译OTA安全增强模块

setup enable or disable advanced ota module

export ENABLE_ADVANCED_OTA=false


是否编译安全存储模块

setup advanced security module

export ENABLE_ADVANCED_SECURITY=false


是否编译pktfwd模块

setup build pktfwd module

export BUILD_PKTFWD_BIN=true


3) 编译目录相关设置，一般不需要修改

setup build dir, general vendor no need modify

export BUILDROOT=$(pwd)

export BUILDTMP=tmp          //编译过程中产生的临时文件

export BUILDOUT=out          //最终需要放在设备上运行时的文件 

export BUILDOUTPUT=build     //所有模块编译结果输出文件，包含头文件、静态库


3. 编译说明


1) 完整编译

./build.sh all


2) 单模块编译

build.sh lib [third libalilog iotkit ipc-bus]

build.sh libraries

build.sh module [watchdog mqtt pktfwd monitor remote_debug update security]

build.sh modules

build.sh all

build.sh clean

编译完成后，最终需要放在设备上运行时的文件，在${BUILDOUT}目录下。


4. Changelog

v2.3.0 2018-11-30

修改说明：

1) 使用新的SDK目录结构；

2) 增加watchdog功能；

3) 增加monitor功能；

4) 增加dbus ipc通信接口；

5）增加了增强OTA功能（提供签名和异常回滚）；

6）增加敏感数据安全存储功能；

7）更新gwiotapi的参考实现


v2.4.0 2019-03-28

修改说明：

1) mqtt模块，增加ABP节点添加/更新/删除功能；

2) monitor模块，增加本地NS服务状态上报；

3) pktfwd模块，非法节点过滤功能迭代，支持网关过滤掉非LaRaWAN协议标准的节点上行包；

4) iotkit模块，升级iotkit套件版本(v2.30); 

5) libalilog/watchdog/monitor/remote_debug/update-deamon模块，改为源码开放；

6) SDK相关问题修复及优化；

