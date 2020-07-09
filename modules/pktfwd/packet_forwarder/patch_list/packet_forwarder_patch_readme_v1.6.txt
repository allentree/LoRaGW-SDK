1. pktfwd/packet_forwarder/patch_list
是基于Semtech网关packet_forwarder官方代码（对应版本v4.0.1），对相应修改所制作的所有patch，
打patch时，请下载如下Semtech代码，根据patch编号依次打上每个patch；
Semtech packet_forwarder v4.0.1 github下载地址:
https://github.com/Lora-net/packet_forwarder.git

2. Change List:
v1.0 2018-01-24
1. 修改Packet_forwarder与IoT套件通过UDP方式通讯，对应patch:
0001-modify-for-adapt-iot-lora-sdk.patch

2. 修改Packet_forwarder支持CN470 ClassB Beacon，对应patch:
0002-add-for-ClassB-Beacon-CN470.patch

3. 增加网关系统CPU/内存使用率上报，对应patch: 此patch只作为参考实现，厂商可以根据不同硬件平台作适配修改；
0003-add-report-cpu-and-memory-used-ratio-in-stat-packet.patch

v1.1 2018-04-17
4. 增加当网关发送的状态包在指定时间内（默认值为1小时）一直没有接收到ACK响应时，网关自动进行复位操作，对应patch:
0004-add-for-reset-when-stat-packet-no-ack-in-specify-tim.patch
如果需要修改状态包没有ACK响应计数超时时间，可在global_conf.json文件增加stat_no_ack_timeout_cnt字段配置，如下：
"stat_no_ack_timeout_cnt": 120
如果此字段没有配置，此默认值为60，表示状态包没有ACK响应计数超时时间为1小时；

v1.2 2018-05-10
修改了ClassB Beacon默认频点及CPU使用率计算方法，重新更新了以下2个patch文件：
0002-add-for-ClassB-Beacon-CN470.patch
0003-add-report-cpu-and-memory-used-ratio-in-stat-packet.patch

v1.3 2018-06-13
5. 增加了网关侧对节点join包/业务包黑白名单过滤功能：
0005-add-the-packet-filtering-feature.patch

6. 根据网关接入规范，修改网关默认配置参数：
0006-add-for-modify-gateway-default-conf-for-accord-with-.patch

修改网关系统内存使用率统计方法，将cached memory 和 buffers memory从使用内存中扣除，减少网关内存过高的告警现象，重新更新了以下这个patch文件
0003-add-report-cpu-and-memory-used-ratio-in-stat-packet.patch

v1.4 2018-07-31
7. 增加了网关之间时间同步功能，用于支持室内网关ClassB业务，对应patch:
0007-add-the-gateway-timesync-for-support-indoor-gateway-.patch
时间同步自测验证，请参考文档《室内Class B时间同步流程说明.txt》

v1.5 2018-11-29
8. 增加了watchdog喂狗、dbus-ipc通讯接口、monitor监控1301状态等相关代码，对应patch:
0008-add-for-watchdog-and-dbus-ipc-and-monitor-feature.patch

v1.6 2019-03-27
8. a)增加支持对非LoRaWAN协议包的过滤，即如果所接收到的包不符合LoRaWAN协议规范，网关不作转发，直接丢弃，
   b)增加对txpk power值检查，如果power值网关不支持，则使用power默认值17，对应patch:
0009-add-for-support-filter-the-no-LoRaWAN-rxpk-and-use-d.patch
   c)修复了SX1301 内部counter 翻转后的时间戳问题
   d)修复了pktfwd thread_down喂狗时机错误问题
0010-add-for-fixing-1301-counter-wrap-up-and-thread_down-feeddogs.patch
