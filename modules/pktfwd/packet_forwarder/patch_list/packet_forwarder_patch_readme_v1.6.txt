1. pktfwd/packet_forwarder/patch_list
�ǻ���Semtech����packet_forwarder�ٷ����루��Ӧ�汾v4.0.1��������Ӧ�޸�������������patch��
��patchʱ������������Semtech���룬����patch������δ���ÿ��patch��
Semtech packet_forwarder v4.0.1 github���ص�ַ:
https://github.com/Lora-net/packet_forwarder.git

2. Change List:
v1.0 2018-01-24
1. �޸�Packet_forwarder��IoT�׼�ͨ��UDP��ʽͨѶ����Ӧpatch:
0001-modify-for-adapt-iot-lora-sdk.patch

2. �޸�Packet_forwarder֧��CN470 ClassB Beacon����Ӧpatch:
0002-add-for-ClassB-Beacon-CN470.patch

3. ��������ϵͳCPU/�ڴ�ʹ�����ϱ�����Ӧpatch: ��patchֻ��Ϊ�ο�ʵ�֣����̿��Ը��ݲ�ͬӲ��ƽ̨�������޸ģ�
0003-add-report-cpu-and-memory-used-ratio-in-stat-packet.patch

v1.1 2018-04-17
4. ���ӵ����ط��͵�״̬����ָ��ʱ���ڣ�Ĭ��ֵΪ1Сʱ��һֱû�н��յ�ACK��Ӧʱ�������Զ����и�λ��������Ӧpatch:
0004-add-for-reset-when-stat-packet-no-ack-in-specify-tim.patch
�����Ҫ�޸�״̬��û��ACK��Ӧ������ʱʱ�䣬����global_conf.json�ļ�����stat_no_ack_timeout_cnt�ֶ����ã����£�
"stat_no_ack_timeout_cnt": 120
������ֶ�û�����ã���Ĭ��ֵΪ60����ʾ״̬��û��ACK��Ӧ������ʱʱ��Ϊ1Сʱ��

v1.2 2018-05-10
�޸���ClassB BeaconĬ��Ƶ�㼰CPUʹ���ʼ��㷽�������¸���������2��patch�ļ���
0002-add-for-ClassB-Beacon-CN470.patch
0003-add-report-cpu-and-memory-used-ratio-in-stat-packet.patch

v1.3 2018-06-13
5. ���������ز�Խڵ�join��/ҵ����ڰ��������˹��ܣ�
0005-add-the-packet-filtering-feature.patch

6. �������ؽ���淶���޸�����Ĭ�����ò�����
0006-add-for-modify-gateway-default-conf-for-accord-with-.patch

�޸�����ϵͳ�ڴ�ʹ����ͳ�Ʒ�������cached memory �� buffers memory��ʹ���ڴ��п۳������������ڴ���ߵĸ澯�������¸������������patch�ļ�
0003-add-report-cpu-and-memory-used-ratio-in-stat-packet.patch

v1.4 2018-07-31
7. ����������֮��ʱ��ͬ�����ܣ�����֧����������ClassBҵ�񣬶�Ӧpatch:
0007-add-the-gateway-timesync-for-support-indoor-gateway-.patch
ʱ��ͬ���Բ���֤����ο��ĵ�������Class Bʱ��ͬ������˵��.txt��

v1.5 2018-11-29
8. ������watchdogι����dbus-ipcͨѶ�ӿڡ�monitor���1301״̬����ش��룬��Ӧpatch:
0008-add-for-watchdog-and-dbus-ipc-and-monitor-feature.patch

v1.6 2019-03-27
8. a)����֧�ֶԷ�LoRaWANЭ����Ĺ��ˣ�����������յ��İ�������LoRaWANЭ��淶�����ز���ת����ֱ�Ӷ�����
   b)���Ӷ�txpk powerֵ��飬���powerֵ���ز�֧�֣���ʹ��powerĬ��ֵ17����Ӧpatch:
0009-add-for-support-filter-the-no-LoRaWAN-rxpk-and-use-d.patch
   c)�޸���SX1301 �ڲ�counter ��ת���ʱ�������
   d)�޸���pktfwd thread_downι��ʱ����������
0010-add-for-fixing-1301-counter-wrap-up-and-thread_down-feeddogs.patch
