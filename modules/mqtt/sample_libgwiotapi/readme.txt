˵����
1. API�ӿ�������룬��ο�gwiotapi.c��
�����������ָ����Ĭ�ϼӽ���key���볧���Լ����������£�
/* ��ΪĬ�ϼӽ���key���볧���Լ���������������ʱkey��ʼ�����鲻Ҫֱ��ʹ��key�ַ��������壬����key���������ȡ�� */
char key[32] = "IWf8d2vXAfuyORMJ";

2. API�ӿڲ��Դ��룬��ο�gwiotapi_test.c��

3. ��Ԫ����ܹ���:
1������aes���ܹ���
����: ECB
���: zeropadding
���ݿ�: 128λ
�ӽ�����Կ: IWf8d2vXAfuyORMJ
���: hex
�ַ���: gb2312
��ַ: http://tool.chacuo.net/cryptaes

2��linux���ܹ��ߴ��룬��ο�key_en_tool.c; 
���룺gcc key_en_tool.c ../src/utils/aes.c -o key_en_tool -I../src/utils/
���У�
./key_en_tool �ӽ�����Կ ��Ҫ���ܵ��ַ��� �Ƿ�Ϊʮ�������ַ�������������Ԫ��˲���Ϊ0��
���磺
./key_en_tool IWf8d2vXAfuyORMJ d896e0fff0101122 0

4. �Ѽ���������Ԫ�������ļ���auth_key.json��

5. �����豸��Ϣ�����ļ����볧���Լ�������dev_info.json��

6. OTA������ʾ���ļ���lora_ota.tar.gz��
