1. ���빫Կ˽Կ���ߣ�
Դ������lora_sign_src�£�����openssl�⣬�����������ϱ���openssl��Ȼ�����lora_signģ�顣

2. lora_sginʹ�ã�
����key:
./lora_sign -g ./
�ڵ�ǰĿ¼������һ�Թ�Կ��˽Կ
����ǩ����
./lora_sign -r ./needSignFile -s ./filesign -k ./PrivateKey.pem
��֤ǩ����
./lora_sign -r ./needVerifyFile -v ./filesign -k ./PublicKey.pem

3. �޸�ota�ļ�����
�޸�packages��ota�ļ�����ϸ˵���ο�SDK�û��ֲ᣺4.2.7 OTA ��ǿ���ܽ��ܺ�ע�����

4. ����ota����
./gen_ota.sh

�ű��������£��Ƚ�packages���ļ����Ϊlora_ota.tar.gz��Ȼ��ʹ��lora_sign����ǩ�������lora_ota.tar.gz��signһ����Ϊ���յ�ota�ļ�ota.tar.gz.

5. ע�⣬ota��������µĹ�Կ˽Կ����������ϵĹ�Կһ�¡�
