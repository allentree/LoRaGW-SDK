说明：
1. API接口适配代码，请参考gwiotapi.c；
在适配代码中指定了默认加解密key，请厂商自己更换，如下：
/* 此为默认加解密key，请厂商自己更换，厂商适配时key初始化建议不要直接使用key字符串来定义，避免key被反编译获取到 */
char key[32] = "IWf8d2vXAfuyORMJ";

2. API接口测试代码，请参考gwiotapi_test.c；

3. 三元组加密工具:
1）在线aes加密工具
加密: ECB
填充: zeropadding
数据块: 128位
加解密密钥: IWf8d2vXAfuyORMJ
输出: hex
字符集: gb2312
网址: http://tool.chacuo.net/cryptaes

2）linux加密工具代码，请参考key_en_tool.c; 
编译：gcc key_en_tool.c ../src/utils/aes.c -o key_en_tool -I../src/utils/
运行：
./key_en_tool 加解密密钥 需要加密的字符串 是否为十六进制字符（加密网关三元组此参数为0）
例如：
./key_en_tool IWf8d2vXAfuyORMJ d896e0fff0101122 0

4. 已加密网关三元组配置文件：auth_key.json；

5. 网关设备信息配置文件，请厂商自己更换：dev_info.json；

6. OTA升级包示例文件：lora_ota.tar.gz；
