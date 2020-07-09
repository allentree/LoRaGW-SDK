1. 编译公钥私钥工具：
源代码在lora_sign_src下，依赖openssl库，请先在主机上编译openssl，然后编译lora_sign模块。

2. lora_sgin使用：
生成key:
./lora_sign -g ./
在当前目录下生成一对公钥和私钥
生成签名：
./lora_sign -r ./needSignFile -s ./filesign -k ./PrivateKey.pem
验证签名：
./lora_sign -r ./needVerifyFile -v ./filesign -k ./PublicKey.pem

3. 修改ota文件包：
修改packages下ota文件，详细说明参考SDK用户手册：4.2.7 OTA 增强功能介绍和注意事项。

4. 生成ota包：
./gen_ota.sh

脚本操作如下：先将packages下文件打包为lora_ota.tar.gz，然后使用lora_sign生成签名，最后将lora_ota.tar.gz和sign一起打包为最终的ota文件ota.tar.gz.

5. 注意，ota打包环境下的公钥私钥必须和网关上的公钥一致。
