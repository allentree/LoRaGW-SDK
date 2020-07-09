1. pktfwd/lora_gateway/patch_list
是基于Semtech网关lora_gateway官方代码（对应版本v5.0.1），对相应修改所制作的所有patch，
打patch时，请下载如下Semtech代码，根据patch编号依次打上每个patch；
Semtech lora_gateway v5.0.1 github下载地址:
https://github.com/Lora-net/lora_gateway.git

2. Change List:
v1.0 2018-07-31
1. 修改lgw_cnt2gps及lgw_gps2cnt计算错误问题（当target比reference小时），对应patch:
0001-fix-sx1301-coutner-wrap-up.patch

v1.1 2019-05-08
1. 修改lgw_cnt2utc及lgw_utc2cnt计算错误问题（当target比reference小时），对应patch:
0002-fix-sx1301-coutner-wrap-up-for-cnt2utc-convert.patch
