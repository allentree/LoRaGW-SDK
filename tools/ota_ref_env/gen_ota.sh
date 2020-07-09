#!/bin/bash
rm -f ./lora_ota.tar.gz 
rm -f ./ota.tar.gz
rm -f ./sign
cd ./packages/
tar -zcf ../lora_ota.tar.gz ./*
cd ../
echo "ota files have been packaged to lora_ota.tar.gz"
./lora_sign -r ./lora_ota.tar.gz -s ./sign -k ./PrivateKey.pem
echo "create sign for lora_ota.tar.gz"
tar -zcf ota.tar.gz ./lora_ota.tar.gz ./sign
echo "create final ota file: ota.tar.gz"
