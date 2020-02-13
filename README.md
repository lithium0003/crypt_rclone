# crypt_rclone
rclone encryption demo

## prepare
* MinGW(windows) or gcc environment
* libsodium https://github.com/jedisct1/libsodium

## make
``` bash
make
```

## run
encryption
``` bash
crypt_rclone.exe c input.txt encrypted.bin password saltstr
```
decryption
``` bash
crypt_rclone.exe d encrypted.bin plain.txt password saltstr
```
