#!/bin/sh

#if [ -f manifest.sgx -a ! -f nextfs.manifest.sgx ]; then
#    mv manifest.sgx nextfs.manifest.sgx
#fi
#
#if [ -f token -a ! -f manifest.sgx.token ]; then
#    mv token manifest.sgx.token
#fi

./nextfs.manifest.sgx -v \
    -bbdverity:/srv/fs.mt:macpassword:cee5d8c11403f6d36bf8958a78fbec692d34e7b4e008b9e569cda647bccfab59 \
    -Z /srv/root.crt /srv/proc.crt /srv/proc.key /etc/clash /srv/fs.img
