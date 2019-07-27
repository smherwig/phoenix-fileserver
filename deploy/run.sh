#!/bin/sh

#if [ -f manifest.sgx -a ! -f nextfs.manifest.sgx ]; then
#    mv manifest.sgx nextfs.manifest.sgx
#fi
#
#if [ -f token -a ! -f manifest.sgx.token ]; then
#    mv token manifest.sgx.token
#fi

# sgx-bdstd
#./nextfs.manifest.sgx  -Z /srv/root.crt /srv/proc.crt /srv/proc.key \
#    -bbdstd \
#    /etc/clash /srv/fs.std.img

# sgx-bdcrypt-xts
#./nextfs.manifest.sgx -Z /srv/root.crt /srv/proc.crt /srv/proc.key \
#    -b bdcrypt:password:aes-256-xts \
#    /etc/clash /srv/fs.crypt.xts.img

# sgx-bdverity
#./nextfs.manifest.sgx -Z /srv/root.crt /srv/proc.crt /srv/proc.key \
#    -b bdverity:/srv/fs.std.mt:macpassword:48156a4b561493a0fc36296d392a2d180f56ef59074edc089e10f60a97095f98 \
#    /etc/clash /srv/fs.std.img 

# sgx-bdverity
./nextfs.manifest.sgx -Z /srv/root.crt /srv/proc.crt /srv/proc.key \
    -b bdvericrypt:/srv/fs.crypt.xts.mt:macpassword:137f14b5a89fac5931a1900ae592e2cf6bb42f490dfb1f8d94efbb69d8904fd7:password:aes-256-xts \
    /etc/clash /srv/fs.crypt.xts.img 

#./nextfs.manifest.sgx -v \
#    -bbdverity:/srv/fs.mt:macpassword:cee5d8c11403f6d36bf8958a78fbec692d34e7b4e008b9e569cda647bccfab59 \
#    -Z /srv/root.crt /srv/proc.crt /srv/proc.key /etc/clash /srv/fs.img


