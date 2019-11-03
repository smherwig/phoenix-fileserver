Overview
========
phoenix-fileserver, also called nextfs, is a userspace fileserver used by the Phoenix SGX
microkernel.  nextfs extends the
[lwext4](https://github.com/gkostka/lwext4) userspace implementation of an ext2
filesystem into a networked server.  nextfs uses an untrusted host file as the
backing store, similar to a block device, and  implements four variants of this
device:

- **bd-std**: stores data blocks in plaintext, wihtout integrity guarantees
- **bd-crypt**: encrypts each block using AES-256 in XTS mode; each block's IV
is based on the block's ID.
- **bd-verity**: maintains a Merkle tree over the blocks for integrity
protection: a leaf of the tree is an HMAC of the associated block, and an
internal node the HMAC of its two children.
- **bd-vericrypt**: the composition of bd-verity with bd-crypt; the Merkle Tree
is over the encrypted blocks.


Building
========
I will assume that sources are downloaded to `$HOME/src/` and that artifacts
are installed under `$HOME`.  

First download and install lwext4.  I have a
[fork](https://github.com/smherwig/lwext4) of gkostka's lwext4 that adds
a `Makefile.smherwig` for the purpose of simplifying installation.

```
cd ~/src
git clone https://github.com/smherwig/lwext4
cd lwext4
make -f Makefile.smherwig
make -f Makefile.smherwig install INSTALL_TOP=$HOME
```


Next, download, build, and install the block device library,
[libbd](https://github.com/smherwig/phoenix-libbd):

```
cd ~/src
git clone https://github.com/smherwig/phoenix-libbd libbd
cd libbd
make
make install INSTALL_TOP=$HOME
```

Download and build nextfs:

```
cd ~/src
git clone https://github.com/smherwig/phoenix-fileserver fileserver
cd fileserver/server
make
```


Creating a Filesystem Image
===========================

The script `src/fileserver/makefs/makefs.py` formats a file as an ext2 image
with the contents of a directory.  Currently, the directory must be non-empty.
Let's first create an example directory, called `root`:


```
cd ~/src/fileserver/makefs
mkdir root
echo hello world > root/hello.txt
```

`makefs.py` depends on the Python `cryptography`
library (`makefs.py` works with versions 2.6.1 and 2.8, and probably all
versions in between), which may be installed with `pip`:

```
pip install cryptography
```


bd-std image
------------

```
cd ~/src/fileserver/makefs
./makefs.py -v -s 128M fs.std.img root
```

bd-crypt image
--------------

```
cd ~/src/fileserver/makefs
./makefs.py -v -s 128M -p encpassword fs.crypt.img root
```

Here, `encpassword` is the password used to generate the encryption key.


bd-verity and bd-vericrypt images
---------------------------------

The script `src/fileserver/makefs/makemerkle.py` takes as an argument the
filesystem image, computes the Merkle tree of the image, and outputs a
serialized representation of the tree to a file.


A bd-verity block device entails computing the merkle tree of a bd-std filesystem
image:

```
./makemerkle.py -k macpassword fs.std.img fs.std.mt
```

Here, `macpassword` is the key used for the Merkle tree's HMAC, and `fs.std.mt`
the Merkle Tree output file.


Similarly, a bd-vericrypt block device entails computing the Merkle tree of a
bd-crypt filesystem image:

```
./makemerkle.py -k macpassword fs.crypt.img fs.crypt.mt
```


Micro-Benchmarks
================

The micro-benchmarks require the [phoenix](https://github.com/smherwig/phoenix)
libOS and
[phoenix-makemanifest](https://github.com/smherwig/phoenix-makemanifest)
configuration packager. Download and setup these two projects.  The
instructions here assume that the phoenix source is located at
`$HOME/src/phoenix` and the phoenix-makemanifest project at
`$HOME/src/makemanifest`.


Build and install the [fio](https://github.com/axboe/fio) I/O workload
benchmarking tool.  We apply a small patch to `fio` that removes a call to
`nice(3)`.  `nice(3)` is a C library wrapper for the system call
`setpriority`, which Graphene does not implement (that is, Graphene will return
`ENOSYS`).  If we do not apply this patch, `fio` will abort upon
inspecting the return value of `nice`.


```
cd ~/src
git clone https://github.com/axboe/fio
cd fio
git checkout 2f75f0223
patch -p1 --dry-run < ~/src/fileserver/bench/fio-patch/fio-3.13.patch
patch -p1 < ~/src/fileserver/bnech/fio-patch/fio-3.13.patch
./configure --prefix=$HOME
make
make install
```

We use `fio` to measure the performance of sequential reads to a 16 MiB file
hosted on a nextfs server over 10 seconds; each read transfers 4096 bytes of
data.  `fio` runs inside an exnclave, uses exitless system calls, and invokes
read operations from a single thread.  Package fio to run in an enclave 


```
cd ~/src/makemanifest
./make_sgx.py -g ~/src/phoenix -k enclave-key.pem -p
~/src/fileserver/bench/sgx/fio.conf -t $PWD -v -o fio
cd fio
mv manifest.sgx fio.manifest.sgx
```


We test the nextfs server running outside of enclave, in an enclave, and in an
enclave with exitless system calls.  Package nextfs to run in an enclave:

```
cp ~/src/fileserver/makefs/fs.std.img ~/src/fileserver/deploy/fs/srv
cd ~/src/makemanifest
./make_sgx.py -g ~/src/phoenix -k enclave-key.pem -p ~/src/fileserver/deploy/manifest.conf -t $PWD -v -o nextfsserver
cd nextfsserver
cp manifest.conf nextfsserver.manifest.conf
```


Next, create or copy over the keying material.  I will assume the keying
material is from the
[phoenix-nginx-eval](https://github.com/smherwig/phoenix-nginx-eval), but
OpenSSL may also be used to create a root certificate (`root.crt`) and a leaf
certificate and key (`proc.crt`, `proc.key`).

```
cd ~
git clone https://github.com/smherwig/phoenix-nginx-eval nginx-eval
cp ~/nginx-eval/config/root.crt ~/src/fileserver/deploy/fs/srv/
cp ~/nginx-eval/config/proc.crt ~/src/fileserver/deploy/fs/srv/
cp ~/nginx-eval/config/proc.key ~/src/fileserver/deploy/fs/srv/
```


Copy the filesystem images and Merkle tree files to `deploy/fs/srv/`

```
cd ~/src/fileserver/makefs
cp fs.std.img ../deploy/fs/srv
cp fs.crypt.img ../deploy/fs/srv
cp fs.crypt.mt ../deploy/fs/srv
```

non-SGX
-------

In one terminal, run the nextfsserver:

```
cd ~/src/fileserver/server
./nextfsserver -b bdstd -Z ../deploy/fs/srv/root.crt ../deploy/fs/srv/proc.crt ../deploy/fs/srv/proc.key -a /graphene/123456/fc055dcc ../deploy/fs/srv/fs.std.img
```

In another terminal, run the `fio` tool:

```
cd ~/src/makemanifest/fio
./fio.manifest.sgx /tests/test-graphene-seqread-n1.fio --output
/results/graphene-bdstd.out
```

For bd-crypt, the nextfsserver command-line is:

```
./nextfsserver -b bdcrypt:encpassword:aes-256-xts -Z ../deploy/fs/srv/root.crt ../deploy/fs/srv/proc.crt ../deploy/fs/srv/proc.key -a /graphene/123456/fc055dcc ../deploy/fs/srv/fs.std.img
```


For bd-vericrypt, the nextfsserver command-line is:
```
./nextfsserver -b bdvericrypt:../deploy/fs/srv/fs.std.mt:ROOTHASH:encpassword:aes-256-xts -Z ../deploy/fs/srv/root.crt ../deploy/fs/srv/proc.crt ../deploy/fs/srv/proc.key -a /graphene/123456/fc055dcc ../deploy/fs/srv/fs.std.img
```


SGX
---


exitless
--------



RPC Specification
=================

