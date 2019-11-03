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
are installed under `$HOME`.  nextfs depends on
[lwext4](https://github.com/gkostka/lwext4),
[librho](https://github.com/smherwig/librho), and
[libbd](https://github.com/smherwig/libbd).

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

Download, build, and install librho:

```
git clone https:/github.com/smherwig/librho
cd librho/src
make
make instlal INSTALL_TOP=$HOME
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

The last line that `./makemerkle.py` outputs is a hexstring of the root hash;
jot down this hash, as it is passed as a command-line argument to the
nextfsserver.


Packaging
=========

Next, create or copy over the keying material.  I assume the keying
material is from 
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

Copy the relevant filesystem image and Merkle tree file to
`~src/fileserver/deploy/fs/srv/`.

Package nextffserver to run in an enclave:

```
cd ~/src/makemanifest
./make_sgx.py -g ~/src/phoenix -k enclave-key.pem -p ~/src/fileserver/deploy/manifest.conf -t $PWD -v -o nextfsserver
cd nextfsserver
cp manifest.conf nextfsserver.manifest.conf
```

The `~src/fileserver/deploy/manifest.conf` looks like:

```
EXEC file:/home/smherwig/phoenix/fileserver/server/nextfsserver

MOUNT file:/home/smherwig/phoenix/fileserver/deploy/fs/srv /srv chroot rw
MOUNT file:/home/smherwig/phoenix/fileserver/deploy/fs/etc /etc chroot rw

ENCLAVE_SIZE 128

THREADS 1
#THREADS 1 exitless

DEBUG off
```

The `EXEC` directive is the path to the nextffserver of the executable.  The
`MOUNT` directives are chroot mounts; Graphene maps these hosts directories
read-write onto Graphene's filesystem (e.g., the Graphene userspace sees a
`/srv` directory which is really the untrusted host's
`/home/smherwig/phoenix/fileserver/deploy/fs/srv` directory).
`THREADS` indicates the maximum number SGX threads, and whether these threads
use exitless system calls.


UNIX Domain Sockets
===================

Internally, Graphene namespaces and hashes UNIX domain socket paths.   For
instance, if a server in the Graphene userspace listens on the UNIX domain
socket `/etc/clash`, the Graphene kernel and platform abstraction layer (PAL)
translate this to a UNIX domain socket on the untrusted host named
`/\x00/graphene/123456/fc05dcc`.  The leading `\x00` signifies that the path is
abstract; `/graphene/123456/` is a hardcoded namespace, and `fc05dcc` is
Graphene's custom hash of `/etc/clash`.

Admittedly, this can be confusing.  A rule of thumb is that when specifying a
network host endpoint in `manifest.conf` with the `MOUNT` directive, use the
decimal hash value (e.g, `4228210124`); when running a server outside of SGX,
the server should liste on the full host path (e.g.,
`\x00/graphene/123456/fc05dcc`);  when running a server inside
of SGX, the server should liste on the Graphene userspace path (eg.,
`/etc/clash`).

The utility `graphene-udsname` computes the mapping from path name to hashed
name:

```
cd ~/src/fileserver/misc/graphene-udsname
make
./graphene-udsname /etc/clash
decimal: 4228210124
hex....: fc055dcc
```


Micro-Benchmarks
================

We use [`fio`](https://github.com/axboe/fio) to measure the performance of
sequential reads to a 16 MiB file hosted on a nextfsserver over 10 seconds;
each read transfers 4096 bytes of data.  `fio` runs inside an enclave, uses
exitless system calls, and invokes read operations from a single thread.  


The micro-benchmarks require the [phoenix](https://github.com/smherwig/phoenix)
libOS and
[phoenix-makemanifest](https://github.com/smherwig/phoenix-makemanifest)
configuration packager. Download and setup these two projects.  The
instructions here assume that the phoenix source is located at
`$HOME/src/phoenix` and the phoenix-makemanifest project at
`$HOME/src/makemanifest`.

Build and install the [fio](https://github.com/axboe/fio) I/O workload
benchmarking tool.  

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

We apply a small patch to `fio` that removes a call to
`nice(3)`.  `nice(3)` is a C library wrapper for the system call
`setpriority`, which Graphene does not implement (that is, Graphene will return
`ENOSYS`).  If we do not apply this patch, `fio` will abort upon
inspecting the return value of `nice`.

Package fio to run in an enclave 

```
cd ~/src/makemanifest
./make_sgx.py -g ~/src/phoenix -k enclave-key.pem -p
~/src/fileserver/bench/sgx/fio.conf -t $PWD -v -o fio
cd fio
mv manifest.sgx fio.manifest.sgx
```

We test the nextfsserver using bd-std, bd-crypt, bd-vericrypt running outside
of enclave (*non-SGX*), in an enclave (*SGX*), and in an enclave with exitless
system calls (*exitless*)


non-SGX
-------

In one terminal, run the nextfsserver:

```
cd ~/src/fileserver/server
./nextfsserver -b bdstd -Z ../deploy/fs/srv/root.crt ../deploy/fs/srv/proc.crt ../deploy/fs/srv/proc.key -a /graphene/123456/fc055dcc ../deploy/fs/srv/fs.std.img
```

Note that `-a /graphene/123456/fc055dcc` signifies that the server listens on
the abstract UNIX domain socket `\x00/graphene/123456/fc05dcc`.

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

where `ROOTHASH` is the hexstring of the root hash for the Merkle tree.



SGX
---

Ensure that `~/src/fileserver/deploy/manifest.conf` has the line `THREADS 1`.
Next, package nextfsserver to run in an enclave.


To run the nextfsserver with bd-std, enter:

```
cd ~/src/makemanifest/nextfsserver
./nextfsserver.manifest.conf -b bdstd -Z /srv/root.crt /srv/proc.crt /srv/proc.key /etc/clash /srv/fs.std.img
```

The command-line for bd-crypt is:

```
./nextfsserver.manifest.conf -b bdcrypt:encpassword:aes-256-xts -Z /srv/root.crt /srv/proc.crt /srv/proc.key /etc/clash /srv/fs.crypt.img
```

and bd-vericrypt:


```
./nextfsserver.manifest.conf -b bdvericrtypt:/srv/fs.crypt.mt:macpassword:ROOTHASH:encpassword:aes-256-xts -Z /srv/root.crt /srv/proc.crt /srv/proc.key /etc/clash /srv/fs.crypt.img
```

where `ROOTHASH` is the hexstring of the root hash for the Merkle tree.


exitless
--------
Ensure that `~/src/fileserver/deploy/manifest.conf` has the line `THREADS 1
exitless`, and otherwise repeat as for SGX.



Limitations
===========

A limitation when using a Merkle-tree enhanced block device (i.e., bd-verity or
bd-vericrypt) is that the root hash will change during the execution,
but nextfs does not provide a mechanism for persisting this value.  Thus, if
the nextfsserver is killed, and then run again, the Merkle tree verification
will not succeed.


