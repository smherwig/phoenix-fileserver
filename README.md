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
[fork](https://github.com/smherwig/lwext4) of gkostka's lwext4 that simply adds
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


Creating a bd-std image
-----------------------

```
cd ~/src/fileserver/makefs
./makefs.py -v -s 128M fs.std.img root
```

Creating a bd-crypt image
-------------------------

```
cd ~/src/fileserver/makefs ./makefs.py -v -s 128M -p encpassword fs.crypt.img root
```

Here, `encpassword` is the password used to generate the encryption key.


Creating a bd-verity or bd-vericrypt image
------------------------------------------

The script `src/fileserver/makefs/makemerkle.py` takes as an argument the
filesystem image, computes the Merkle Tree of the image, and outputs a
serialized representation of the tree to a file.


A bd-verity block device entails computing the merkle tree of a bd-std filesystem
image:

```
./makemerkle.py -k macpassword fs.std.img fs.std.mt
```

Here, `macpassword` is the key used for the Merkle tree's HMAC, and `fs.std.mt`
is the Merkle Tree output file.


Similarly, bd-vericrypt block device entails computing the merkle tree of a bd-crypt filesystem image:

```
./makemerkle.py -k macpassword fs.crypt.img fs.crypt.mt
```


Micro-Benchmarks
================
Build and install the [fio](https://github.com/axboe/fio).  We apply a small
patch to `fio` that removes a call to `nice(3)`.  `nice(3)` is a C library call
wrapper for the system call `setpriority`, which Grpahene does not implement
(that is, Graphene will return `ENOSYS`).  If we do not apply this patch, `fio`
will abort upon insepcting the return value of `nice`.


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

Next, build three different versionf of the file image: a plaintext version
(bd-std), an encrypted version (bd-crypt), and an encryted and Merkle-tree
protecteimed image (bd-vericrypt)



RPC Specification
=================

