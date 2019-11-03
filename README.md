Overview
========
phoenix-fileserver, also called nextfs, is a userspace fileserver used by the Phoenix SGX
microkernel.  nextfs extends the
[lwext4](https://github.com/gkostka/lwext4) userspace implementation of an ext2
filesystem into a networked server.  nextfs uses an untrusted host file as the
bakcing store, similar to a block device, and  provides four variants of this
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
[fork](https://github.com/smherwig/lwext4) of gkostka's lwext that simply adds
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
with the contents of a directory.  The script depends on the Python `cryptography`
library (`makefs.py` works with versions 2.6.1 and 2.8, and probably all
versions in between).

```
pip install cryptography
```

The script `src/fileserver/makefs/makemerkle.py` takes as an argument the
filesystem image and outputs a file that contains a serialized representation
of the Merkle Tree computed over the image.


Creating a bd-std image
-----------------------


Creating a bd-crypt image
-------------------------


Creating a bd-verity image
--------------------------


Creating a bd-vericrypt image
-----------------------------



Micro-Benchmarks
================






RPC Specification
=================


