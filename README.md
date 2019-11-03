Overview
========
phoenix-fileserver, also called nextfs, is a userspace fileserver used by the Phoenix SGX
microkernel.  nextfs extends
[lwext4](https://github.com/gkostka/lwext4) userspace implementation of an ext2
filesystem into a networked server.  nextfs uses an untursted host file as the
bakcing store, similar to a block device.  nextfs provides four variants of the
block device:

- **bd-std**: stores data blocks in plaintext, wihtout integrity guarantees
- **bd-crypt**: encrypts each blcok using AES-256 in XTS mode; the IV for
each block is based on the block's ID.
- **bd-verity**: maintains a Merkle tree over the blocks for integrity
protection: a leaf of the tree is an HMAC of the associated block, and an
internal node the HMAC of its two children.
- **bd-vericrypt**: the composition of bd-crypt and bd-verity; the Merkle Tree
is over the encrypted blocks.


Building
========
I will assume that sources are downloaded to `$HOME/src/` and that artifacts
are installed under `$HOME`.  

First download and install lwext4.  I have a
[fork](https://github.com/smherwig/lwext4) of gkostka's lwext that simply adds
a Makefile for the purpose of simplifying installation.

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

Download and build [nextfs](https://github.com/smherwig/phoenix-fileserver):

```
cd ~/src
git clone https://github.com/smherwig/phoenix-fileserver fileserver
cd fileserver/server
make
```

