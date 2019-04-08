#!/usr/bin/env python

import binascii
import getopt
import hashlib
import hmac
import math
import os
import sys

# TODO: make sure block size isnt' smaller than hash's block size
#   -- why would this be important?
#
#

# IMPORTANT PROPERITES OF COMPLETE BINARY TREES
#
# Laymans definition:
#   A binary tree is a complete binary tree if all levels are
#   completely filled except for possibly the last level, and the
#   last level has all keys as left as possible.
#
# A complete binary tree of v leaves has 2v-1 nodes
#
# TODO: verify this one
# A complete binary tree with n nodes has height log_2(n)
#
# left_child(i) : 2*i + 1
# right_child(i): 2*i + 2
# parent(i)     : (i-1)/2
#
#

verbose = False
hash_name2func = {
    'md5':  hashlib.md5,
    'sha1': hashlib.sha1, 
    'sha224': hashlib.sha224,
    'sha256': hashlib.sha256,
    'sha384': hashlib.sha384,
    'sha512': hashlib.sha512
   }

USAGE = """
makemerkle.py [options] INPUT_FILE OUTPUT_FILE
  Compute a Merkle tree of INPUT_FILE and write the tree
  to OUTPUT_FILE.  Print the root hash of the tree to stdout.

  The Merkle tree is implemented as a complete binary
  tree serialized as an array, with the root at index 0
  (which is also file offset 0).

  OPTIONS
    -a, --hash-algorithm HASH_ALGORITHM
        HASH_ALGORITHM must be one of:
            md5
            sha1
            sha224
            sha256
            sha384
            sha512

        The default is sha256. 

    -b, --block-size BLOCK_SIZE
        Default is 1024 bytes.

    -h, --help
        Show this help message and exit.

    -k, --hmac-key KEY
        The key (for now, password) to use for the HMAC.
        If a key is not provided, the merkle tree is simply over
        the hash of each block;  if a key is provided, the merkle
        tree is over the hmac of each block.

    -v, --verbose
        Verbose output

  ARGUMENTS
    INPUT_FILE
        The file over which to compute the merkle tree
        (e.g., a filesystem image)

    OUTPUT_FILE
        The file to write the serialized Merkle tree to.
""".strip()

def debug(fmt, *args):
    if not verbose:
        return
    fmt = '[debug] %s' % fmt
    if not fmt.endswith('\n'):
        fmt += '\n'
    sys.stderr.write(fmt % args)

def warn(fmt, *args):
    fmt = '[warn] %s' % fmt
    if not fmt.endswith('\n'):
        fmt += '\n'
    sys.stderr.write(fmt % args)

def die(fmt, *args):
    fmt = '[die] %s' % fmt
    if not fmt.endswith('\n'):
        fmt += '\n'
    sys.stderr.write(fmt % args)
    sys.exit(1)

def usage(exit_code):
    sys.stderr.write("%s\n" % USAGE)
    sys.exit(exit_code)

def num_leafs(inpath, block_size):
    n = os.path.getsize(inpath)
    debug("input file '%s' is %d bytes", inpath, n)
    return int(math.ceil(n * 1.0 / block_size))

def digest_size(algorithm):
    h = hashlib.new(algorithm)
    return h.digest_size

def do_hash(algorithm, data, hmac_key=None):
    # XXX: Python doesn't provide a way to reset a hash object;
    # hence we must generate a new instance for every hash value
    # we compute -- ahh, feel that CPU burn.
    if not hmac_key:
        h = hashlib.new(algorithm)
        h.update(data)
        return h.digest()
    else:
        hash_func = hash_name2func[algorithm]
        h = hmac.new(hmac_key, data, hash_func)
        return h.digest()

def merkle(inpath, outpath, algorithm, block_size, hmac_key=None):
    # get the size of inpath and determine total number
    # of leafs you will need
    nleafs = num_leafs(inpath, block_size)
    debug('number of leafs = %d', nleafs)

    # NEED_1 a formula to compute the number of nodes in
    # the resultant merkle tree based on the number of leaves.
    #
    # Phrased generally: Given that a complete binary tree has
    # x leaves, how many nodes does the tree have?
    nnodes = (2 * nleafs) - 1
    debug('number of nodes = %d', nnodes)

    # compute the size of the digest the hash algorihm produces
    md_size = digest_size(algorithm)

    # compute nodes * md_size to get the size of the output
    # file.  Create a new file of this size full of zeros.
    outpath_size = nnodes * md_size
    debug("size of output file '%s' = %d", outpath, outpath_size)
    ofh = open(outpath, 'w+b')
    ofh.truncate(outpath_size)

    # NEED_2 a formula to compute the mt array index of the first
    # leaf (the leaves will occupy sequential indices at the 
    # very end of the mt array)
    #
    # This should actually fall out of NEED_1.  NEED_1 gives us
    # the total number of nodes in the tree.  Since we know the
    # number of leaves, and since all leaves are at the end,
    # we just compute (num_total_nodes - num_leafs) * block_size)
    # to get the starting position of the first hash(leaf).
    off_first_leaf = (nnodes - nleafs) * md_size
    debug("offset of first leaf: %d", off_first_leaf) 

    # seek to the position in outpath where the first leave 
    # is to be written.
    ofh.seek(off_first_leaf)

    # iterate through inpath block by block, and write the hashes
    # of the block to the outpath.
    ifh = open(inpath, 'rb')
    blk = ifh.read(block_size)
    while blk:
        md = do_hash(algorithm, blk, hmac_key)
        ofh.write(md)
        blk = ifh.read(block_size)
    ifh.close()

    # iterate backwards through outpath to compute the 
    # inner nodes of the merkle tree.  Note that siblings are
    # next to one another in the array-based representation of the
    # merkle tree.
    for off in xrange(outpath_size - (2 * md_size), 0, -2 * md_size):
        ofh.seek(off)
        data = ofh.read(2 * md_size)
        md = do_hash(algorithm, data, hmac_key)
        idx = off / md_size     # file offset  -> (array) index
        pidx = (idx - 1) / 2    # index        -> parent index
        poff = pidx * md_size   # parent index -> file offset
        ofh.seek(poff)
        ofh.write(md)
        print 'pidx=%d, hash=%s' % (pidx, binascii.hexlify(md))

    ofh.seek(0)
    root_hash = ofh.read(md_size)
    ofh.close()
    return root_hash

def main(argv):
    shortopts = 'a:b:hk:v'
    longopts = ['hash-algorithm=', 'block-size=', 'help', 'hmac-key=', 'verbose']
    # options
    global verbose
    block_size = 1024
    algorithm = 'sha256'
    hmac_key = None
    # args
    inpath = None
    outpath = None

    valid_hash_algorithms = hash_name2func.keys()

    try:
        opts, args = getopt.getopt(argv[1:], shortopts, longopts)
    except getopt.GetoptError as err:
        sys.stderr.write('%s\n' % str(err))
        usage(1)

    for o, a in opts:
        if o in ('-a', '--hash-algorithm'):
            algorithm = a
            if algorithm not in valid_hash_algorithms:
                die('--hash-algorithm must be one of: %s',
                        ', '.join(valid_hash_algorithms))
        elif o in ('-b', '--block-size'):
            try:
                block_size = int(a)
            except ValueError:
                die("--block-size expects an integer, but got '%s'", a)
        elif o in ('-h', '--help'):
            usage(0)
        elif o in ('-k', '--hmac-key'):
            hmac_key = a
        elif o in ('-v', '--verbose'):
            verbose = True
        else:
            die("unhandled option '%s'", o)

    if len(args) != 2:
        usage(1)

    inpath = args[0]
    outpath = args[1]

    debug("inpath='%s', outpath='%s', algorithm=%s, block_size=%d",
            inpath, outpath, algorithm, block_size)
    root_hash = merkle(inpath, outpath, algorithm, block_size, hmac_key)
    print binascii.hexlify(root_hash)
    
if __name__ == '__main__':
    main(sys.argv)
