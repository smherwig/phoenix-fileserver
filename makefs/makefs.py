#!/usr/bin/env python

import atexit
import binascii
import getopt
import hashlib
import os
import struct
import subprocess
import sys
import re
import tempfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend



# PBKDF2 (Password Based Key Derivation Function 2) / PBKDF2HMAC
#
#   #include <openssl/evp.h>
#
#   int
#   PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
#           const unsigned char *salt, int saltlen, int iter,
#           const EVP_MD *digest, int keylen, unsigned char *out);
#
# HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
#
#   EVP_PKEY_HKDF


IMAGE_SIZE_REGEX = '(\d+)([KMG])'

verbose = False
keep_mounted = False

mounted = False
mountpoint = None

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

def parse_int(s, tag, validvals=None):
    try:
        i = int(s)
    except ValueError:
        msg = ''
        if tag:
            msg += '%s: ' % tag
        msg += 'expected an integer'
        if validvals:
            msg += ' (' + ','.join(validvals) + ')'
        msg += ", but got '%s'" % s
        die(msg)
    else:
        return i

def parse_image_size(s):
    mobj = re.match(IMAGE_SIZE_REGEX, s)
    if mobj is None:
        die("'%s' is not a valid image size", s)
    size = int(mobj.group(1))
    unit = mobj.group(2)
    return (size, unit)

def run_cmd(cmd, dodie=True):
    debug('running cmd: %s', cmd)
    try:
        subprocess.check_call(cmd, shell=True)
    except subprocess.CalledProcessError as err:
        if dodie:
            die("cmd '%s' returned %d: %s", cmd, err.returncode, str(err))
        else:
            warn("cmd '%s' returned %d: %s", cmd, err.returncode, str(err))
            return err.returncode 
    else:
        return 0

def dd_image(image, size, size_unit):
    count = size
    if size_unit == 'K':
        bs = 1024
    elif size_unit == 'M':
        bs = '1M'
    elif size_unit == 'G':
        # keep the bs to 1M
        bs = '1M'
        count *= 1024
    else:
        assert False, "size_unit must be 'K', 'M', or 'G'"

    cmd = 'dd if=/dev/zero of=%s bs=%s count=%d' % (image, bs, count)
    run_cmd(cmd)

def format_image(lwext4_mkfs, image, ext, block_size):
    global verbose
    cmd = '%s -i %s -e %d -b %d' % (lwext4_mkfs, image, ext, block_size)
    if verbose:
        cmd += ' -v'
    run_cmd(cmd)

def pread(f, count):
    pos = f.tell()
    data = f.read(count)
    f.seek(pos, 0)
    return data

def encrypt_block(key, iv, blk):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(blk) + encryptor.finalize()
    return ct

# TODO:
#   check that you read/write the correct number of bytes
#   what to do if last blk is not a multiple of 16?
#
#   option to create a new file, rather than
#   overwriting the existing
#
# The first 1024 bytes are empty/unused
# The next 1024 bytes are the superblock
#
def encrypt_image(image, key, blksize):
    debug('encrypting %s (key %s, blksize=%d)',
            image, binascii.hexlify(key), blksize)
    f = open(image, 'r+b')
    # seek past superblock
    #f.seek(2048)
    blk = pread(f, blksize)
    blknum = 0
    while blk:
        iv = struct.pack('<I12x', blknum)
        if blknum < 10:
            debug("blk_id %d (filepos=%d) iv=%s", blknum, f.tell(), binascii.hexlify(iv))
        ct = encrypt_block(key, iv, blk)
        f.write(ct)
        blk = pread(f, blksize)
        blknum += 1
    f.close()

def make_tmp_mountpoint(image, directory):
    a = os.path.basename(image)
    b = os.path.basename(directory)
    suffix = '.%s.%s' % (a,b)
    path = tempfile.mkdtemp(prefix='makefs.', suffix=suffix)
    return path

def mount(image, mountpoint):
    global mounted
    cmd = 'sudo mount %s %s' % (image, mountpoint)
    run_cmd(cmd)
    mounted = True

def copy_directory(directory, mountpoint):
    cmd = 'cp -r %s/* %s' % (directory, mountpoint)
    run_cmd(cmd)

def unmount(mountpoint):
    global mounted
    cmd = 'sudo umount %s' % mountpoint
    run_cmd(cmd)
    mounted = False

# atexit handler 
def cleanup():
    debug('cleaning up')
    global keep_mounted
    global mountpoint
    global mounted

    if keep_mounted:
        return

    if mounted and mountpoint:
        err = run_cmd('sudo umount %s' % mountpoint, dodie=False)
        if err != 0:
            # avoid possibly loops
            os._exit(1)

    if mountpoint and os.path.exists(mountpoint):
        debug("rmdir mountpoint '%s'", mountpoint)
        os.rmdir(mountpoint)

USAGE = """
makefs.py [options] IMAGE DIRECTORY

  options:
    -b, --block-size BLOCK_SIZE
        block size: 1024, 2048, 4096 (default 1024)    

    -h, --help
        Show this help message and exit

    -k, --keep-mounted
        Leave the image mounted.  The mountpoint is located at
        /tmp/makefs.RAND.A.B', where RAND is a random string,
        A is the basename of IMAGE, and B is the basename of
        DIRECTORY.  The default is to unmount.

    -l, --lwext4-mkfs PATH
        The path to the lwext4-mkfs tool.  If not specified, assumes
        that the lwext4-mkfs executable is on $PATH.

    -p, --password PASSWORD
        Indicates that IMAGE should be encrypted.  Must
        not be used with the --keep-mounted option.

    -s, --size IMAGE_SIZE
        The image size, as an integer.  One of the followig suffixes
        must be used:

            K   - kilobytes (1024 bytes)
            M   - megabytes (1024 * 1024 bytes)
            G   - gigabytes (1024 * 1024 * 1024 bytes)

        The default is 1G.  Images must be larger than 20M.

    -t, --type FSTYPE
        fs type (ext2: 2, ext3: 3 ext4: 4)) (default 2)

    -v, --verbose
        Verbose output
""".strip()

def usage(exit_code):
    sys.stderr.write('%s\n' % USAGE)
    os._exit(exit_code)

def main(argv):
    shortopts ='b:hkl:p:s:t:v'
    longopts = ['block-size=', 'help', 'keep-mounted', 'lwext4-mkfs=',
            'password=', 'size=', 'type=', 'verbose']
    # options
    global verbose
    global keep_mounted
    lwext4_mkfs = 'lwext4-mkfs'
    block_size = 1024
    ext = 2
    size = 1
    size_unit = 'G'
    password = None
    # args
    image = None
    directory = None
    # other
    global mountpoint

    atexit.register(cleanup)

    try:
        opts, args = getopt.getopt(argv[1:], shortopts, longopts)
    except getopt.GetoptError as err:
        sys.stderr.write('%s\n' % str(err))
        usage(1)

    for o, a in opts:
        if o in ('-b', '--block-size'):
            block_size = parse_int(a, '--block-size', (1024, 2048, 4096))
        elif o in ('-h', '--help'):
            usage(0)
        elif o in ('-k', '--keep-mounted'):
            keep_mounted = True
        elif o in ('-l', '--lwext4-mkfs'):
            lwext4_mkfs = a
        elif o in ('-p', '--password'):
            password = a 
        elif o in ('-s', '--size'):
            size, size_unit = parse_image_size(a)
        elif o in ('-t', '--type'):
            ext = parse_int(a, '--type', (2,3,4))
        elif o in ('-v', '--verbose'):
            verbose = True
        else:
            assert False, "unhandled option '%s'" % o
    
    if len(args) != 2:
        usage(1)

    if keep_mounted and password:
        usage(1)

    image = os.path.abspath(args[0])
    directory = os.path.abspath(args[1])

    dd_image(image, size, size_unit)
    format_image(lwext4_mkfs, image, ext, block_size)

    mountpoint = make_tmp_mountpoint(image, directory)
    mount(image, mountpoint)
    copy_directory(directory, mountpoint)

    if password:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                length=32,
                salt=b'',
                iterations=1000,
                backend=default_backend())
        key = kdf.derive(password)
        debug('key derived from password: %s', binascii.hexlify(key))
        unmount(mountpoint)
        encrypt_image(image, key, block_size)

if __name__ == '__main__':
    main(sys.argv)
