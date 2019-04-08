#!/usr/bin/env python

import errno
import getopt
import os
import shlex
import sys

import nextfs

# TODO:
#   add readline support

_SIZEOF_SUN_PATH = 108

_USAGE = """
usage: testclient [options] UDSPATH
  options:
    -a
        Treat UDSPATH as an abstract socket (adds a nul byte)

    -h
        Show this help message and exit
    
    -r,--cacert CACERT
        CA certificate file

    -c,--cert CERT
        Client cretificate

    -k,--key KEYFILE
        Private key file

  args:
    UDSPATH
        The path to the UNIX domain socket to connect to

If all of (cacert, cert, key) is omitted, the client does
not use SSL.

If any of (cacert, cert, key) is given, then all three must
be provided, and the client uses SSL.
""".strip()

def _warn(fmt, *args):
    fmt = '[warn] %s' % fmt
    if not fmt.endswith('\n'):
        fmt += '\n'
    sys.stdout.write(fmt % args)

def _usage(exitcode):
    sys.stderr.write('%s\n' % _USAGE)
    sys.exit(exitcode)

def _create_udspath(udspath, anonymous):
    pathlen = len(udspath)
    if anonymous:
        frontpad = '\x00'
        backpad = '\x00' * (_SIZEOF_SUN_PATH - pathlen - 1)
    else:
        frontpad = ''
        # Python will add an extra nul-byte for non-anonymous
        # unix socket paths, hence the  - 1
        backpad = '\x00' * (_SIZEOF_SUN_PATH - pathlen - 1)
    path = frontpad + udspath + backpad
    print 'len=%d, path="%s"' % (len(path), path)
    return path

def _parse_int(s, tag):
    try:
        i = int(s)
    except ValueError:
        raise ValueError(tag)
    else:
        return i

def _file_remove_proxy(client, args):
    path = args[0]
    error = client.file_remove(path)
    return error

def _file_link_proxy(client, args):
    path = args[0]
    hardlink_path = args[1]
    error = client.file_link(path, hardlink_path)
    return error

def _file_rename_proxy(client, args):
    path = args[0]
    new_path = args[1]
    error = client.file_rename(path, new_path)
    return error

def _file_open_proxy(client, args):
    path = args[0]
    openflags = args[1]
    fd = client.file_open(path, openflags)
    return fd

def _file_open2_proxy(client, args):
    path = args[0]
    flags = _parse_int(args[1], 'file_open2: fd must be an int')
    fd = client.file_open2(path, flags)
    return fd

def _file_close_proxy(client, args):
    fd = _parse_int(args[0], 'file_close: fd must be an int')
    error = client.file_close(fd)
    return error

def _file_truncate_proxy(client, args):
    fd = _parse_int(args[0], 'file_truncate: fd must be an int')
    size = _parse_int(args[1], 'file_truncate: size must be an int')
    error = client.file_truncate(fd, size)
    return error

def _file_read_proxy(client, args):
    fd = _parse_int(args[0], 'file_read: fd must be an int')
    count = _parse_int(args[1], 'file_read: count must be an int')
    buf = client.file_read(fd, count)
    return buf

def _file_write_proxy(client, args):
    fd = _parse_int(args[0], 'file_read: fd must be an int')
    buf = args[1]
    count = client.file_write(fd, buf)
    return count

def _file_seek_proxy(client, args):
    fd = _parse_int(args[0], 'file_seek: fd must be an int')
    offset = _parse_int(args[0], 'file_seek: offset must be an int')
    origin = _parse_int(args[0], 'file_seek: origin must be an int')
    error = client.file_seek(fd, offset, origin)
    return error

def _file_tell_proxy(client, args):
    fd = _parse_int(args[0], 'file_seek: fd must be an int')
    pos = client.file_tell(fd)
    return pos

def _file_size_proxy(client, args):
    fd = _parse_int(args[0], 'file_seek: fd must be an int')
    size = client.file_size(fd)
    return size

def _dir_rm_proxy(client, args):
    path = args[0]
    error = client.dir_rm(path)
    return error

def _dir_mv_proxy(client, args):
    oldpath = args[0]
    newpath = args[1]
    error = client.dir_mv(oldpath, newpath)
    return error

def _dir_mk_proxy(client, args):
    path = args[0]
    error = client.dir_mk(path)
    return error

def _dir_open_proxy(client, args):
    path = args[0]
    fd = client.dir_open(path)
    return fd

def _dir_close_proxy(client, args):
    fd = _parse_int(args[0], 'dir_close: fd must be an int')
    error = client.dir_close(fd)
    return error

def _dir_entry_rewind_proxy(client, args):
    fd = _parse_int(args[0], 'dir_close: fd must be an int')
    error = client.dir_entry_rewind(fd)
    return error

def _symlink_proxy(client, args):
    target = args[0]
    linkpath = args[1]
    error = client.symlink(target, linkpath)
    return error

def _readlink_proxy(client, args):
    path = args[0]
    target = client.readlink(path)
    return target

def _raw_inode_proxy(client, args):
    path = args[0]
    vals = client.raw_inode(path)
    return vals

def _mode_set_proxy(client, args):
    path = args[0]
    mode = _parse_int(args[1], 'mode_set: mode must be an int')
    error = client.mode_set(path, mode)
    return error

def _mode_get_proxy(client, args):
    path = args[0]
    mode = client.mode_get(path)
    return mode

def _owner_set_proxy(client, args):
    path = args[0]
    uid = _parse_int(args[1], 'owner_set: uid must be an int')
    gid = _parse_int(args[2], 'owner_set: gid must be an int')
    error = client.owner_set(path, uid, gid)
    return error

def _owner_get_proxy(client, args):
    path = args[0]
    uid, gid = client.owner_get(path)
    return (uid, gid)

def _atime_set_proxy(client, args):
    path = args[0]
    atime = _parse_int(args[1], 'atime_set: atime must be an int')
    error = client.atime_set(path, atime)
    return error

def _atime_get_proxy(client, args):
    path = args[0]
    atime = client.atime_get(path)
    return atime

def _mtime_set_proxy(client, args):
    path = args[0]
    mtime = _parse_int(args[1], 'mtime_set: mtime must be an int')
    error = client.mtime_set(path, mtime)
    return error

def _mtime_get_proxy(client, args):
    path = args[0]
    mtime = client.mtime_get(path)
    return mtime

def _ctime_set_proxy(client, args):
    path = args[0]
    ctime = _parse_int(args[1], 'ctime_set: ctime must be an int')
    error = client.mtime_set(path, ctime)
    return error

def _ctime_get_proxy(client, args):
    path = args[0]
    ctime = client.ctime_get(path)
    return ctime

def _fork_proxy(client, args):
    ident = client.fork()
    return ident

def _child_attach_proxy(client, args):
    ident = _parse_int(args[0], 'child_attach: ident must be an int')
    error = client.child_attach(ident)
    return error

def _new_fdtable_proxy(client, args):
    error = client.new_fdtable()
    return error

_cmdtable = {
    # cmd             func                      nargs
    'file_remove':      (_file_remove_proxy,        1),
    'file_link':        (_file_link_proxy,          2),
    'file_rename':      (_file_rename_proxy,        2),
    'file_open':        (_file_open_proxy,          2),
    'file_open2':       (_file_open2_proxy,         2),
    'file_close':       (_file_close_proxy,         1),
    'file_truncate':    (_file_truncate_proxy,      2),
    'file_read':        (_file_read_proxy,          2),
    'file_write':       (_file_write_proxy,         2),
    'file_seek':        (_file_seek_proxy,          3),
    'file_tell':        (_file_tell_proxy,          1),
    'file_size':        (_file_size_proxy,          1),
    'dir_rm':           (_dir_rm_proxy,             1),
    'dir_mv':           (_dir_mv_proxy,             2),
    'dir_mk':           (_dir_mk_proxy,             1),
    'dir_open':         (_dir_open_proxy,           1),
    'dir_close':        (_dir_close_proxy,          1),
    'dir_entry_rewind': (_dir_entry_rewind_proxy,   1),
    'symlink':          (_symlink_proxy,            2),
    'readlink':         (_readlink_proxy,           1),
    'raw_inode':        (_raw_inode_proxy,          1),
    'mode_set':         (_mode_set_proxy,           2),
    'mode_get':         (_mode_get_proxy,           1),
    'owner_set':        (_owner_set_proxy,          3),
    'owner_get':        (_owner_get_proxy,          1),
    'atime_set':        (_atime_set_proxy,          2),
    'atime_get':        (_atime_get_proxy,          1),
    'mtime_set':        (_mtime_set_proxy,          2),
    'mtime_get':        (_mtime_get_proxy,          1),
    'ctime_set':        (_ctime_set_proxy,          2),
    'ctime_get':        (_ctime_get_proxy,          1),
    'fork':             (_fork_proxy,               0),
    'child_attach':     (_child_attach_proxy,       1),
    'new_fdtable':      (_new_fdtable_proxy,        0)
}

def _fscall(client, cmd, args): 
    if cmd not in _cmdtable:
        _warn("'%s' not a valid command\n" % cmd)
        return
    
    fn, nargs = _cmdtable[cmd]
    if len(args) != nargs:
        _warn("'%s' takes %d args; %d provided" % \
                (cmd, nargs, len(args)))
        return

    try:
        ret = fn(client, args)
    except (ValueError, nextfs.NEXTFSError) as err:
        _warn(str(err))
        return

    print ret 

def _cmdloop(client):
    while True:
        # CTRL-D => EOFError
        # CTRL-C => KeyboardInterrupt
        try:
            cmdline = raw_input('> ')
        except (EOFError, KeyboardInterrupt) as err:
            client.disconnect()
            sys.exit(0)
        args = shlex.split(cmdline)
        if not args:
            continue
        cmd = args.pop(0)
        _fscall(client, cmd, args)

def main(argv):
    shortopts = 'ahr:c:k:'
    longopts = ['anonymous', 'help', 'cacert=', 'cert=', 'privkey=']
    # options
    anonymous = False
    cacert = None
    cert = None
    privkey = None

    try:
        opts, args = getopt.getopt(argv[1:], shortopts, longopts)
    except getopt.GetoptError as err:
        sys.stderr.write('%s\n', str(err))
        _usage(1)

    for o, a in opts:
        if o in ('-a', '--anonymous'):
            anonymous = True
        elif o in ('-h', '--help'):
            _usage(0)
        elif o in ('-r', '--cacert'):
            cacert = a
        elif o in ('-c', '--cert'):
            cert = a
        elif o in ('-k', '--privkey'):
            privkey = a
        else:
            assert False, "unhandled option '%s'" % o

    if len(args) != 1:
        _usage(1)

    udspath = args[0]
    udspath = _create_udspath(udspath, anonymous)

    sslinfo = [cacert, cert, privkey]
    if any(sslinfo) and not all(sslinfo):
        _usage(1)

    client = nextfs.NEXTFSClient(udspath, cacert, cert, privkey, verbose=True)
    client.connect()
    _cmdloop(client)

if __name__ == '__main__':
    main(sys.argv)
