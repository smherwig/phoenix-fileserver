import binascii
import os
import socket
import ssl
import struct
import sys

# TODO:
#   For now, the purpose of this module is testing.
#   All network calls are blocking.  In the future, we
#   might want to allow non-blocking I/O.

_NEXTFS_OP_DEVICE_REGISTER      = 0
_NEXTFS_OP_MOUNT                = 1
_NEXTFS_OP_UMOUNT               = 2
_NEXTFS_OP_MOUNT_POINT_STATS    = 3
_NEXTFS_OP_CACHE_WRITE_BACK     = 4

_NEXTFS_OP_FILE_REMOVE          = 5 
_NEXTFS_OP_FILE_LINK            = 6
_NEXTFS_OP_FILE_RENAME          = 7
_NEXTFS_OP_FILE_OPEN            = 8
_NEXTFS_OP_FILE_OPEN2           = 9
_NEXTFS_OP_FILE_CLOSE           = 10
_NEXTFS_OP_FILE_TRUNCATE        = 11
_NEXTFS_OP_FILE_READ            = 12
_NEXTFS_OP_FILE_WRITE           = 13
_NEXTFS_OP_FILE_SEEK            = 14
_NEXTFS_OP_FILE_TELL            = 15
_NEXTFS_OP_FILE_SIZE            = 16

_NEXTFS_OP_DIR_RM               = 17
_NEXTFS_OP_DIR_MV               = 18
_NEXTFS_OP_DIR_MK               = 19
_NEXTFS_OP_DIR_MKDIR            = 20
_NEXTFS_OP_DIR_OPEN             = 21
_NEXTFS_OP_DIR_CLOSE            = 22
_NEXTFS_OP_DIR_ENTRY_NEXT       = 23
_NEXTFS_OP_DIR_ENTRY_REWIND     = 24
_NEXTFS_OP_DIR_LIST             = 25

_NEXTFS_OP_SYMLINK              = 26
_NEXTFS_OP_MKNOD                = 26
_NEXTFS_OP_READLINK             = 28

_NEXTFS_OP_RAW_INODE            = 29
_NEXTFS_OP_MODE_SET             = 30
_NEXTFS_OP_MODE_GET             = 31
_NEXTFS_OP_OWNER_SET            = 32
_NEXTFS_OP_OWNER_GET            = 33
_NEXTFS_OP_ATIME_SET            = 34
_NEXTFS_OP_ATIME_GET            = 35
_NEXTFS_OP_MTIME_SET            = 36
_NEXTFS_OP_MTIME_GET            = 37
_NEXTFS_OP_CTIME_SET            = 38
_NEXTFS_OP_CTIME_GET            = 39

_NEXTFS_OP_FORK                 = 40
_NEXTFS_OP_CHILD_ATTACH         = 41
_NEXTFS_OP_NEW_FDTABLE          = 42

_NEXTFS_ERPC = 999

def _pp_hexlify(buf):
    b = binascii.hexlify(buf)
    w = []
    for i in xrange(0, len(b), 4):
        w.append(b[i: i+4])
    return ' '.join(w)

class NEXTFSError(OSError):
    def __init__(self, errnoval, filename=None):
        if errnoval == _NEXTFS_ERPC:
            msg = 'nextfs RPC error'
        else:
            msg = os.strerror(errnoval)
        if filename:     
            OSError.__init__(self, errnoval, msg, filename)
        else:
            OSError.__init__(self, errnoval, msg)

class NEXTFSClient:
    def __init__(self, udspath, cacert=None, cert=None, privkey=None,
            verbose=False):
        self.udspath = udspath
        self.cacert = cacert
        self.cert = cert
        self.privkey = privkey
        self.verbose = verbose

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) 

    def _debug(self, fmt, *args):
        if self.verbose:
            fmt = '[debug] %s' % fmt
            if not fmt.endswith('\n'):
                fmt += '\n'
            sys.stdout.write(fmt % args)

    def _recvn(self, want):
        self._debug('want %d bytes' % want)
        need = want
        b = ''
        while need:
            b += self.sock.recv(need)
            need = want - len(b)
        self._debug('got %d bytes' % len(b))
        return b

    def _marshal_str(self, s):
        slen = len(s)
        fmt = '>I%ds' % slen
        b = struct.pack(fmt, slen, s)
        return b

    def _marshal_blob(self, blob):
        blen = len(blob)
        fmt = '>I%ds' % blen
        b = struct.pack(fmt, blen, blob)
        return b

    def _demarshal_str(self, s):
        slen = struct.unpack('>I', s)[0]
        val = s[4:slen]
        assert len(val) == slen
        return (slen, val)

    def _marshal_hdr(self, op, bodylen):
        return struct.pack('>II', op, bodylen)

    def _demarshal_hdr(self, resphdr):
        return struct.unpack('>II', resphdr)

    def _request(self, req):
        self._debug('raw request: %s', _pp_hexlify(req));
        self.sock.sendall(req)
        resphdr = self._recvn(8)
        status, bodylen = self._demarshal_hdr(resphdr)
        body = ''
        if bodylen:
            body = self._recvn(bodylen)
        self._debug('raw response: %s', _pp_hexlify(resphdr + body))
        self._debug('parsed response: status=%d, bodylen=%d, body=%s',
                status, bodylen, _pp_hexlify(body))
        return (status, body)

    def file_remove(self, path):
        pathbuf = self._marshal_str(path)
        bodylen = len(pathbuf)
        header = self._marshal_hdr(_NEXTFS_OP_FILE_REMOVE, bodylen)
        req = header + pathbuf
        error, respbody = self._request(req)
        assert respbody == ''
        if error != 0:
            raise NEXTFSError(error, path)
        return error

    def file_link(self, path, hardlink_path):
        pass

    def file_rename(self, path, new_path):
        pass

    def file_open(self, path, flags):
        pathbuf = self._marshal_str(path)
        flagsbuf = self._marshal_str(flags)
        bodylen = len(pathbuf) + len(flagsbuf)
        header = self._marshal_hdr(_NEXTFS_OP_FILE_OPEN, bodylen)
        req = header + pathbuf + flagsbuf
        error, respbody = self._request(req)
        if error != 0:
            assert respbody == ''
            raise NEXTFSError(error, path)
        assert len(respbody) == 4
        fd = struct.unpack('>I', respbody)[0]
        return fd

    def file_open2(self, path, flags):
        pathbuf = self._marshal_str(path)
        flagsbuf = struct.pack('>I', flags)
        bodylen = len(pathbuf) + len(flagsbuf)
        header = self._marshal_hdr(_NEXTFS_OP_FILE_OPEN2, bodylen)
        req = header + pathbuf + flagsbuf
        error, respbody = self._request(req)
        if error != 0:
            assert respbody == ''
            raise NEXTFSError(error, path)
        assert len(respbody) == 4
        fd = struct.unpack('>I', respbody)[0]
        return fd

    def file_close(self, fd):
        fdbuf = struct.pack('>I', fd)
        header = self._marshal_hdr(_NEXTFS_OP_FILE_CLOSE, len(fdbuf))
        req = header + fdbuf
        error, respbody = self._request(req)
        assert respbody == ''
        if error != 0:
            raise NEXTFSError(error)
        return error    # TODO: make this a void function

    def file_truncate(self, fd, size):
        pass

    def file_read(self, fd, count):
        bodybuf = struct.pack('>II', fd, count)
        header = self._marshal_hdr(_NEXTFS_OP_FILE_READ, len(bodybuf))
        req = header + bodybuf
        error, respbody = self._request(req)
        if error != 0:
            assert respbody == ''
            raise NEXTFSError(error)
        return respbody

    def file_write(self, fd, buf):
        bodybuf = struct.pack('>I', fd)
        bodybuf += self._marshal_blob(buf)
        header = self._marshal_hdr(_NEXTFS_OP_FILE_WRITE, len(bodybuf))
        req = header + bodybuf
        error, respbody = self._request(req)
        if error != 0:
            assert respbody == ''
            raise NEXTFSError(error)
        assert len(respbody) == 4
        count = struct.unpack('>I', respbody)[0]
        return count

    def file_seek(self, fd, offset, origin):
        pass

    def file_tell(self, fd):
        pass

    def file_size(self, fd):
        pass

    def dir_rm(self, path):
        pathbuf = self._marshal_str(path)
        bodylen = len(pathbuf)
        header = self._marshal_hdr(_NEXTFS_OP_DIR_RM, bodylen)
        req = header + pathbuf
        error, respbody = self._request(req)
        assert respbody == ''
        if error != 0:
            raise NEXTFSError(error, path)
        return error

    def dir_mv(self, oldpath, newpath):
        oldpathbuf = self._marshal_str(oldpath)
        newpathbuf = self._marshal_str(newpath)
        body = oldpathbuf + newpathbuf
        bodylen = len(body)
        header = self._marshal_hdr(_NEXTFS_OP_DIR_MV, bodylen)
        req = header + body
        error, respbody = self._request(req)
        assert respbody == ''
        if error != 0:
            raise NEXTFSError(error)
        return error

    def dir_mk(self, path):
        pathbuf = self._marshal_str(path)
        bodylen = len(pathbuf)
        header = self._marshal_hdr(_NEXTFS_OP_DIR_MK, bodylen)
        req = header + pathbuf
        error, respbody = self._request(req)
        assert respbody == ''
        if error != 0:
            raise NEXTFSError(error, path)
        return error

    def dir_open(self, path):
        body = self._marshal_str(path)
        bodylen = len(body)
        header = self._marshal_hdr(_NEXTFS_OP_DIR_OPEN, bodylen)
        req = header + body
        error, respbody = self._request(req)
        if error != 0:
            assert respbody == ''
            raise NEXTFSError(error, path)
        assert len(respbody) == 4
        fd = struct.unpack('>I', respbody)[0]
        return fd

    def dir_close(self, fd):
        fdbuf = struct.pack('>I', fd)
        header = self._marshal_hdr(_NEXTFS_OP_DIR_CLOSE, len(fdbuf))
        req = header + fdbuf
        error, respbody = self._request(req)
        assert respbody == ''
        if error != 0:
            raise NEXTFSError(error)
        return error    # TODO: make this a void function

    def dir_entry_next(self, fd):
        pass

    def dir_entry_rewind(self, fd):
        fdbuf = struct.pack('>I', fd)
        header = self._marshal_hdr(_NEXTFS_OP_DIR_ENTRY_REWIND, len(fdbuf))
        req = header + fdbuf
        error, respbody = self._request(req)
        assert respbody == ''
        if error != 0:
            raise NEXTFSError(error)
        return error    # TODO: make this a void function

    def symlink(self, target, linkpath):
        targetbuf = self._marshal_str(target)
        linkpathbuf = self._marshal_str(linkpath)
        body = targetbuf + linkpathbuf
        bodylen = len(body)
        header = self._marshal_hdr(_NEXTFS_OP_SYMLINK, bodylen)
        req = header + body
        error, respbody = self._request(req)
        assert respbody == ''
        if error != 0:
            raise NEXTFSError(error)
        return error

    def readlink(self, path):
        body = self._marshal_str(target)
        bodylen = len(body)
        header = self._marshal_hdr(_NEXTFS_OP_READLINK, bodylen)
        req = header + body
        error, respbody = self._request(req)
        if error != 0:
            assert respbody == ''
            raise NEXTFSError(error, path)
        assert len(respbody) > 0
        _, val = self._demarshal_str(respbody)
        return val

    def raw_inode(self, path):
        body = self._marshal_str(path)
        bodylen = len(body)
        header = self._marshal_hdr(_NEXTFS_OP_RAW_INODE, bodylen)
        req = header + body
        error, respbody = self._request(req)
        if error != 0:
            assert respbody == ''
            raise NEXTFSError(error)
        assert len(resbody) == ((4 * 2) + (8 * 4))
        vals = struct.unpack('>IHHIIIIIIII')
        # (ino (4), mode (2), uid (2), size_lo (4), 
        #  access_time (4),  changed_inode_time (4), modification_time (4),
        # deletion_time (4),  gid (2), links_count (2), 
        # blocks_count_lo (4) , flags (4)) 
        return vals

    def mode_set(self, path, mode):
        pathbuf = self._marshal_str(path)
        modebuf = struct.pack('>I', mode)
        body = pathbuf + modebuf
        bodylen = len(body)
        header = self._marshal_hdr(_NEXTFS_OP_MODE_SET, bodylen)
        req = header + body
        error, respbody = self._request(req)
        assert respbody == ''
        if error != 0:
            raise NEXTFSError(error)
        return error

    def mode_get(self, path):
        pathbuf = self._marshal_str(path)
        bodylen = len(pathbuf)
        header = self._marshal_hdr(_NEXTFS_OP_MODE_GET, bodylen)
        req = header + pathbuf
        error, respbody = self._request(req)
        if error != 0:
            assert respbody == ''
            raise NEXTFSError(error, path)
        assert len(respbody) == 4
        mode = struct.unpack('>I', respbody)[0]
        return mode

    def owner_set(self, path, uid, gid):
        pathbuf = self._marshal_str(path)
        ownerbuf = struct.pack('>II', uid, gid)
        body = pathbuf + ownerbuf
        bodylen = len(body)
        header = self._marshal_hdr(_NEXTFS_OP_OWNER_SET, bodylen)
        req = header + body
        error, respbody = self._request(req)
        assert respbody == ''
        if error != 0:
            raise NEXTFSError(error)
        return error

    def owner_get(self, path):
        pathbuf = self._marshal_str(path)
        bodylen = len(pathbuf)
        header = self._marshal_hdr(_NEXTFS_OP_OWNER_GET, bodylen)
        req = header + pathbuf
        error, respbody = self._request(req)
        if error != 0:
            assert respbody == ''
            raise NEXTFSError(error, path)
        assert len(respbody) == 8
        uid, gid = struct.unpack('>II', respbody)
        return (uid, gid)

    def atime_set(self, path, atime):
        pathbuf = self._marshal_str(path)
        timebuf = struct.pack('>I', atime)
        body = pathbuf + timebuf
        bodylen = len(body)
        header = self._marshal_hdr(_NEXTFS_OP_ATIME_SET, bodylen)
        req = header + body
        error, respbody = self._request(req)
        assert respbody == ''
        if error != 0:
            raise NEXTFSError(error)
        return error

    def atime_get(self, path):
        pathbuf = self._marshal_str(path)
        bodylen = len(pathbuf)
        header = self._marshal_hdr(_NEXTFS_OP_ATIME_GET, bodylen)
        req = header + pathbuf
        error, respbody = self._request(req)
        if error != 0:
            assert respbody == ''
            raise NEXTFSError(error, path)
        assert len(respbody) == 4
        atime = struct.unpack('>I', respbody)[0]
        return atime

    def mtime_set(self, path, mtime):
        pathbuf = self._marshal_str(path)
        timebuf = struct.pack('>I', mtime)
        body = pathbuf + timebuf
        bodylen = len(body)
        header = self._marshal_hdr(_NEXTFS_OP_MTIME_SET, bodylen)
        req = header + body
        error, respbody = self._request(req)
        assert respbody == ''
        if error != 0:
            raise NEXTFSError(error)
        return error

    def mtime_get(self, path):
        pathbuf = self._marshal_str(path)
        bodylen = len(pathbuf)
        header = self._marshal_hdr(_NEXTFS_OP_MTIME_GET, bodylen)
        req = header + pathbuf
        error, respbody = self._request(req)
        if error != 0:
            assert respbody == ''
            raise NEXTFSError(error, path)
        assert len(respbody) == 4
        mtime = struct.unpack('>I', respbody)[0]
        return mtime

    def ctime_set(self, path, ctime):
        pathbuf = self._marshal_str(path)
        timebuf = struct.pack('>I', ctime)
        body = pathbuf + timebuf
        bodylen = len(body)
        header = self._marshal_hdr(_NEXTFS_OP_CTIME_SET, bodylen)
        req = header + body
        error, respbody = self._request(req)
        assert respbody == ''
        if error != 0:
            raise NEXTFSError(error)
        return error

    def ctime_get(self, path):
        pathbuf = self._marshal_str(path)
        bodylen = len(pathbuf)
        header = self._marshal_hdr(_NEXTFS_OP_CTIME_GET, bodylen)
        req = header + pathbuf
        error, respbody = self._request(req)
        if error != 0:
            assert respbody == ''
            raise NEXTFSError(error, path)
        assert len(respbody) == 4
        ctime = struct.unpack('>I', respbody)[0]
        return ctime

    def fork(self):
        req = self._marshal_hdr(_NEXTFS_OP_FORK, 0)
        error, respbody = self._request(req)
        if error != 0:
            assert respbody == ''
            raise NEXTFSError(error)
        assert len(respbody) == 8
        ident = struct.unpack('>Q', respbody)[0]
        return ident

    def child_attach(self, ident):
        body = struct.pack('>Q', ident)
        bodylen = len(body)
        header = self._marshal_hdr(_NEXTFS_OP_CHILD_ATTACH, bodylen)
        req = header + body
        error, respbody = self._request(req)
        assert respbody == ''
        if error != 0:
            raise NEXTFSError(error)
        return error

    def new_fdtable(self):
        req = self._marshal_hdr(_NEXTFS_OP_NEW_FDTABLE, 0)
        error, respbody = self._request(req)
        assert respbody == ''
        if error != 0:
            raise NEXTFSError(error)
        return error

    def connect(self):
        self.sock.connect(self.udspath) 
        if self.cert:
            """
            self.sock = ssl.wrap_socket(
                    self.sock,
                    keyfile=self.privkey,
                    certfile=self.cert,
                    server_side=False,
                    cert_reqs=ssl.CERT_REQUIRED,
                    ca_certs=self.cacert,
                    ssl_version=ssl.PROTOCOL_TLSv1_2,
                    do_handshake_on_connect=False)
            """
            self.sock = ssl.wrap_socket(
                    self.sock,
                    server_side=False,
                    cert_reqs=ssl.CERT_REQUIRED,
                    ca_certs=self.cacert,
                    ssl_version=ssl.PROTOCOL_TLSv1_2,
                    do_handshake_on_connect=False)
            self.sock.do_handshake()

    def disconnect(self):
        self.sock.close()
