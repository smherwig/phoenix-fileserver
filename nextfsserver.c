#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ext4.h> 

#include <rho/rho.h>
#include <rpc.h>
#include <bd.h>

#include "nextfs.h"

/*  
 *  TODO:
 *  How would we handle unlink by client A if client B
 *  has the file open?  Similarly, for umount.
 */

/**************************************
 * TYPES
 **************************************/
struct nextfs_bdconf {
    char *bd_name;           /* required */
    char *bd_imagepath;      /* required */

    char *bd_mtpath;         /* bdverity, bdvericrypt */
    char *bd_macpassword;    /* bdverity, bdvericrypt */
    uint8_t bd_roothash[32]; /* bdverity, bdvericrypt (as bytes, not hexstr)*/

    char *bd_encpassword;    /* bdcrypt, bdvericrypt */
    /* must be either RHO_CIPHER_AES_256_XTS or RHO_CIPHER_AES_256_CBC */
    enum rho_cipher_type bd_cipher;
};

struct nextfs_server {
    struct rho_sock *srv_sock;
    struct rho_ssl_ctx *srv_sc;
    /* TODO: don't hardcode 108 */
    uint8_t srv_udspath[108];
    struct ext4_blockdev *srv_bdp;
};

#define NEXTFS_FTYPE_FILE  1
#define NEXTFS_FTYPE_DIR   2

struct nextfs_file {
    RHO_LIST_ENTRY(nextfs_file) f_next_file;
    union {
        ext4_file   f_file;
        ext4_dir    f_dir;
    };
    int f_ftype;
    int f_refcnt; /* dup*(), and fork() can cuase a nextfs_file to be shared */
    int f_flags;  /* intended for CLOEXEC */
};

/* 
 * defines struct nextfs_file_list
 * (head of list of open files)
 */
RHO_LIST_HEAD(nextfs_file_list, nextfs_file);

struct nextfs_fdtable {
    struct rho_bitmap *ft_map;   /* bitmap of which fd's have been allocated */
    struct nextfs_file **ft_openfiles; /* array of pointers to open files */
};

/*
 * We generally think of a client as an application that is connected;
 * the application has a socket (sock) and file descriptor table (fdtab).
 *
 * However, forking complicates this view.  When a parent forks,
 * it creates a new client, the client has an fdtab, but it's sock is null.
 *
 * When the child connect(2)'s, by virtue of this action, it gets
 * a sturct nextfs_client.  If this is the first client (the equivalent of
 * init) connecting, then we should create an fdtab for it.  If the
 * client is a child, we should "splice" the nextfs_client created
 * during the client's connection with the nextfs_client the parent
 * created for it.
 */
struct nextfs_client {
    RHO_LIST_ENTRY(nextfs_client) cli_next_client;
    struct rpc_agent *cli_agent;
    struct nextfs_fdtable *cli_fdtab;
    uint64_t cli_id;
};

/* 
 * defines struct nextfs_client_list; 
 * (head of list of clients)
 */
RHO_LIST_HEAD(nextfs_client_list, nextfs_client); 

typedef void (*nextfs_opcall)(struct nextfs_client *client);

/**************************************
 * FORWARD DECLARATIONS
 **************************************/

static void nextfs_device_register_proxy(struct nextfs_client *client);
static void nextfs_mount_proxy(struct nextfs_client *client);
static void nextfs_umount_proxy(struct nextfs_client *client);
static void nextfs_mount_point_stats_proxy(struct nextfs_client *client);
static void nextfs_cache_write_back_proxy(struct nextfs_client *client);

static void nextfs_file_remove_proxy(struct nextfs_client *client);
static void nextfs_file_link_proxy(struct nextfs_client *client);
static void nextfs_file_rename_proxy(struct nextfs_client *client);
static void nextfs_file_open_proxy(struct nextfs_client *client);
static void nextfs_file_open2_proxy(struct nextfs_client *client);
static void nextfs_file_close_proxy(struct nextfs_client *client);
static void nextfs_file_truncate_proxy(struct nextfs_client *client);
static void nextfs_file_read_proxy(struct nextfs_client *client);
static void nextfs_file_write_proxy(struct nextfs_client *client);
static void nextfs_file_seek_proxy(struct nextfs_client *client);
static void nextfs_file_tell_proxy(struct nextfs_client *client);
static void nextfs_file_size_proxy(struct nextfs_client *client);
static void nextfs_file_mmap_proxy(struct nextfs_client *client);

static void nextfs_symlink_proxy(struct nextfs_client *client);
static void nextfs_mknod_proxy(struct nextfs_client *client);
static void nextfs_readlink_proxy(struct nextfs_client *client);

static void nextfs_raw_inode_proxy(struct nextfs_client *client);
static void nextfs_mode_set_proxy(struct nextfs_client *client);
static void nextfs_mode_get_proxy(struct nextfs_client *client);
static void nextfs_owner_set_proxy(struct nextfs_client *client);
static void nextfs_owner_get_proxy(struct nextfs_client *client);
static void nextfs_atime_set_proxy(struct nextfs_client *client);
static void nextfs_atime_get_proxy(struct nextfs_client *client);
static void nextfs_mtime_set_proxy(struct nextfs_client *client);
static void nextfs_mtime_get_proxy(struct nextfs_client *client);
static void nextfs_ctime_set_proxy(struct nextfs_client *client);
static void nextfs_ctime_get_proxy(struct nextfs_client *client);

static void nextfs_dir_rm_proxy(struct nextfs_client *client);
static void nextfs_dir_mv_proxy(struct nextfs_client *client);
static void nextfs_dir_mk_proxy(struct nextfs_client *client);
static void nextfs_dir_open_proxy(struct nextfs_client *client);
static void nextfs_dir_close_proxy(struct nextfs_client *client);
static void nextfs_dir_entry_next_proxy(struct nextfs_client *client);
static void nextfs_dir_entry_rewind_proxy(struct nextfs_client *client);
static void nextfs_dir_list_proxy(struct nextfs_client *client);

static void nextfs_fork_proxy(struct nextfs_client *client);
static void nextfs_child_attach_proxy(struct nextfs_client *client);
static void nextfs_new_fdtable_proxy(struct nextfs_client *client);

static int nextfs_file_open(struct nextfs_fdtable *fdtab, 
        const char *path, const char *flags, int *fd);
static int nextfs_file_open2(struct nextfs_fdtable *fdtab, const char *path,
        int flags, int *fd);
static int nextfs_file_close(struct nextfs_fdtable *fdtab, int fd);

static int nextfs_dir_open(struct nextfs_fdtable *fdtab, const char *path);
static int nextfs_dir_close(struct nextfs_fdtable *fdtab, int fd);

static struct nextfs_fdtable * nextfs_fdtable_create(void);
static struct nextfs_fdtable * nextfs_fdtable_copy(
        const struct nextfs_fdtable *fdtab);
static void nextfs_fdtable_destroy(struct nextfs_fdtable *fdtab);
static void nextfs_fdtable_expand(struct nextfs_fdtable *fdtab);
static int nextfs_fdtable_fdalloc(struct nextfs_fdtable *fdtab);
static int nextfs_fdtable_setopenfile(struct nextfs_fdtable *fdtab,
        struct nextfs_file *file);

static void nextfs_client_add(struct nextfs_client *client);
static struct nextfs_client * nextfs_client_find(uint64_t id);

static struct nextfs_client * nextfs_client_alloc(void);
static struct nextfs_client * nextfs_client_create(struct rho_sock *sock);
static void nextfs_client_destroy(struct nextfs_client *client);
static struct nextfs_client * nextfs_client_fork(struct nextfs_client *parent);
static void nextfs_client_splice(struct nextfs_client *a,
        struct nextfs_client *b);

static void nextfs_client_dispatch_call(struct nextfs_client *client);
static void nextfs_client_cb(struct rho_event *event, int what,
        struct rho_event_loop *loop);

static struct nextfs_server * nextfs_server_alloc(void);
static void nextfs_server_destroy(struct nextfs_server *server);
static void nextfs_server_config_ssl(struct nextfs_server *server,
        const char *cafile, const char *certfile, const char *keyfile);
static void nextfs_server_unix_socket_create(struct nextfs_server *server,
        const char *udspath, bool anonymous);
static void nextfs_server_tcp4_socket_create(struct nextfs_server *server,
        short port);
        
static void nextfs_server_open_block_device(struct nextfs_server *server,
        struct nextfs_bdconf *bdconf);
static void nextfs_server_cb(struct rho_event *event, int what,
        struct rho_event_loop *loop);

static void nextfs_bdconf_checkname(const char *bdname);
static struct nextfs_bdconf * nextfs_bdconf_parse(const char *s);
static struct nextfs_bdconf * nextfs_bdconf_default_create(void);
static void nextfs_bdconf_set_imagepath(struct nextfs_bdconf *bdconf,  const char *path);

static void nextfs_log_init(const char *logfile, bool verbose);

static void usage(int exitcode);

/**************************************
 * GLOBALS
 **************************************/

struct rho_log *nextfs_log = NULL;

struct nextfs_client_list nextfs_clients = 
        RHO_LIST_HEAD_INITIALIZER(nextfs_clients);

struct nextfs_file_list nextfs_files = 
        RHO_LIST_HEAD_INITIALIZER(nextfs_files);

static const char *nextfs_valid_bdnames[] = { 
    BDSTD_NAME, BDVERITY_NAME, BDCRYPT_NAME, BDVERICRYPT_NAME, NULL
};

static nextfs_opcall nextfs_opcalls[] = {
    [NEXTFS_OP_DEVICE_REGISTER]     = nextfs_device_register_proxy,
    [NEXTFS_OP_MOUNT]               = nextfs_mount_proxy,
    [NEXTFS_OP_UMOUNT]              = nextfs_umount_proxy,
    [NEXTFS_OP_MOUNT_POINT_STATS]   = nextfs_mount_point_stats_proxy,
    [NEXTFS_OP_CACHE_WRITE_BACK]    = nextfs_cache_write_back_proxy,

    [NEXTFS_OP_FILE_REMOVE]         = nextfs_file_remove_proxy,
    [NEXTFS_OP_FILE_LINK]           = nextfs_file_link_proxy, 
    [NEXTFS_OP_FILE_RENAME]         = nextfs_file_rename_proxy,
    [NEXTFS_OP_FILE_OPEN]           = nextfs_file_open_proxy,
    [NEXTFS_OP_FILE_OPEN2]          = nextfs_file_open2_proxy,
    [NEXTFS_OP_FILE_CLOSE]          = nextfs_file_close_proxy,
    [NEXTFS_OP_FILE_TRUNCATE]       = nextfs_file_truncate_proxy,
    [NEXTFS_OP_FILE_READ]           = nextfs_file_read_proxy,
    [NEXTFS_OP_FILE_WRITE]          = nextfs_file_write_proxy,
    [NEXTFS_OP_FILE_SEEK]           = nextfs_file_seek_proxy,
    [NEXTFS_OP_FILE_TELL]           = nextfs_file_tell_proxy,
    [NEXTFS_OP_FILE_SIZE]           = nextfs_file_size_proxy,

    [NEXTFS_OP_FILE_MMAP]           = nextfs_file_mmap_proxy,

    /* TODO: more inode/stat type operations */
    [NEXTFS_OP_RAW_INODE]           = nextfs_raw_inode_proxy,
    [NEXTFS_OP_MODE_SET]            = nextfs_mode_set_proxy,
    [NEXTFS_OP_MODE_GET]            = nextfs_mode_get_proxy,
    [NEXTFS_OP_OWNER_SET]           = nextfs_owner_set_proxy,
    [NEXTFS_OP_OWNER_GET]           = nextfs_owner_get_proxy,
    [NEXTFS_OP_ATIME_SET]           = nextfs_atime_set_proxy,
    [NEXTFS_OP_ATIME_GET]           = nextfs_atime_get_proxy,
    [NEXTFS_OP_MTIME_SET]           = nextfs_mtime_set_proxy,
    [NEXTFS_OP_MTIME_GET]           = nextfs_mtime_get_proxy,
    [NEXTFS_OP_CTIME_SET]           = nextfs_ctime_set_proxy,
    [NEXTFS_OP_CTIME_GET]           = nextfs_ctime_get_proxy,

    [NEXTFS_OP_SYMLINK]             = nextfs_symlink_proxy,
    [NEXTFS_OP_MKNOD]               = nextfs_mknod_proxy,
    [NEXTFS_OP_READLINK]            = nextfs_readlink_proxy,

    /* TODO: extended attributes */

    [NEXTFS_OP_DIR_RM]              = nextfs_dir_rm_proxy,
    [NEXTFS_OP_DIR_MV]              = nextfs_dir_mv_proxy,
    [NEXTFS_OP_DIR_MK]              = nextfs_dir_mk_proxy,
    [NEXTFS_OP_DIR_OPEN]            = nextfs_dir_open_proxy,
    [NEXTFS_OP_DIR_CLOSE]           = nextfs_dir_close_proxy,
    [NEXTFS_OP_DIR_ENTRY_NEXT]      = nextfs_dir_entry_next_proxy,
    [NEXTFS_OP_DIR_ENTRY_REWIND]    = nextfs_dir_entry_rewind_proxy,
    [NEXTFS_OP_DIR_LIST]            = nextfs_dir_list_proxy,

    /* fork/exec */
    [NEXTFS_OP_FORK]                = nextfs_fork_proxy,
    /* TODO: might want to rename to attach_fdtable */
    [NEXTFS_OP_CHILD_ATTACH]        = nextfs_child_attach_proxy,
    [NEXTFS_OP_NEW_FDTABLE]         = nextfs_new_fdtable_proxy,

};

/**************************************
 * FILE
 **************************************/
static int
nextfs_file_open(struct nextfs_fdtable *fdtab, const char *path,
        const char *flags, int *fd)
{
    int error = 0;
    ext4_file file;
    struct nextfs_file *fp = NULL;

    RHO_TRACE_ENTER();

    error = ext4_fopen(&file, path, flags);
    if (error != 0)
        goto done;

    fp = rhoL_zalloc(sizeof(*fp));
    fp->f_file = file;
    fp->f_ftype = NEXTFS_FTYPE_FILE;
    fp->f_refcnt = 1;
    *fd = nextfs_fdtable_setopenfile(fdtab, fp);
    RHO_LIST_INSERT_HEAD(&nextfs_files, fp, f_next_file);

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
nextfs_file_open2(struct nextfs_fdtable *fdtab, const char *path,
        int flags, int *fd)
{
    int error = 0;
    ext4_file file;
    struct nextfs_file *fp = NULL;

    RHO_TRACE_ENTER();

    error = ext4_fopen2(&file, path, flags);
    if (error != 0)
        goto done;

    fp = rhoL_zalloc(sizeof(*fp));
    fp->f_file = file;
    fp->f_ftype = NEXTFS_FTYPE_FILE;
    fp->f_refcnt = 1;
    *fd = nextfs_fdtable_setopenfile(fdtab, fp);
    RHO_LIST_INSERT_HEAD(&nextfs_files, fp, f_next_file);

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
nextfs_file_close(struct nextfs_fdtable *fdtab, int fd)
{
    int error = 0;
    struct nextfs_file *fp = NULL;

    RHO_TRACE_ENTER();

    if (!rho_bitmap_isset(fdtab->ft_map, fd)) {
        error = EBADF;
        goto done;
    }

    fp = fdtab->ft_openfiles[fd];
    fp->f_refcnt--;

    if (fp->f_refcnt == 0) {
        error = ext4_fclose(&fp->f_file);
        RHO_LIST_REMOVE(fp, f_next_file);
    }

    rho_bitmap_clear(fdtab->ft_map, fd);

done:
    RHO_TRACE_EXIT();
    return (error);
}

/* returns -errno on failure; fd on success */
static int
nextfs_dir_open(struct nextfs_fdtable *fdtab, const char *path)
{
    int error = 0;
    ext4_dir dir;
    struct nextfs_file *fp = NULL;

    RHO_TRACE_ENTER();

    error = ext4_dir_open(&dir, path);
    if (error != 0)
        goto done;

    fp = rhoL_zalloc(sizeof(*fp));
    fp->f_dir = dir;
    fp->f_ftype = NEXTFS_FTYPE_DIR;
    fp->f_refcnt = 1;
    error = nextfs_fdtable_setopenfile(fdtab, fp);
    RHO_LIST_INSERT_HEAD(&nextfs_files, fp, f_next_file);

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
nextfs_dir_close(struct nextfs_fdtable *fdtab, int fd)
{
    int error = 0;
    struct nextfs_file *fp = NULL;

    RHO_TRACE_ENTER();

    if (!rho_bitmap_isset(fdtab->ft_map, fd)) {
        error = EBADF;
        goto done;
    }

    fp = fdtab->ft_openfiles[fd];
    if (fp->f_ftype != NEXTFS_FTYPE_DIR) {
        error = ENOTDIR;
        goto done;
    }

    fp->f_refcnt--;

    if (fp->f_refcnt == 0) {
        error = ext4_dir_close(&fp->f_dir);
        RHO_LIST_REMOVE(fp, f_next_file);
    }

    rho_bitmap_clear(fdtab->ft_map, fd);

done:
    RHO_TRACE_EXIT();
    return (error);
}

/**************************************
 * FDTABLE
 **************************************/

static struct nextfs_fdtable *
nextfs_fdtable_create(void)
{
    struct nextfs_fdtable *fdtab = NULL;

    RHO_TRACE_ENTER();

    fdtab = rhoL_zalloc(sizeof(*fdtab));
    fdtab->ft_map = rho_bitmap_create(true, 20);
    fdtab->ft_openfiles = rhoL_mallocarray(20, sizeof(struct nextfs_file *), 0);

    RHO_TRACE_EXIT();
    return (fdtab);
}

static void
nextfs_fdtable_expand(struct nextfs_fdtable *fdtab)
{
    size_t newmaxbits = 0;
    struct rho_bitmap *map = fdtab->ft_map;

    RHO_TRACE_ENTER();
    
    /* TODO: check for overflow; also, check that this actually
     * expands, since the range of size_t is greater than int
     */
    newmaxbits = rho_bitmap_size(map) + 32;
    rho_bitmap_resize(map, newmaxbits);
    fdtab->ft_openfiles = rhoL_reallocarray(fdtab->ft_openfiles,
            newmaxbits, sizeof(struct nextfs_file), 0);

    RHO_TRACE_EXIT();
}
static struct nextfs_fdtable *
nextfs_fdtable_copy(const struct nextfs_fdtable *fdtab)
{
    struct nextfs_fdtable *newp = NULL;
    struct nextfs_file *fp = NULL;
    size_t fd = 0;
    int bitval = 0;
    size_t n = 0;

    RHO_TRACE_ENTER();

    newp = rhoL_zalloc(sizeof(*newp));
    newp->ft_map = rho_bitmap_copy(fdtab->ft_map);

    n = rho_bitmap_size(fdtab->ft_map);
    newp->ft_openfiles = rhoL_mallocarray(n, sizeof(struct nextfs_file *), 0);

    for (fd = 0; fd < n; fd++) {
        bitval = rho_bitmap_get(fdtab->ft_map, fd);
        if (bitval == 0)
            continue;
        fp = fdtab->ft_openfiles[fd];
        fp->f_refcnt++;
        newp->ft_openfiles[fd] = fp;
    }

    RHO_TRACE_EXIT();
    return (newp);
}

static void
nextfs_fdtable_destroy(struct nextfs_fdtable *fdtab)
{
    size_t fd = 0;
    int bitval = 0;

    RHO_TRACE_ENTER();

    for (fd = 0; fd < rho_bitmap_size(fdtab->ft_map); fd++) {
        bitval = rho_bitmap_get(fdtab->ft_map, fd);
        if (bitval == 0)
            continue;
        nextfs_file_close(fdtab, fd);
    }

    rhoL_free(fdtab->ft_openfiles);
    rho_bitmap_destroy(fdtab->ft_map);
    rhoL_free(fdtab);

    RHO_TRACE_EXIT();
    return;
}

/*
 * Allocate a file descriptor for the client.
 */
static int
nextfs_fdtable_fdalloc(struct nextfs_fdtable *fdtab)
{
    int fd = 0;
    size_t oldmaxbits = 0;
    struct rho_bitmap *map = fdtab->ft_map;

    RHO_TRACE_ENTER();

    /* TODO: you might want some upper limit on how many files a client can
     * have open
     */
    fd = rho_bitmap_ffc(map);
    if (fd == -1) {
        oldmaxbits = rho_bitmap_size(map);
        nextfs_fdtable_expand(fdtab);
        fd = oldmaxbits;
    }

    rho_bitmap_set(fdtab->ft_map, fd);

    RHO_TRACE_EXIT("fd=%d", fd);
    return (fd);
}

/*
 * Create and allocate a file descriptor for the
 * client that refers to it.
 */
static int
nextfs_fdtable_setopenfile(struct nextfs_fdtable *fdtab,
        struct nextfs_file *file)
{
    int fd = 0;

    RHO_TRACE_ENTER();

    fd = nextfs_fdtable_fdalloc(fdtab);
    fdtab->ft_openfiles[fd] = file;

    RHO_TRACE_EXIT("fd=%d", fd);
    return (fd);
}


/**************************************
 * FILESYSTEM RPCs
 **************************************/

static void
nextfs_device_register_proxy(struct nextfs_client *client)
{
    RHO_TRACE_ENTER();
    (void)client;
    RHO_TRACE_EXIT();
}

/* 
 * TODO:
 *  currently, we have main open and configure a block device.
 *
 *  Eventually, we want to move that operation to the mount proxy,
 *  so that the nextfs server can serve different block devices to
 *  different clients.
 *
 * For now, we assume that all clients are mounting the same
 * block device.  We just need to handle a forked child inheriting
 * a fdtable.  It's not clear to me whether mount is the right
 * place to handle this, or if we should make a separate syscall.
 */
static void
nextfs_mount_proxy(struct nextfs_client *client)
{
    struct rpc_agent *agent = client->cli_agent;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, 0);
        
    RHO_TRACE_EXIT();
}

static void
nextfs_umount_proxy(struct nextfs_client *client)
{
    RHO_TRACE_ENTER();
    (void)client;
    RHO_TRACE_EXIT();
}

static void
nextfs_mount_point_stats_proxy(struct nextfs_client *client)
{
    RHO_TRACE_ENTER();
    (void)client;
    RHO_TRACE_EXIT();
}

static void
nextfs_cache_write_back_proxy(struct nextfs_client *client)
{
    RHO_TRACE_ENTER();
    (void)client;
    RHO_TRACE_EXIT();
}

/**************************************
 * FILE RPCs
 **************************************/
static void
nextfs_file_remove_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = ext4_fremove(path);

done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" remove(\"%s\")",
            client->cli_id, path);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_file_link_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    char hardlink_path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_read_u32size_str(buf, hardlink_path,
            sizeof(hardlink_path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = ext4_flink(path, hardlink_path);

done: 
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" link(\"%s\", \"%s\")",
            client->cli_id, path, hardlink_path);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_file_rename_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    char new_path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_read_u32size_str(buf, new_path, sizeof(new_path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = ext4_frename(path, new_path);

done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(nextfs_log, error,
            "id=0x%"PRIx64" rename(\"%s\", \"%s\")",
            client->cli_id, path, new_path, error);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_file_open_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    char flags[NEXTFS_MAX_OPENFLAGS_LENGTH + 1] = { 0 };
    int fd = -1;

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_read_u32size_str(buf, flags, sizeof(flags));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = nextfs_file_open(client->cli_fdtab, path, flags, &fd);

done:
    rpc_agent_new_msg(agent, error);
    if (!error) {
        rpc_agent_set_bodylen(agent, 4);
        rho_buf_writeu32be(buf, fd);
    }

    rho_log_errno_debug(nextfs_log, error,
            "id=0x%"PRIx64" open(\"%s\", \"%s\") -> %d",
            client->cli_id, path, flags, fd);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_file_open2_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    int flags = 0;
    int fd = -1;

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_read32be(buf, &flags);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    error = nextfs_file_open2(client->cli_fdtab, path, flags, &fd);

done:
    rpc_agent_new_msg(agent, error);
    if (!error) {
        rpc_agent_set_bodylen(agent, 4);
        rho_buf_writeu32be(buf, fd);
    }

    rho_log_errno_debug(nextfs_log, error,
            "id=0x%"PRIx64" open2(\"%s\", %d) -> %d",
            client->cli_id, path, flags, fd);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_file_close_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    int fd = -1;

    RHO_TRACE_ENTER();
    
    error = rho_buf_read32be(buf, &fd);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    error = nextfs_file_close(client->cli_fdtab, fd);

done: 
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" close(%d)",
            client->cli_id, fd);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_file_truncate_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct nextfs_fdtable *fdtab = client->cli_fdtab;
    struct nextfs_file *fp = NULL;
    int fd = -1;
    uint64_t size = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, (uint32_t *)&fd);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_readu64be(buf, &size);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    if (!rho_bitmap_isset(fdtab->ft_map, fd)) {
        error = EBADF;
        goto done;
    }

    fp = fdtab->ft_openfiles[fd];
    error = ext4_ftruncate(&fp->f_file, size);

done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(nextfs_log, error,
            "id=0x%"PRIx64" truncate(%d, %"PRIu64")",
            client->cli_id, fd, size);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_file_read_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct nextfs_fdtable *fdtab = client->cli_fdtab;
    struct nextfs_file *fp = NULL;
    int fd = 0;
    uint32_t size = 0;
    size_t rcnt = 0;
    uint8_t *tmp = NULL;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, (uint32_t *)&fd);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_readu32be(buf, &size);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    if (!rho_bitmap_isset(fdtab->ft_map, fd)) {
        error = EBADF;
        goto done;
    }
    fp = fdtab->ft_openfiles[fd];

    /*
     * XXX: we're double buffering for simplicity
     */

    tmp = rhoL_zalloc(size);
    error = ext4_fread(&fp->f_file, tmp, size, &rcnt);

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_errno_debug(nextfs_log, error,
                "id=0x%"PRIx64" read(%d, %"PRIu32")",
                client->cli_id, fd, size);
    } else {
        rho_buf_write(buf, tmp, rcnt);
        rpc_agent_autoset_bodylen(agent);
        rho_log_errno_debug(nextfs_log, error,
                "id=0x%"PRIx64" read(%d, %"PRIu32") -> %zu",
                client->cli_id, fd, size, rcnt);
    }

    if (tmp != NULL)
        rhoL_free(tmp);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_file_write_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct nextfs_fdtable *fdtab = client->cli_fdtab;
    struct nextfs_file *fp = NULL;
    int fd = 0;
    size_t size = 0;
    size_t wcnt = 0;
    uint8_t *tmp = NULL;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, (uint32_t*)&fd);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    if (!rho_bitmap_isset(fdtab->ft_map, fd)) {
        error = EBADF;
        goto done;
    }
    fp = fdtab->ft_openfiles[fd];

    error = rho_buf_readu32be(buf, (uint32_t *)&size);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }
    /*
     * XXX: we're double buffering for simplicity
     */
    tmp = rhoL_malloc(size);
    (void)rho_buf_read(buf, tmp, size);
    error = ext4_fwrite(&fp->f_file, tmp, size, &wcnt);

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" write(%d, %zu)",
            client->cli_id, fd, size);
    } else {
        rpc_agent_set_bodylen(agent, 4);
        rho_buf_writeu32be(buf, wcnt);
        rho_log_errno_debug(nextfs_log, error,"id=0x%"PRIx64" write(%d, %zu) -> %zu",
            client->cli_id, fd, size, wcnt);
    }
    
    if (tmp != NULL)
        rhoL_free(tmp);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_file_seek_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct nextfs_fdtable *fdtab = client->cli_fdtab;
    struct nextfs_file *fp = NULL;
    int fd = 0;
    int64_t offset = 0;
    uint32_t origin = 0;
    uint64_t newoffset = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, (uint32_t *)&fd);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_read64be(buf, &offset);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_readu32be(buf, &origin);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    if (!rho_bitmap_isset(fdtab->ft_map, fd)) {
        error = EBADF;
        goto done;
    }

    fp = fdtab->ft_openfiles[fd];
    error = ext4_fseek(&fp->f_file, offset, origin);
    if (error != 0) {
        goto done;
    }

    newoffset = ext4_ftell(&fp->f_file);

done:
    rpc_agent_new_msg(agent, error);
    if (error != 0) {
        rho_log_errno_debug(nextfs_log, error,
                "id=0x%"PRIx64" seek(%d, %"PRId64", %"PRIu32")",
                client->cli_id, fd, offset, origin);
    } else {
        rpc_agent_set_bodylen(agent, 8);
        rho_buf_writeu64be(buf, newoffset);
        rho_log_errno_debug(nextfs_log, error,
                "id=0x%"PRIx64" seek(%d, %"PRId64", %"PRIu32") -> %"PRIu64")",
                client->cli_id, fd, offset, origin, newoffset);
    }

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_file_tell_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct nextfs_fdtable *fdtab = client->cli_fdtab;
    struct nextfs_file *fp = NULL;
    int fd = 0;
    uint64_t pos = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, (uint32_t *)&fd);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    if (!rho_bitmap_isset(fdtab->ft_map, fd)) {
        error = EBADF;
        goto done;
    }

    fp = fdtab->ft_openfiles[fd];
    pos = ext4_ftell(&fp->f_file);

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" tell(%d)",
            client->cli_id, fd);
    } else {
        rpc_agent_set_bodylen(agent, 8);
        rho_buf_writeu64be(buf, pos);
        rho_log_errno_debug(nextfs_log, error, 
                "id=0x%"PRIx64" tell(%d) -> %"PRIu64")",
                client->cli_id, fd, pos);
    }

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_file_size_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct nextfs_fdtable *fdtab = client->cli_fdtab;
    struct nextfs_file *fp = NULL;
    int fd = 0;
    uint64_t size = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, (uint32_t *)&fd);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }
    
    if (!rho_bitmap_isset(fdtab->ft_map, fd)) {
        error = EBADF;
        goto done;
    }

    fp = fdtab->ft_openfiles[fd];
    size = ext4_fsize(&fp->f_file);

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" size(%d)",
            client->cli_id, fd);
    } else {
        rpc_agent_set_bodylen(agent, 8);
        rho_buf_writeu64be(buf, size);
        rho_log_errno_debug(nextfs_log, error,
                "id=0x%"PRIx64" size(%d) -> %"PRIu64")",
                client->cli_id, fd, size);
    }
    RHO_TRACE_EXIT();
    return;
}

/* XXX: this is essentially a pread(2) */
static void
nextfs_file_mmap_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct nextfs_fdtable *fdtab = client->cli_fdtab;
    struct nextfs_file *fp = NULL;
    int fd = 0;
    uint32_t size = 0;
    uint32_t offset = 0;
    uint64_t  orig_offset;
    size_t rcnt = 0;
    uint8_t *tmp = NULL;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, (uint32_t *)&fd);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_readu32be(buf, &size);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_readu32be(buf, &offset);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    if (!rho_bitmap_isset(fdtab->ft_map, fd)) {
        error = EBADF;
        goto done;
    }
    fp = fdtab->ft_openfiles[fd];


    orig_offset = ext4_ftell(&fp->f_file);

    error = ext4_fseek(&fp->f_file, offset, SEEK_SET);
    if (error != 0)
        goto done;


    tmp = rhoL_zalloc(size);
    error = ext4_fread(&fp->f_file, tmp, size, &rcnt);
    (void)ext4_fseek(&fp->f_file, orig_offset, SEEK_SET);

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_errno_debug(nextfs_log, error,
                "id=0x%"PRIx64" mmap(%d, %"PRIu32", %"PRIu32")",
                client->cli_id, fd, size, offset);
    } else {
        rho_buf_write(buf, tmp, rcnt);
        rpc_agent_autoset_bodylen(agent);
        rho_log_errno_debug(nextfs_log, error,
                "id=0x%"PRIx64" mmap(%d, %"PRIu32", %"PRIu32") -> %zu",
                client->cli_id, fd, size, offset, rcnt);
    }

    if (tmp != NULL)
        rhoL_free(tmp);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_symlink_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char target[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    char linkpath[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, target, sizeof(target));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_read_u32size_str(buf, linkpath, sizeof(linkpath));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = ext4_fsymlink(target, linkpath);

done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(nextfs_log, error,
            "id=0x%"PRIx64" symlink(\"%s\", \"%s\")",
            client->cli_id, target, linkpath);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_mknod_proxy(struct nextfs_client *client)
{
    (void)client;
}

/* 
 * XXX the semantics of the RPC differ slightly from the syscall;
 * the syscall takes a few arguments, whereas the RCP only
 * needs the first argument (`path').  We might have to twiddle
 * things slightly so that the graphene ultimately gets the same
 * semantics as the normal readlink(2) syscall.
 */
static void
nextfs_readlink_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    char outpath[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    size_t rcnt = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = ext4_readlink(path, outpath, NEXTFS_MAX_PATH_LENGTH, &rcnt);
    if (error != 0) {
        goto done;
    }

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" readlink(\"%s\")",
            client->cli_id, path);
    } else {
        rpc_agent_set_bodylen(agent, rcnt + 4);
        /* the body is a len-value string, so as to be consistent
         * with how paths are serialized when they are used as input
         * parameters to the nextfs RPC calls.
         */
        rho_buf_writeu32be(buf, rcnt);
        rho_buf_write(buf, outpath, rcnt);

        rho_log_errno_debug(nextfs_log, error,
                "id=0x%"PRIx64" readlink(\"%s\") -> \"%s\"",
                client->cli_id, path, outpath);
    }
    RHO_TRACE_EXIT();
    return;
}

/**************************************
 * DIRECTORY RPCs
 **************************************/

static void
nextfs_dir_rm_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path)); 
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = ext4_dir_rm(path);

done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" dir_rm(\"%s\")",
        client->cli_id, path);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_dir_mv_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char oldpath[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    char newpath[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, oldpath, sizeof(oldpath));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_read_u32size_str(buf, newpath, sizeof(newpath));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = ext4_dir_mv(oldpath, newpath);

done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" dir_mv(\"%s\", \"%s\")",
        client->cli_id, oldpath, newpath);

    RHO_TRACE_EXIT();
    return;
}

/* TODO: add mode as an argument */
static void
nextfs_dir_mk_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = ext4_dir_mk(path);

done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" dir_mk(\"%s\")",
        client->cli_id, path);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_dir_open_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    int fd = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    /* TODO: should we pass fd as an argument? */
    error = nextfs_dir_open(client->cli_fdtab, path);
    if (error >= 0) {
        fd = error;
        error = 0;
    }

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_debug(nextfs_log, "id=0x%"PRIx64" dir_open(\"%s\") -> (error=%d)",
            client->cli_id, path, error);

    } else {
        rpc_agent_set_bodylen(agent, 4);
        rho_buf_writeu32be(buf, fd);

        rho_log_errno_debug(nextfs_log, error,
                "id=0x%"PRIx64" dir_open(\"%s\") -> %d",
                client->cli_id, path, fd);
    }

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_dir_close_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    int fd = 0;

    RHO_TRACE_ENTER();
    
    error = rho_buf_read32be(buf, &fd);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    error = nextfs_dir_close(client->cli_fdtab, fd);
    
done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" dir_close(%d)",
        client->cli_id, fd, error);

    RHO_TRACE_EXIT();
    return;
}

/*
 * XXX: a direntry represents a directory entry, and is fundamentally
 * a tuple (inode, filename), perhaps with some optional metadata.
 *
 */
static void
nextfs_dir_entry_next_proxy(struct nextfs_client *client)
{
    RHO_TRACE_ENTER();


    /* read fd */

    /* make sure fd is valid and is a directory */


    (void)client;

    RHO_TRACE_EXIT();
}

static void
nextfs_dir_entry_rewind_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct nextfs_fdtable *fdtab = client->cli_fdtab;
    struct nextfs_file *fp = NULL;
    int fd = 0;

    RHO_TRACE_ENTER();
    
    error = rho_buf_read32be(buf, &fd);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    if (!rho_bitmap_isset(fdtab->ft_map, fd)) {
        error = EBADF;
        goto done;
    }
    
    fp = fdtab->ft_openfiles[fd];
    if (fp->f_ftype != NEXTFS_FTYPE_DIR) {
        error = ENOTDIR;
        goto done;
    }

    /* NB: a void return */
    ext4_dir_entry_rewind(&fp->f_dir);

done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" dir_entry_rewind(%d)",
        client->cli_id, fd);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_dir_list_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct nextfs_fdtable *fdtab = client->cli_fdtab;
    struct nextfs_file *fp = NULL;
    int fd = 0;
    const ext4_direntry *direntry = NULL;
    uint32_t n = 0;

    RHO_TRACE_ENTER();
    
    error = rho_buf_read32be(buf, &fd);
    if (error == -1) {
        error = EPROTO;
        goto fail;
    }

    if (!rho_bitmap_isset(fdtab->ft_map, fd)) {
        error = EBADF;
        goto fail;
    }
    
    fp = fdtab->ft_openfiles[fd];
    if (fp->f_ftype != NEXTFS_FTYPE_DIR) {
        error = ENOTDIR;
        goto fail;
    }

    rpc_agent_new_msg(agent, 0);
    rho_buf_seek(buf, 4, SEEK_SET);

    ext4_dir_entry_rewind(&fp->f_dir);
    direntry = ext4_dir_entry_next(&fp->f_dir);
    while (direntry != NULL) {
        if (rho_str_equal((const char *)direntry->name, "."))
            goto next;
        if (rho_str_equal((const char *)direntry->name, ".."))
            goto next;

        n++;
        rho_buf_writeu32be(buf, direntry->inode);
        rho_buf_writeu8(buf, direntry->inode_type);
        rho_buf_writeu32be(buf, direntry->name_length);
        rho_buf_write(buf, direntry->name, direntry->name_length);
        rho_buf_fillu8(buf, (uint8_t)0x00, 255 - direntry->name_length);
next:
        direntry = ext4_dir_entry_next(&fp->f_dir);
    }
    ext4_dir_entry_rewind(&fp->f_dir);
    rho_buf_seek(buf, 0, SEEK_SET);
    rho_buf_writeu32be(buf, n);
    rpc_agent_autoset_bodylen(agent);

    rho_log_errno_debug(nextfs_log, error,
            "id=0x%"PRIx64" dir_list(%d) -> %"PRIu32" entries",
            client->cli_id, fd, n);

    goto succeed;

fail:
    rpc_agent_new_msg(agent, error);
    rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" dir_list(%d)",
        client->cli_id, fd, error);
succeed:
    RHO_TRACE_EXIT();
    return;
}

/**************************************
 * STAT RPCs
 **************************************/

/*
 * XXX: I don't yet know how much of the inode we really need
 * to send back; for now, I choose the fields that seem most useful.
 */
static void
nextfs_raw_inode_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    struct ext4_inode inode;
    uint32_t ret_ino = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    /*
     * TODO: inode has separate fields for hi bits of uid and gid;
     *       add these in
     */
    rho_memzero(&inode, sizeof(inode));
    error = ext4_raw_inode_fill(path, &ret_ino, &inode);
    rho_log_debug(nextfs_log,
            "ext4_raw_inode_fill(\"%s\") returned %d, size_lo=%"PRIu32", size_hi=%"PRIu32,
            path, error, inode.size_lo, inode.size_hi);

done:
    rpc_agent_new_msg(agent, error);
    if (!error) {
        rpc_agent_set_bodylen(agent, 40);
        rho_buf_writeu32be(buf, ret_ino);
        rho_buf_writeu16be(buf, inode.mode);
        rho_buf_writeu16be(buf, inode.uid);
        rho_buf_writeu32be(buf, inode.size_lo);
        rho_buf_writeu32be(buf, inode.access_time);
        rho_buf_writeu32be(buf, inode.change_inode_time);
        rho_buf_writeu32be(buf, inode.modification_time);
        rho_buf_writeu32be(buf, inode.deletion_time);
        rho_buf_writeu16be(buf, inode.gid);
        rho_buf_writeu16be(buf, inode.links_count);
        rho_buf_writeu32be(buf, inode.blocks_count_lo);
        rho_buf_writeu32be(buf, inode.flags);
    }

    rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" raw_inode(\"%s\") size=%ld",
        client->cli_id, path, (long) inode.size_lo);

    RHO_TRACE_ENTER();
    return;
}

static void
nextfs_mode_set_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    uint32_t mode = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_readu32be(buf, &mode);
    if (error == -1) {
        /* tried to read past end of buffer */
        error = EPROTO;
        goto done;
    }

    error = ext4_mode_set(path, mode);

done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(nextfs_log, error,
            "id=0x%"PRIx64" mode_set(\"%s\") -> %d", client->cli_id, path);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_mode_get_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    uint32_t mode = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = ext4_mode_get(path, &mode);

done:
    rpc_agent_new_msg(agent, error);
    if (!error) {
        rpc_agent_set_bodylen(agent, 4);
        rho_buf_writeu32be(buf, mode);
    }

    rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" mode_get(\"%s\")",
        client->cli_id, path);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_owner_set_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    uint32_t uid = 0;
    uint32_t gid = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_readu32be(buf, &uid);
    if (error == -1) {
        /* tried to read past end of buffer */
        error = EPROTO;
        goto done;
    }

    error = rho_buf_readu32be(buf, &gid);
    if (error == -1) {
        /* tried to read past end of buffer */
        error = EPROTO;
        goto done;
    }

    error = ext4_owner_set(path, uid, gid);

done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(nextfs_log, error,
            "id=0x%"PRIx64" owner_set(\"%s\", %"PRIu32", %"PRIu32")",
            client->cli_id, path, uid, gid);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_owner_get_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    uint32_t uid = 0;
    uint32_t gid = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = ext4_owner_get(path, &uid, &gid);

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" owner_get(\"%s\")",
            client->cli_id, path, error);
    } else {
        rpc_agent_set_bodylen(agent, 8);
        rho_buf_writeu32be(buf, uid);
        rho_buf_writeu32be(buf, gid);
        rho_log_errno_debug(nextfs_log, error,
                "id=0x%"PRIx64" owner_get(\"%s\") -> (%"PRIu32", %"PRIu32")",
                client->cli_id, path, uid, gid);
    }
    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_atime_set_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    uint32_t atime = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_readu32be(buf, &atime);
    if (error == -1) {
        /* tried to read past end of buffer */
        error = EPROTO;
        goto done;
    }

    error = ext4_atime_set(path, atime);

done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(nextfs_log, error,
            "id=0x%"PRIx64" atime_set(\"%s\", %"PRIu32")",
            client->cli_id, path, atime);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_atime_get_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    uint32_t atime = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = ext4_atime_get(path, &atime);

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" atime_get(\"%s\")",
            client->cli_id, path);
    } else {
        rpc_agent_set_bodylen(agent, 4);
        rho_buf_writeu32be(buf, atime);
        rho_log_errno_debug(nextfs_log, error,
                "id=0x%"PRIx64" atime_set(\"%s\") -> %"PRIu32,
                client->cli_id, path, atime);
    }
    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_mtime_set_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    uint32_t mtime = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_readu32be(buf, &mtime);
    if (error == -1) {
        /* tried to read past end of buffer */
        error = EPROTO;
        goto done;
    }

    error = ext4_atime_set(path, mtime);

done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(nextfs_log, error,
            "id=0x%"PRIx64" mtime_set(\"%s\", %"PRIu32")",
            client->cli_id, path, mtime);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_mtime_get_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    uint32_t mtime = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = ext4_atime_get(path, &mtime);

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" mtime_get(\"%s\")",
            client->cli_id, path);
    } else {
        rpc_agent_set_bodylen(agent, 4);
        rho_buf_writeu32be(buf, mtime);
        rho_log_errno_debug(nextfs_log, error,
                "id=0x%"PRIx64" mtime_set(\"%s\") -> %"PRIu32,
                client->cli_id, path, mtime);
    }
    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_ctime_set_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    uint32_t ctime = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_readu32be(buf, &ctime);
    if (error == -1) {
        /* tried to read past end of buffer */
        error = EPROTO;
        goto done;
    }

    error = ext4_atime_set(path, ctime);

done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(nextfs_log, error,
            "id=0x%"PRIx64" ctime_set(\"%s\", %"PRIu32")",
            client->cli_id, path, ctime);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_ctime_get_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NEXTFS_MAX_PATH_LENGTH + 1] = { 0 };
    uint32_t ctime = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = ext4_atime_get(path, &ctime);

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" ctime_get(\"%s\")",
            client->cli_id, path);
    } else {
        rpc_agent_set_bodylen(agent, 4);
        rho_buf_writeu32be(buf, ctime);
        rho_log_errno_debug(nextfs_log, error,
                "id=0x%"PRIx64" ctime_get(\"%s\") -> %"PRIu32,
                client->cli_id, path, ctime);
    }
    RHO_TRACE_EXIT();
    return;
}

/**************************************
 * FORK/EXEC RPCs
 **************************************/

/*
 * RPC invoked by parent.
 * Create a nextfs_cilent state for child, and return the child's id.
 */
static void
nextfs_fork_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct nextfs_client *child = NULL;
    uint64_t id = 0;

    RHO_TRACE_ENTER();

    child = nextfs_client_fork(client);
    nextfs_client_add(child);
    id = child->cli_id;

    rpc_agent_new_msg(agent, error);
    rpc_agent_set_bodylen(agent, 8);
    rho_buf_writeu64be(buf, id);

    rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" fork() -> 0x%"PRIx64,
        client->cli_id, id);

    RHO_TRACE_EXIT();
}

/*
 * RPC invoked by child.
 * 
 * Find the nextfs_client that parent created for the child 
 * when the parent invokded the fork RPC.
 */
static void
nextfs_child_attach_proxy(struct nextfs_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint64_t id;
    struct nextfs_client *attachee = NULL;;

    RHO_TRACE_ENTER();

    error = rho_buf_readu64be(buf, &id);
    if (error == -1) {
        /* 
         * TODO: we might want to replace EPROTO with EREMOTEIO,
         * which, I think, is a non-POSIX errno value that Linux uses
         */
        error = EPROTO;
        goto done;
    }

    attachee = nextfs_client_find(id);
    if (attachee == NULL) {
        /* XXX: there might be a more specific errno value for this scenario */
        error = EINVAL;
        goto done;
    }

    nextfs_client_splice(client, attachee);
    
done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(nextfs_log, error, "id=0x%"PRIx64" child_attach()",
        client->cli_id);

    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_new_fdtable_proxy(struct nextfs_client *client)
{
    struct rpc_agent *agent = client->cli_agent;

    RHO_TRACE_ENTER();

    if (client->cli_fdtab != NULL)
        nextfs_fdtable_destroy(client->cli_fdtab);

    client->cli_fdtab = nextfs_fdtable_create();

    rpc_agent_new_msg(agent, 0);

    rho_log_errno_debug(nextfs_log, 0, "id=0x%"PRIx64" new_fdtable()",
        client->cli_id);

    RHO_TRACE_EXIT();
    return;
}

/**************************************
 * CLIENT
 **************************************/

static void
nextfs_client_add(struct nextfs_client *client)
{
    uint64_t id = 0;
    struct nextfs_client *iter = NULL;

    RHO_TRACE_ENTER();

    /* find a unique client id */
    do {
again:
        id = rho_rand_u64();
        RHO_LIST_FOREACH(iter, &nextfs_clients, cli_next_client) {
            if (iter->cli_id == id)
                goto again;
        }
        break;
    } while (1);

    client->cli_id = id;
    RHO_LIST_INSERT_HEAD(&nextfs_clients, client, cli_next_client);

    RHO_TRACE_EXIT();
    return;
}

static struct nextfs_client *
nextfs_client_find(uint64_t id)
{
    struct nextfs_client *iter = NULL;

    RHO_TRACE_ENTER();

    RHO_LIST_FOREACH(iter, &nextfs_clients, cli_next_client) {
        if (iter->cli_id == id)
            goto done;
    }

    iter = NULL;

done:
    RHO_TRACE_EXIT();
    return (iter);
}

/*
 * XXX: 
 *
 * In order to support fork/exec, we need to decouple
 * allocation of the client * from creation of the sock
 * and filedesc, hence the reason for the separate
 * _alloc(), _create(), and _fork() functions.
 */

static struct nextfs_client *
nextfs_client_alloc(void)
{
    struct nextfs_client *client = NULL;

    RHO_TRACE_ENTER();

    client = rhoL_zalloc(sizeof(*client));
    client->cli_agent = rpc_agent_create(NULL, NULL);

    RHO_TRACE_EXIT();
    return (client);
}

static struct nextfs_client *
nextfs_client_create(struct rho_sock *sock)
{
    struct nextfs_client *client = NULL;
    struct rpc_agent *agent = NULL;

    RHO_TRACE_ENTER();

    client = nextfs_client_alloc();
    agent = client->cli_agent;
    agent->ra_sock = sock;

    if (sock->ssl != NULL)
        agent->ra_state = RPC_STATE_HANDSHAKE;
    else
        agent->ra_state = RPC_STATE_RECV_HDR;

    RHO_TRACE_EXIT();
    return (client);
}

static void
nextfs_client_destroy(struct nextfs_client *client)
{
    RHO_ASSERT(client != NULL);

    RHO_TRACE_ENTER();

    rpc_agent_destroy(client->cli_agent);
    if (client->cli_fdtab != NULL)
        nextfs_fdtable_destroy(client->cli_fdtab);
    rhoL_free(client);

    RHO_TRACE_EXIT();
}

static struct nextfs_client *
nextfs_client_fork(struct nextfs_client *parent)
{
    struct nextfs_client *client = NULL;

    RHO_TRACE_ENTER();

    client = nextfs_client_alloc();
    client->cli_fdtab = nextfs_fdtable_copy(parent->cli_fdtab);

    RHO_TRACE_EXIT();
    return (client);
}

/*
 * a is from the child connecing
 * b is from the parent's fork
 *
 * a gets b's filedescriptor table
 * b is deleted
 */
static void
nextfs_client_splice(struct nextfs_client *a, struct nextfs_client *b)
{
    RHO_TRACE_ENTER();

    a->cli_fdtab = b->cli_fdtab;
    b->cli_fdtab = NULL;

    RHO_LIST_REMOVE(b, cli_next_client);
    nextfs_client_destroy(b);

    RHO_TRACE_EXIT();
    return;
};

static void
nextfs_client_dispatch_call(struct nextfs_client *client)
{
    struct rpc_agent *agent = client->cli_agent;
    uint32_t opcode = agent->ra_hdr.rh_code;
    nextfs_opcall opcall = NULL;

    RHO_ASSERT(agent->ra_state == RPC_STATE_DISPATCHABLE);
    RHO_ASSERT(rho_buf_tell(agent->ra_bodybuf) == 0);

    RHO_TRACE_ENTER("fd=%d, opcode=%d", agent->ra_sock->fd, opcode);

    if (opcode >= RHO_C_ARRAY_SIZE(nextfs_opcalls)) {
        rho_log_warn(nextfs_log, "bad opcode (%"PRIu32")", opcode);
        rpc_agent_new_msg(agent, ENOSYS);
        goto done;
    } 

    if ((client->cli_fdtab == NULL) && 
        ((opcode != NEXTFS_OP_NEW_FDTABLE) && (opcode != NEXTFS_OP_CHILD_ATTACH))) {
        rho_log_warn(nextfs_log, 
                "client attempting file operations without an fdtable");
        rpc_agent_new_msg(agent, EPERM);
        goto done;
    }

    opcall = nextfs_opcalls[opcode];
    opcall(client);

done:
    rpc_agent_ready_send(agent);
    RHO_TRACE_EXIT();
    return;
}

static void
nextfs_client_cb(struct rho_event *event, int what, struct rho_event_loop *loop)
{
    int ret = 0;
    struct nextfs_client *client = NULL;
    struct rpc_agent *agent = NULL;

    RHO_ASSERT(event != NULL);
    RHO_ASSERT(event->userdata != NULL);
    RHO_ASSERT(loop != NULL);

    (void)what;

    client = event->userdata;
    agent = client->cli_agent;

    RHO_TRACE_ENTER("fd=%d, what=%08x, state=%s",
            event->fd,
            what,
            rpc_state_to_str(agent->ra_state));
            
    if (agent->ra_state == RPC_STATE_HANDSHAKE) {
        ret = rho_ssl_do_handshake(agent->ra_sock);
        rho_debug("rho_ssl_do_handshake returned %d", ret);
        if (ret == 0) {
            /* ssl handshake complete */
            agent->ra_state  = RPC_STATE_RECV_HDR;
            event->flags = RHO_EVENT_READ;
            goto again;
        } else if (ret == 1) {
            /* ssl handshake still in progress: want_read */
            event->flags = RHO_EVENT_READ;
            goto again;
        } else if (ret == 2) {
            /* ssl handshake still in progress: want_write */
            event->flags = RHO_EVENT_WRITE;
            goto again;
        } else {
            /* an error occurred during the handshake */
            agent->ra_state = RPC_STATE_ERROR; /* not needed */
            goto done;
        }
    }

    if (agent->ra_state == RPC_STATE_RECV_HDR)
        rpc_agent_recv_hdr(agent);

    if (agent->ra_state == RPC_STATE_RECV_BODY) 
        rpc_agent_recv_body(agent);

    if (agent->ra_state == RPC_STATE_DISPATCHABLE)
        nextfs_client_dispatch_call(client);

    if (agent->ra_state == RPC_STATE_SEND_HDR)
        rpc_agent_send_hdr(agent);

    if (agent->ra_state == RPC_STATE_SEND_BODY)
        rpc_agent_send_body(agent);

    if ((agent->ra_state == RPC_STATE_ERROR) ||
            (agent->ra_state == RPC_STATE_CLOSED)) {
        goto done;
    }

again:
    rho_event_loop_add(loop, event, NULL); 
    RHO_TRACE_EXIT("reschedule callback; state=%s", 
            rpc_state_to_str(agent->ra_state));
    return;

done:
    RHO_LIST_REMOVE(client, cli_next_client);
    rho_log_info(nextfs_log, "id=0x%"PRIx64" disconnected", client->cli_id);
    nextfs_client_destroy(client);
    RHO_TRACE_EXIT("client done");
    return;
}

/**************************************
 * SERVER
 **************************************/
static struct nextfs_server *
nextfs_server_alloc(void)
{
    struct nextfs_server *server = NULL;
    server = rhoL_zalloc(sizeof(*server));
    return (server);
}

static void
nextfs_server_destroy(struct nextfs_server *server)
{
    int error = 0;

    if (server->srv_sock != NULL) {
        if (server->srv_udspath[0] != '\0') {
            error = unlink((const char *)server->srv_udspath);
            if (error != 0)
                rho_errno_warn(errno, "unlink('%s') failed", server->srv_udspath);
        }
        rho_sock_destroy(server->srv_sock);
    }

    /* TODO: umount and deregister */

    rhoL_free(server);
}

static void
nextfs_server_config_ssl(struct nextfs_server *server,
        const char *cafile, const char *certfile, const char *keyfile)
{
    struct rho_ssl_params *params = NULL;
    struct rho_ssl_ctx *sc = NULL;

    RHO_TRACE_ENTER("cafile=%s, certfile=%s, keyfile=%s",
            cafile, certfile, keyfile);

    params = rho_ssl_params_create();
    rho_ssl_params_set_mode(params, RHO_SSL_MODE_SERVER);
    rho_ssl_params_set_protocol(params, RHO_SSL_PROTOCOL_TLSv1_2);
    rho_ssl_params_set_private_key_file(params, keyfile);
    rho_ssl_params_set_certificate_file(params, certfile);
    rho_ssl_params_set_ca_file(params, cafile);
    //rho_ssl_params_set_verify(params, true);
    rho_ssl_params_set_verify(params, false);
    sc = rho_ssl_ctx_create(params);
    server->srv_sc = sc;
    rho_ssl_params_destroy(params);

    RHO_TRACE_EXIT();
}

static void
nextfs_server_unix_socket_create(struct nextfs_server *server, const char *udspath,
        bool anonymous)
{
    size_t pathlen = 0;
    struct rho_sock *sock = NULL;

    pathlen = strlen(udspath) + 1;
    if (anonymous) {
        strcpy((char *)(server->srv_udspath + 1), udspath);
        pathlen += 1;
    } else {
        strcpy((char *)server->srv_udspath, udspath);
    }
    
    sock = rho_sock_unixserver_create(server->srv_udspath, pathlen, 5);
    rho_sock_setnonblocking(sock);
    server->srv_sock = sock;
}

static void
nextfs_server_tcp4_socket_create(struct nextfs_server *server, short port)
{
    struct rho_sock *sock = NULL; 
    
    sock = rho_sock_tcp4server_create(NULL, port, 5);
    rho_sock_setnonblocking(sock);
    rhoL_setsockopt_disable_nagle(sock->fd);
    server->srv_sock = sock;
}

/* XXX: lwext4 allows for multiple simulatenously fsimgs, and for
 * multiple mountpoints.  For now, keep things simple and have
 * the server open a single fsimage and mount it at /.  In the future,
 * we can move some of these options to the client.
 */
static void
nextfs_server_open_block_device(struct nextfs_server *server, 
        struct nextfs_bdconf *bdconf)
{
    int error = 0;
    struct ext4_blockdev *bdp = NULL;

    RHO_ASSERT(server != NULL);
    RHO_ASSERT(bdconf != NULL);
    RHO_ASSERT(bdconf->bd_name != NULL);
    RHO_ASSERT(bdconf->bd_imagepath != NULL);

    RHO_TRACE_ENTER("name=%s, imagepath=%s",
            bdconf->bd_name, bdconf->bd_imagepath);

    if (rho_str_equal(bdconf->bd_name, BDSTD_NAME))
        bdp = bdstd_init(bdconf->bd_imagepath);
    else if (rho_str_equal(bdconf->bd_name, BDVERITY_NAME))
        bdp = bdverity_init(bdconf->bd_imagepath, bdconf->bd_mtpath,
                bdconf->bd_macpassword, bdconf->bd_roothash);
    else if (rho_str_equal(bdconf->bd_name, BDCRYPT_NAME))
        bdp = bdcrypt_init(bdconf->bd_imagepath, bdconf->bd_encpassword,
                bdconf->bd_cipher);
    else if (rho_str_equal(bdconf->bd_name, BDVERICRYPT_NAME))
        bdp = bdvericrypt_init(bdconf->bd_imagepath, bdconf->bd_mtpath,
                bdconf->bd_macpassword, bdconf->bd_roothash, 
                bdconf->bd_encpassword, bdconf->bd_cipher);
    else
        rho_die("unknown block device name '%s'\n", bdconf->bd_name);

    rho_log_debug(nextfs_log, "registering block device");
    error = ext4_device_register(bdp, bdconf->bd_imagepath);
    if (error != 0)
        rho_errno_die(error, "ext4_device_register(imagepath='%s') failed",
                bdconf->bd_imagepath);

    rho_log_debug(nextfs_log, "mounting block device");
    error = ext4_mount(bdconf->bd_imagepath, "/", false);
    if (error != 0)
        rho_errno_die(error, "ext4_mount(imagepath='%s', '/', ro=false) failed",
                bdconf->bd_imagepath);

    server->srv_bdp = bdp;
    RHO_TRACE_EXIT();
}

static void
nextfs_server_cb(struct rho_event *event, int what, struct rho_event_loop *loop)
{
    int cfd = 0;
    struct sockaddr_un addr;
    socklen_t addrlen = sizeof(addr);
    struct rho_event *cevent = NULL;
    struct nextfs_client *client = NULL;
    struct nextfs_server *server = NULL;
    struct rho_sock *csock = NULL;

    RHO_ASSERT(event != NULL);
    RHO_ASSERT(loop != NULL);
    RHO_ASSERT(event->userdata != NULL);
    server = event->userdata;

    (void)what;
    //fprintf(stderr, "server callback (fd=%d, what=%08x)\n", event->fd, what);

    cfd = accept(event->fd, (struct sockaddr *)&addr, &addrlen);
    if (cfd == -1)
        rho_errno_die(errno, "accept failed");
    /* TODO: check that addrlen == sizeof struct soackaddr_un */

    if (server->srv_sock->af == AF_UNIX) {
        csock = rho_sock_unix_from_fd(cfd);
    } else {
        /* TCP */
        rhoL_setsockopt_disable_nagle(cfd);
        csock = rho_sock_tcp_from_fd(cfd);
    }
    rho_sock_setnonblocking(csock);

    if (server->srv_sc != NULL)
        rho_ssl_wrap(csock, server->srv_sc);
    client = nextfs_client_create(csock);
    nextfs_client_add(client);
    rho_log_info(nextfs_log, "new connection: id=0x%"PRIx64, client->cli_id);
    /* 
     * XXX: do we have a memory leak with event -- where does it get destroyed?
     */
    cevent = rho_event_create(cfd, RHO_EVENT_READ, nextfs_client_cb, client);
    client->cli_agent->ra_event = cevent;
    rho_event_loop_add(loop, cevent, NULL); 
}

/**************************************
 * BLOCK DEVICE CONFIG
 **************************************/

static void
nextfs_bdconf_checkname(const char *bdname)
{
    const char **npp = NULL;

    for (npp = nextfs_valid_bdnames; *npp != NULL; npp++) {
        if (rho_str_equal(bdname, *npp))
            goto valid;
    }

    rho_die("invalid block device name: '%s'", bdname);

valid:
    return;
}

static struct nextfs_bdconf *
nextfs_bdconf_parse(const char *s)
{
    struct nextfs_bdconf *bdconf = NULL;
    char **toks = NULL;
    size_t n = 0;

    RHO_TRACE_ENTER("s=%s", s);

    bdconf = rhoL_zalloc(sizeof(*bdconf));
    toks = rho_str_splitc(s, ':', &n);
    if (n == 0)
        rho_die("block device not specified");

    bdconf->bd_name = rhoL_strdup(toks[0]);
    nextfs_bdconf_checkname(bdconf->bd_name);

    if (rho_str_equal(bdconf->bd_name, BDVERITY_NAME)) {
        if (n != 4)
            rho_die("block device \"%s\" requires MERKLEFILE:MACPASSWORD:ROOTHASH",
                    BDVERITY_NAME);
        bdconf->bd_mtpath = rhoL_strdup(toks[1]);
        bdconf->bd_macpassword = rhoL_strdup(toks[2]);
        rho_binascii_unhexlify(toks[3], strlen(toks[3]), bdconf->bd_roothash);
    } else if (rho_str_equal(bdconf->bd_name, BDCRYPT_NAME)) {
        if (n != 3)
            rho_die("block device \"%s\" requires ENCPASSWORD:CIPHER", BDCRYPT_NAME);
        bdconf->bd_encpassword = rhoL_strdup(toks[1]);
        if (rho_str_equal_ci(toks[2], "aes-256-xts"))
            bdconf->bd_cipher = RHO_CIPHER_AES_256_XTS;
        else if (rho_str_equal_ci(toks[2], "aes-256-cbc"))
            bdconf->bd_cipher = RHO_CIPHER_AES_256_CBC;
        else
            rho_die("invalid cipher for %s: \"%s\"", BDCRYPT_NAME, toks[2]);
    } else if (rho_str_equal(bdconf->bd_name, BDVERICRYPT_NAME)) {
        if (n != 6)
            rho_die("block device \"%s\" requires MERKELFILE:MACPASSWORD:ROOTHASH:ENCPASSWORD:CIPHER",
                    BDVERICRYPT_NAME);
        bdconf->bd_mtpath = rhoL_strdup(toks[1]);
        bdconf->bd_macpassword = rhoL_strdup(toks[2]);
        rho_binascii_unhexlify(toks[3], strlen(toks[3]), bdconf->bd_roothash);
        bdconf->bd_encpassword = rhoL_strdup(toks[4]);
        if (rho_str_equal_ci(toks[5], "aes-256-xts"))
            bdconf->bd_cipher = RHO_CIPHER_AES_256_XTS;
        else if (rho_str_equal_ci(toks[5], "aes-256-cbc"))
            bdconf->bd_cipher = RHO_CIPHER_AES_256_CBC;
        else
            rho_die("invalid cipher for %s: \"%s\"", BDVERICRYPT_NAME, toks[5]);
    }

    rho_str_array_destroy(toks);

    RHO_TRACE_EXIT();
    return (bdconf);
}

static struct nextfs_bdconf *
nextfs_bdconf_default_create(void)
{
    struct nextfs_bdconf *bdconf = NULL;

    RHO_TRACE_ENTER();

    bdconf = rhoL_zalloc(sizeof(*bdconf));
    bdconf->bd_name = rhoL_strdup(BDSTD_NAME);

    RHO_TRACE_EXIT();
    return (bdconf);
}

static void
nextfs_bdconf_set_imagepath(struct nextfs_bdconf *bdconf, const char *path)
{
    RHO_TRACE_ENTER();

    if (bdconf->bd_imagepath != NULL)
        rhoL_free(bdconf->bd_imagepath);

    bdconf->bd_imagepath = rhoL_strdup(path);
    rho_log_info(nextfs_log, "block device set to \"%s\"", path);

    RHO_TRACE_EXIT();
}

/**************************************
 * LOG
 **************************************/

static void
nextfs_log_init(const char *logfile, bool verbose)
{
    int fd = STDERR_FILENO;

    RHO_TRACE_ENTER();

    if (logfile != NULL) {
        fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT,
                S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH,S_IWOTH);
        if (fd == -1)
            rho_errno_die(errno, "can't open or creat logfile \"%s\"", logfile);
    }

    nextfs_log = rho_log_create(fd, RHO_LOG_INFO, rho_log_default_writer, NULL);

    if (verbose) 
        rho_log_set_level(nextfs_log, RHO_LOG_DEBUG);

    if (logfile != NULL) {
        rho_log_redirect_stderr(nextfs_log);
        (void)close(fd);
    }

    RHO_TRACE_EXIT();
}

#define NEXTFSSERVER_USAGE \
    "usage: nextfsserver [options] IMAGE\n" \
    "\n" \
    "OPTIONS:\n" \
    "\n"\
    " One of -p or -u must be specified.\n" \
    "\n" \
    "   -a\n" \
    "       Treat UDSPATH as an abstract socket\n" \
    "       (adds a leading nul byte to UDSPATH)\n" \
    "\n" \
    "   -b BLOCK_DEVICE[:config]\n" \
    "       The block device to use.  The options are:\n" \
    "           - bdstd\n" \
    "               Vanilla (standard) file block device\n" \
    "\n" \
    "           - bdverity:MERKLEFILE:MACPASSWORD:ROOTHASH\n" \
    "               Verified (integrity-protected) file block device.\n" \
    "               MERKLEFILE is the path to the merkle tree.  The MAC-keys\n"\
    "               for the Merkle tree nodes are derived from MACPASSWORD.\n" \
    "               ROOTHASH is the root node of the tree, as a hex-string.\n" \
    "\n" \
    "           - bdcrypt:ENCPASSWORD:CIPHER\n" \
    "               Encrypted file block device.\n" \
    "               ENCPASSWORD is the password used to encrypt the fs image\n" \
    "               CIPHER is the encryption algorithm to use, and must be \n" \
    "               either aes-256-xts or aes-256-cbc\n" \
    "\n" \
    "           - bdvericrypt:MERKELFILE:MACPASSWORD:ROOTHASH:ENCPASSWORD:CIPHER\n" \
    "               Verified and encrypted file block device.\n" \
    "               The arguments are the union of those for bdverity and\n" \
    "               and bdcrypt.\n" \
    "\n" \
    "       If not specified, uses 'bdstd'.\n" \
    "\n" \
    "   -d\n" \
    "       Daemonize\n" \
    "\n" \
    "   -h\n" \
    "       Show this help message and exit\n" \
    "\n" \
    "   -l LOG_FILE\n" \
    "       Log file to use.  If not specified, logs are printed to stderr.\n" \
    "       If specified, stderr is also redirected to the log file.\n" \
    "\n" \
    "   -p PORT\n" \
    "       Server should listen on TCP address *:PORT \n" \
    "\n" \
    "   -u UNIX_DOMAIN_SOCKET_PATH\n" \
    "       Server should listen on the specified UNIX domain socket.  See\n" \
    "       also the -a flag.\n" \
    "\n" \
    "   -v\n" \
    "       Verbose logging.\n" \
    "\n" \
    "   -Z  CACERT CERT PRIVKEY\n" \
    "       Sets the path to the server certificate file and private key\n" \
    "       in PEM format.  This also causes the server to start SSL mode\n" \
    "\n" \
    "\n" \
    "ARGUMENTS:\n" \
    "   IMAGE\n" \
    "       A path to the image file (file formatted as an ext2/3/4 filesystem\n" \
    "       using lwext4_mkfs)"

static void
usage(int exitcode)
{
    fprintf(stderr, "%s\n", NEXTFSSERVER_USAGE);
    exit(exitcode);
}

int
main(int argc, char *argv[])
{
    int c = 0;
    struct nextfs_server *server = NULL;
    struct rho_event *event = NULL;
    struct rho_event_loop *loop = NULL;
    /* options */
    bool addr_tcp4 = false;
    short port;
    bool addr_unix = false;
    bool anonymous = false;
    const char *udspath = NULL;
    struct nextfs_bdconf *bdconf = NULL;
    bool daemonize  = false;
    const char *logfile = NULL;
    bool verbose = false;

    rho_ssl_init();

    server  = nextfs_server_alloc();
    while ((c = getopt(argc, argv, "ab:dhl:p:vu:Z:")) != -1) {
        switch (c) {
        case 'a':
            anonymous = true;
            break;
        case 'b':
            bdconf = nextfs_bdconf_parse(optarg);
            break;
        case 'd':
            daemonize = true;
            break;
        case 'h':
            usage(EXIT_SUCCESS);
            break;
        case 'l':
            logfile = optarg;
            break;
        case 'p':
            port = rho_str_toshort(optarg, 10);
            addr_tcp4 = true;
            break;
        case 'u':
            udspath = optarg;
            addr_unix = true;
            break;
        case 'v':
            verbose = true;
            break;
        case 'Z':
            /* make sure there's three arguments */
            if ((argc - optind) < 2)
                usage(EXIT_FAILURE);
            nextfs_server_config_ssl(server, optarg, argv[optind], argv[optind + 1]);
            optind += 2;
            break;
        default:
            usage(1);
        }
    }
    argc -= optind;
    argv += optind;

    if (argc != 1)
        usage(EXIT_FAILURE);

    if (!addr_unix && !addr_tcp4) {
        fprintf(stderr, "must specifiy either -p or -u\n");
        exit(EXIT_FAILURE);
    }

    if (addr_unix && addr_tcp4) {
        fprintf(stderr, "must specifiy one of -p or -u, not both\n");
        exit(EXIT_FAILURE);
    }

    if (addr_tcp4 && anonymous) {
        fprintf(stderr, "cannot speicfy -p and -a together\n");
        exit(EXIT_FAILURE);
    }

    if (daemonize)
        rho_daemon_daemonize(NULL, 0);

    nextfs_log_init(logfile, verbose);

    if (bdconf == NULL)
        bdconf = nextfs_bdconf_default_create();

    nextfs_bdconf_set_imagepath(bdconf, argv[0]);

    nextfs_server_open_block_device(server, bdconf);

    if (addr_unix) 
        nextfs_server_unix_socket_create(server, udspath, anonymous);
    else
        nextfs_server_tcp4_socket_create(server, port);

    event = rho_event_create(server->srv_sock->fd, RHO_EVENT_READ | RHO_EVENT_PERSIST, 
            nextfs_server_cb, server); 

    loop = rho_event_loop_create();
    rho_event_loop_add(loop, event, NULL); 
    rho_event_loop_dispatch(loop);

    /* TODO: destroy event and event_loop */

    nextfs_server_destroy(server);
    rho_ssl_fini();

    return (0);
}
