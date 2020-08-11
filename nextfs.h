#ifndef _NEXTFS_H__
#define _NEXTFS_H_

/*
 * REQUEST TYPES
 *
 * XXX: We can probably pair this down.  Some requests,
 * like NEXTFS_OP_DIR_LIST and NEXTFS_OP_DIR_MKDIR, are
 * conveniences in the sense that they make two or more
 * lwext4 function calls, whereas most RCPS map directly
 * to a single lwext4 function.
 */

#define NEXTFS_OP_DEVICE_REGISTER       0
#define NEXTFS_OP_MOUNT                 1
#define NEXTFS_OP_UMOUNT                2
#define NEXTFS_OP_MOUNT_POINT_STATS     3
#define NEXTFS_OP_CACHE_WRITE_BACK      4

#define NEXTFS_OP_FILE_REMOVE           5
#define NEXTFS_OP_FILE_LINK             6
#define NEXTFS_OP_FILE_RENAME           7
#define NEXTFS_OP_FILE_OPEN             8
#define NEXTFS_OP_FILE_OPEN2            9
#define NEXTFS_OP_FILE_CLOSE            10
#define NEXTFS_OP_FILE_TRUNCATE         11
#define NEXTFS_OP_FILE_READ             12
#define NEXTFS_OP_FILE_WRITE            13
#define NEXTFS_OP_FILE_SEEK             14
#define NEXTFS_OP_FILE_TELL             15
#define NEXTFS_OP_FILE_SIZE             16

#define NEXTFS_OP_DIR_RM                17
#define NEXTFS_OP_DIR_MV                18
#define NEXTFS_OP_DIR_MK                19
#define NEXTFS_OP_DIR_MKDIR             20
#define NEXTFS_OP_DIR_OPEN              21
#define NEXTFS_OP_DIR_CLOSE             22
#define NEXTFS_OP_DIR_ENTRY_NEXT        23
#define NEXTFS_OP_DIR_ENTRY_REWIND      24
#define NEXTFS_OP_DIR_LIST              25

#define NEXTFS_OP_SYMLINK               26
#define NEXTFS_OP_MKNOD                 27
#define NEXTFS_OP_READLINK              28

#define NEXTFS_OP_RAW_INODE             29
#define NEXTFS_OP_MODE_SET              30
#define NEXTFS_OP_MODE_GET              31
#define NEXTFS_OP_OWNER_SET             32
#define NEXTFS_OP_OWNER_GET             33
#define NEXTFS_OP_ATIME_SET             34
#define NEXTFS_OP_ATIME_GET             35
#define NEXTFS_OP_MTIME_SET             36
#define NEXTFS_OP_MTIME_GET             37
#define NEXTFS_OP_CTIME_SET             38
#define NEXTFS_OP_CTIME_GET             39

#define NEXTFS_OP_FORK                  40
#define NEXTFS_OP_CHILD_ATTACH          41
#define NEXTFS_OP_NEW_FDTABLE           42

#define NEXTFS_OP_FILE_MMAP             43

/*
 * LIMITS
 */

#define NEXTFS_MAX_PATH_LENGTH          255
#define NEXTFS_MAX_OPENFLAGS_LENGTH     3

#endif /* _NEXTFS_H_ */
