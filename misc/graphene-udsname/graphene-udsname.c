#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long HASHTYPE;

#if 0
static void
dump_buf(const char *name, unsigned int len)
{
    unsigned int i = 0;

    for (i = 0; i < len; i++)
        putchar(name[i]);
    putchar('\n');
}
#endif

static unsigned int
fold_hash(unsigned long hash)
{
    hash += hash >> (8*sizeof(int));
    return hash;
}

static uint64_t
hash_one(const char *name, unsigned int len)
{
    unsigned long a = 0;
    unsigned long mask = 0;
    uint64_t hash = 0;

#if 0
    dump_buf(name, len);
#endif

    for (;;) {
        if (len < sizeof(unsigned long)) {
            a = 0;
            while (len) {
                a += *name;
                a <<= 8;
                name++;
                len--;
            }
        } else {
            a = *((unsigned long *) name);
            len -= sizeof(unsigned long);
        }
        hash += a;
        hash *= 9;
        name += sizeof(unsigned long);
        if (!len)
            goto done;
    }
    mask = ~(~0ul << len*8);
    hash += mask & a;
done:
    hash = fold_hash(hash);
    return hash;
}

static int 
__check_sep (int c, const char * sep)
{
    if (!*sep)
        return 0;

    if (!*(sep + 1))
        return c == *sep;

    if (!*(sep + 2))
        return c == *sep || c == *(sep + 1);

    for (const char * t = sep ; *sep ; sep++)
        if (c == *t)
            return 1;

    return 0;
}

static uint64_t
__hash_path (const char * path, int size, const char * sep)
{
    uint64_t hash = 0;
    uint64_t digest = 0;

    const char * next_name = path;
    const char * c = path;
    while (c < path + size && *c) {
        if (__check_sep(*c, sep)) {
            if (next_name < c) {
                hash = hash_one(next_name, c - next_name);
                digest ^= hash;
            }
            next_name = c + 1;
        }
        c++;
    }

    if (next_name < c) {
        hash = hash_one(next_name, c - next_name);
        digest ^= hash;
    }

    return digest;
}

HASHTYPE hash_path (const char * path, int size,
                    const char * sep)
{
    return  __hash_path(path, size, sep ? sep : "/");
} 

int
main(int argc, char *argv[])
{
	HASHTYPE h = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s USDPATH\n", argv[0]);
        exit(1);
    }

	h = hash_path(argv[1], strlen(argv[1]), "/");
	printf("decimal: %lu\n", h);
	printf("hex....: %08lx\n", h);

	return (0);
}
