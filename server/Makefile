INCLUDES=$(HOME)/include
STATIC_LIBS= $(addprefix $(HOME)/lib/, librpc.a libbd.a librho.a liblwext4.a)

CPPFLAGS= -I $(INCLUDES)
#CFLAGS= -Wall -Werror -Wextra -DRHO_DEBUG -DRHO_TRACE
CFLAGS= -Wall -Werror -Wextra
LDFLAGS= $(STATIC_LIBS) -lssl -lcrypto -lpthread

OBJS = nextfsserver.o

nextfsserver: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

nextfsserver.o: nextfsserver.c nextfs.h

clean:
	rm -f nextfsserver $(OBJS)

.PHONY: clean
