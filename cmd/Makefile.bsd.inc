CFLAGS+= -Wall -g -pipe -Werror -Wno-unknown-pragmas
CFLAGS+=  -D_SYS_VMEM_H_ -D_SYS_PROC_H_ -DVM_H -D_SYS_USER_H_
CFLAGS+= -DSYSCONFDIR=
CFLAGS+= -include $(ZFSBASE)/include/os/freebsd/spl/sys/ccompile.h
CFLAGS+= -I/usr/include
CFLAGS+= -I/usr/local/include
CFLAGS+= -I$(ZFSBASE)/lib/libspl/include
CFLAGS+= -I$(ZFSBASE)/include
#CFLAGS+= -I$(ZFSBASE)/include/os/linux/spl
CFLAGS+= -DTEXT_DOMAIN=\"zfs-linux-user\"

LDFLAGS+= -lm

$(objs): %.o: %.c
	 $(CC) -c $(CFLAGS) $< -o $@

$(PROG): $(objs)
	$(CC) $(LDFLAGS) $(objs) -o $(PROG)

all: $(PROG)


clean:
	 rm -f *.o *~