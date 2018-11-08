CFLAGS+= -Wall -g -pipe -Werror -Wno-unknown-pragmas
CFLAGS+=  -D_SYS_VMEM_H_ -D_SYS_PROC_H_ -DVM_H -D_SYS_USER_H_
CFLAGS+= -DSYSCONFDIR=
CFLAGS+= -include $(ZFSBASE)/include/os/freebsd/spl/sys/ccompile.h
CFLAGS+= -I/usr/include
CFLAGS+= -I/usr/local/include
CFLAGS+= -I$(ZFSBASE)/lib/libspl/include
CFLAGS+= -I$(ZFSBASE)/include
CFLAGS+= -DTEXT_DOMAIN=\"zfs-linux-user\"
CFLAGS+= -DHAVE_ISSETUGID
CFLAGS+= -DZFS_DEBUG
CFLAGS+= -Wno-enum-conversion
CFLAGS+= -fPIC

DEFAULT_LDFLAGS=   -fstack-protector-strong -shared -Wl,-x -Wl,--fatal-warnings -Wl,--warn-shared-textrel -lm


LDFLAGS+= $(DEFAULT_LDFLAGS)

$(objs): %.o: %.c
	 $(CC) -c $(CFLAGS) $< -o $@

all: $(LIB).so


$(LIB).so: $(objs) $(asm_objs)
	$(CC) $(LDFLAGS) -o $(LIB).so.full -Wl,-soname,$(LIB).so $(objs) $(asm_objs)
	objcopy --only-keep-debug $(LIB).so.full $(LIB).so.debug
	objcopy --strip-debug --add-gnu-debuglink=$(LIB).so.debug  $(LIB).so.full $(LIB).so

clean:
	 rm -f *.o *~ *.so

