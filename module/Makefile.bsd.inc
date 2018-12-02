CFLAGS = -D_KERNEL -D__KERNEL__  
CFLAGS+= -O0 -DZFS_DEBUG  -DKMEM_DEBUG
CFLAGS+=  -D_SYS_VMEM_H_ -DFREEBSD_NAMECACHE -DBUILDING_ZFS 

CFLAGS+= -Wall -g
CFLAGS+= -nostdinc -fno-common -fno-builtin -Wno-unknown-pragmas
CFLAGS+= -fno-strict-aliasing -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer
CFLAGS+= -MD -mcmodel=kernel  -mno-red-zone -mno-mmx -mno-sse -msoft-float
CFLAGS+= -fno-asynchronous-unwind-tables -ffreestanding -fwrapv -fstack-protector
# remove once zfs_ioctl.c is fixed
#CFLAGS+= -Wno-unused-function
CFLAGS+= -DKLD_MODULE -DHAVE_UIO_ZEROCOPY -DHAVE_KSID
CFLAGS+= -Werror
CFLAGS+= -I$(ZFSBASE)/include
CFLAGS+= -I$(ZFSBASE)/include/spl
CFLAGS+= -I$(ZFSBASE)/include/os/freebsd/spl
CFLAGS+= -I$(ZFSBASE)/include/os/freebsd/zfs
CFLAGS+= -I$(KERNBASE)/sys
CFLAGS+= -I$(ZFSBASE)/include/os/freebsd/internal
CFLAGS+= -include $(ZFSBASE)/include/os/freebsd/spl/sys/ccompile.h
CFLAGS+= -pipe
CFLAGS+= -DINVARIANTS -DWITNESS

$(objs): %.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f *.o *~ *.a *.ko
