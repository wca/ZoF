KERNEL_H = \
	$(top_srcdir)/include/spl/sys/debug.h \
	$(top_srcdir)/include/spl/sys/kstat.h \
	$(top_srcdir)/include/spl/sys/procfs_list.h \
	$(top_srcdir)/include/spl/sys/sunddi.h

if CONFIG_KERNEL
kerneldir = @prefix@/src/zfs-$(VERSION)/include/spl/sys
kernel_HEADERS = $(KERNEL_H)
endif
