target = hook_demo
obj-m := $(target).o
KERNELDIR = /lib/modules/`uname -r`/build
default:
	$(MAKE) -C $(KERNELDIR) M=`pwd` modules
install:
	insmod $(target).ko
unstall:
	rmmod $(target).ko
clean:
	rm -rf *.o *.ko *.mod.c
	rm -rf Module.symvers .*cmd .tmp_versions
