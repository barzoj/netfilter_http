MODULENAME=nf_http_module

#ccflags-y= -w -Wall

obj-m += nf_http_module.o
nf_http_module-objs+=nf_http_hooks.o nf_http_module_main.o nf_http_analyzer.o

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	sudo insmod $(MODULENAME).ko

uninstall:
	sudo rmmod $(MODULENAME)
