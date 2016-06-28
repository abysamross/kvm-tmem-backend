obj-m += ktb.o

#ktb-objs := tmem.o ktb_main.o ktb-radix-tree.o ktb_rbtree.o
ktb-objs := network_client.o network_server.o bloom_filter.o remote.o tmem.o ktb_main.o 

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

