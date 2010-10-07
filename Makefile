include arm_env.mk

# Snow Leopard has left ppc64 behind
UNI_ARCH=-arch i386 -arch x86_64 -arch ppc #-arch ppc64 

gcore: gcore_uni
	mv gcore_uni gcore

gcore_uni: gcore.c
	gcc -O2 $(UNI_ARCH) -Wall -o $@ $<

gcore_arm: gcore.c
	$(GCC_ARM) -o $@ $<

clean:
	rm -f gcore gcore_uni gcore_arm *.o 
