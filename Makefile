all: gcore

gcore: gcore.c
	gcc -O2 -arch ppc -arch i386 -Wall -o $@ $<

gcore64: gcore.c
	gcc -O2 -arch ppc64 -arch x86_64 -Wall -o $@ $<

clean:
	rm -f gcore gcore64
