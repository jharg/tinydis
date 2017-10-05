all: tinydis

ARCHS=arm.c sh4.c cr16.c
LOADERS=elf.c ne.c pe.c
MODULES=

tinydis: tinydis.c ${ARCHS} ${LOADERS} ${MODULES}
	gcc -g -o td tinydis.c ${ARCHS} ${LOADERS} ${MODULES} -DTDIS -Wformat=0 

