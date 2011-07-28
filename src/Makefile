LUALIB=$(shell lua -e "print(package.path:match(';(.-)?.lua'))")
CLIB=$(shell lua -e "print(package.path:match ';([^;]+lib[^?]+)?')")

CC= gcc
CFLAGS= $(INCS) $(WARN) -O2 -fPIC $G
#WARN= -ansi -pedantic -Wall
INCS= -I$(LUAINC)
MAKESO= $(CC) -shared

OBJS = crypto_scrypt-ref.o memlimit.o scrypt_calibrate.o lscrypt.o scryptenc_cpuperf.o sha256.o

all: $(OBJS)
	$(MAKESO) -o scryptc.so $(OBJS) -ldl

test:
	lua test.lua

install:
	cp scryptc.so $(CLIB)
	cp lscrypt.lua $(LUALIB)

uninstall:
	rm $(LUALIB)lscrypt.lua
	rm $(CLIB)scryptc.so

clean:
	rm *.o *.so
