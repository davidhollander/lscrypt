LUA=$(shell lua -e "print(package.path:match(';(.-)?.lua'))")

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
	mkdir -p $(LUA)lscrypt/
	cp scryptc.so $(LUA)lscrypt/
	cp lscrypt.lua $(LUA)lscrypt/

uninstall:
	rm -r $(LUA)lscrypt/

clean:
	rm *.o *.so
