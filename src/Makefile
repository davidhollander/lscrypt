LUAINC= /usr/include/lua5.1
LUALIB= /usr/local/lib/lua/5.1
LUABIN= /usr/bin/

CC= gcc
CFLAGS= $(INCS) $(WARN) -O2 -fPIC $G
#WARN= -ansi -pedantic -Wall
INCS= -I$(LUAINC)
MAKESO= $(CC) -shared

OBJS = crypto_scrypt-ref.o memlimit.o scrypt_calibrate.o lscrypt.o scryptenc_cpuperf.o sha256.o

all: $(OBJS)
	$(MAKESO) -o scryptc.so $(OBJS) -ldl

clean:
	rm *.o *.so
