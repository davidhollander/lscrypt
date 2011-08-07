#include <lua.h>
#include <lauxlib.h>
#include <string.h>
#include "scrypt_calibrate.h"
#include "crypto_scrypt.h"

static int lscrypt_calibrate(lua_State *L) {

	size_t mm = luaL_checkint(L, 1) * 1024;
	double mf = luaL_checknumber(L, 2);
	double mt = luaL_checknumber(L, 3);

	uint64_t n = 0;
	uint32_t r = 0;
	uint32_t p = 0;
	if (calibrate( mm, mf, mt, & n, & r, & p ) == 0)
	{
		lua_pushnumber(L, n);
		lua_pushnumber(L, r);
		lua_pushnumber(L, p);
		return 3;
	}
	return luaL_error(L, "error");
}

static int lscrypt_crypt(lua_State *L) {
	const char * key = luaL_checkstring(L, 1);
	const char * salt = luaL_checkstring(L, 2);
	uint64_t n = luaL_checknumber(L, 3);
	uint32_t r = luaL_checknumber(L, 4);
	uint32_t p = luaL_checknumber(L, 5);
		
	const size_t buffer_size = 256;
	char buffer[256];

	int result = crypto_scrypt(
		(uint8_t *) key, strlen(key),
		(uint8_t *) salt, strlen(salt),
		n, r, p,
		(uint8_t *) buffer, buffer_size
	);

	if (result == 0)
	{
		lua_pushlstring(L, buffer, buffer_size);
		return 1;
	}
	return luaL_error(L, "error %d \n", result );
}

static const struct luaL_Reg lscrypt_lib[]={
	{"calibrate", lscrypt_calibrate},
	{"crypt", lscrypt_crypt},
	{NULL,NULL},
};

int luaopen_scryptc(lua_State *L) {
	luaL_register(L, "scryptc", lscrypt_lib);
	return 1;
}
