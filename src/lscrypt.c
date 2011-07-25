#include <lua.h>
#include <lauxlib.h>
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
		char cost_str[36];
		memset( cost_str, '\0', 36 );
		sprintf( cost_str, "%llx$%x$%x$", n, r, p );
		lua_pushstring(L, cost_str);
	}
	return 1;
}

static int lscrypt_crypt(lua_State *L) {
	const char * key = luaL_checkstring(L, 1);
	const char * salt = luaL_checkstring(L, 2);
	const char * cost = luaL_checkstring(L, 3);

	const size_t buffer_size = 256;
	char buffer[buffer_size];
	memset( buffer, '\0', buffer_size );

	uint64_t n = 0;
	uint32_t r = 0;
	uint32_t p = 0;
	sscanf( cost, "%llx$%x$%x$", & n, & r, & p );

	int result = crypto_scrypt(
		(uint8_t *) key, strlen(key),
		(uint8_t *) salt, strlen(salt),
		n, r, p,
		(uint8_t *) buffer, buffer_size
	);

	if (result == 0)
	{
		lua_pushstring(L, buffer);
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
