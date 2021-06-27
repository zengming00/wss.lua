#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netdb.h>
#include <linux/netfilter_ipv4.h>
#include "lua.h"
#include "lauxlib.h"

typedef struct Rc4_t {
    char s[256];
    int i, j;
} Rc4_t;

static int keysched(lua_State *L) {
    size_t len;
    const char *key = lua_tolstring(L, 1, &len);
    if (len != 16) {
        lua_pushnil(L);
        lua_pushstring(L, "#key != 16");
        return 2;
    }
    Rc4_t *o = lua_newuserdata(L, sizeof(Rc4_t));
    o->i = o->j = 0;
    char *s = o->s;
    for (int i = 0; i < 256; i++) {
        s[i] = i;
    }
    char tmp;
    for (int j = 0, i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % 16]) & 0xff;
        tmp = s[j];
        s[j] = s[i];
        s[i] = tmp;
    }
    return 1;
}

static int rc4(lua_State *L) {
    Rc4_t *o = lua_touserdata(L, -2);
    size_t len;
    const char *plain = lua_tolstring(L, -1, &len);
    char *buf = malloc(len);
    memcpy(buf, plain, len);

    for (int i = 0; i < len; i++) {
        o->i = (o->i + 1) & 0xff;
        o->j = (o->j + o->s[o->i]) & 0xff;
        char tmp = o->s[o->j];
        o->s[o->j] = o->s[o->i];
        o->s[o->i] = tmp;
        char k = o->s[(o->s[o->i] + o->s[o->j]) & 0xff];
        buf[i] ^= k;
    }
    lua_pushlstring(L, buf, len);
    free(buf);
    return 1;
}

static int getdestaddr(lua_State *L) {
    struct sockaddr_in destaddr;
    socklen_t socklen = sizeof(struct sockaddr_in);
    int error;
    int fd = (int)lua_tonumber(L, 1);

    error = getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &destaddr, &socklen);
    if (error) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }
    lua_pushnumber(L, (lua_Number)destaddr.sin_addr.s_addr);
    lua_pushnumber(L, (lua_Number)destaddr.sin_port);
    return 2;
}

static const struct luaL_Reg wss_clib_funcs[] = {
    {"rc4", rc4},
    {"keysched", keysched},
    {"getdestaddr", getdestaddr},
    {NULL, NULL},
};

LUALIB_API int luaopen_wss_clib(lua_State *L) {
    luaL_register(L, "wss_clib", wss_clib_funcs);
    return 1;
}
