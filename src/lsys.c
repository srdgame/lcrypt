#define LUA_LIB

#include "lcrypt.h"

#include <unistd.h>
#include <time.h>
#include <ifaddrs.h>

#if defined(__MSYS__) || defined(__CYGWIN__)
  #define __OS__ ("Windows")
#elif defined(__APPLE__)
  #define __OS__ ("Apple")
#elif defined(linux) || defined(__linux) || defined(__linux__)
  #define __OS__ ("Linux")
#elif defined(__OpenBSD__) || defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
  #define __OS__ ("BSD")
#else
  #define __OS__ ("Unix")
#endif

 /* 此方法提供一个精确到微秒级的时间戳 */
static double now(void){
	struct timespec now = {};
	clock_gettime(CLOCK_REALTIME, &now);
	return now.tv_sec + now.tv_nsec * 1e-9;
}

/* 返回当前操作系统类型 */
static const char* os(void) {
  return __OS__;
}

// 提供一个精确到微秒的时间戳
int lnow(lua_State *L){
  lua_pushnumber(L, now());
  return 1;
}

// 提供一个精确到毫秒的时间戳
int ltime(lua_State *L){
  lua_pushinteger(L, (uint64_t)(now() * 1e3));
  return 1;
}

/* 返回当前操作系统类型 */
int los(lua_State *L){
  lua_pushstring(L, os());
  return 1;
}

/* 返回主机名 */
int lhostname(lua_State *L){
  size_t max_hostaname = 4096;
  char *hostname = lua_newuserdata(L, max_hostaname);
  memset(hostname, 0x0, max_hostaname);
  int len = gethostname(hostname, max_hostaname);
  if (0 > len)
    return 0;
  lua_pushlstring(L, hostname, strlen(hostname));
  return 1;
}

