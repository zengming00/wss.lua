非常屌炸天的东西

不支持ipv6，需要把路由器关掉ipv6，配置文件在/etc/config.lua

opkg install ipset luabitop luasocket lua-copas lua-coxpcall lua-md5

OpenWrt 21.02.0-rc2 r16122-c2139eef27
ipset         7.6-1
lua-coxpcall  1.17.0-1
lua-copas     2.0.2-1
lua-md5       1.3-1
luabitop      1.0.2-1
luasocket     2019-04-21-733af884-1
lua           5.1.5-8

下载openwrt sdk放到package/wss.lua
make package/wss.lua/compile