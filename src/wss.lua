#!/usr/bin/lua

-- 不支持ipv6，需要把路由器关掉ipv6
-- opkg install ipset luabitop luasocket lua-copas lua-coxpcall
--[[
lua-coxpcall	1.17.0-1
lua-copas	2.0.2-1
luabitop	1.0.2-1
luasocket	2019-04-21-733af884-1
lua         5.1.5-8
--]] --
local cfg = dofile('/etc/config.lua')
local redirPort = cfg.redirPort
local udpPort = cfg.udpPort
local socks5Port = cfg.socks5Port
local serverHost = cfg.serverHost
local serverPort = cfg.serverPort
local password = cfg.password

local copas = require('copas')
local socket = require('socket')
local bit = require('bit')
local md5 = require('md5')
local clib = require('wss_clib')

local rshift, lshift, band = bit.rshift, bit.lshift, bit.band
local bxor, bor = bit.bxor, bit.bor
local b, ch = string.byte, string.char

-- 读出查询的DNS域名
local function parseDNSData(data)
    if type(data) == 'table' then
        local id = data[1] * 256 + data[2] -- BigEndian Uint16
        local v = data[3] * 256 + data[4] -- BigEndian Uint16
        if band(rshift(v, 15), 0x1) == 0 then -- QR
            if band(rshift(v, 11), 0xF) == 0 then -- OPCODE
                local i = 13
                local str = {}
                while data[i] ~= 0 do
                    local tmp, len = {}, data[i]
                    for ii = 1, len do
                        tmp[#tmp + 1] = string.char(data[i + ii])
                    end
                    i = i + 1 + len
                    str[#str + 1] = table.concat(tmp)
                end
                return {id = id, domain = table.concat(str, '.')}
            end
        end
    elseif type(data) == 'string' then
        local id = data:byte(1) * 256 + data:byte(2) -- BigEndian Uint16
        local v = data:byte(3) * 256 + data:byte(4) -- BigEndian Uint16
        if band(rshift(v, 15), 0x1) == 0 then -- QR
            if band(rshift(v, 11), 0xF) == 0 then -- OPCODE
                local i = 13
                local str = {}
                while data:byte(i) ~= 0 do
                    local len = data:byte(i)
                    i = i + 1
                    str[#str + 1] = data:sub(i, i + len)
                    i = i + len
                end
                return {id = id, domain = table.concat(str, '.')}
            end
        end
    end
    print('parseDNSData err:', type(data))
    return nil
end

-- 纯lua实现的rc4
local function keysched(key)
    assert(#key == 16) -- key must be a 16-byte string
    local s = {}
    local j, ii, jj
    for i = 0, 255 do s[i + 1] = i end
    j = 0
    for i = 0, 255 do
        ii = i + 1
        j = band((j + s[ii] + b(key, (i % 16) + 1)), 0xff)
        jj = j + 1
        s[ii], s[jj] = s[jj], s[ii]
    end
    return s
end

local function step(s, i, j)
    i = band((i + 1), 0xff)
    local ii = i + 1
    j = band((j + s[ii]), 0xff)
    local jj = j + 1
    s[ii], s[jj] = s[jj], s[ii]
    local k = s[band((s[ii] + s[jj]), 0xff) + 1]
    return s, i, j, k
end

local function newRc4(key)
    local s, i, j = keysched(key), 0, 0
    return function(plain)
        local k
        local t = {}
        for n = 1, #plain do
            s, i, j, k = step(s, i, j)
            t[n] = ch(bxor(b(plain, n), k))
        end
        return table.concat(t)
    end
end

local function newRc42(key)
    local s = clib.keysched(key)
    return function(plain) return clib.rc4(s, plain) end
end

--------------------------------------------------------------------------------

local function binToUint16Le(s) return b(s, 1) + lshift(b(s, 2), 8) end
local function binToUint16Be(s) return lshift(b(s, 1), 8) + b(s, 2) end

local function tabToStr(list)
    local tmp = {}
    for index, value in ipairs(list) do tmp[#tmp + 1] = string.char(value) end
    return table.concat(tmp)
end

local function strToTab(s)
    local tmp = {}
    for i = 1, #s, 1 do tmp[#tmp + 1] = s:byte(i) end
    return tmp
end

local function hexdump(s)
    local t = strToTab(s)
    local str = {
        '1', '2', '3', '4', '5', '6', '7', '8', '9', --
        'A', 'B', 'C', 'D', 'E', 'F'
    }
    str[0] = '0'
    for i, v in ipairs(t) do t[i] = str[rshift(v, 4)] .. str[band(v, 0xF)] end
    print(table.concat(t, ','))
end

local function readWebSocketMessageHeader(c)
    local v = c:receive(2) -- v的大小为两个字节
    if v == nil then return nil end
    v = binToUint16Le(v)
    return {
        opcode = band(v, 0xF), -- 4 bit
        rsv = band(rshift(v, 4), 0x7), -- 3 bit
        fin = band(rshift(v, 7), 0x1), -- 1 bit
        payloadLength = band(rshift(v, 8), 0x7f), -- 7 bit
        mask = band(rshift(v, 15), 0x1) -- 1 bit
    }
end

local function writeWebSocketMessageHeader(c, header)
    local opcode = band(header.opcode, 0xF) -- 4 bit
    local rsv = lshift(band(header.rsv, 0x7), 4) -- 3 bit
    local fin = lshift(band(header.fin, 0x1), 7) -- 1 bit

    local payloadLength = band(header.payloadLength, 0x7f) -- 7 bit
    local mask = lshift(band(header.mask, 0x1), 7) -- 1 bit
    local data = tabToStr {bor(opcode, rsv, fin), bor(payloadLength, mask)}
    return c:send(data)
end

local function WebSocketMessageUnmaskPayload(payload, mask)
    local t1 = strToTab(payload)
    local t2 = strToTab(mask)
    for i = 1, #t1 do t1[i] = bxor(t1[i], t2[(i - 1) % 4 + 1]) end
    return tabToStr(t1)
end

local function readWebSocketMessage(c, header)
    local num = 2 -- 消息的总大小(2字节header)
    local payloadLength = header.payloadLength
    if payloadLength == 127 then
        -- local v = assert(c:receive(8)) -- uint64
        -- num = num + 8 + ntoh64(v)
        -- 暂不支持过大的消息(超过65535字节)
        return nil, 'header.payloadLength == 127'

    elseif payloadLength == 126 then
        local v = assert(c:receive(2)) -- uint16
        payloadLength = binToUint16Be(v)
        num = num + 2 + payloadLength
    else
        num = num + payloadLength
    end

    local mask
    if header.mask == 1 then
        num = num + 4
        print("mask payload")
        mask = assert(c:receive(4))
    end
    local payload = assert(c:receive(payloadLength))
    if header.mask == 1 then
        payload = WebSocketMessageUnmaskPayload(payload, mask)
        print(payload)
    end
    return {num = num, payload = payload, payloadLength = payloadLength}
end

local function sendWebSocketMessage(c, data)
    local header = {
        opcode = 0x02, -- 4 bit
        rsv = 0, -- 3 bit
        fin = 1, -- 1 bit
        payloadLength = 0, -- 7 bit
        mask = 1 -- 1 bit 发送必需是1
    }
    --[[
    if mask ~= nil then
        data = WebSocketMessageUnmaskPayload(data, mask) -- 由于发送的掩码为0时还是原数据，所以没必要
        header.mask = 1
    end
    --]]
    local n, err
    local payloadLength = #data
    if payloadLength < 126 then
        header.payloadLength = payloadLength
        n, err = writeWebSocketMessageHeader(c, header)
        if n == nil then return n, err end

    elseif payloadLength <= 65535 then
        header.payloadLength = 126
        n, err = writeWebSocketMessageHeader(c, header)
        if n == nil then return n, err end

        local t = {rshift(payloadLength, 8), band(payloadLength, 0xff)}
        n, err = c:send(tabToStr(t))
        if n == nil then return n, err end

    elseif payloadLength > 65535 then
        return nil, "send message too long, max message length is 65535"
    end

    -- if mask ~= nil then assert(c:send(mask)) end
    n, err = c:send('\0\0\0\0') -- 发送掩码 0
    if n == nil then return n, err end
    return c:send(data)
end

local connectServer, addToIpset, newWS

-- 开机启动时可能还没网
addToIpset = function(serverHost)
    local ip, t = socket.dns.toip(serverHost)
    if ip ~= nil then
        local r = os.execute('ipset test ss_spec_wan_ac ' .. ip ..
                                 ' >>/dev/null 2>&1')
        -- 返回0表示在里面
        if r == 0 then return true end
        for key, value in pairs(t.ip) do --
            os.execute('ipset add ss_spec_wan_ac ' .. value)
        end
        return true
    end
    return nil, 'addToIpset err'
end

newWS = function(api, onData)
    local skt = assert(socket.connect(serverHost, serverPort))
    skt:settimeout(0) -- important: make it non-blocking

    local c = copas.wrap(skt)
    local key = 'FUlPm8DgS00JN1dxsQapFg==' -- 16 byte 应该是随机字节，这里简化为固定
    local header = {
        'GET ' .. api .. ' HTTP/1.1\r\n', --
        'Host: ' .. serverHost .. ':' .. serverPort .. '\r\n', --
        'Connection: Upgrade\r\n', --
        'Upgrade:websocket\r\n', --
        'Sec-WebSocket-Key: ' .. key .. '\r\n', --
        'Sec-WebSocket-Version: 13\r\n', --
        '\r\n'
    }
    assert(c:send(table.concat(header)))

    local line = assert(c:receive("*l"))
    while line ~= "" do
        -- print('"' .. line .. '"')
        line = assert(c:receive("*l"))
    end

    key = md5.sum(password)
    local enc = newRc42(key)
    local dec = newRc42(key)

    local function send(data)
        data = enc(data)
        return sendWebSocketMessage(c, data)
    end

    local function recv()
        while true do
            local header = readWebSocketMessageHeader(c)
            if header == nil then break end
            local m = assert(readWebSocketMessage(c, header))
            -- print(m.num, m.payloadLength)

            if header.opcode == 0x02 then -- binary frame
                -- print("[opcode]binary frame")
                local data = dec(m.payload)
                onData(data)

            elseif header.opcode == 0x01 then -- text frame
                print("[opcode]text frame", m.payload)

            elseif header.opcode == 0x08 then -- connection close
                -- print("[opcode]connection close")
                break
            elseif header.opcode == 0x09 then -- ping
                print("[opcode]ping")
            elseif header.opcode == 0x0A then -- pong
                print("[opcode]pong")
            elseif header.opcode == 0x00 then -- continuation frame
                print("[opcode]continuation frame")
            else -- reserved
                print("[opcode]reserved: " .. header.opcode)
            end
            -- print('---------------------------')
            collectgarbage()
        end
    end
    copas.addthread(recv)
    return send
end

connectServer = function(api, onData)
    local r, err = addToIpset(serverHost)
    if r then
        connectServer = newWS
        return newWS(api, onData)
    end
    return nil, err
end

local function tcpRemote(rawc, wrapc, head)
    local send = connectServer('/t', function(data) wrapc:send(data) end)
    if send == nil then return end
    send(head)

    while true do
        local data, err, partial = rawc:receive(1024) -- 注意不是包装过的c
        if data == nil then
            data = partial
            if err == 'timeout' then
                copas.sleep(1)
            elseif err == 'closed' then
                break
            end
        end
        if #data ~= 0 then
            local n, err = send(data)
            if n == nil and err == 'closed' then break end
        end
    end
end

local function socks5Handler(rawc)
    local c = copas.wrap(rawc)
    local r = assert(c:receive(3))
    if b(r, 1) ~= 5 then
        print('socks5 version err')
        return
    end
    c:send("\5\0")

    r = assert(c:receive(3))
    if (b(r, 1) ~= 5) or (b(r, 2) ~= 1) then
        print("only support connect cmd")
        c:send("\05\07\00\01\00\00\00\00\00\00")
        return
    end
    c:send("\05\00\00\01\00\00\00\00\00\00")

    --------------------------------------------------------
    local head = {}
    r = assert(c:receive(1));
    table.insert(head, r)

    local atype = b(r, 1)
    local dstAddr = ""
    if atype == 3 then -- domain
        r = assert(c:receive(1));
        table.insert(head, r)

        local dstAddrLen = b(r, 1)
        dstAddr = assert(c:receive(dstAddrLen))
        table.insert(head, dstAddr)

    elseif atype == 1 then -- ipv4
        dstAddr = assert(c:receive(4))
        table.insert(head, dstAddr)

        local t = strToTab(dstAddr)
        dstAddr = table.concat(t, '.')
    else
        print('Unsupported address type!')
        return
    end
    local dstPort = assert(c:receive(2))
    table.insert(head, dstPort)
    head = table.concat(head)

    dstPort = b(dstPort, 1) * 256 + b(dstPort, 2)
    print('Target is ' .. dstAddr .. ' port is ' .. dstPort, #head)
    tcpRemote(rawc, c, head)
end

copas.addserver(assert(socket.bind('*', socks5Port)), socks5Handler)

local function tcpHandler(rawc)
    local c = copas.wrap(rawc)
    local ip, port = assert(clib.getdestaddr(rawc:getfd()))
    --[[
    local t = {
        bit.rshift(ip, 24), --
        bit.band(bit.rshift(ip, 16), 0xff), --
        bit.band(bit.rshift(ip, 8), 0xff), --
        bit.band(ip, 0xff) --
    }
    print(table.concat(t, '.') .. ":" .. port)
    --]]
    local socks5Head = {
        '\1', -- atype
        ch(band(rshift(ip, 24), 0xff)), --
        ch(band(rshift(ip, 16), 0xff)), --
        ch(band(rshift(ip, 8), 0xff)), --
        ch(band(ip, 0xff)), --
        ch(band(rshift(port, 8), 0xff)), -- port_h
        ch(band(port, 0xff)) -- port_l
    }
    tcpRemote(rawc, c, table.concat(socks5Head))
end

copas.addserver(assert(socket.bind('*', redirPort)), tcpHandler)

local function udpHandler()
    local udpServer = assert(socket.udp())
    assert(udpServer:setsockname("*", udpPort))

    local s = copas.wrap(udpServer)
    local nat = {}

    local function onData(data)
        local id = data:byte(1) * 256 + data:byte(2) -- BigEndian Uint16
        local r = nat[id]
        if r then
            -- print('dns resp:', id, #data, r.ip, r.port)
            s:sendto(data, r.ip, r.port)
        end
    end

    local send, n, err = nil, nil, 'closed'
    while true do
        while true do
            local data, ip, port = s:receivefrom() -- 默认8k
            if data == nil then
                print("Receive error: ", ip)
                break -- 因为没有continue语句
            end

            local id = data:byte(1) * 256 + data:byte(2) -- BigEndian Uint16
            nat[id] = {ip = ip, port = port}

            if send ~= nil then n, err = send(data) end
            if n == nil and err == 'closed' then
                send = connectServer('/u', onData)
                if send == nil then break end
                send(data)
            end
            --[[
            local r = parseDNSData(data)
            if r then
                print('query dns:', id, #data, ip, port, r.domain)
            else
                print('query dns:', id, #data, ip, port, '<err>')
            end
            --]]
        end
    end
end

copas.addthread(udpHandler)

copas.loop()
