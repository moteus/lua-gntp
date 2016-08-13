------------------------------------------------------------------
--
--  Author: Alexey Melnichuk <alexeymelnichuck@gmail.com>
--
--  Copyright (C) 2015-2016 Alexey Melnichuk <alexeymelnichuck@gmail.com>
--
--  Licensed according to the included 'LICENSE' document
--
--  This file is part of lua-gntp library.
--
------------------------------------------------------------------

local GNTP   = require "gntp"
local ut     = require "gntp.utils"

local Connector = ut.class() do

function Connector:__init(app, opt)
  if getmetatable(app) ~= GNTP.Application then
    app = GNTP.Application.new(app)
  end

  opt = opt or {}

  self._host    = opt.host     or "127.0.0.1"
  self._port    = opt.port     or "23053"
  self._enc     = opt.encrypt  or 'NONE'
  self._hash    = opt.hash     or 'MD5'
  self._pass    = opt.pass     or ''
  self._timeout = opt.timeout
  self._create  = opt.create   or require "socket".tcp

  self._app     = app

  return self
end

function Connector:_send(msg)
  local cli = self._create()

  if self._timeout then
    cli:settimeout(self._timeout)
  end

  local ok, err = cli:connect(self._host, self._port)
  if not cli then return nil, err end

  cli:send(msg:encode(self._pass, self._hash, self._enc))

  local parser, msg, err = GNTP.Parser.new(pass), cli:receive("*a")
  cli:close()

  if not msg then return nil, err end
  parser:append(msg)

  local unpack = unpack or table.unpack
  local res = {}
  while true do
    msg, err = parser:next_message()
    if not msg then return nil, err, unpack(res) end
    if msg == true then return unpack(res) end
    res[#res + 1] = msg
  end
end

function Connector:register(...)
  local msg, err = self._app:register(...)
  if not msg then return nil, err end

  return self:_send(msg, true, cb)
end

function Connector:notify(...)
  local msg, err = self._app:notify(...)
  if not msg then return nil, err end

  return self:_send(msg, true, cb)
end

end

return setmetatable({
  new = Connector.new
},{__call = function(self, ...)
  return self.new(...)
end})
