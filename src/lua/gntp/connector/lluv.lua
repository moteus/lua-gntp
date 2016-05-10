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

local GNTP = require "gntp"
local uv   = require "lluv"
local ut   = require "gntp.utils"

local Connector = ut.class() do

local EOF = uv.error('LIBUV', uv.EOF)

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
  self._app     = app

  return self
end

function Connector:_send(msg, only_last, cb)
  local parser = GNTP.Parser.new()
  local timer, last_msg, encoded

  local cli = uv.tcp():connect(self._host, self._port, function(cli, err)
    if err then
      cli:close()
      return cb(self, err)
    end

    cli:write(encoded)
    cli:start_read(function(cli, err, data)
      if err then
        cli:close()
        if timer then timer:close() end
        if err == EOF then cb(self, nil, last_msg) else cb(self, err) end
        return
      end

      local resp, err = parser:append(data):next_message()

      if resp == true then return end

      if not resp then
        cli:close()
        if timer then timer:close() end
        return cb(self, err)
      end

      if only_last then
        if resp:status() == 'END' then
          cb(self, nil, last_msg)
          last_msg = nil
        else
          last_msg = resp
        end
      else
        cb(self, nil, resp)
      end
    end)
  end)

  local err
  encoded, err = msg:encode(self._pass, self._hash, self._enc)
  if not encoded then
    cli:close()
    uv.defer(cb, self, err)
  end

  if self._timeout then
    timer = uv.timer():start(self._timeout, function()
      timer:close()
      cli:close()
      cb(self, "timeout")
    end)
  end

end

function Connector:register(opt, cb)
  if type(opt) == 'function' then opt, cb = nil, opt end

  local msg = self._app:register(opt)

  self:_send(msg, true, cb)
end

local function opt_add(msg, h, v)
  if v ~= nil then msg:add_header(h, v) end
end

function Connector:notify(name, opt, cb)
  if type(opt) == 'function' then cb, opt = opt end

  local msg, err = self._app:notify(name, opt)
  if not msg then uv.defer(cb, self, err)
  else self:_send(msg, true, cb) end
end

end

return setmetatable({
  new = Connector.new
},{__call = function(self, ...)
  return self.new(...)
end})
