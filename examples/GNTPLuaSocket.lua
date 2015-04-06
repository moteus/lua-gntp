-- Using LuaSocket library to communicate with Growl
local GNTP   = require "lluv.gntp"
local ut     = require "lluv.utils"
local socket = require "socket"

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
  self._app     = app

  return self
end

function Connector:_send(msg)
  local cli = socket.tcp()

  if socket._timeout then
    cli:settimeout(socket._timeout)
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

local app = GNTP.Application.new{"GNTP.LUASOCKET",
  notifications = {
    {"General Notification", enabled = true}
  }
}

local cnn = Connector.new(app, {pass = '123456'})

msg = assert(cnn:register())
assert(msg:status() == '-OK')

msg1, msg2 = assert(cnn:notify{'Hello from LuaSocket', callback = true})
assert(msg1:status() == '-OK')
assert(msg2:status() == '-CALLBACK')
