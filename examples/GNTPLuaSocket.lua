-- Using LuaSocket library to communicate with Growl
local GNTP   = require "lluv.gntp"
local socket = require "socket"

local function gntp_send_recv(msg, pass, host, port)
  local cli, err = socket.connect(host or "127.0.0.1", port or "23053")
  if not cli then return nil, err end

  cli:send(msg:encode(pass))

  local parser, msg, err = GNTP.Parser.new(pass), cli:receive("*a")
  cli:close()
  if not msg then return nil, err end

  return parser:append(msg):next_message()
end

local function register_and_notify(reg, note, ...)
  local msg, err = gntp_send_recv(reg, ...)
  print(msg:encode())
  assert(msg:status() == '-OK')

  local msg, err = gntp_send_recv(note, ...)
  print(msg:encode())
  assert(msg:status() == '-OK')
end

do -- Using Low-Level API

local reg = GNTP.Message.new()
  :set_info('REGISTER', 'SHA256', 'AES')
  :add_header("Application-Name", "GNTP.LUASOCKET")
  :add_notification{name = "General Notification", enabled = true}

local note = GNTP.Message.new()
  :set_info('NOTIFY', 'SHA256', 'AES')
  :add_header("Application-Name", "GNTP.LUASOCKET")
  :add_header("Notification-Name", "General Notification")
  :add_header("Notification-Title", "LuaSocket")
  :add_header("Notification-Text", "Hello from LuaSocket")

register_and_notify(reg, note, '123456')

end

do -- Using Application object

local app = GNTP.Application.new{"GNTP.LUASOCKET",
  notifications = {
    {"General Notification", enabled = true}
  }
}

local reg  = app:register()

local note = app:notify('Hello from LuaSocket')

register_and_notify(reg, note, '123456')

end
