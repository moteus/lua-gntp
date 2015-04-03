-- Using LuaSocket library to communicate with Growl
local GNTP   = require "lluv.gntp"
local socket = require "socket"

local function gntp_send_recv(msg, pass, host, port)
  local cli, err = socket.connect(host or "127.0.0.1", port or "23053")
  if not cli then return nil, err end

  cli:send(msg:encode(pass))

  local parser, msg, err = GNTP.Parser.new(pass)
  while true do
    msg, err = cli:receive("*l") -- really not safe for binary/data with `\n`
    if not msg then break end
    parser:append(msg):append("\r\n")

    msg, err = parser:next_message()
    if not msg then break end
    if msg ~= true then break end
  end

  cli:close()
  return msg, err
end

local icon = GNTP.Resource.load_from_file('coulson.jpg')

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

local msg, err = gntp_send_recv(reg, "123456")
print(msg:encode())
assert(msg:type() == '-OK')

local msg, err = gntp_send_recv(note, "123456")
print(msg:encode())
assert(msg:type() == '-OK')
