local GNTP = require "gntp"

local app = GNTP.Application.new{"GNTP.LUASOCKET",
  notifications = {
    {"General Notification", enabled = true}
  }
}

local cnn = GNTP.Connector.luasocket(app, {pass = '123456'})

msg = assert(cnn:register())
assert(msg:status() == '-OK')

msg1, msg2 = assert(cnn:notify{'Hello from LuaSocket', callback = true})
assert(msg1:status() == '-OK')
assert(msg2:status() == '-CALLBACK')
