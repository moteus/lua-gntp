# lua-gntp
[![Build Status](https://travis-ci.org/moteus/lua-gntp.svg?branch=master)](https://travis-ci.org/moteus/lua-gntp)
[![Coverage Status](https://coveralls.io/repos/moteus/lua-gntp/badge.svg)](https://coveralls.io/r/moteus/lua-gntp)
[![License](http://img.shields.io/badge/License-MIT-brightgreen.svg)](LICENSE)

Implementation of Growl Notify Transport Protocol (GNTP) for Lua

### Make common GNTP objects
```Lua
local icon = GNTP.Resource.load_from_file('coulson.jpg')

local app = GNTP.Application.new{'LLUV_GNTP', icon = icon,
  notifications = {
    { 'CONNECT',
      title   = 'ConnectTitle',
      display = 'ConnectDisplay',
      enabled = true,
      icon    = icon
    };
    { 'DISCONNECT',
      title   = 'DisconnectTitle',
      display = 'DisconnectDisplay',
      enabled = true,
      icon    = icon
    };
  }
}
```

### Using lluv async connector
```Lua
local growl = GNTP.Connector.lluv(app, {
  host    = '127.0.0.1';
  port    = '23053';
  pass    = '123456';
  encrypt = 'AES';
  hash    = 'SHA256';
})

growl:register(function(self, err, msg)
  print(err or msg:encode())
  growl:notify('CONNECT', 'User connected',
    function(self, err, msg)
      print(err or msg:encode())
    end
  )
end)
```

### Using LuaSocket sync connector
```Lua
local growl = GNTP.Connector.luasocket(app, {
  host    = '127.0.0.1';
  port    = '23053';
  pass    = '123456';
  encrypt = 'AES';
  hash    = 'SHA256';
})

local msg, err = growl:register()
print(err or msg:encode())

local msg1, msg2 = growl:notify('CONNECT', {'User connected', callback = true})
if not msg1 then print(msg2)
else
  print(msg1:encode())
  print(msg2 and msg2:encode())
end
```