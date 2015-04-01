# lua-lluv-gntp
Implementation of Growl Notify Transport Protocol (GNTP) for lluv library

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

local growl = GNTP.Connector.new(app, {
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