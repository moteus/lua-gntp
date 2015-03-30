# lua-lluv-gntp
Implementation of Growl Notify Transport Protocol (GNTP) for lluv library

```Lua
local cli = GNTP.Connector.new{
  host    = '127.0.0.1';
  port    = '23053';
  pass    = '123456';
  encrypt = 'AES';
  hash    = 'SHA256';
}

local Notifications = {
  {name = "CONNECT",    enabled = true};
  {name = "DISCONNECT", enabled = true};
}

cli:register(Notifications, function(self, err, msg)
  print("Register:", err or msg:type())
  self:notify({
    name  = 'CONNECT';
    title = 'Connect';
    text  = 'User connected';
  }, function(self, err, msg)
    print("Notify:", err or msg:type())
  end)
end)
```