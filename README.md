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
  {"CONNECT",    enabled = true};
  {"DISCONNECT", enabled = true};
}

cli:register(Notifications, function(err, msg)
  print("Register:", err or msg:type())
  cli:notify({
    name = 'CONNECT';
    text = 'User connected';
    title = 'Connect';
  }, function(err, msg)
    print("Notify:", err or msg:type())
  end)
end)
```