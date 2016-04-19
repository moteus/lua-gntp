package.path = "../src/lua/?.lua;" .. package.path

local uv   = require "lluv"
local GNTP = require "gntp"
local uuid = require "uuid"

local options = {
  -- self identify on remote growl server
  name           = 'GNTPSubscriber';
  sid            = uuid.new();

  -- encryption/auth options
  pass           = '123456';
  encrypt        = 'AES';
  hash           = 'SHA256';

  retry_timeout  = 30;

  -- start local growl server to accept notify
  listen_host    = '*';
  listen_port    = '23054';

  -- connect to growl server
  server_host    = '127.0.0.1';
  server_port    = '23053';
}

local function GNTPSubscribe(opt, cb)
  local msg = GNTP.Message.new('SUBSCRIBE', opt.hash, opt.encrypt)
    :add_header('Subscriber-ID',   opt.sid)
    :add_header('Subscriber-Name', opt.sname)
    :add_header('Subscriber-Port', opt.sport or '23053')

  uv.tcp():connect(opt.host or "127.0.0.1", opt.port or 23053, function(cli, err)
    if err then
      cli:close()
      return cb(err)
    end

    local parser = GNTP.Parser.new()
    cli:start_read(function(cli, err, data)
      if err then
        cli:close()
        return cb(err)
      end

      parser:append(data)
      local msg, err = parser:next_message(opt.pass)
      if msg ~= true then
        if msg or err then
          cli:close()
          return cb(err, msg)
        end
      end
    end)

    cli:write(msg:encode(opt.pass), function(cli, err)
      if err then
        cli:close()
        return cb(err)
      end
    end)
  end)
end

local function GNTPListen(opt, cb)
  uv.tcp():bind(opt.host or "127.0.0.1", opt.port or 23053, function(srv, err)
    if err then
      print("SERVER BIND ERROR:", err)
      return uv.stop()
    end

    srv:listen(function()
      local cli, err = srv:accept()
      if cli then
        local parser = GNTP.Parser.new()
        cli:start_read(function(cli, err, data)
          if err then return cli:close() end
          parser:append(data)
          local msg, err = parser:next_message(opt.pass, true)
          if msg == true then return end
          return cb(cli, err, msg)
        end)
      end
    end)
  end)
end

local function OnMessage(cli, err, msg)
  local response = GNTP.Message.new()

  if err then
    print("RECV ERROR:", tostring(err))
    if err:cat() ~= 'GNTP' then
      return cli:close()
    end

    response:set_info('-ERROR')
    if err:name() == 'EAUTH' then
      response
        :add_header('Error-Code', '400')
        :add_header('Error-Description', 'The request supplied a missing or wrong password/key or was otherwise not authorized')
    else
      response
        :add_header('Error-Code', '300')
        :add_header('Error-Description', 'The request contained an unsupported directive, invalid headers or values, or was otherwise malformed')
    end
  else
    response:set_info('-OK', options.hash, options.encrypt)
  end

  if msg then
    response
      :add_header('Notification-ID', msg:header('Notification-ID'))
      :add_header('Response-Action', msg:status())
  end

  local pass = (response:status() == '-OK') and options.pass

  cli:write(response:encode(pass))
end

GNTPListen({
  host = options.listen_host, port = options.listen_port,
  hash = options.hash, encrypt = options.encrypt,
  pass = options.pass .. options.sid
}, OnMessage)

uv.timer():start(function(timer)
  GNTPSubscribe({
    host = options.server_host, port = options.server_port,
    sid = options.sid, pass = options.pass, sname = options.name,
    sport = options.listen_port
  }, function(err, msg)
    if err then
      print("SUBSCRIBE ERROR:", err)
      return timer:again(options.retry_timeout)
    end

    if msg:status() == '-ERROR' then
      print(string.format("Sybscribe error: [%s] %s",
        msg:header('Error-Code') or '----',
        msg:header('Error-Description') or '----'
      ))
      return timer:again(options.retry_timeout)
    end

    if msg:status() == '-OK' then
      local ttl = tonumber(msg:header('Subscription-TTL'))
      if not ttl then
        print("WARNING: no `Subscription-TTL` header in response")
        ttl = 60
      end
      local exp = math.max(ttl - 10, math.floor(0.9 * ttl))
      print(string.format("Subscribe TTL: %d/%d", ttl, exp))
      return timer:again(exp*1000)
    end

    print('ERROR: UNKNOWN RESPONSE')
    print(msg:encode())
    timer:again(options.retry_timeout)
  end)
end)

uv.run()
