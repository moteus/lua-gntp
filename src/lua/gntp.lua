------------------------------------------------------------------
--
--  Author: Alexey Melnichuk <alexeymelnichuck@gmail.com>
--
--  Copyright (C) 2015 Alexey Melnichuk <alexeymelnichuck@gmail.com>
--
--  Licensed according to the included 'LICENSE' document
--
--  This file is part of lua-gntp library.
--
------------------------------------------------------------------

local ut     = require "lluv.utils"
local crypto = require "gntp.crypto"

local _VERSION = '0.1.0'

local EOL = '\r\n'
local EOB = EOL..EOL

local function parse_request_info(line)
  -- GNTP/<version> <messagetype> <encryptionAlgorithmID>[:<ivValue>][ <keyHashAlgorithmID>:<keyHash>.<salt>]

  local version, messageType, encryption, key = string.match(line, "^GNTP/(%d+%.%d+)%s+(%S+)%s+(%S+)%s*(%S-)%s*$")
  local keyHashAlgorithmID, keyHash, salt

  if not version then return nil, "invalid message" end

  encryptionAlgorithmID, ivValue = ut.split_first(encryption, ":", true)

  if key ~= '' then
    keyHashAlgorithmID, keyHash, salt = string.match(key, "^([^:]+):([^.]+)%.(%S+)$")
    if not keyHashAlgorithmID then return nil, "invalid message" end
  end

  return version, messageType, encryptionAlgorithmID, ivValue, keyHashAlgorithmID, keyHash, salt
end

local function build_request_info(version, messageType, encryptionAlgorithmID, ivValue, keyHashAlgorithmID, keyHash, salt)
  local encryption = encryptionAlgorithmID
  if ivValue then
    encryption = encryption .. ":" .. ivValue
  end

  local key
  if keyHashAlgorithmID then
    key = string.format("%s:%s.%s", keyHashAlgorithmID, keyHash, salt)
  end

  local line = "GNTP/" .. version .. " " .. messageType .. " " .. encryption
  if key then line = line .. " " .. key end
  return line
end

local function is_grown_res(val)
  if type(val) ~= 'string' then return end
  return string.match(val, "^x%-growl%-resource://(%S+)%s*$")
end

local function ltrim(s)
  return (string.gsub(s, "^%s+",""))
end

local function rtrim(s)
  return (string.gsub(s, "%s+$",""))
end

local function trim(s)
  return rtrim(ltrim(s))
end

local function hex_encode(str)
  if not str then return nil end
  return (str:gsub(".", function(ch)
    return string.format("%.2X",string.byte(ch))
  end))
end

local function hex_decode(str)
  if not str then return nil end
  return (str:gsub("..", function(ch)
    return string.char(tonumber(ch, 16))
  end))
end

local function make_key(algo, pass, salt)
  local hash = crypto.hash[algo]
  if not hash then return nil, "unsupported hash algorithm:" .. algo end

  local salt = salt or crypto.rand_bytes(8)

  local key = hash.digest(pass .. salt)

  local keyHash = hash.digest(key)

  return keyHash, salt, key
end

local function read_file(fname)
  local f, err = io.open(fname, "rb")
  if not f then return nil, err end
  data = f:read("*all")
  f:close()
  return data
end

local function write_file(fname, data)
  local f, err = io.open(fname, "w+b")
  if not f then return nil, err end
  f:write(data)
  f:close()
  return true
end

local function load_resurce(msg, name)
  if type(name) == "string" and not name:find('^%w+://') then
    -- this is should be file path
    local data, err = read_file(name)
    if not data then return nil, err end
    name = msg:add_resource(data)
  else -- url / GNTPResource
    name = msg:add_resource(name)
  end

  return name
end

local GNTPError = ut.class() do

function GNTPError:__init(no, name, msg, ext)
  self._no     = assert(no)
  self._name   = assert(name or ERRORS[no])
  self._msg    = msg    or ''
  self._ext    = ext    or ''
  self._code   = code   or 1000
  self._reason = reason or ''
  return self
end

function GNTPError:cat()    return 'GNTP'       end

function GNTPError:no()     return self._no     end

function GNTPError:name()   return self._name   end

function GNTPError:msg()    return self._msg    end

function GNTPError:ext()    return self._ext    end

function GNTPError:__tostring()
  local err = string.format("[%s][%s] %s (%d)",
    self:cat(), self:name(), self:msg(), self:no()
  )
  if self:ext() then
    err = string.format("%s - %s", err, self:ext())
  end
  return err
end

function GNTPError:__eq(rhs)
  return self._no == rhs._no
end

end

GNTPError.EPROTO = -1
local function GNTPError_EPROTO(...)
  return GNTPError.new(GNTPError.EPROTO, 'EPROTO', ...)
end

GNTPError.EINVAL = -2
local function GNTPError_EINVAL(...)
  return GNTPError.new(GNTPError.EINVAL, 'EINVAL', ...)
end

GNTPError.EAUTH = -3
local function GNTPError_EAUTH(...)
  return GNTPError.new(GNTPError.EAUTH, 'EAUTH', ...)
end

local GNTPResource = ut.class() do

function GNTPResource:__init(id, data)
  self:_set(id, data)
  return self
end

function GNTPResource:_set(id, data)
  if id and not data then
    data = id
    id = crypto.hash.MD5.digest(data, true)
  end
  self._id   = id
  self._data = data
  return self
end

function GNTPResource.load_from_file(self, name)
  if type(self) == 'string' then
    self, name = GNTPResource.new(), self
  end

  local data, err = read_file(name)
  if not data then return nil, err end
  self:_set(data)
  return self
end

function GNTPResource:save_to_file(name)
  local ok, err = write_file(name, self:data())
  if not ok then return nil, err end
  return self
end

function GNTPResource:id()
  return self._id
end

function GNTPResource:data()
  return self._data
end

function GNTPResource:set(id, data)
  return self:_set(id, data)
end

end

local GNTPMessage = ut.class() do

function GNTPMessage:__init(messageType, keyHashAlgorithmID, encryptionAlgorithmID)
  self._info = {}
  self._headers = {}
  self._notices = {}
  self._resources = {}

  return self:set_info(messageType, keyHashAlgorithmID, encryptionAlgorithmID)
end

local function append_headers(t, headers)
  for k, v in pairs(headers) do
    if k == 'Received' then
      for _, v in ipairs(v) do
        t[#t + 1] = k .. ': ' .. tostring(v) .. EOL
      end
    else
      t[#t + 1] = k .. ': ' .. tostring(v) .. EOL
    end
  end
end

function GNTPMessage:encode(password, keyHashAlgorithmID, encryptionAlgorithmID)
  local encrypt, hashAlgo, encAlgo, keyHash, salt, key, ivValue

  if password and #password > 0 then
    hashAlgo = (keyHashAlgorithmID or self._info.keyHashAlgorithmID or 'MD5'):upper()
    keyHash, salt, key = make_key(hashAlgo, password)
    if not keyHash then return nil, salt end

    encAlgo = (encryptionAlgorithmID or self._info.encryptionAlgorithmID or 'NONE'):upper()
    if encAlgo ~= 'NONE' then
      local enc = crypto.cipher[encAlgo]
      if not enc then
        return nil, GNTPError_EINVAL('unsupported encrypt algorithm: ' .. self._info.encryptionAlgorithmID)
      end

      if #key < enc.key_size then
        return nil, GNTPError_EINVAL('invalid hash algorithm for this type of encryption')
      end

      key     = key:sub(1, enc.key_size)
      ivValue = crypto.rand_bytes(enc.iv_size)
      encrypt = enc.encrypt
    end
  else
    encAlgo, hashAlgo = 'NONE'
  end

  local t = {}

  t[#t + 1] = build_request_info(
    self._info.version,
    self._info.messageType,
    encAlgo, hex_encode(ivValue),
    hashAlgo, hex_encode(keyHash), hex_encode(salt)
  ) .. EOL

  local headers = encrypt and {} or t

  append_headers(headers, self._headers)

  for i = 1, #self._notices do
    local note = self._notices[i]
    headers[#headers + 1] = EOL
    append_headers(headers, note)
  end

  if encrypt then
    t[#t + 1] = encrypt(table.concat(headers), key, ivValue)
    t[#t + 1] = EOL
  end

  if #self._resources > 0 then
    for i = 1, #self._resources do
      t[#t + 1] = EOL
      local res = self._resources[i]
      local dat = res[0]
      if encrypt then
        dat = assert(encrypt(res[0], key, ivValue))
      end

      t[#t + 1] = "Identifier: " .. res.Identifier .. EOL
      t[#t + 1] = "Length: " .. #dat
      t[#t + 1] = EOB

      t[#t + 1] = dat
      t[#t + 1] = EOL
    end
  end

  t[#t + 1] = EOL

  local msg = table.concat(t)

  return msg
end

function GNTPMessage:set_info(messageType, keyHashAlgorithmID, encryptionAlgorithmID)
  self._info.version               = '1.0'
  self._info.messageType           = messageType
  self._info.encryptionAlgorithmID = encryptionAlgorithmID or 'NONE'
  self._info.keyHashAlgorithmID    = keyHashAlgorithmID
  return self
end

function GNTPMessage:add_header(key, value)
  if getmetatable(value) == GNTPResource then
    value = self:add_resource(value)
  end

  self._headers[key] = value
  return self
end

function GNTPMessage:add_resource(id, data)
  if getmetatable(id) == GNTPResource then
    id, data = id:id(), id:data()
  elseif not data then
    data = id
    id   = hex_encode(HASH.MD5:digest(data))
  end

  for i = 1, #self._resources do
    local res = self._resources[i]
    if res.Identifie == id then
      return 'x-growl-resource://' .. id
    end
  end

  local res = {Identifier = id, [0] = data}
  self._resources[#self._resources + 1] = res

  return 'x-growl-resource://' .. id
end

function GNTPMessage:add_notification(opt)
  local note = {
    ['Notification-Name']         = opt.name;    -- Required
    ['Notification-Display-Name'] = opt.display; -- Optional (name)
    ['Notification-Enabled']      = opt.enabled; -- Optional (false)

  }

  if opt.icon then
    note['Notification-Icon'] = load_resurce(self, opt.icon)
  end

  self._notices[#self._notices + 1] = note

  self:add_header('Notifications-Count', #self._notices)
  return self
end

local function _header(self, headers, name)
  local value = headers[name]
  if not value then return end
  local res = is_grown_res(value)
  if res then
    for i = 1, #self._resources do
      local t = self._resources[i]
      if t.Identifier == res then
        return GNTPResource.new(t.Identifier, t[0])
      end
    end
    return
  end
  return value
end

function GNTPMessage:header(name)
  return _header(self, self._headers, name)
end

function GNTPMessage:notification_count()
  return #self._notices
end

function GNTPMessage:notification_header(i, name)
  return _header(self, self._notices[i], name)
end

function GNTPMessage:to_lua_table()
  local res = {
    info          = self._info;
    headers       = {};
    notifications = {};
  }

  for k in pairs(self._headers) do
    res.headers[k] = self:header(k)
  end

  for i = 1, #self._notices do
    res.notifications[i] = {}
    for k in pairs(self._notices[i]) do
      res.notifications[i][k] = self:notification_header(i, k)
    end
  end

  return res
end

function GNTPMessage:status()
  return self._info.messageType
end

function GNTPMessage:auth()
  return not not self._info.keyHashAlgorithmID
end

function GNTPMessage:encrypted()
  return self._info.encryptionAlgorithmID and
    self._info.encryptionAlgorithmID ~= 'NONE'
end

end

local GNTPParser = ut.class() do

function GNTPParser:__init()
  self._buf = ut.Buffer.new('\r\n')
  self:_reset_context()
  return self
end

function GNTPParser:_reset_context()
  self._ctx = {
    state   = 'info';
    headers = {};
    notices = {};
    resources = {n = 0; set = {}};
  }
end

function GNTPParser:append(data)
  self._buf:append(data)
  return self
end

function GNTPParser:_check_res(val)
  local res = is_grown_res(val)
  if res then
   local resources = self._ctx.resources
    if not resources.set[res] then
      local i = resources.n + 1
      resources.set[res] = i
      resources.n = i
    end
  end
  return rtrim(val)
end

function GNTPParser:_skip_trash()
  while true do
    local line = self._buf:read("*l")
    if not line then return end
    if line:find('^GNTP/1%.0') then return line end
  end
end

function GNTPParser:next_message(password)
  local ctx       = self._ctx
  local headers   = ctx.headers
  local notices   = ctx.notices
  local resources = ctx.resources

  if ctx.state == 'info' then
    local line = self:_skip_trash()
    if not line then return true end

    local version, messageType, encryptionAlgorithmID, ivValue,
      keyHashAlgorithmID, keyHash, salt = parse_request_info(line)
    if not version then
      return nil, GNTPError_EPROTO(messageType, line)
    end

    if password then
      if not keyHashAlgorithmID then
        return nil, GNTPError_EAUTH('no password provided')
      end

      local keyHash, salt = hex_decode(keyHash), hex_decode(salt)
      local etalonHash, err, encryptKey = make_key(keyHashAlgorithmID, password, salt)
      if not etalonHash then
        return nil, GNTPError_EAUTH(err, keyHashAlgorithmID)
      end

      if keyHash ~= etalonHash then return nil, "invalid password" end
      if encryptionAlgorithmID ~= 'NONE' and messageType ~= '-ERROR' then
        local enc = crypto.cipher[encryptionAlgorithmID]
        if not enc then
          return nil, GNTPError_EAUTH('unsupported encrypt algorithm: ' .. encryptionAlgorithmID)
        end

        ctx.encrypt_key, ctx.iv = encryptKey, hex_decode(ivValue)
        ctx.decrypt = enc.decrypt
      end
    elseif encryptionAlgorithmID ~= 'NONE' and messageType ~= '-ERROR' then
      return nil, GNTPError_EPROTO('need password to decrypt message')
    end

    ctx.info = {
      version               = version,
      messageType           = messageType,
      encryptionAlgorithmID = encryptionAlgorithmID,
      ivValue               = ivValue,
      keyHashAlgorithmID    = keyHashAlgorithmID,
      keyHash               = keyHash,
      salt                  = salt
    }

    if messageType == 'END' then ctx.state = 'done'
    elseif ctx.decrypt then      ctx.state = 'decrypt'
    else                         ctx.state = 'header' end

  end

  if ctx.state == 'decrypt' then
    local encrypted = self._buf:read_line(EOB)
    if not encrypted then return true end

    local decrypted, err = ctx.decrypt(encrypted, ctx.encrypt_key, ctx.iv)
    if not decrypted then return nil, err end

    self._buf:prepend(EOL):prepend(decrypted)
    ctx.state = 'header'
  end

  while ctx.state == 'header' do
    local line = self._buf:read("*l")
    if not line then return true end

    if line == '' then
      local count = tonumber(headers['Notifications-Count'])
      if count and count > 0 then
        ctx.state = 'notice'
        notices.n = count
        ctx.i     = 1
      elseif resources.n > 0 then
        ctx.state = 'resource'
        ctx.i     = 1
      else ctx.state = 'done' end
      break
    end

    local key, val = ut.split_first(line, "%s*:%s*")
    if not val then
      return nil, GNTPError_EPROTO("invalid header: " .. line)
    end

    if key == 'Received' then
      local t = headers[key] or {}
      t[#t + 1] =  val
      headers[key] = t
    else
      headers[key] = self:_check_res(val)
    end
  end

  if ctx.state == 'notice' then
    while ctx.i <= notices.n do
      local i    = ctx.i
      local note = notices[i] or {}
      notices[i] = note

      while true do
        local line = self._buf:read("*l")
        if not line then return true end
        if line == '' then
          ctx.i = i + 1
          break
        end

        local key, val = ut.split_first(line, "%s*:%s*")
        if not val then
          return nil, GNTPError_EPROTO("invalid header: " .. line)
        end
        note[key] = self:_check_res(val)
      end
    end

    if resources.n > 0 then
      ctx.state = 'resource'
      ctx.i     = 1
    else ctx.state = 'done' end
  end

  if ctx.state == 'resource' then
    while ctx.i <= resources.n do
      local i      = ctx.i
      local res    = resources[i] or {[0] = true}
      resources[i] = res

      if res[0] == true then
        while res[0] == true do
          local line = self._buf:read("*l")
          if not line then return true end
          if line == '' then
            res[0] = nil
            break
          end

          local key, val = ut.split_first(line, "%s*:%s*")
          if not val then return "invalid header: " .. line end

          res[key] = rtrim(val)
        end

        if not res.Identifier then
          return nil, GNTPError_EPROTO("invalid resouce message")
        end

        if not resources.set[res.Identifier] then
          return nil, GNTPError_EPROTO("unknown resource: " .. res.Identifier)
        end

        local size = tonumber(res.Length)
        if not size then
          return nil, GNTPError_EPROTO("invalid header Length:" .. res.Length)
        end

        res.Length = size
      end

      if not res[0] then
        res[0] = self._buf:read(res.Length)
        if not res[0] then return true end
        if ctx.decrypt then
          local decoded, err = ctx.decrypt.digest(res[0], ctx.encrypt_key, ctx.iv)
          if not decoded then return nil, err end
          res[0] = decoded
        end
      end

      local eol = self._buf:read(4)
      if not eol then return true end

      if eol ~= EOB then
        return nil, GNTPError_EPROTO("invalid resource eol")
      end

      res.Length = nil

      ctx.i = i + 1
    end
  end

  ctx.state = 'done'

  local msg = GNTPMessage.new()

  msg._info    = ctx.info
  msg._headers = headers
  for i = 1, #notices do msg._notices[i] = notices[i] end
  for i = 1, #resources do msg._resources[i] = resources[i] end

  self:_reset_context()
  return msg
end

function GNTPParser:reset()
  self._buf:reset()
  self:_reset_context()
  return self
end

end

local MessageBuilder = ut.class() do

function MessageBuilder:__init()
  self._headers = {}
  self._custom  = {}
  return self
end

function MessageBuilder:add_header(key, value)
  self._headers[key] = value
  return self
end

function MessageBuilder:add_custom_header(key, value)
  self._custom[key] = value
  return self
end

function MessageBuilder:remove_custom_header(key)
  return self:add_header(key, nil)
end

function MessageBuilder:remove_header(key)
  return self:add_header(key, nil)
end

function MessageBuilder:header(key)
  return  self._headers[key]
end

function MessageBuilder:custom_header(key)
  return  self._custom[key]
end

function MessageBuilder:append_notify(msg, headers)
  local t = {}
  for k, h in pairs(headers) do
    t[k] = self:header(h)
  end

  t.custom = {}
  for k, v in pairs(self._custom) do
    t.custom[k] = v
  end

  return msg:add_notification(t)
end

function MessageBuilder:append_header(msg, headers)
  for i = 1, #headers do
    local k, v = headers[i], self:header(headers[i])
    if v ~= nil then msg:add_header(k, v) end
  end

  for k, v in pairs(self._custom) do
    if v ~= nil then msg:add_header(k, v) end
  end

  return msg
end

end

local Notification = ut.class(MessageBuilder) do
local base = MessageBuilder

function Notification:__init(note)
  self = base.__init(self)

  if type(note) == 'string' then note = {name = note} end

  local i, name, title, icon = 1
  if note.name  then name  = note.name  else name  = note[i] i = i + 1 end
  if note.title then title = note.title else title = note[i] i = i + 1 end
  if note.icon  then icon  = note.icon  else icon  = note[i] i = i + 1 end

  self
    :add_header('Notification-Name',         name                          )
    :add_header('Notification-Title',        title or name                 )
    :add_header('Notification-Display-Name', note.display or title or name )
    :add_header('Notification-Enabled',      not not note.enabled          )
    :add_header('Notification-Sticky',       note.sticky       or false    )
    :add_header('Notification-Priority',     note.priority     or 0        )
    :add_header('Origin-Machine-Name',       note.machineName              )
    :add_header('Origin-Software-Name',      note.softwareName             )
    :add_header('Origin-Software-Version',   note.softwareVersion          )
    :add_header('Origin-Platform-Name',      note.platformName             )
    :add_header('Origin-Platform-Version',   note.platformVersion          )

  if icon then self:add_header('Notification-Icon', icon) end

  if note.custom then
    for k, v in pairs(note.custom) do
      self:add_custom_header(k, v)
    end
  end

  return self
end

function Notification:append_notify(msg)
  local headers = {
    name            = 'Notification-Name',
    display         = 'Notification-Display-Name',
    enabled         = 'Notification-Enabled',
    icon            = 'Notification-Icon',
  }
  return base.append_notify(self, msg, headers)
end

function Notification:append_header(msg)
  local headers = {
    'Notification-Name',
    'Notification-Title',
    'Notification-Sticky',
    'Notification-Priority',
    'Origin-Machine-Name',
    'Origin-Software-Name',
    'Origin-Software-Version',
    'Origin-Platform-Name',
    'Origin-Platform-Version',
  }
  return base.append_header(self, msg, headers)
end

function Notification:name()
  return self:header('Notification-Name')
end

end

local Application = ut.class(MessageBuilder) do
local base = MessageBuilder

function Application:__init(app)
  self = base.__init(self)
  self._notices = {set = {}}

  if type(app) == 'string' then app = {name = app} end

  self
    :add_header('Application-Name',        app.name or app[1] or "Lua/GNTP" )
    :add_header('Origin-Machine-Name',     app.machineName                  )
    :add_header('Origin-Software-Name',    app.softwareName                 )
    :add_header('Origin-Software-Version', app.softwareVersion              )
    :add_header('Origin-Platform-Name',    app.platformName                 )
    :add_header('Origin-Platform-Version', app.platformVersion              )

  if app.icon then self:add_header('Application-Icon', app.icon) end

  if app.notifications then self:add_notifications(app.notifications) end

  if app.custom then
    for k, v in pairs(app.custom) do
      self:add_custom_header(k, v)
    end
  end

  return self
end

function Application:add_notification(note)
  if getmetatable(note) ~= Notification then
    note = Notification.new(note)
  end

  local no = #self._notices + 1
  self._notices[no] = note
  self._notices.set[note:name()] = no

  return self
end

function Application:add_notifications(notices)
  for i = 1, #notices do
    self:add_notification(notices[i])
  end
end

function Application:get_notification(name)
  local note
  if name then
    local i = self._notices.set[name]
    if not i then return nil, GNTPError_EINVAL('Unknown notification: ' .. name) end
    note = assert(self._notices[i])
  else
    note = assert(self._notices[1])
  end
  return note
end

function Application:append_header(msg)
  local headers = {
    'Application-Name',
    'Application-Icon',
    'Origin-Machine-Name',
    'Origin-Software-Name',
    'Origin-Software-Version',
    'Origin-Platform-Name',
    'Origin-Platform-Version',
  }

  return base.append_header(self, msg, headers)
end

function Application:register(opt)
  local msg = GNTPMessage.new('REGISTER')

  self:append_header(msg)

  for i = 1, #self._notices do
    local note = self._notices[i]
    note:append_notify(msg)
  end

  if opt and opt.custom then
    for name, value in pairs(opt.custom) do
      msg:add_header(name, value)
    end
  end

  return msg
end

local function opt_add(msg, h, v)
  if v ~= nil then msg:add_header(h, v) end
end

function Application:notify(name, opt)
  local msg = GNTPMessage.new('NOTIFY')

  self:append_header(msg)

  if not opt then opt, name = name end
  
  local note, err = self:get_notification(name)
  if not note then return nil, err end

  note:append_header(msg)

  if type(opt) == 'string' then opt = {text = opt} end

  opt_add(msg, 'Notification-Title',                 opt.title            )
  opt_add(msg, 'Notification-Text',                  opt.text or opt[1]   )
  opt_add(msg, 'Notification-ID',                    opt.id               )
  opt_add(msg, 'Notification-Sticky',                opt.sticky           )
  opt_add(msg, 'Notification-Priority',              opt.priority         )
  opt_add(msg, 'Notification-Coalescing-ID',         opt.coalescingID     )
  opt_add(msg, 'Notification-Callback-Context',      opt.callbackContext  )
  opt_add(msg, 'Notification-Callback-Context-Type', opt.callbackType     )
  opt_add(msg, 'Notification-Callback-Target',       opt.callbackTarget   )

  if opt.icon then
    local name, err = load_resurce(msg, opt.icon)
    if not name then return nil, GNTPError_EINVAL(err, opt.icon) end
    msg:add_header("Notification-Icon", name)
  end

  if opt.callback ~= nil then
    if type(opt.callback) == 'boolean' then
      msg
        :add_header('Notification-Callback-Context',      opt.callback )
        :add_header('Notification-Callback-Context-Type', 'boolean'    )
    else
      msg:add_header('Notification-Callback-Target',      opt.callback )
    end
  end

  if opt.custom then
    for name, value in pairs(opt.custom) do
      msg:add_header(name, value)
    end
  end

  return msg
end

end

local Connector = setmetatable({},{
  __index = function(self, name)
    local mod = require("gntp.connector." .. name)
    self.name = mod
    return mod
  end;
})

local GNTP = {
  _VERSION     = _VERSION;
  Resource     = GNTPResource;
  Message      = GNTPMessage;
  Parser       = GNTPParser;
  Application  = Application;
  Notification = Notification;
  Connector    = Connector;

  parse_request_info = parse_request_info;
  hex_decode         = hex_decode;
  hex_encode         = hex_encode;
  make_key           = make_key;
}

return GNTP
