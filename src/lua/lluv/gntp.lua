------------------------------------------------------------------
--
--  Author: Alexey Melnichuk <alexeymelnichuck@gmail.com>
--
--  Copyright (C) 2015 Alexey Melnichuk <alexeymelnichuck@gmail.com>
--
--  Licensed according to the included 'LICENSE' document
--
--  This file is part of lua-lluv-gntp library.
--
------------------------------------------------------------------

local uv     = require "lluv"
local ut     = require "lluv.utils"
local pp     = require "pp"

local ok, OpenSSL = pcall(require, "openssl")
if not ok then OpenSSL = nil end

local HASH, ENCRYPT do
  if not OpenSSL then HASH, ENCRYPT = {}, {} else
    local Cipher = OpenSSL.cipher
    local Digest = OpenSSL.digest

    HASH = {
      MD5    = Digest.get('MD5');
      SHA1   = Digest.get('SHA1');
      SHA256 = Digest.get('SHA256');
      SHA512 = Digest.get('SHA512');
    }

    ENCRYPT = {
      AES = {
        encoder = function(key, iv)
          return Cipher.new('AES-192-CBC', true, key, iv, true)
        end;
        key_size    = 24;
        block_size  = 16;
        iv_size     = 16;
      };
      DES = {
        encoder = function(key, iv)
          return Cipher.new('DES-CBC', true, key, iv, true)
        end;
        key_size    = 8;
        block_size  = 8;
        iv_size     = 8;
      };
      ['3DES'] = {
        encoder = function(key, iv)
          return Cipher.new('DES3', true, key, iv, true)
        end;
        key_size    = 24;
        block_size  = 8;
        iv_size     = 8;
      };
    }
  end
end

local rand_bytes do
  if OpenSSL then
    rand_bytes = OpenSSL.random
  else
    rand_bytes = function (n)
      local r = {}
      for i = 1, n do
        r[#r + 1] = string.char(math.random(0, 0xFF))
      end
      return table.concat(r)
    end
  end
end

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
  local hash = HASH[algo]
  if not hash then return nil, "unsupported hash algorithm:" .. algo end

  local salt = salt or rand_bytes(8)

  local key = hash:digest('123456' .. salt)

  local keyHash = hash:digest(key)

  return keyHash, salt, key
end

local GNTPMessage = ut.class() do

function GNTPMessage:__init()
  self._info = {}
  self._headers = {}
  self._notices = {}
  self._resources = {}

  return self
end

local function append_headers(t, headers)
  for k, v in pairs(headers) do t[#t + 1] = k .. ': ' .. tostring(v) end
end

function GNTPMessage:encode(password)
  local hashAlgo, keyHash, salt, key = self._info.keyHashAlgorithmID
  local ivValue, encrypter

  if password and #password > 0 then
    if not hashAlgo then hashAlgo = 'MD5' end
    keyHash, salt, key = make_key(hashAlgo, password)
    if not keyHash then return nil, salt end

    if self._info.encryptionAlgorithmID ~= 'NONE' then
      local enc = ENCRYPT[self._info.encryptionAlgorithmID]
      if not enc then
        return nil, 'unsupported encrypt algorithm: ' .. self._info.encryptionAlgorithmID
      end

      if #key < enc.key_size then
        return nil, 'invalid hash algorithm for this type encryption'
      end

      key = key:sub(1, enc.key_size)
      ivValue = rand_bytes(enc.iv_size)

      encrypter = enc.encoder(key, ivValue)
    end
  else hashAlgo = nil  end

  local t = {}

  t[#t + 1] = build_request_info(
    self._info.version,
    self._info.messageType,
    self._info.encryptionAlgorithmID,
    hex_encode(ivValue),
    hashAlgo, hex_encode(keyHash), hex_encode(salt)
  )

  append_headers(t, self._headers)
  t[#t + 1] = ''

  for i = 1, #self._notices do
    local note = self._notices[i]
    append_headers(t, note)
    t[#t + 1] = ''
  end

  for i = 1, #self._resources do
    local res = self._resources[i]
    t[#t + 1] = "Identifier: " .. res.Identifier
    t[#t + 1] = "Length: " .. #res[0]
    t[#t + 1] = ''
    t[#t + 1] = res[0]
    t[#t + 1] = ''
  end

  if encrypter then
    local encrypted = {}
    for i = 2, #t do
      encrypted[#encrypted + 1] = encrypter:update(t[i])
      encrypted[#encrypted + 1] = encrypter:update('\r\n')
    end
    encrypted[#encrypted + 1] = encrypter:final()
    return t[1] .. "\r\n" .. table.concat(encrypted) .. "\r\n\r\n"
  end

  t[#t + 1] = ''

  return table.concat(t, '\r\n')
end

function GNTPMessage:set_info(messageType, keyHashAlgorithmID, encryptionAlgorithmID)
  self._info.version               = '1.0'
  self._info.messageType           = messageType
  self._info.encryptionAlgorithmID = encryptionAlgorithmID or 'NONE'
  self._info.keyHashAlgorithmID    = keyHashAlgorithmID
  return self
end

function GNTPMessage:type()
  return self._info.messageType
end

function GNTPMessage:add_header(key, value)
  self._headers[key] = value
  return self
end

function GNTPMessage:add_resource(id, data)
  if not data then id, data = md5_digest(id), id end
  --! @todo check for recource duplicate
  local res = {Identifier = id, [0] = data}
  self._resources[#self._resources + 1] = res
  return 'x-growl-resource://' .. id
end

function GNTPMessage:add_notification(name, enabled)
  local note = {
    ['Notification-Name'] = name,
    ['Notification-Enabled'] = enabled,
  }
  self._notices[#self._notices + 1] = note

  self:add_header('Notifications-Count', #self._notices)
  return self
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

function GNTPParser:next_message()
  local ctx       = self._ctx
  local headers   = ctx.headers
  local notices   = ctx.notices
  local resources = ctx.resources

  if ctx.state == 'info' then
    local line = self._buf:read("*l")
    if not line then return true end

    local version, messageType, encryptionAlgorithmID, ivValue,
      keyHashAlgorithmID, keyHash, salt = parse_request_info(line)
    if not version then return nil, messageType end

    ctx.info = {
      version               = version,
      messageType           = messageType,
      encryptionAlgorithmID = encryptionAlgorithmID,
      ivValue               = ivValue,
      keyHashAlgorithmID    = keyHashAlgorithmID,
      keyHash               = keyHash,
      salt                  = salt
    }

    if messageType == 'END' then
      ctx.state = 'done'
    else
      ctx.state = 'header'
    end
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
    if not val then return "invalid header: " .. line end
    headers[key] = self:_check_res(val)
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
        if not val then return "invalid header: " .. line end
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
          return nil, "invalid resouce message"
        end

        if not resources.set[res.Identifier] then
          return nil, "unknown resource: " .. res.Identifier
        end

        local size = tonumber(res.Length)
        if not size then
          return nil, "invalid header Length:" .. res.Length
        end

        res.Length = size
      end

      if not res[0] then
        res[0] = self._buf:read(res.Length)
        if not res[0] then return true end
      end

      local eol = self._buf:read(4)
      if not eol then return true end

      if eol ~= '\r\n\r\n' then
        return nil, "invalid resource eol"
      end

      assert(res.Length == #res[0])
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

end

local Connector = ut.class() do

local EOF = uv.error('LIBUV', uv.EOF)

function Connector:__init(opt)
  self._host = opt.host     or "127.0.0.1"
  self._port = opt.port     or "23053"
  self._name = opt.name     or "lua-lluv-gntp"
  self._enc  = opt.encrypt  or 'NONE'
  self._hash = opt.hash     or 'MD5'
  self._pass = opt.pass     or ''

  return self
end

function Connector:_send(msg, only_last, cb)
  local parser = GNTPParser.new()
  local last_msg, encoded

  uv.tcp():connect(self._host, self._port, function(cli, err)
    if err then
      cli:close()
      return cb(err)
    end

    cli:write(encoded)
    cli:start_read(function(cli, err, data)
      if err then
        cli:close()
        if err == EOF then cb(nil, last_msg) else cb(err) end
        return
      end

      local resp, err = parser:append(data):next_message()

      if resp == true then return end

      if not resp then
        cli:close()
        return cb(err)
      end

      if only_last then
        if resp:type() == 'END' then
          cb(nil, last_msg)
          last_msg = nil
        else
          last_msg = resp
        end
      else
        cb(nil, resp)
      end
    end)
  end)

  encoded = msg:encode(self._pass)
end

function Connector:_message(type)
  return GNTPMessage.new()
    :set_info(type, self._hash, self._enc)
    :add_header("Application-Name",  self._name)
end

function Connector:register(notices, cb)
  local msg = self:_message("REGISTER")

  for i = 1, #notices do
    local note = notices[i]
    msg:add_notification(note.name or note[1] , not not note.enabled)
  end

  self:_send(msg, true, cb)
end

function Connector:notify(note, cb)
  local msg = self:_message("NOTIFY")
    :add_header('Notification-Text',         assert(note.text))
    :add_header('Notification-Name',         note.name     or 'Basic Notification')
    :add_header('Notification-ID',           note.id       or '')
    :add_header('Notification-Title',        note.title    or '')
    :add_header('Notification-Sticky',       note.sticky   or false)
    :add_header('Notification-Priority',     note.priority or 0)
    :add_header('Notification-Coalescing-ID', '')
    :add_header('Notification-Callback-Context', 'context')
    :add_header('Notification-Callback-Context-Type', 'string')
  self:_send(msg, true, cb)
end

end

local cnn = Connector.new{
  hash = 'SHA256';
  pass = '123456';
}

local GNTP = {
  Message   = GNTPMessage;
  Parser    = GNTPParser;
  Connector = Connector;
}

return GNTP
