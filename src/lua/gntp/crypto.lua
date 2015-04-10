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

local ut = require "lluv.utils"

local function prequire(m)
  local ok, err = pcall(require, m)
  if ok then return err, m end
  return nil, err
end

local function orequire(...)
  for _, name in ipairs{...} do
    local mod = prequire(name)
    if mod then return mod, name end
  end
end

local function vrequire(...)
  local m, n = orequire(...)
  if m then return m, n end
  error("Can not fine any of this modules: " .. table.concat({...}, "/"), 2)
end

local crypto, cryptoName = orequire('crypto', 'openssl')

local rand_bytes, make_hash, make_encrypt_fn, make_decrypt_fn

if cryptoName == 'openssl' then
  local Cipher = crypto.cipher
  local Digest = crypto.digest

  make_hash  = function(algo)
    local hash = Digest.get(algo)
    return {
      digest = function(data, hex) return hash:digest(data, hex) end
    }
  end

  make_encrypt = function(algo)
    local ctx = Cipher.get(algo)
    return{
      encrypt = setmetatable{
        digest = function(data, key, iv, pad) return ctx:encrypt(data, key, iv) end;
        new    = function(key, iv, pad) return ctx:encrypt_new(key, iv, true) end;
      };
      decrypt = {
        digest = function(data, key, iv, pad) return ctx:digest(data, key, iv) end;
        new    = function(key, iv, pad) return ctx:decrypt_new(key, iv, true) end;
      };
    }
  end

  rand_bytes      = crypto.random

elseif cryptoName == 'crypto' then

  make_hash = function(algo)
    return {
      digest = function(data, hex) return crypto.digest(algo, data, not hex) end
    }
  end

  make_encrypt = function(algo)
    return{
      encrypt = {
        digest = function(data, key, iv, pad) return crypto.encrypt(algo, data, key, iv) end;
        new    = function(key, iv, pad) return crypto.encrypt.new(algo, key, iv, true) end;
      };
      decrypt = {
        digest = function(data, key, iv, pad) return crypto.decrypt(algo, data, key, iv) end;
        new    = function(key, iv, pad) return crypto.decrypt.new(algo, key, iv, true) end;
      };
    }
  end

  rand_bytes      = crypto.rand.pseudo_bytes

end

if not rand_bytes then
  rand_bytes = function (n)
    local r = {}
    for i = 1, n do
      r[#r + 1] = string.char(math.random(0, 0xFF))
    end
    return table.concat(r)
  end
end

local HASH = {} if make_hash then
  HASH.MD5    = make_hash('MD5')
  HASH.SHA1   = make_hash('SHA1')
  HASH.SHA256 = make_hash('SHA256')
  HASH.SHA512 = make_hash('SHA512')
end

local ENCRYPT = {} if make_encrypt then
  ENCRYPT.AES = make_encrypt('AES-192-CBC');
  ENCRYPT.AES.key_size    = 24;
  ENCRYPT.AES.block_size  = 16;
  ENCRYPT.AES.iv_size     = 16;

  ENCRYPT.DES = make_encrypt('DES-CBC');
  ENCRYPT.DES.key_size    = 8;
  ENCRYPT.DES.block_size  = 8;
  ENCRYPT.DES.iv_size     = 8;

  ENCRYPT['3DES'] = make_encrypt('DES3');
  ENCRYPT['3DES'].key_size    = 24;
  ENCRYPT['3DES'].block_size  = 8;
  ENCRYPT['3DES'].iv_size     = 8;
end

local NoneEncrypter = ut.class() do
function NoneEncrypter:update(str) return str end
function NoneEncrypter:final()end
end

do local encoder = NoneEncrypter.new()
ENCRYPT.NONE = {
  encrypt = {
    digest = function(data) return data end;
    new    = function() return encoder end;
  };
  decrypt = {
    digest = function(data) return data end;
    new    = function() return encoder end;
  };
  key_size    = 0;
  block_size  = 0;
  iv_size     = 0;
}
end

return {
  hash       = HASH;
  cipher     = ENCRYPT;
  rand_bytes = rand_bytes;
}
