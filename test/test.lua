package.path = "..\\src\\lua\\?.lua;" .. package.path

pcall(require, "luacov")

local utils       = require "utils"
local TEST_CASE   = require "lunit".TEST_CASE
local RUN, IT = utils.RUN, utils.IT

local print, require = print, require

local GNTP = require "gntp"
local ut   = require "gntp.utils"

print("------------------------------------")
print("Module    name: " .. GNTP._NAME);
print("Module version: " .. GNTP._VERSION);
print("Lua    version: " .. (_G.jit and _G.jit.version or _G._VERSION))
print("------------------------------------")
print("")

local ENABLE = true

local _ENV = TEST_CASE'gntp.self_test' if ENABLE then
local it = IT(_ENV)

it('should pass self test', function()
  ut.self_test()
end)

end

local _ENV = TEST_CASE'gntp.application' if ENABLE then

local it = IT(_ENV)

it('should provide app name',function()
  local app = GNTP.Application.new{
    notifications = {{'NOTE1'}}
  }
  msg = app:register():encode()

  assert_match('GNTP/1.0 REGISTER NONE', msg)
  assert_match('Application%-Name: Lua/GNTP', msg)
  assert_match('Notifications%-Count: 1', msg)
  assert_match('Notification%-Display%-Name: NOTE1', msg)
  assert_match('Notification%-Name: NOTE1', msg)
  assert_match('Notification%-Enabled: false', msg)
end)

it('should get app name as first element from config table',function()
  local app = GNTP.Application.new{'MyAPP',
    notifications = {{'NOTE1'}}
  }
  msg = app:register():encode()
  assert_match('Application%-Name: MyAPP', msg)
end)

it('should get app name from config table',function()
  local app = GNTP.Application.new{name = 'MyAPP',
    notifications = {{'NOTE1'}}
  }
  msg = app:register():encode()
  assert_match('Application%-Name: MyAPP', msg)
end)

it('should notify only with text',function()
  local app = GNTP.Application.new{
    notifications = {{'NOTE1'}}
  }
  msg = app:notify('hello'):encode()

  assert_match('GNTP/1.0 NOTIFY NONE', msg)
  assert_match('Notification%-Name: NOTE1', msg)
  assert_match('Notification%-Title: NOTE1', msg)
  assert_match('Notification%-Text: hello', msg)
end)

it('should notify with config',function()
  local app = GNTP.Application.new{
    notifications = {{'NOTE1'}}
  }
  msg = app:notify{'hello', priority = -1}:encode()

  assert_match('GNTP/1.0 NOTIFY NONE', msg)
  assert_match('Notification%-Name: NOTE1', msg)
  assert_match('Notification%-Title: NOTE1', msg)
  assert_match('Notification%-Text: hello', msg)
  assert_match('Notification%-Priority: %-1', msg)
end)

it('notify should select notetification',function()
  local app = GNTP.Application.new{
    notifications = {{'NOTE1'},{'NOTE2'}}
  }
  msg = app:notify('NOTE2', 'hello'):encode()

  assert_match('GNTP/1.0 NOTIFY NONE', msg)
  assert_match('Notification%-Name: NOTE2', msg)
  assert_match('Notification%-Title: NOTE2', msg)
  assert_match('Notification%-Text: hello', msg)
end)

end

RUN()