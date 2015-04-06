package = "gntp"
version = "scm-0"

source = {
  url = "https://github.com/moteus/lua-gntp/archive/master.zip",
  dir = "lua-lluv-gntp-master",
}

description = {
  summary    = "Implementation of Growl Notify Transport Protocol (GNTP) for Lua.",
  homepage   = "https://github.com/moteus/lua-gntp",
  license    = "MIT/X11",
  maintainer = "Alexey Melnichuk",
  detailed   = [[
  ]],
}

dependencies = {
  "lua >= 5.1, < 5.4",
  "lluv > 0.1.1",
}

build = {
  copy_directories = {'examples', 'test'},

  type = "builtin",

  modules = {
    [ "gntp"                     ] = "src/lua/gntp.lua",
    [ "gntp.connector.lluv"      ] = "src/gntp/connector/lluv.lua",
    [ "gntp.connector.luasocket" ] = "src/gntp/connector/luasocket.lua",
  }
}
