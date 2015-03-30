package = "lluv-gntp"
version = "scm-0"

source = {
  url = "https://github.com/moteus/lua-lluv-gntp/archive/master.zip",
  dir = "lua-lluv-gntp-master",
}

description = {
  summary    = "Implementation of Growl Notify Transport Protocol (GNTP) for lluv library.",
  homepage   = "https://github.com/moteus/lua-lluv-gntp",
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
    [ "lluv.gntp" ] = "src/lua/lluv/gntp.lua",
  }
}
