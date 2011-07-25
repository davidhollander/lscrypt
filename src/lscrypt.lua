local lscryptc = require 'scryptc'
local calibrate = lscryptc.calibrate
local crypt = lscryptc.crypt
local ti, tc = table.insert, table.concat

local M={}
M.crypt = lscryptc.crypt
M.calibrate = lscryptc.calibrate

---Generate a random salt n bits in length
local function salt(n) end

local f = io.open '/dev/urandom'

if f then
  --salt = function(n) return f:read(math.ceil(n/2)):gsub('.',function(c) return ('%x'):format(string.byte(c)) end):sub(1,n) end
  salt = function(n) return f:read(n) end
else
  math.randomseed(os.time())
  local rand, char = math.random, string.char
  salt = function(n)
    local t={}
    local m=0
    repeat
      local x=('%x'):format(rand(10e10))
      ti(t, x)
      m=m+#x
    until m>=n
    return tc(t):sub(1,n-m-1)
  end
end

M.salt = salt

---Compare a password to a string containing a hash, salt, and cost.
--@ret true or false
function M.check(pass, str)
  local salt, cost, hash = str:match '(%x+)$(%x+$%x+$%x+$)(.+)'
  return crypt(pass, salt, cost) == hash
end

---Create a password string encoding function
-- @param maxmem The maximum amount of memory to use in kilobytes. Never uses less than 1024.
-- @param maxmemfrac: The maximum fraction of available memory to utilize. Never uses more than .5.
-- @param maxtime The maximum time hashing a password should take. Default .2 (200ms)
-- @ret function(pass)
--  - pass: a password
--  - returns: a string containing the hash, salt, and cost.
function M.encoder(maxmem, maxmemfrac, max_time)
  local cost = calibrate(max_mem or 1048576, max_mfrac or .5, max_time or .2)
  return function(pass)
    local s = salt(32)
    return tc{s,'$',cost,crypt(pass,s,cost)}
  end
end

return M
