local lscryptc = require 'scryptc'
local calibrate = lscryptc.calibrate
local crypt = lscryptc.crypt
local ti, tc = table.insert, table.concat
local rand, floor, char, byte = math.random, math.floor, string.char, string.byte

local M={}
M.crypt = lscryptc.crypt
M.calibrate = lscryptc.calibrate

---Convert a random salt n bytes long to hexadecimal
function salt(n) end

urandom = io.open '/dev/urandom'

if urandom then
  salt = function(n) return urandom:read(n) end
else
  math.randomseed(os.time())
  salt = function(n)
    local t={}
    for i=1,n do ti(t, char(rand(255))) end
    return tc(t)
  end
end

M.salt = salt

---Check if key unlocks a password storage string
--@param str password storage string containing the hash, salt, and cost.
--@param key password to validate
--@return true or false
function M.check(str, key)
  local a, b, n, r, p = str:find '^(%d+)$(%d+)$(%d+)%$'
  print'CHECk'
  print'checkstr'
  print(str)
  --print('checkkey', key)
  print'checkcost'
  print(n, r, p)
  print'checkcrypt'
  local x = crypt(key, str:sub(b+1,b+32), n, r, p)
  print(x)
  print'checkcrypt'
  local y = str:sub(b+33,#str)
  print(y)
  --return (crypt(key, str:sub(b+1,b+32), n, r, p)) == str:sub(b+33)
  return x==y
end

---Create a function for creating password storage strings
-- @param maxmem The maximum amount of memory in kilobytes to use during hashing. Never uses less than 1024.
-- @param maxmemfrac The maximum fraction of available memory to use during hashing. Never uses more than .5.
-- @param maxtime The maximum time to spend on hashing a password. Default .2 (200ms)
-- @return function(key)
--
--  - Returns a password storage string generated from key
function M.encoder(maxmem, maxmemfrac, maxtime)
  local n, r, p = calibrate(maxmem or 1048576, maxmemfrac or .5, maxtime or .2)
  local cost = ('%d$%d$%d$'):format(n,r,p)
  return function(key)
    local s = salt(32)
    assert(#s==32)
    return tc{cost, s, crypt(key,s,n,r,p)}
  end
end

return M
