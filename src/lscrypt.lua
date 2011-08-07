---lscrypt.lua

local lscryptc = require 'scryptc'
local ti, tc = table.insert, table.concat
local rand, floor, char, byte = math.random, math.floor, string.char, string.byte
local urandom = io.open '/dev/urandom'

local crypt, calibrate = lscryptc.crypt, lscryptc.calibrate
local M={crypt=lscryptc.crypt, calibrate=lscryptc.calibrate}

---Outputs a hash using the scrypt key-derivation algorithm
--@param key string
--@param salt string
--@param cost string
--@function crypt(key, salt, cost)

---Generate a n, r, p cost string based on current system performance
-- @param maxmem The maximum amount of memory in kilobytes to use during hashing. Never uses less than 1024.
-- @param maxmemfrac The maximum fraction of available memory to use during hashing. Never uses more than .5.
-- @param maxtime The maximum time to spend on hashing a password. Default .2 (200ms)
-- @function calibrate(maxmem, maxmemfrac, maxtime)

---Create random salt, using /dev/urandom if available
--@param n number of bytes
--@function salt(n)
local salt
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
<<<<<<< HEAD
  local cost = str:match '^%x+%$%x+%$%x+%$'
  print('checkstr', str)
  print('checkkey', key)
  print('checkcost', cost)
  print('checkcrypt', (crypt(key, str:sub(#cost+1,#cost+32), cost)))
  return (crypt(key, str:sub(#cost+1,#cost+32), cost)) == str:sub(#cost+33)
=======
  local a, b, n, r, p = str:find '^(%d+)$(%d+)$(%d+)%$'
  return crypt(key, str:sub(b+1,b+32), n, r, p) == str:sub(b+33,#str)
>>>>>>> 6345132
end

---Create a function for creating password storage strings
-- @param maxmem The maximum amount of memory in kilobytes to use during hashing. Never uses less than 1024.
-- @param maxmemfrac The maximum fraction of available memory to use during hashing. Never uses more than .5.
-- @param maxtime The maximum time to spend on hashing a password. Default .2 (200ms)
-- @return function(key)
--
--  - Returns a password storage string generated from key
function M.encoder(maxmem, maxmemfrac, maxtime)
<<<<<<< HEAD
  local cost = calibrate(maxmem or 1048576, maxmemfrac or .5, maxtime or .2)
  return function(key)
    local s = salt(32)
    return tc{cost, s, crypt(key,s,cost)}
=======
  local n, r, p = calibrate(maxmem or 1048576, maxmemfrac or .5, maxtime or .2)
  local cost = ('%d$%d$%d$'):format(n,r,p)
  return function(key)
    local s = salt(32)
    assert(#s==32)
    return tc{cost, s, crypt(key,s,n,r,p)}
>>>>>>> 6345132
  end
end

return M
