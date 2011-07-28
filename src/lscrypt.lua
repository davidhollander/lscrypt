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

---Compare a password to a string containing a hash, salt, and cost.
--@ret true or false
function M.check(str, pass)
  local cost = str:match '^%x+%$%x+%$%x+%$'
  return (crypt(pass, str:sub(#cost+1,#cost+32), cost)) == str:sub(#cost+33)
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
    return tc{cost, s, crypt(pass,s,cost)}
  end
end

return M
