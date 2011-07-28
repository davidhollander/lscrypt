local l=require'lscrypt'

assert(#l.salt(32)==32, 'Salt did not return requested length')

local pattern = '(%x+)%$(%x+)%$(%x+)%$'
local cost = l.calibrate(1024,.5,.2)
print(cost)
local n, r, p = cost:match(pattern)
assert(n, 'Calibrate returned bad cost string')

local start = os.clock()
assert(l.crypt('helloworld', l.salt(32), cost), 'Crypt did not return')
local d1 = os.clock()-start

local cost2 = l.calibrate(8192*8192,.5,.2)
local n2, r2, p2 = cost2:match(pattern)
assert(tonumber(n2,16)>tonumber(n,16), 'Calibrate n should increase as desired memory use increases'..cost..' '..cost2)

local cost3 = l.calibrate(8192*8192,.001,.2)
local n3, r3, p3 = cost3:match(pattern)
assert(tonumber(n2,16)>tonumber(n3,16), 'Calibrate n should decrease as maxmemfrac decreases'..cost2..' '..cost3)

local cost2 = l.calibrate(1024,.2,1)
local n2, r2, p2 = cost2:match(pattern)
assert(tonumber(p2,16)>tonumber(p,16), 'Calibrate p should increase as desired time increases'..cost..' '..cost2)

local start = os.clock()
assert(l.crypt('helloworld', l.salt(32), cost2), 'Crypt did not return with new cost string')
local d2 = os.clock()-start
assert(d2>d1, 'Hashing time did not increase when permutations increased')

enc=l.encoder(2048,.5,.2)
local str = enc 'Hello World'
assert(str:match '%x+%$%x+%$%x+%$', 'Encoder returned bad string')

assert(l.check(str, 'Foo Bar')==false, 'Check should return false for bad password')
assert(l.check(str, 'Hello World'), 'Check should return true for correct password')

print 'passed.'
return true
