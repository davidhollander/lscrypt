local l=require'lscrypt'

assert(#l.salt(32)==32, 'Salt did not return requested length')

local n,r,p = l.calibrate(1024,.5,.2)
assert(n and r and p, 'Calibrate returned bad cost')

local start = os.clock()
assert(l.crypt('helloworld', l.salt(32), n,r,p), 'Crypt did not return')
local d1 = os.clock()-start

local n2, r2, p2 = l.calibrate(8192*8192,.5,.2)
assert(n2>n, 'Calibrate n should increase as desired memory use increases'..n2..' '..n)

local n3, r3, p3 = l.calibrate(8192*8192,.001,.2)
assert(n2>n3, 'Calibrate n should decrease as maxmemfrac decreases'..n2..' '..n3)

local n2, r2, p2 = l.calibrate(1024,.2,1)
assert(p2>p, 'Calibrate p should increase as desired time increases'..p2..' '..p)

local start = os.clock()
assert(l.crypt('helloworld', l.salt(32), n2,r2,p2), 'Crypt did not return when using new cost')
local d2 = os.clock()-start
assert(d2>d1, 'Hashing time did not increase when permutations increased')

enc=l.encoder(2048,.5,.2)
local str = enc 'Hello World'
assert(str:match '%x+%$%x+%$%x+%$', 'Encoder returned bad string')

assert(l.check(str, 'Foo Bar')==false, 'Check should return false for bad password')
for i=1,100 do
  assert(l.check(str, 'Hello World'), 'Check should return true for correct password')
end
print 'passed.'
return true
