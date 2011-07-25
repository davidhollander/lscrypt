lscrypt is a Lua C binding to the scrypt hashing library from [Tarsnap](http://www.tarsnap.com/scrypt.html) with helpers for generating and checking password strings.

##Install
###luarocks
not yet added
###manual
    make
    make install

##Usage
calibrate(max_mem, mem_ratio, max_time)

* Return a cost string based on the machines hardware

crypt(key, salt, cost)

* Returns the hash of key using strings salt and cost

###Password Helpers

check(pass, str)

* Compare a password to a string containing a hash, salt, and cost.

engine(max_mem, mem_ratio, max_time)

* return lambda(pass) after calibrating
* lambda(pass)
    * return a string containing a hash, random salt, and the calibrated cost
