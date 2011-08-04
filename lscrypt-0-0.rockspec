package = "lscrypt"
version = "0-0"
source = {
	url = "./.git",
	dir = "src",
}
description = {
	summary = "Password hashing library binding to scrypt key derivation from tarsnap",
	homepage = "https://github.com/davidhollander/lscrypt",
	maintainer = "David Hollander <dhllndr@gmail.com>",
	license = "MIT/X11"
}
dependencies = {
	"lua >= 5.1",
}
build = {
	type = "make",
}

