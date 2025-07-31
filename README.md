# go-mcf-password

Golang library that handles hashing and verifying Modular Crypt Format password strings.

Fully compatible with hashes produced by PHP's [password_hash](https://www.php.net/manual/en/function.password-hash.php) and virtually all argon2 libraries.

# What is Modular Crypt Format?

Modular Crypt Format (MCF) is a *de-facto* standard for a password hash string format.
The format includes the algorithm used, the parameters, the salt and the hash itself.
Due to the information the format contains, it's easy to just store the string in your database and let a library handle the rest.

It is implemented by several popular password hashing functions, including:
 - POSIX's [crypt](https://en.wikipedia.org/wiki/Crypt_(C))
 - PHP's [password_hash](https://www.php.net/manual/en/function.password-hash.php)
 - The [reference implementation of argon2](https://github.com/P-H-C/phc-winner-argon2)
 - The [argon2](https://www.npmjs.com/package/argon2) NPM package

# Supported Algorithms

The library supports the following algorithms:
 - Argon2id (default)
 - Argon2i
 - Bcrypt

At the time of writing, this covers all algorithms supported by PHP's [password_hash](https://www.php.net/manual/en/function.password-hash.php).
It can also properly handle PHP's `2y` bcrypt format.

# Examples

Hash a password.

```go
package main

import (
	mcfpassword "github.com/termermc/go-mcf-password"
)

func main() {
	hash, err := mcfpassword.HashPassword("abc123_bad_password")
	if err != nil {
		panic(err)
	}
	
	println(hash) // $argon2id$v=19$m=65536,t=3,p=4$CWk8oanYEpzw8BtUkt/n6g$nzFamtDqeupREf7LOP+EJxz+KhYfz3Bg8pPrrE/LZVg
}
```

Verify a password, rehashing it if necessary.

```go
package main

import (
	"fmt"
	mcfpassword "github.com/termermc/go-mcf-password"
)

func main() {
	const pass = "123haha"
	// bcrypt hash from PHP password_hash
	const hash = "$2y$12$eEVXNKAl0njwd7RAPEQm8uJoj1DYTLt9FQhMdrP8tA3B1MY.ZfWGC"
	
	matches, rehash, err := mcfpassword.VerifyPassword(pass, hash)
	if err != nil {
		panic(err)
	}
	if !matches {
		panic("password didn't match")
	}
	
	if rehash {
		newHash, err := mcfpassword.HashPassword(pass)
		if err != nil {
			panic(err)
		}
		
		fmt.Printf("password hash was old, rehashed: %s\n", newHash)
	}
}
```

See the [_example](_example) directory for more.

# Dependencies

This library only depends on `golang.org/x/crypto` and `golang.org/x/sys` (transitively).
