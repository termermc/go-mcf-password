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
