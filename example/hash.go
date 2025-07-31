package main

import (
	mcfpassword "github.com/termermc/go-mcf-password"
)

func main() {
	hash, err := mcfpassword.HashPassword("abc123_bad_password")
	if err != nil {
		panic(err)
	}

	println(hash)
}
