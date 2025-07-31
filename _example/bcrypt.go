package main

import (
	"fmt"
	mcfpassword "github.com/termermc/go-mcf-password"
)

func main() {
	const pass = ">implying_secure"

	defHash, err := mcfpassword.HashPasswordBcryptDefault(pass)
	if err != nil {
		panic(err)
	}

	fmt.Printf("bcrypt hash with default params: %s\n", defHash)

	const cost = 15
	costHash, err := mcfpassword.HashPasswordBcrypt(pass, cost)
	if err != nil {
		panic(err)
	}

	fmt.Printf("bcrypt hash with cost %d: %s\n", cost, costHash)
}
