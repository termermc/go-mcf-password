package main

import (
	"fmt"
	mcfpassword "github.com/termermc/go-mcf-password"
)

func main() {
	const pass = "winn3r_uv_phc"

	defIdHash := mcfpassword.HashPasswordArgon2Default(mcfpassword.Argon2id, pass)

	fmt.Printf("argon2id hash with default params: %s\n", defIdHash)

	// More difficult parameters than normal.
	params := mcfpassword.Argon2Parameters{
		HashLen:     mcfpassword.DefaultArgon2Parameters.HashLen,
		SaltLen:     mcfpassword.DefaultArgon2Parameters.SaltLen,
		Time:        10,
		Memory:      65536 * 2, // 128MiB
		Parallelism: 12,
	}

	paramIdHash := mcfpassword.HashPasswordArgon2(mcfpassword.Argon2id, pass, params)

	fmt.Printf("argon2id hash with harder params: %s\n", paramIdHash)

	defIHash := mcfpassword.HashPasswordArgon2Default(mcfpassword.Argon2i, pass)

	fmt.Printf("argon2i hash with default params: %s\n", defIHash)

	paramIHash := mcfpassword.HashPasswordArgon2(mcfpassword.Argon2i, pass, params)

	fmt.Printf("argon2i hash with harder params: %s\n", paramIHash)
}
