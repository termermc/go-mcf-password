package mcfpassword

import (
	"fmt"
	"testing"
)

type trial struct {
	Name     string
	Password string
	Hash     string
	Rehash   bool
}

var passes = []trial{
	{
		Name:     "argon2id from NPM argon2",
		Password: "$$stupid_p4ss??",
		Hash:     "$argon2id$v=19$m=65536,t=3,p=4$LkIJZWa6sMdfcIQLyRuERw$fH0LH5OWm/+q5pTXaB12wtZxrMZE5UyM04sM0YvXGEg",
		Rehash:   false,
	},
	{
		Name:     "argon2id from PHP password_hash",
		Password: "$$stupid_p4ss??",
		Hash:     "$argon2id$v=19$m=65536,t=4,p=1$QVd2dm42ZjVOUlUua05jSA$3/k7fvy942SkqW4BE3U5qPlIC813wmX+Q/+yN+Xrvt8",
		Rehash:   false,
	},
	{
		Name:     "argon2i from PHP password_hash",
		Password: "$$stupid_p4ss??",
		Hash:     "$argon2i$v=19$m=65536,t=4,p=1$aS5WelhiMU9hTUouS21KSw$H5yFavZDOXbUKtRZ4EaZsCckJTNWrY2uPWRrJ1IFieo",
		Rehash:   true,
	},
	{
		Name:     "bcrypt from PHP password_hash",
		Password: "$$stupid_p4ss??",
		Hash:     "$2y$12$OJjEqw00p.bzGoFRgSeo9OxJkv4H6s.Onsrv/1XAr/UzSBxzXpPF.",
		Rehash:   true,
	},
	//{
	//	Password: "$$stupid_p4ss??",
	//
	//	// Generated with this library
	//	Hash: ""
	//},
}
var argon2idPass1 = trial{
	Password: "$$stupid_p4ss??",

	// Generated with NPM argon2
	Hash: "$argon2id$v=19$m=65536,t=3,p=4$LkIJZWa6sMdfcIQLyRuERw$fH0LH5OWm/+q5pTXaB12wtZxrMZE5UyM04sM0YvXGEg",
}
var argon2iPass1 = trial{
	Password: "$$stupid_p4ss??",

	// Generated with PHP password_hash
	Hash: "$argon2i$v=19$m=65536,t=4,p=1$VFFoUVp2OFAuY3FBcGU4Mg$9VF47RNkt3ZOmZFJ6VTyg1X+GPtcFZnCGDfiEYM5ugc",
}
var bcryptPass1 = trial{
	Password: "$$stupid_p4ss??",

	// Generated with PHP password_hash
	Hash: "$2y$12$Yur8jcqy22Jto2SVDCQtbO7Mg6rC6ZObfDddh8JLtGhfQxUCF4.ou",
}

func TestVerify(t *testing.T) {
	for _, pass := range passes {
		t.Run("verify "+pass.Name, func(t *testing.T) {
			match, rehash, err := VerifyPassword(pass.Password, pass.Hash)
			if err != nil {
				t.Error(err)
			}

			if !match {
				t.Errorf("password %s was supposed to match hash %s", pass.Password, pass.Hash)
			}
			if rehash != pass.Rehash {
				if pass.Rehash {
					t.Errorf("password hash %s matched but did not indicate rehash when it needed one", pass.Hash)
				} else {
					t.Errorf("password hash %s matched but indicated rehash when it did not need", pass.Hash)
				}
			}
		})
	}
}

func TestVerifyLibHashes(t *testing.T) {
	pass := "SupaBase__SUCKS"
	algos := []string{"argon2id", "argon2i", "bcrypt"}

	trials := make([]trial, 10)
	for i := range trials {
		algo := algos[i%len(algos)]

		var hash string
		var rehash bool
		switch algo {
		case "argon2id":
			hash = HashPasswordArgon2Default(Argon2id, pass)
			rehash = false
		case "argon2i":
			hash = HashPasswordArgon2Default(Argon2i, pass)
			rehash = true
		case "bcrypt":
			var err error
			hash, err = HashPasswordBcryptDefault(pass)
			if err != nil {
				t.Error(err)
			}
			rehash = true
		}

		trials[i] = trial{
			Name:     fmt.Sprintf("verify library-generated %s hash: %s", algo, hash),
			Password: pass,
			Hash:     hash,
			Rehash:   rehash,
		}
	}

	for _, ph := range trials {
		match, rehash, err := VerifyPassword(ph.Password, ph.Hash)
		if err != nil {
			t.Error(err)
		}

		if !match {
			t.Errorf("password %s was supposed to match hash %s", ph.Password, ph.Hash)
		}
		if rehash != ph.Rehash {
			if ph.Rehash {
				t.Errorf("password hash %s matched but did not indicate rehash when it needed one", ph.Hash)
			} else {
				t.Errorf("password hash %s matched but indicated rehash when it did not need", ph.Hash)
			}
		}
	}
}

func TestRehashFromPhp(t *testing.T) {
	pass := "123haha"
	oldHash := "$2y$12$Uip..DKUTlJ7GGhABYlUmel5UlJLXe6U9PT8L8m5zlJ5sK/sMn3U2"

	matches, rehash, err := VerifyPassword(pass, oldHash)
	if err != nil {
		t.Error(err)
	}
	if !matches {
		t.Errorf("expected hash to match")
	}
	if !rehash {
		t.Errorf("expected bcrypt hash to need rehash")
	}

	newHash, err := HashPassword(pass)
	if err != nil {
		t.Error(err)
	}

	matches, rehash, err = VerifyPassword(pass, newHash)
	if err != nil {
		t.Error(err)
	}
	if rehash {
		t.Errorf("newly hashed password should not need rehash")
	}
	if !matches {
		t.Errorf("newly hashed password should match original password")
	}
}
