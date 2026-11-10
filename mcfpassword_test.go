package mcfpassword

import (
	"errors"
	"fmt"
	"strings"
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

const (
	npmSalt = "LkIJZWa6sMdfcIQLyRuERw"
	npmHash = "fH0LH5OWm/+q5pTXaB12wtZxrMZE5UyM04sM0YvXGEg"
)

func argon2idWith(params, salt, hash string) string {
	return "$argon2id$v=19$" + params + "$" + salt + "$" + hash
}

func TestVerifyWrongPassword(t *testing.T) {
	for _, pass := range passes {
		t.Run("wrong password "+pass.Name, func(t *testing.T) {
			match, rehash, err := VerifyPassword(pass.Password+"x", pass.Hash)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if match {
				t.Errorf("wrong password matched")
			}
			if rehash {
				t.Errorf("needsRehash must be false when the password does not match")
			}
		})
	}
}

func TestVerifyMalformed(t *testing.T) {
	var invalid *InvalidHashFormatError
	var unsupported *UnsupportedPasswordHashAlgorithmError

	cases := []struct {
		Name    string
		Hash    string
		WantErr any
	}{
		{"empty", "", &invalid},
		{"no leading $", "argon2id", &invalid},
		{"no second $", "$argon2id", &invalid},
		{"unknown algorithm", "$foo$bar", &unsupported},
		{"argon2d", "$argon2d$v=19$m=65536,t=3,p=4$" + npmSalt + "$" + npmHash, &unsupported},
		{"bcrypt truncated", "$2y$", &invalid},
		{"bcrypt garbage", "$2a$12$notavalidhash", &invalid},
		{"bcrypt bad cost", "$2y$99$OJjEqw00p.bzGoFRgSeo9OxJkv4H6s.Onsrv/1XAr/UzSBxzXpPF.", &invalid},
		{"argon2 too few fields", "$argon2id$v=19$m=65536,t=3,p=4", &invalid},
		{"argon2 too many fields", argon2idWith("m=65536,t=3,p=4", npmSalt, npmHash) + "$x", &invalid},
		{"argon2 empty hash", argon2idWith("m=65536,t=3,p=4", npmSalt, ""), &invalid},
		{"argon2 short hash", argon2idWith("m=65536,t=3,p=4", npmSalt, "AAA"), &invalid},
		{"argon2 empty salt", argon2idWith("m=65536,t=3,p=4", "", npmHash), &invalid},
		{"argon2 bad salt base64", argon2idWith("m=65536,t=3,p=4", "!!!", npmHash), &invalid},
		{"argon2 bad hash base64", argon2idWith("m=65536,t=3,p=4", npmSalt, "!!!!"), &invalid},
		{"argon2 t=0", argon2idWith("m=65536,t=0,p=4", npmSalt, npmHash), &invalid},
		{"argon2 p=0", argon2idWith("m=65536,t=3,p=0", npmSalt, npmHash), &invalid},
		{"argon2 m<8p", argon2idWith("m=8,t=3,p=4", npmSalt, npmHash), &invalid},
		{"argon2 missing p", argon2idWith("m=65536,t=3", npmSalt, npmHash), &invalid},
		{"argon2 duplicate m", argon2idWith("m=65536,m=8,t=3,p=4", npmSalt, npmHash), &invalid},
		{"argon2 unknown param", argon2idWith("m=65536,t=3,p=4,x=1", npmSalt, npmHash), &invalid},
		{"argon2 empty params", argon2idWith("", npmSalt, npmHash), &invalid},
		{"argon2 p overflow", argon2idWith("m=65536,t=3,p=256", npmSalt, npmHash), &invalid},
		{"argon2 missing version", "$argon2id$19$m=65536,t=3,p=4$" + npmSalt + "$" + npmHash, &invalid},
		{"argon2 bad version", "$argon2id$v=abc$m=65536,t=3,p=4$" + npmSalt + "$" + npmHash, &invalid},
		{"argon2 negative version", "$argon2id$v=-19$m=65536,t=3,p=4$" + npmSalt + "$" + npmHash, &invalid},
		{"argon2 version 16", "$argon2id$v=16$m=65536,t=3,p=4$" + npmSalt + "$" + npmHash, &unsupported},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			match, rehash, err := VerifyPassword("$$stupid_p4ss??", c.Hash)
			if match || rehash {
				t.Errorf("malformed hash returned matches=%v needsRehash=%v", match, rehash)
			}
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !errors.As(err, c.WantErr) {
				t.Errorf("expected error of type %T, got %T: %v", c.WantErr, err, err)
			}
			if c.Hash != "" && strings.Contains(err.Error(), c.Hash) {
				t.Errorf("error message leaks hash string: %v", err)
			}
		})
	}
}

func TestParseArgon2McfErrors(t *testing.T) {
	var invalid *InvalidHashFormatError
	var unsupported *UnsupportedPasswordHashAlgorithmError
	valid := argon2idWith("m=65536,t=3,p=4", npmSalt, npmHash)

	if _, err := ParseArgon2Mcf(Argon2id, ""); !errors.As(err, &invalid) {
		t.Errorf("empty string: expected InvalidHashFormatError, got %T: %v", err, err)
	}
	if _, err := ParseArgon2Mcf(Argon2id, "garbage"); !errors.As(err, &invalid) {
		t.Errorf("garbage: expected InvalidHashFormatError, got %T: %v", err, err)
	}
	if _, err := ParseArgon2Mcf(Argon2i, valid); !errors.As(err, &unsupported) {
		t.Errorf("variant mismatch: expected UnsupportedPasswordHashAlgorithmError, got %T: %v", err, err)
	}
	if _, err := ParseArgon2Mcf(Argon2Variant("argon2d"), valid); !errors.As(err, &unsupported) {
		t.Errorf("invalid variant: expected UnsupportedPasswordHashAlgorithmError, got %T: %v", err, err)
	}
	if _, err := VerifyArgon2Password(Argon2id, "x", "garbage"); !errors.As(err, &invalid) {
		t.Errorf("VerifyArgon2Password garbage: expected InvalidHashFormatError, got %T: %v", err, err)
	}

	h, err := ParseArgon2Mcf(Argon2id, valid)
	if err != nil {
		t.Fatal(err)
	}
	if h.Version != 19 || h.Parameters.Memory != 65536 || h.Parameters.Time != 3 || h.Parameters.Parallelism != 4 ||
		h.Parameters.SaltLen != 16 || h.Parameters.HashLen != 32 {
		t.Errorf("unexpected parse result: %+v", h)
	}
}

func TestRehashWeakArgon2id(t *testing.T) {
	const pass = "weak params"
	weakParams := Argon2Parameters{HashLen: 32, SaltLen: 16, Time: 1, Memory: 64, Parallelism: 1}
	hash := HashPasswordArgon2(Argon2id, pass, weakParams)

	match, rehash, err := VerifyPassword(pass, hash)
	if err != nil || !match {
		t.Fatalf("expected match, got matches=%v err=%v", match, err)
	}
	if !rehash {
		t.Errorf("argon2id hash weaker than defaults should need rehash")
	}

	match, rehash, err = VerifyPassword(pass+"x", hash)
	if err != nil || match || rehash {
		t.Errorf("wrong password: got matches=%v needsRehash=%v err=%v", match, rehash, err)
	}

	// With a custom target matching the hash's params, no rehash is needed.
	match, rehash, err = VerifyPasswordWithOptions(pass, hash, VerifyOptions{Argon2RehashParameters: weakParams})
	if err != nil || !match {
		t.Fatalf("expected match, got matches=%v err=%v", match, err)
	}
	if rehash {
		t.Errorf("argon2id hash meeting the custom target should not need rehash")
	}

	// Stronger-than-target hashes, and lower parallelism, do not trigger a rehash.
	strong := HashPasswordArgon2(Argon2id, pass, Argon2Parameters{HashLen: 32, SaltLen: 16, Time: 2, Memory: 128, Parallelism: 1})
	_, rehash, _ = VerifyPasswordWithOptions(pass, strong, VerifyOptions{
		Argon2RehashParameters: Argon2Parameters{HashLen: 32, SaltLen: 16, Time: 1, Memory: 64, Parallelism: 4},
	})
	if rehash {
		t.Errorf("hash stronger than target should not need rehash")
	}
}

func TestVerifyLimits(t *testing.T) {
	var limitErr *HashParametersExceedLimitError
	npm := passes[0]
	bcryptPhp := passes[3]

	cases := []struct {
		Name string
		Hash string
		Opts VerifyOptions
	}{
		{"argon2 memory", npm.Hash, VerifyOptions{MaxArgon2Memory: 1024}},
		{"argon2 time", npm.Hash, VerifyOptions{MaxArgon2Time: 2}},
		{"argon2 huge memory", argon2idWith("m=4294967295,t=3,p=4", npmSalt, npmHash), VerifyOptions{MaxArgon2Memory: 1 << 20}},
		{"bcrypt cost", bcryptPhp.Hash, VerifyOptions{MaxBcryptCost: 10}},
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			match, rehash, err := VerifyPasswordWithOptions(npm.Password, c.Hash, c.Opts)
			if match || rehash {
				t.Errorf("limited hash returned matches=%v needsRehash=%v", match, rehash)
			}
			if !errors.As(err, &limitErr) {
				t.Errorf("expected HashParametersExceedLimitError, got %T: %v", err, err)
			}
		})
	}

	// Limits at or above the hash's parameters allow verification.
	opts := VerifyOptions{MaxArgon2Memory: 65536, MaxArgon2Time: 4, MaxBcryptCost: 12}
	for _, pass := range passes {
		match, _, err := VerifyPasswordWithOptions(pass.Password, pass.Hash, opts)
		if err != nil || !match {
			t.Errorf("%s: expected match within limits, got matches=%v err=%v", pass.Name, match, err)
		}
	}
}

func TestHashPasswordArgon2InvalidParams(t *testing.T) {
	cases := []struct {
		Name    string
		Variant Argon2Variant
		Params  Argon2Parameters
	}{
		{"invalid variant", Argon2Variant("argon2d"), DefaultArgon2Parameters},
		{"zero params", Argon2id, Argon2Parameters{}},
		{"short salt", Argon2id, Argon2Parameters{HashLen: 32, SaltLen: 4, Time: 1, Memory: 64, Parallelism: 1}},
		{"short hash", Argon2id, Argon2Parameters{HashLen: 3, SaltLen: 16, Time: 1, Memory: 64, Parallelism: 1}},
		{"memory below 8*p", Argon2id, Argon2Parameters{HashLen: 32, SaltLen: 16, Time: 1, Memory: 31, Parallelism: 4}},
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("expected panic")
				}
			}()
			HashPasswordArgon2(c.Variant, "pw", c.Params)
		})
	}
}

func FuzzVerifyPassword(f *testing.F) {
	for _, pass := range passes {
		f.Add(pass.Password, pass.Hash)
	}
	f.Add("pw", "$2y$")
	f.Add("pw", "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$AAAAAAAAAAAAAAAAAAAAAA")
	f.Add("pw", argon2idWith("m=65536,t=3,p=4", npmSalt, ""))
	f.Add("pw", "")

	// Cheap valid hashes, so mutations reach the hashing and comparison code instead of stopping at the limits.
	cheap := Argon2Parameters{HashLen: 16, SaltLen: 8, Time: 1, Memory: 64, Parallelism: 1}
	f.Add("pw", HashPasswordArgon2(Argon2id, "pw", cheap))
	f.Add("pw", HashPasswordArgon2(Argon2i, "pw", cheap))
	if h, err := HashPasswordBcrypt("pw", MinBcryptCost); err == nil {
		f.Add("pw", h)
	}

	// Keep the work per input small.
	opts := VerifyOptions{MaxArgon2Memory: 1024, MaxArgon2Time: 3, MaxBcryptCost: 6}

	f.Fuzz(func(t *testing.T, password, mcf string) {
		match, rehash, err := VerifyPasswordWithOptions(password, mcf, opts)
		if err != nil && (match || rehash) {
			t.Errorf("error with matches=%v needsRehash=%v: %v", match, rehash, err)
		}
		if rehash && !match {
			t.Errorf("needsRehash without match")
		}
	})
}

func FuzzParseArgon2Mcf(f *testing.F) {
	for _, pass := range passes {
		f.Add(pass.Hash)
	}
	f.Add(argon2idWith("m=65536,t=3,p=4", npmSalt, ""))
	f.Add("$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$AAAAAAAAAAAAAAAAAAAAAA")

	// Parsing does no hashing work, so unlimited parameters are fine here.
	f.Fuzz(func(t *testing.T, mcf string) {
		for _, variant := range []Argon2Variant{Argon2id, Argon2i} {
			h, err := ParseArgon2Mcf(variant, mcf)
			if err != nil {
				continue
			}
			p := h.Parameters
			if h.Variant != variant || h.Version != 19 || p.Time < 1 || p.Parallelism < 1 ||
				uint64(p.Memory) < 8*uint64(p.Parallelism) || p.SaltLen < 1 || p.HashLen < MinArgon2HashLen ||
				p.SaltLen != len(h.Salt) || p.HashLen != len(h.Hash) {
				t.Errorf("parse accepted a hash that violates invariants: %+v", h)
			}
		}
	})
}

// bcryptKey returns the 72 key bytes bcrypt actually uses for password: the password plus a NUL terminator,
// repeated cyclically and truncated to 72 bytes. Passwords with equal keys verify against each other's hashes.
// Since passwords containing NUL are rejected, this only happens when both share the same first 72 bytes.
func bcryptKey(password string) string {
	k := password + "\x00"
	return strings.Repeat(k, MaxBcryptPasswordLen/len(k)+1)[:MaxBcryptPasswordLen]
}

func FuzzHashVerifyRoundTrip(f *testing.F) {
	f.Add("", "x")
	f.Add("$$stupid_p4ss??", "$$stupid_p4ss?")
	f.Add("p\x00ss", "p")

	cheap := Argon2Parameters{HashLen: 16, SaltLen: 8, Time: 1, Memory: 64, Parallelism: 1}

	f.Fuzz(func(t *testing.T, password, other string) {
		if strings.IndexByte(password, 0) != -1 {
			if _, err := HashPassword(password); !errors.Is(err, ErrNullByte) {
				t.Fatalf("HashPassword: expected ErrNullByte, got %v", err)
			}
			if _, err := HashPasswordBcrypt(password, MinBcryptCost); !errors.Is(err, ErrNullByte) && len(password) <= MaxBcryptPasswordLen {
				t.Fatalf("HashPasswordBcrypt: expected ErrNullByte, got %v", err)
			}
			defer func() {
				if err, _ := recover().(error); !errors.Is(err, ErrNullByte) {
					t.Fatalf("HashPasswordArgon2: expected panic with ErrNullByte, got %v", err)
				}
			}()
			HashPasswordArgon2(Argon2id, password, cheap)
			return
		}

		hashes := []string{
			HashPasswordArgon2(Argon2id, password, cheap),
			HashPasswordArgon2(Argon2i, password, cheap),
		}
		if h, err := HashPasswordBcrypt(password, MinBcryptCost); err == nil {
			hashes = append(hashes, h)
		} else if len(password) <= MaxBcryptPasswordLen {
			t.Fatalf("bcrypt failed for a %d-byte password: %v", len(password), err)
		}

		for _, h := range hashes {
			match, _, err := VerifyPassword(password, h)
			if err != nil || !match {
				t.Fatalf("own hash %q did not verify: matches=%v err=%v", h, match, err)
			}

			if other == password || (strings.HasPrefix(h, "$2") && bcryptKey(other) == bcryptKey(password)) {
				continue
			}
			match, rehash, err := VerifyPassword(other, h)
			if strings.IndexByte(other, 0) != -1 {
				if !errors.Is(err, ErrNullByte) || match || rehash {
					t.Fatalf("password with null byte: expected ErrNullByte, got matches=%v needsRehash=%v err=%v", match, rehash, err)
				}
				continue
			}
			if err != nil || match || rehash {
				t.Fatalf("different password verified against %q: matches=%v needsRehash=%v err=%v", h, match, rehash, err)
			}
		}
	})
}

func TestNullBytes(t *testing.T) {
	const pass = "$$stupid_p4ss??"
	for _, p := range passes {
		t.Run("verify "+p.Name, func(t *testing.T) {
			for _, c := range []struct{ Password, Hash string }{
				{pass + "\x00", p.Hash},
				{"\x00" + pass, p.Hash},
				{pass, p.Hash + "\x00"},
				{pass, p.Hash[:10] + "\x00" + p.Hash[10:]},
			} {
				match, rehash, err := VerifyPassword(c.Password, c.Hash)
				if !errors.Is(err, ErrNullByte) || match || rehash {
					t.Errorf("password %q hash %q: expected ErrNullByte, got matches=%v needsRehash=%v err=%v", c.Password, c.Hash, match, rehash, err)
				}
			}
		})
	}

	for _, variant := range []Argon2Variant{Argon2id, Argon2i} {
		func() {
			defer func() {
				err, _ := recover().(error)
				if !errors.Is(err, ErrNullByte) {
					t.Errorf("HashPasswordArgon2Default(%s): expected panic with ErrNullByte, got %v", variant, err)
				}
			}()
			HashPasswordArgon2Default(variant, "a\x00a")
		}()
	}
	if _, err := HashPassword("a\x00a"); !errors.Is(err, ErrNullByte) {
		t.Errorf("HashPassword: expected ErrNullByte, got %v", err)
	}
	if _, err := HashPasswordBcrypt("a\x00a", MinBcryptCost); !errors.Is(err, ErrNullByte) {
		t.Errorf("HashPasswordBcrypt: expected ErrNullByte, got %v", err)
	}
	if _, err := VerifyArgon2Password(Argon2id, pass+"\x00", passes[0].Hash); !errors.Is(err, ErrNullByte) {
		t.Errorf("VerifyArgon2Password: expected ErrNullByte, got %v", err)
	}
	if _, err := ParseArgon2Mcf(Argon2id, passes[0].Hash+"\x00"); !errors.Is(err, ErrNullByte) {
		t.Errorf("ParseArgon2Mcf: expected ErrNullByte, got %v", err)
	}
}
