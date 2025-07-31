package mcfpassword

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"strconv"
	"strings"
)

// UnsupportedPasswordHashAlgorithmError is returned when a password hash is provided that was created with an unsupported algorithm.
type UnsupportedPasswordHashAlgorithmError struct {
	// The algorithm that was not supported.
	Algorithm string
}

func (err *UnsupportedPasswordHashAlgorithmError) Error() string {
	return "unsupported password hashing algorithm: " + err.Algorithm
}

// InvalidHashFormatError is returned when a password hash string is malformed.
type InvalidHashFormatError struct {
	Message string
}

func (err *InvalidHashFormatError) Error() string {
	return "malformed password hash string: " + err.Message
}

// Argon2Variant is a variant of the argon2 algorithm.
type Argon2Variant string

func (v Argon2Variant) String() string {
	return string(v)
}

const (
	// Argon2id is a hybrid between argon2i and the legacy argon2d, providing a balance between GPU cracking and side-channel attack resistance.
	// It is the recommended variant.
	Argon2id = Argon2Variant("argon2id")

	// Argon2i is a variant of argon2 that provides resistance to side-channel attacks.
	// It is recommended to use Argon2id instead.
	Argon2i = Argon2Variant("argon2i")
)

// Argon2Parameters are parameters used to create argon2 hashes.
type Argon2Parameters struct {
	// The hash length, in bytes.
	HashLen int

	// The salt length, in bytes.
	SaltLen int

	// The number of iterations (time cost).
	Time uint32

	// The amount of memory to use, in kibibytes.
	Memory uint32

	// The number of threads to use.
	Parallelism uint8
}

// DefaultArgon2Parameters are the default argon2 parameters to use.
var DefaultArgon2Parameters = Argon2Parameters{
	HashLen:     32,
	SaltLen:     16,
	Time:        3,
	Memory:      65536,
	Parallelism: 4,
}

// DefaultBcryptCost is the default bcrypt cost parameter to use.
const DefaultBcryptCost = 12

// Argon2Hash represents an argon2 (argon2i or argon2id) hash and all its supporting parameters.
type Argon2Hash struct {
	// The argon2 variant.
	Variant Argon2Variant

	// The specific algorithm version used.
	Version int

	// The salt bytes.
	Salt []byte

	// The hash bytes.
	Hash []byte

	// The parameters used.
	Parameters Argon2Parameters
}

// ParseArgon2Mcf parses an argon2 (argon2i or argon2id) MCF hash string and returns the hash and parameters.
// The variant parameter must be either "argon2i" or "argon2id".
// If the hash string is invalid, InvalidHashFormatError is returned.
// If the hash algorithm in the string portion does not match `variant`, UnsupportedPasswordHashAlgorithmError is returned.
func ParseArgon2Mcf(variant Argon2Variant, hashStr string) (Argon2Hash, error) {
	var empty Argon2Hash

	parts := strings.Split(hashStr, "$")
	if len(parts) != 6 || parts[1] != variant.String() {
		return empty, &InvalidHashFormatError{Message: fmt.Sprintf(`invalid algorithm "%s", expected "%s": %s`, parts[1], variant, hashStr)}
	}

	// Parse version
	versionStr := strings.TrimPrefix(parts[2], "v=")
	version, err := strconv.Atoi(versionStr)
	if err != nil {
		return empty, &InvalidHashFormatError{Message: "invalid version " + versionStr + ": " + hashStr}
	}

	// Parse parameters
	params := strings.Split(parts[3], ",")
	var memoryKib, timeInt uint32
	var parallelism uint8
	for _, param := range params {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) != 2 {
			return empty, &InvalidHashFormatError{Message: "invalid parameter format " + param + ": " + hashStr}
		}
		switch kv[0] {
		case "m":
			mem, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return empty, &InvalidHashFormatError{Message: "invalid memory value " + kv[1] + ": " + hashStr}
			}
			memoryKib = uint32(mem)
		case "t":
			t, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return empty, &InvalidHashFormatError{Message: "invalid time value " + kv[1] + ": " + hashStr}
			}
			timeInt = uint32(t)
		case "p":
			p, err := strconv.ParseUint(kv[1], 10, 8)
			if err != nil {
				return empty, &InvalidHashFormatError{Message: "invalid parallelism value " + kv[1] + ": " + hashStr}
			}
			parallelism = uint8(p)
		}
	}

	salt := parts[4]
	hash := parts[5]

	saltBytes, err := base64.RawStdEncoding.DecodeString(salt)
	if err != nil {
		// Try StdEncoding (with padding)
		saltBytes, err = base64.StdEncoding.DecodeString(salt)
		if err != nil {
			return empty, fmt.Errorf("invalid salt base64: %v", err)
		}
	}
	hashBytes, err := base64.RawStdEncoding.DecodeString(hash)
	if err != nil {
		// Try StdEncoding (with padding)
		hashBytes, err = base64.StdEncoding.DecodeString(hash)
		if err != nil {
			return empty, fmt.Errorf("invalid hash base64: %v", err)
		}
	}

	return Argon2Hash{
		Variant: variant,
		Version: version,
		Hash:    hashBytes,
		Salt:    saltBytes,
		Parameters: Argon2Parameters{
			HashLen:     len(hashBytes),
			SaltLen:     len(saltBytes),
			Time:        timeInt,
			Memory:      memoryKib,
			Parallelism: parallelism,
		},
	}, nil
}

// HashPasswordArgon2 hashes the provided password with the specified argon2 variant and returns an MCF string containing the hash and all parameters used.
// To use default parameters, call HashPasswordArgon2Default instead.
// If any parameters are missing or the variant is invalid, the function will panic.
//
// If you don't know which algorithm to use, use HashPassword instead.
func HashPasswordArgon2(
	variant Argon2Variant,
	password string,
	params Argon2Parameters,
) string {
	saltLen := params.SaltLen
	hashLen := params.HashLen
	time := params.Time
	memoryKib := params.Memory
	parallelism := params.Parallelism

	// Validate parameters.
	if saltLen < 1 {
		panic("HashPasswordArgon2: params.SaltLen is unspecified or <1")
	}
	if hashLen < 1 {
		panic("HashPasswordArgon2: params.HashLen is unspecified or <1")
	}
	if time < 1 {
		panic("HashPasswordArgon2: params.Time is unspecified or <1")
	}
	if memoryKib < 1 {
		panic("HashPasswordArgon2: params.Memory is unspecified or <1")
	}
	if parallelism < 1 {
		panic("HashPasswordArgon2: params.Parallelism is unspecified or <1")
	}

	// Generate random salt.
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		panic(fmt.Errorf("HashPasswordArgon2: failed to generate random salt for argon2id password hash: %w", err))
	}

	// Hash the password.
	var hash []byte
	switch variant {
	case Argon2i:
		hash = argon2.Key([]byte(password), salt, time, memoryKib, parallelism, uint32(hashLen))
	case Argon2id:
		hash = argon2.IDKey([]byte(password), salt, time, memoryKib, parallelism, uint32(hashLen))
	default:
		panic(fmt.Errorf(`HashPasswordArgon2: invalid argon2 variant "%s"`, variant))
	}

	// Encode salt and hash to base64 (no padding).
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: `$<variant>$v=<version>$m=<memoryKib>,t=<time>,p=<parallelism>$<salt>$<hash>`.
	mcf := fmt.Sprintf(
		"$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		variant.String(), argon2.Version, memoryKib, time, parallelism, b64Salt, b64Hash,
	)

	return mcf
}

// HashPasswordArgon2Default hashes the provided password with the specified argon2 variant and returns an MCF string containing the hash and all parameters used.
// Uses default recommended parameters.
// If the variant is invalid, the function will panic.
//
// If you don't know which algorithm to use, use HashPassword instead.
func HashPasswordArgon2Default(variant Argon2Variant, password string) string {
	return HashPasswordArgon2(variant, password, DefaultArgon2Parameters)
}

// MinBcryptCost is the minimum bcrypt cost.
const MinBcryptCost = bcrypt.MinCost

// MaxBcryptPasswordLen is the maximum password length that bcrypt can handle.
const MaxBcryptPasswordLen = 72

// ErrBcryptPasswordTooLong is returned when the password passed to HashPasswordBcrypt exceeds the maximum length of 72 bytes.
var ErrBcryptPasswordTooLong = errors.New("password passed to HashPasswordBcrypt exceeds max length of 72 bytes")

// ErrBcryptCostTooLow is returned when the cost specified in HashPasswordBcrypt is below the minimum.
var ErrBcryptCostTooLow = fmt.Errorf("specified bcrypt cost is less than the minimum cost of %d", MinBcryptCost)

// HashPasswordBcrypt hashes the provided password with bcrypt and returns an MCF string containing the hash and all parameters used.
// To use default parameters, call HashPasswordBcryptDefault instead.
//
// If you don't know which algorithm to use, use HashPassword instead.
func HashPasswordBcrypt(password string, cost int) (string, error) {
	if cost < MinBcryptCost {
		return "", ErrBcryptCostTooLow
	}
	if len(password) > MaxBcryptPasswordLen {
		return "", ErrBcryptPasswordTooLong
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("bcrypt: %w", err)
	}

	return string(hash), nil
}

// HashPasswordBcryptDefault hashes the provided password with bcrypt and returns an MCF string containing the hash and all parameters used.
// Uses default recommended parameters.
//
// If you don't know which algorithm to use, use HashPassword instead.
func HashPasswordBcryptDefault(password string) (string, error) {
	return HashPasswordBcrypt(password, DefaultBcryptCost)
}

// VerifyArgon2Password verifies a password against an argon2 MCF hash.
// The MCF hash's argon2 variant must match the specified variant.
// If the MCF is not the same variant, returns UnsupportedPasswordHashAlgorithmError.
func VerifyArgon2Password(variant Argon2Variant, password string, mcf string) (matches bool, err error) {
	oldHash, err := ParseArgon2Mcf(variant, mcf)
	if err != nil {
		return false, err
	}

	var newHashBytes []byte
	switch variant {
	case Argon2i:
		newHashBytes = argon2.Key(
			[]byte(password),
			oldHash.Salt,
			oldHash.Parameters.Time,
			oldHash.Parameters.Memory,
			oldHash.Parameters.Parallelism,
			uint32(len(oldHash.Hash)),
		)
	case Argon2id:
		newHashBytes = argon2.IDKey(
			[]byte(password),
			oldHash.Salt,
			oldHash.Parameters.Time,
			oldHash.Parameters.Memory,
			oldHash.Parameters.Parallelism,
			uint32(len(oldHash.Hash)),
		)
	default:
		return false, fmt.Errorf(`VerifyArgon2Password: invalid argon2 variant "%s"`, variant)
	}

	return bytes.Equal(oldHash.Hash, newHashBytes), nil
}

// HashPassword hashes the provided password with the default algorithm and parameters and returns an MCF string containing the hash and all parameters used.
// The default algorithm is currently Argon2id.
//
// Does not return any errors currently; error return is reserved for future use.
// You should still check for errors in case the underlying algorithm changes in the future.
func HashPassword(password string) (string, error) {
	return HashPasswordArgon2Default(Argon2id, password), nil
}

// VerifyPassword verifies a password against a Modular Crypt Format hash.
// If the hash is invalid, returns InvalidHashFormatError.
// If the hash algorithm is not supported, returns UnsupportedPasswordHashAlgorithmError.
// Otherwise, returns true or false for `matches`.
//
// If the password needs to be rehashed, returns true for `needsRehash`.
// If so, call `HashPassword` to rehash the password.
func VerifyPassword(password string, mcf string) (matches bool, needsRehash bool, err error) {
	if len(mcf) == 0 {
		return false, false, &InvalidHashFormatError{Message: "empty string"}
	}
	if mcf[0] != '$' {
		return false, false, &InvalidHashFormatError{Message: "missing leading $: " + mcf}
	}
	dollarIdx := strings.IndexByte(mcf[1:], '$')
	if dollarIdx == -1 {
		return false, false, &InvalidHashFormatError{Message: "missing second $: " + mcf}
	}

	algo := mcf[1 : dollarIdx+1]
	switch algo {
	case "2y", "2a", "2b":
		// Bcrypt
		res := bcrypt.CompareHashAndPassword([]byte(mcf), []byte(password))
		if errors.Is(res, bcrypt.ErrMismatchedHashAndPassword) {
			return false, false, nil
		}

		// Password matches, but needs rehashing.
		return true, true, nil
	case "argon2i":
		matches, err = VerifyArgon2Password(Argon2i, password, mcf)
		if err != nil {
			return false, false, err
		}

		// Password matches, but needs rehashing.
		return matches, true, nil
	case "argon2id":
		matches, err = VerifyArgon2Password(Argon2id, password, mcf)
		if err != nil {
			return false, false, err
		}

		// Password matches.
		// Best supported algorithm; does not need rehashing.
		return matches, false, nil
	}

	return false, false, &UnsupportedPasswordHashAlgorithmError{Algorithm: algo}
}
