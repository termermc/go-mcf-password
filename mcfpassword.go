package mcfpassword

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
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
// The message never contains the hash string itself, so it is safe to log.
type InvalidHashFormatError struct {
	Message string
}

func (err *InvalidHashFormatError) Error() string {
	return "malformed password hash string: " + err.Message
}

// ErrNullByte is returned when a password or password hash string contains a null byte.
// Null bytes are rejected for every algorithm. Some implementations treat them as string terminators, which
// lets different passwords produce the same hash (for example, with bcrypt "a" and "a\x00a" are equivalent).
var ErrNullByte = errors.New("password or password hash contains a null byte")

func containsNull(s string) bool {
	return strings.IndexByte(s, 0) != -1
}

// HashParametersExceedLimitError is returned by VerifyPasswordWithOptions when a hash's cost parameters
// exceed the limits configured in VerifyOptions. No hashing work is done in that case.
type HashParametersExceedLimitError struct {
	// The name of the parameter that exceeded its limit (e.g. "m", "t" or "cost").
	Parameter string

	// The value found in the hash.
	Value uint64

	// The configured limit.
	Limit uint64
}

func (err *HashParametersExceedLimitError) Error() string {
	return fmt.Sprintf("password hash parameter %s=%d exceeds configured limit of %d", err.Parameter, err.Value, err.Limit)
}

// Argon2Variant is a variant of the argon2 algorithm.
type Argon2Variant string

func (v Argon2Variant) String() string {
	return string(v)
}

func (v Argon2Variant) isValid() bool {
	return v == Argon2i || v == Argon2id
}

const (
	// Argon2id is a hybrid between argon2i and the legacy argon2d, providing a balance between GPU cracking and side-channel attack resistance.
	// It is the recommended variant.
	Argon2id = Argon2Variant("argon2id")

	// Argon2i is a variant of argon2 that provides resistance to side-channel attacks.
	// It is recommended to use Argon2id instead.
	Argon2i = Argon2Variant("argon2i")
)

// MinArgon2SaltLen is the minimum salt length, in bytes, accepted by HashPasswordArgon2.
const MinArgon2SaltLen = 8

// MinArgon2HashLen is the minimum hash (tag) length, in bytes, accepted by HashPasswordArgon2 and ParseArgon2Mcf.
const MinArgon2HashLen = 4

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

func decodeBase64RawOrPadded(s string) ([]byte, error) {
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		// Try StdEncoding (with padding)
		b, err = base64.StdEncoding.DecodeString(s)
	}
	return b, err
}

// ParseArgon2Mcf parses an argon2 (argon2i or argon2id) MCF hash string and returns the hash and parameters.
// The variant parameter must be either "argon2i" or "argon2id".
// Only argon2 version 19 (0x13) is supported.
// If the hash string contains a null byte, ErrNullByte is returned.
// If the hash string is invalid, InvalidHashFormatError is returned.
// If `variant` is invalid, the hash algorithm in the string does not match `variant`,
// or the argon2 version is unsupported, UnsupportedPasswordHashAlgorithmError is returned.
func ParseArgon2Mcf(variant Argon2Variant, hashStr string) (Argon2Hash, error) {
	var empty Argon2Hash

	if !variant.isValid() {
		return empty, &UnsupportedPasswordHashAlgorithmError{Algorithm: variant.String()}
	}
	if containsNull(hashStr) {
		return empty, ErrNullByte
	}

	parts := strings.Split(hashStr, "$")
	if len(parts) < 2 || parts[0] != "" {
		return empty, &InvalidHashFormatError{Message: "missing leading $"}
	}
	if parts[1] != variant.String() {
		return empty, &UnsupportedPasswordHashAlgorithmError{Algorithm: parts[1]}
	}
	if len(parts) != 6 {
		return empty, &InvalidHashFormatError{Message: fmt.Sprintf("expected 6 $-separated fields, got %d", len(parts))}
	}

	// Parse version
	versionStr, ok := strings.CutPrefix(parts[2], "v=")
	if !ok {
		return empty, &InvalidHashFormatError{Message: `missing "v=" version field`}
	}
	version, err := strconv.ParseUint(versionStr, 10, 32)
	if err != nil {
		return empty, &InvalidHashFormatError{Message: fmt.Sprintf("invalid version %q", versionStr)}
	}
	if version != argon2.Version {
		return empty, &UnsupportedPasswordHashAlgorithmError{Algorithm: fmt.Sprintf("%s version %d", variant, version)}
	}

	// Parse parameters
	var memoryKib, timeInt uint32
	var parallelism uint8
	var seenM, seenT, seenP bool
	for _, param := range strings.Split(parts[3], ",") {
		key, val, ok := strings.Cut(param, "=")
		if !ok {
			return empty, &InvalidHashFormatError{Message: fmt.Sprintf("invalid parameter format %q", param)}
		}
		switch key {
		case "m":
			if seenM {
				return empty, &InvalidHashFormatError{Message: `duplicate parameter "m"`}
			}
			seenM = true
			mem, err := strconv.ParseUint(val, 10, 32)
			if err != nil {
				return empty, &InvalidHashFormatError{Message: fmt.Sprintf("invalid memory value %q", val)}
			}
			memoryKib = uint32(mem)
		case "t":
			if seenT {
				return empty, &InvalidHashFormatError{Message: `duplicate parameter "t"`}
			}
			seenT = true
			t, err := strconv.ParseUint(val, 10, 32)
			if err != nil {
				return empty, &InvalidHashFormatError{Message: fmt.Sprintf("invalid time value %q", val)}
			}
			timeInt = uint32(t)
		case "p":
			if seenP {
				return empty, &InvalidHashFormatError{Message: `duplicate parameter "p"`}
			}
			seenP = true
			p, err := strconv.ParseUint(val, 10, 8)
			if err != nil {
				return empty, &InvalidHashFormatError{Message: fmt.Sprintf("invalid parallelism value %q", val)}
			}
			parallelism = uint8(p)
		default:
			return empty, &InvalidHashFormatError{Message: fmt.Sprintf("unknown parameter %q", key)}
		}
	}
	if !seenM || !seenT || !seenP {
		return empty, &InvalidHashFormatError{Message: `parameters "m", "t" and "p" are all required`}
	}
	if timeInt < 1 {
		return empty, &InvalidHashFormatError{Message: "time must be at least 1"}
	}
	if parallelism < 1 {
		return empty, &InvalidHashFormatError{Message: "parallelism must be at least 1"}
	}
	if uint64(memoryKib) < 8*uint64(parallelism) {
		return empty, &InvalidHashFormatError{Message: "memory must be at least 8 times parallelism"}
	}

	saltBytes, err := decodeBase64RawOrPadded(parts[4])
	if err != nil {
		return empty, &InvalidHashFormatError{Message: "invalid salt base64: " + err.Error()}
	}
	if len(saltBytes) < 1 {
		return empty, &InvalidHashFormatError{Message: "salt is empty"}
	}
	hashBytes, err := decodeBase64RawOrPadded(parts[5])
	if err != nil {
		return empty, &InvalidHashFormatError{Message: "invalid hash base64: " + err.Error()}
	}
	if len(hashBytes) < MinArgon2HashLen {
		return empty, &InvalidHashFormatError{Message: fmt.Sprintf("hash must be at least %d bytes", MinArgon2HashLen)}
	}

	return Argon2Hash{
		Variant: variant,
		Version: int(version),
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
// If any parameters are missing or invalid, or the variant is invalid, the function will panic.
// If the password contains a null byte, the function panics with ErrNullByte; use HashPassword to get it as an error instead.
// Parameters must satisfy: SaltLen >= MinArgon2SaltLen, HashLen >= MinArgon2HashLen, Time >= 1,
// Parallelism >= 1 and Memory >= 8*Parallelism.
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
	if !variant.isValid() {
		panic(fmt.Errorf(`HashPasswordArgon2: invalid argon2 variant "%s"`, variant))
	}
	if containsNull(password) {
		panic(fmt.Errorf("HashPasswordArgon2: %w", ErrNullByte))
	}
	if saltLen < MinArgon2SaltLen {
		panic(fmt.Sprintf("HashPasswordArgon2: params.SaltLen is unspecified or <%d", MinArgon2SaltLen))
	}
	if hashLen < MinArgon2HashLen {
		panic(fmt.Sprintf("HashPasswordArgon2: params.HashLen is unspecified or <%d", MinArgon2HashLen))
	}
	if time < 1 {
		panic("HashPasswordArgon2: params.Time is unspecified or <1")
	}
	if parallelism < 1 {
		panic("HashPasswordArgon2: params.Parallelism is unspecified or <1")
	}
	if uint64(memoryKib) < 8*uint64(parallelism) {
		panic("HashPasswordArgon2: params.Memory is unspecified or less than 8*params.Parallelism")
	}

	// Generate random salt.
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		panic(fmt.Errorf("HashPasswordArgon2: failed to generate random salt for argon2 password hash: %w", err))
	}

	// Hash the password.
	hash := computeArgon2(variant, []byte(password), salt, time, memoryKib, parallelism, uint32(hashLen))

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

// computeArgon2 runs the argon2 variant. The variant must already be validated.
func computeArgon2(variant Argon2Variant, password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	if variant == Argon2i {
		return argon2.Key(password, salt, time, memory, threads, keyLen)
	}
	return argon2.IDKey(password, salt, time, memory, threads, keyLen)
}

// HashPasswordArgon2Default hashes the provided password with the specified argon2 variant and returns an MCF string containing the hash and all parameters used.
// Uses default recommended parameters.
// If the variant is invalid, or the password contains a null byte, the function will panic.
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
// If the password contains a null byte, ErrNullByte is returned.
//
// If you don't know which algorithm to use, use HashPassword instead.
func HashPasswordBcrypt(password string, cost int) (string, error) {
	if cost < MinBcryptCost {
		return "", ErrBcryptCostTooLow
	}
	if len(password) > MaxBcryptPasswordLen {
		return "", ErrBcryptPasswordTooLong
	}
	if containsNull(password) {
		return "", ErrNullByte
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

// verifyArgon2Hash recomputes the hash for password using parsed's parameters and compares in constant time.
func verifyArgon2Hash(password string, parsed Argon2Hash) bool {
	newHashBytes := computeArgon2(
		parsed.Variant,
		[]byte(password),
		parsed.Salt,
		parsed.Parameters.Time,
		parsed.Parameters.Memory,
		parsed.Parameters.Parallelism,
		uint32(len(parsed.Hash)),
	)

	return subtle.ConstantTimeCompare(parsed.Hash, newHashBytes) == 1
}

// VerifyArgon2Password verifies a password against an argon2 MCF hash.
// The MCF hash's argon2 variant must match the specified variant.
// If the MCF is not the same variant, returns UnsupportedPasswordHashAlgorithmError.
// If the MCF is malformed, returns InvalidHashFormatError.
// If the password or MCF contains a null byte, returns ErrNullByte.
//
// No limits are applied to the hash's cost parameters; see VerifyPasswordWithOptions if the hash may be untrusted.
func VerifyArgon2Password(variant Argon2Variant, password string, mcf string) (matches bool, err error) {
	if containsNull(password) {
		return false, ErrNullByte
	}
	parsed, err := ParseArgon2Mcf(variant, mcf)
	if err != nil {
		return false, err
	}

	return verifyArgon2Hash(password, parsed), nil
}

// HashPassword hashes the provided password with the default algorithm and parameters and returns an MCF string containing the hash and all parameters used.
// The default algorithm is currently Argon2id.
//
// If the password contains a null byte, ErrNullByte is returned.
func HashPassword(password string) (string, error) {
	if containsNull(password) {
		return "", ErrNullByte
	}
	return HashPasswordArgon2Default(Argon2id, password), nil
}

// VerifyOptions configures VerifyPasswordWithOptions.
// The zero value applies no limits and uses DefaultArgon2Parameters as the rehash target.
type VerifyOptions struct {
	// The maximum argon2 memory parameter (m), in kibibytes. 0 means no limit.
	MaxArgon2Memory uint32

	// The maximum argon2 time parameter (t). 0 means no limit.
	MaxArgon2Time uint32

	// The maximum bcrypt cost. 0 means no limit.
	MaxBcryptCost int

	// The argon2id parameters that hashes are expected to meet.
	// If a matching argon2id hash has a lower Memory, Time, HashLen or SaltLen than these, needsRehash is true.
	// Parallelism is not compared, since it does not affect the hash's strength.
	// If all fields are zero, DefaultArgon2Parameters is used.
	Argon2RehashParameters Argon2Parameters
}

// VerifyPassword verifies a password against a Modular Crypt Format hash.
// If the password or hash contains a null byte, returns ErrNullByte.
// If the hash is invalid, returns InvalidHashFormatError.
// If the hash algorithm is not supported, returns UnsupportedPasswordHashAlgorithmError.
// Otherwise, returns true or false for `matches`.
//
// If the password matches and its hash should be upgraded, returns true for `needsRehash`.
// This is the case for non-argon2id hashes, and for argon2id hashes whose parameters are weaker than DefaultArgon2Parameters.
// If so, call `HashPassword` to rehash the password.
// `needsRehash` is never true when `matches` is false.
//
// No limits are applied to the hash's cost parameters. If hashes may come from an untrusted source,
// use VerifyPasswordWithOptions to limit them.
func VerifyPassword(password string, mcf string) (matches bool, needsRehash bool, err error) {
	return VerifyPasswordWithOptions(password, mcf, VerifyOptions{})
}

// VerifyPasswordWithOptions is like VerifyPassword, but accepts options for limiting hash cost parameters
// and for choosing the argon2id parameters that trigger a rehash.
// If a hash's parameters exceed a configured limit, returns HashParametersExceedLimitError without doing any hashing work.
func VerifyPasswordWithOptions(password string, mcf string, opts VerifyOptions) (matches bool, needsRehash bool, err error) {
	if containsNull(password) || containsNull(mcf) {
		return false, false, ErrNullByte
	}
	if len(mcf) == 0 {
		return false, false, &InvalidHashFormatError{Message: "empty string"}
	}
	if mcf[0] != '$' {
		return false, false, &InvalidHashFormatError{Message: "missing leading $"}
	}
	dollarIdx := strings.IndexByte(mcf[1:], '$')
	if dollarIdx == -1 {
		return false, false, &InvalidHashFormatError{Message: "missing second $"}
	}

	algo := mcf[1 : dollarIdx+1]
	switch algo {
	case "2y", "2a", "2b":
		// Bcrypt
		if opts.MaxBcryptCost > 0 {
			cost, err := bcrypt.Cost([]byte(mcf))
			if err != nil {
				return false, false, &InvalidHashFormatError{Message: "invalid bcrypt hash: " + err.Error()}
			}
			if cost > opts.MaxBcryptCost {
				return false, false, &HashParametersExceedLimitError{Parameter: "cost", Value: uint64(cost), Limit: uint64(opts.MaxBcryptCost)}
			}
		}

		// CompareHashAndPassword uses a constant-time comparison internally.
		err := bcrypt.CompareHashAndPassword([]byte(mcf), []byte(password))
		if err == nil {
			// Password matches, but needs rehashing.
			return true, true, nil
		}
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, false, nil
		}
		return false, false, &InvalidHashFormatError{Message: "invalid bcrypt hash: " + err.Error()}
	case "argon2i", "argon2id":
		variant := Argon2Variant(algo)
		parsed, err := ParseArgon2Mcf(variant, mcf)
		if err != nil {
			return false, false, err
		}

		if opts.MaxArgon2Memory > 0 && parsed.Parameters.Memory > opts.MaxArgon2Memory {
			return false, false, &HashParametersExceedLimitError{Parameter: "m", Value: uint64(parsed.Parameters.Memory), Limit: uint64(opts.MaxArgon2Memory)}
		}
		if opts.MaxArgon2Time > 0 && parsed.Parameters.Time > opts.MaxArgon2Time {
			return false, false, &HashParametersExceedLimitError{Parameter: "t", Value: uint64(parsed.Parameters.Time), Limit: uint64(opts.MaxArgon2Time)}
		}

		if !verifyArgon2Hash(password, parsed) {
			return false, false, nil
		}

		if variant != Argon2id {
			// Password matches, but needs rehashing to argon2id.
			return true, true, nil
		}

		// Password matches. Rehash only if the parameters are weaker than the target.
		target := opts.Argon2RehashParameters
		if target == (Argon2Parameters{}) {
			target = DefaultArgon2Parameters
		}
		p := parsed.Parameters
		weaker := p.Memory < target.Memory ||
			p.Time < target.Time ||
			p.HashLen < target.HashLen ||
			p.SaltLen < target.SaltLen
		return true, weaker, nil
	}

	return false, false, &UnsupportedPasswordHashAlgorithmError{Algorithm: algo}
}
