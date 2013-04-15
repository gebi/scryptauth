package scryptauth

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
)

type ScryptAuth struct {
	HmacKey []byte

	// scrypt parameter
	N int
	R int
	P int
}

const (
	// Key length and salt length are 32 bytes (256 bits)
	KEYLENGTH = 32
)

func New(pw_cost uint, hmac_key []byte) (*ScryptAuth, error) {
	if pw_cost > 32 && pw_cost%2 != 0 {
		return nil, errors.New("scryptauth new() - invalid pw_cost specified")
	}
	if len(hmac_key) != KEYLENGTH {
		return nil, errors.New("scryptauth new() - unsupported hmac_key length")
	}
	return &ScryptAuth{HmacKey: hmac_key, N: 1 << pw_cost, R: 8, P: 1}, nil
}

func (s ScryptAuth) Hash(user_password, salt []byte) (result []byte, err error) {
	scrypt_hash, err := scrypt.Key(user_password, salt, s.N, s.R, s.P, KEYLENGTH)
	if err != nil {
		return
	}
	hmac := hmac.New(sha256.New, s.HmacKey)
	if _, err = hmac.Write(scrypt_hash); err != nil {
		return
	}
	result = hmac.Sum(nil)
	return
}

func (s ScryptAuth) Check(hash_ref, user_password, salt []byte) (chk bool, err error) {
	result_hash, err := s.Hash(user_password, salt)
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare(result_hash, hash_ref) != 1 {
		return false, errors.New("Error: Hash verification failed")
	}
	return true, nil
}

func (s ScryptAuth) Gen(user_password []byte) (hash, salt []byte, err error) {
	salt = make([]byte, KEYLENGTH)
	salt_length, err := rand.Read(salt)
	if salt_length != KEYLENGTH {
		return nil, nil, errors.New("Insufficient random bytes for salt")
	}
	if err != nil {
		return nil, nil, err
	}

	hash, err = s.Hash(user_password, salt)
	if err != nil {
		return nil, nil, err
	}
	return
}
