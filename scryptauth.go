/* scryptauth is a GO library for secure password handling

It uses hmac(scrypt(user_password, salt), server_key) to protect against
both dictionarry attacks and DB leaks.

scryptauth additionally provides encode/decode routines using base64 to create strings
for storing into a DB.

Copyright Michael Gebetsroither 2012 (michael \x40 mgeb \x2e org)
*/
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
	HmacKey []byte // HMAC key used to secure scrypt hash
	PwCost  uint   // PwCost parameter used to calculate N parameter of scrypt (1<<PwCost == N)

	// scrypt parameter
	R int
	P int
}

const (
	// Key length and salt length are 32 bytes (256 bits)
	KEYLENGTH = 32
)

// Initialise ScryptAuth struct
func New(pw_cost uint, hmac_key []byte) (*ScryptAuth, error) {
	if pw_cost > 32 {
		return nil, errors.New("scryptauth new() - invalid pw_cost specified")
	}
	if len(hmac_key) != KEYLENGTH {
		return nil, errors.New("scryptauth new() - unsupported hmac_key length")
	}
	return &ScryptAuth{HmacKey: hmac_key, PwCost: pw_cost, R: 8, P: 1}, nil
}

// Create hash_ref suitable from Check()
func (s ScryptAuth) Hash(pw_cost uint, user_password, salt []byte) (hash_ref []byte, err error) {
	scrypt_hash, err := scrypt.Key(user_password, salt, 1<<pw_cost, s.R, s.P, KEYLENGTH)
	if err != nil {
		return
	}
	hmac := hmac.New(sha256.New, s.HmacKey)
	if _, err = hmac.Write(scrypt_hash); err != nil {
		return
	}
	hash_ref = hmac.Sum(nil)
	return
}

// Check / Verify user_password against hash_ref/salt
func (s ScryptAuth) Check(pw_cost uint, hash_ref, user_password, salt []byte) (chk bool, err error) {
	result_hash, err := s.Hash(pw_cost, user_password, salt)
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare(result_hash, hash_ref) != 1 {
		return false, errors.New("Error: Hash verification failed")
	}
	return true, nil
}

// Generate hash_ref and create new salt from crypto.rand
func (s ScryptAuth) Gen(user_password []byte) (hash, salt []byte, err error) {
	salt = make([]byte, KEYLENGTH)
	salt_length, err := rand.Read(salt)
	if salt_length != KEYLENGTH {
		return nil, nil, errors.New("Insufficient random bytes for salt")
	}
	if err != nil {
		return nil, nil, err
	}

	hash, err = s.Hash(s.PwCost, user_password, salt)
	if err != nil {
		return nil, nil, err
	}
	return
}
