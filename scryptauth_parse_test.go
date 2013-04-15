package scryptauth

import (
	"encoding/base64"
	"fmt"
	"github.com/bmizerany/assert" // MIT
	"testing"
)

func TestEncodeBase64(t *testing.T) {
	str := []byte("AAA")
	str_b64 := base64.URLEncoding.EncodeToString(str)
	a := EncodeBase64(12, str, str)
	assert.Equal(t, a, "12:"+str_b64+":"+str_b64)
}

func TestDecodeBase64(t *testing.T) {
	pw_cost, hash, salt, err := DecodeBase64("12:QUFB:QUFB")
	assert.Equal(t, pw_cost, uint(12))
	assert.Equal(t, hash, []byte("AAA"))
	assert.Equal(t, salt, []byte("AAA"))
	assert.Equal(t, err, nil)
}

func TestEncodeDecodeBase64(t *testing.T) {
	str_ref := "12:3Tnrsg5-QaM7OsyRvqcBv9qS-jqGxzRIXQqvbTUf894=:HrHzQ4S016BffZ2TmwLRYYiIggfSmkwKdEtd1Pk_b-I="
	pw_cost, hash, salt, err := DecodeBase64(str_ref)
	assert.Equal(t, err, nil)
	str := EncodeBase64(pw_cost, hash, salt)
	assert.Equal(t, str, str_ref)
}

// Sample Function to generate new password hash for storing in DB
func ExampleEncodeBase64() {
	hmac_key := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") // PLEASE CHANGE THIS KEY FOR PRODUCTION USE
	user_password := []byte("test123")

	pwhash, err := New(12, hmac_key)
	if err != nil {
		fmt.Print(err)
		return
	}
	hash, salt, err := pwhash.Gen(user_password)
	if err != nil {
		fmt.Print(err)
		return
	}
	str := EncodeBase64(pwhash.PwCost, hash, salt)
	fmt.Print(str)
}

// Sample function to verify stored hash from DB
func ExampleDecodeBase64() {
	db_string := "12:3Tnrsg5-QaM7OsyRvqcBv9qS-jqGxzRIXQqvbTUf894=:HrHzQ4S016BffZ2TmwLRYYiIggfSmkwKdEtd1Pk_b-I="
	hmac_key := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") // PLEASE CHANGE THIS KEY FOR PRODUCTION USE
	user_password := []byte("bar")

	pwhash, err := New(12, hmac_key)
	if err != nil {
		fmt.Print(err)
		return
	}

	pw_cost, hash, salt, err := DecodeBase64(db_string)
	if err != nil {
		fmt.Print(err)
		return
	}
	ok, err := pwhash.Check(pw_cost, hash, user_password, salt)
	if !ok {
		fmt.Printf("Error wrong password for user (%s)", err)
		return
	}
	fmt.Print("ok")
	// Output: ok
}
