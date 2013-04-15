package scryptauth

import (
	"fmt"
	"github.com/bmizerany/assert" // MIT
	"testing"
)

var (
	x        *ScryptAuth
	salt     []byte
	hmac_key []byte
)

func init() {
	hmac_key = []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	x, _ = New(12, hmac_key)
	fmt.Sscanf("1eb1f34384b4d7a05f7d9d939b02d16188888207d29a4c0a744b5dd4f93f6fe2", "%x", &salt)
}

func TestNew(t *testing.T) {
	tmp, err := New(12, hmac_key)
	assert.Equal(t, err, nil)

	tmp, err = New(33, hmac_key)
	assert.NotEqual(t, err, nil)
	assert.Equal(t, tmp, (*ScryptAuth)(nil))
}

func TestHash(t *testing.T) {
	hash_ref := "dd39ebb20e7e41a33b3acc91bea701bfda92fa3a86c734485d0aaf6d351ff3de"

	/*
	   data := []string {
	       "dd39ebb20e7e41a33b3acc91bea701bfda92fa3a86c734485d0aaf6d351ff3de", "bar",
	   }
	*/

	h, err := x.Hash(x.PwCost, []byte("bar"), salt)
	assert.Equal(t, err, nil)
	hash := fmt.Sprintf("%x", h)

	assert.Equal(t, hash, hash_ref)
}

func TestHashCheck(t *testing.T) {
	h, err := x.Hash(x.PwCost, []byte("bar"), salt)
	assert.Equal(t, err, nil)
	ok, err := x.Check(x.PwCost, h, []byte("bar"), salt)
	assert.Equal(t, ok, true)
	assert.Equal(t, err, nil)
}

func TestGenCheck(t *testing.T) {
	h, s, err := x.Gen([]byte("bar"))
	assert.Equal(t, err, nil)
	assert.NotEqual(t, h, nil)
	assert.NotEqual(t, s, nil)

	ok, err := x.Check(x.PwCost, h, []byte("bar"), s)
	assert.Equal(t, ok, true)
	assert.Equal(t, err, nil)
}
