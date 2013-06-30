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
	result   []byte
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

func benchmarkScrypt(i int, b *testing.B) {
	user_pw := []byte("bar")
	var r []byte
	for n := 0; n < b.N; n++ {
		r, _ = x.Hash(uint(i), user_pw, salt)
	}
	result = r
}

func BenchmarkScrypt8(b *testing.B)  { benchmarkScrypt(8, b) }
func BenchmarkScrypt9(b *testing.B)  { benchmarkScrypt(9, b) }
func BenchmarkScrypt10(b *testing.B) { benchmarkScrypt(10, b) }
func BenchmarkScrypt11(b *testing.B) { benchmarkScrypt(11, b) }
func BenchmarkScrypt12(b *testing.B) { benchmarkScrypt(12, b) }
func BenchmarkScrypt13(b *testing.B) { benchmarkScrypt(13, b) }
func BenchmarkScrypt14(b *testing.B) { benchmarkScrypt(14, b) }
func BenchmarkScrypt15(b *testing.B) { benchmarkScrypt(15, b) }
func BenchmarkScrypt16(b *testing.B) { benchmarkScrypt(16, b) }
func BenchmarkScrypt17(b *testing.B) { benchmarkScrypt(17, b) }
func BenchmarkScrypt18(b *testing.B) { benchmarkScrypt(18, b) }
func BenchmarkScrypt19(b *testing.B) { benchmarkScrypt(19, b) }

// Example function showing usage of generating hash of user_password
func ExampleScryptAuth_Gen() {
	hmac_key := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") // PLEASE CHANGE THIS KEY FOR PRODUCTION USE
	user_password := []byte("test123")

	// Create new instace of scryptauth with strength factor 12 and hmac_key
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
	fmt.Printf("hash=%x salt=%x\n", hash, salt)
}
