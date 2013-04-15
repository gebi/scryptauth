package scryptauth

import (
	"encoding/base64"
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
