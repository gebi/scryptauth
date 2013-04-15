package scryptauth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func DecodeBase64(str string) (pw_cost uint, hash, salt []byte, err error) {
	tmp := strings.SplitN(str, ":", 3)
	tmp_pwcost, err := strconv.ParseUint(tmp[0], 10, 0)
	if err != nil {
		err = errors.New("Error: parsing pw_cost parameter")
		return
	}
	pw_cost = uint(tmp_pwcost)
	hash, err = base64.URLEncoding.DecodeString(tmp[1])
	if err != nil {
		err = errors.New("Error: decoding base64 hash")
		return
	}
	salt, err = base64.URLEncoding.DecodeString(tmp[2])
	if err != nil {
		err = errors.New("Error: decoding base64 salt")
		return
	}
	return
}

func EncodeBase64(pw_cost uint, hash, salt []byte) (str string) {
	b64_salt := base64.URLEncoding.EncodeToString(salt)
	b64_hash := base64.URLEncoding.EncodeToString(hash)
	str = fmt.Sprintf("%d:%s:%s", pw_cost, b64_hash, b64_salt)
	return
}
