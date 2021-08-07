package storage

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"testing"
)

var token = "Alireza1380##"

var config = &AppConfig{
	HashPassword: nil,
	Key:          nil,
	Cost:         15,
	HmacConf: &HmacConfig{
		HashMethod:    sha512.New,
		HashAlgorithm: sha512.New(),
		HmacSigner:    nil,
	},
}

func TestHmac(t *testing.T) {
	config.KeyGenerator()
	sigToken, err := config.HmacSigToken([]byte(token))
	if err != nil {
		t.Fatal(err)
		return
	}

	same, err := config.CheckSignMsg([]byte(token), sigToken)
	if err != nil {
		t.Fatal(err)
		return
	}
	if same == false {
		t.Error("oldSig and newSig are not equal.")
	}

	fmt.Println(hex.EncodeToString(sigToken))
}
