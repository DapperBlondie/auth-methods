package storage

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"log"
	"math/rand"
	"testing"
	"time"
)

var token = "Alireza1380##"

var config = &AppConfig{
	HashPassword: nil,
	Key:          []byte{},
	Cost:         15,
	HmacConf: &HmacConfig{
		HashMethod:    sha512.New,
		HashAlgorithm: sha512.New(),
		HmacSigner:    nil,
	},
	Rnd:           nil,
	JwtConf:       &JwtConfig{JwtKeyMethod: jwt.SigningMethodHS512},
	Base64Encoder: nil,
}

// TestHmac testing hmac functionalities
func TestHmac(t *testing.T) {
	src := rand.NewSource(time.Now().UnixNano())
	rnd := rand.New(src)
	config.Rnd = rnd
	config.UUIDKeyGenerator()

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

// TestJWT testing jwt functionalities
func TestJWT(t *testing.T) {
	src := rand.NewSource(time.Now().UnixNano())
	rnd := rand.New(src)
	config.Rnd = rnd
	config.UUIDKeyGenerator()

	claims := &UserClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  "localhost:8080",
			ExpiresAt: time.Now().Add(time.Hour * 10).UnixNano(),
			Id:        "123345",
			IssuedAt:  time.Now().UnixNano(),
			Issuer:    "localhost:8080",
			NotBefore: time.Now().UnixNano(),
			Subject:   "Testing JWT functionalities",
		},
		SessionID: 12333,
	}

	st, err := config.CreateSignedToken(claims)
	if err != nil {
		t.Fatal(err.Error())
		return
	}
	fmt.Println(st)

	cm, err := config.ParseSignedToken(st)
	if err != nil {
		t.Fatal(err.Error())
		return
	}
	fmt.Println(cm)
	return
}

// TestEncoding testing the base64 functionalities
func TestEncoding(t *testing.T) {
	msg := "Hello, How are you ?"
	fmt.Println(config.EncodingBase64(base64.URLEncoding, msg))
}

func TestDecoding(t *testing.T) {
	msg := "Hello, How are you ?"
	encoded := config.EncodingBase64(base64.URLEncoding, msg)
	fmt.Println(encoded)

	decoded, err := config.DecodingBase64(encoded)
	if err != nil {
		log.Println(err.Error())
		t.Error(err)
		return
	}

	fmt.Println(string(decoded))
}
