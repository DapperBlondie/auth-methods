package storage

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"github.com/dgrijalva/jwt-go"
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
	Rnd:     nil,
	JwtConf: &JwtConfig{JwtKeyMethod: jwt.SigningMethodHS512},
}

func TestHmac(t *testing.T) {
	src := rand.NewSource(time.Now().UnixNano())
	rnd := rand.New(src)
	config.Rnd = rnd
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

func TestJWT(t *testing.T) {
	src := rand.NewSource(time.Now().UnixNano())
	rnd := rand.New(src)
	config.Rnd = rnd
	config.KeyGenerator()

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
