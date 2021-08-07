package storage

import (
	"github.com/dgrijalva/jwt-go"
	"hash"
	"math/rand"
)

type AppConfig struct {
	HashPassword []byte
	Key          []byte
	Cost         int
	HmacConf     *HmacConfig
	Rnd          *rand.Rand
	JwtConf      *JwtConfig
}

type HmacConfig struct {
	HashMethod    func() hash.Hash
	HashAlgorithm hash.Hash
	HmacSigner    hash.Hash
}

type JwtConfig struct {
	JwtKeyMethod jwt.SigningMethod
}

type UserClaims struct {
	jwt.StandardClaims
	SessionID int64
}
