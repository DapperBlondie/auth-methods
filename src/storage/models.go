package storage

import (
	"encoding/base64"
	"github.com/dgrijalva/jwt-go"
	"hash"
	"math/rand"
)

// AppConfig use for holding the Application configuration
type AppConfig struct {
	HashPassword  []byte
	Key           []byte
	Cost          int
	HmacConf      *HmacConfig
	Rnd           *rand.Rand
	JwtConf       *JwtConfig
	Base64Encoder *base64.Encoding
}

// HmacConfig use for holding the HMAC configurations
type HmacConfig struct {
	HashMethod    func() hash.Hash
	HashAlgorithm hash.Hash
	HmacSigner    hash.Hash
}

// JwtConfig use for holding the jwt configurations
type JwtConfig struct {
	JwtKeyMethod jwt.SigningMethod
}

// UserClaims default claims based on jwt.StandardClaims
type UserClaims struct {
	jwt.StandardClaims
	SessionID int64
}
