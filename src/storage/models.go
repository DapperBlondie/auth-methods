package storage

import (
	"hash"
	"math/rand"
)

type AppConfig struct {
	HashPassword []byte
	Key          []byte
	Cost         int
	HmacConf     *HmacConfig
	Rnd          *rand.Rand
}

type HmacConfig struct {
	HashMethod    func() hash.Hash
	HashAlgorithm hash.Hash
	HmacSigner    hash.Hash
}
