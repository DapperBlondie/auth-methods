package storage

import "hash"

type AppConfig struct {
	HashPassword []byte
	Key          []byte
	Cost         int
	HmacConf     *HmacConfig
}

type HmacConfig struct {
	HashMethod    func() hash.Hash
	HashAlgorithm hash.Hash
	HmacSigner    hash.Hash
}
