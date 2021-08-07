package storage

import "hash"

type AppConfig struct {
	HashPassword []byte
	Key []byte
	Cost int
	HashMethod hash.Hash
	HmacSigner hash.Hash
}
