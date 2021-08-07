package main

import (
	"crypto/sha512"
	"github.com/DapperBlondie/auth-methods/src/storage"
	"log"
)

var config *storage.AppConfig

func main() {
	config = &storage.AppConfig{
		HashPassword: nil,
		Key:          nil,
		Cost: 15,
		HashMethod: sha512.New(),
		HmacSigner: nil,
	}

	err := config.GenerateHash("Alireza1380##")
	if err != nil {
		log.Println(err.Error())
		return
	}

	return
}
