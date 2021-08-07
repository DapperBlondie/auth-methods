package storage

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
)

// GenerateHash with bcrypt pkg
func (conf *AppConfig) GenerateHash(password string) error {
	hashPass, err := bcrypt.GenerateFromPassword([]byte(password), conf.Cost)
	if err != nil {
		log.Println(err.Error())
		return err
	}
	conf.HashPassword = hashPass

	return nil
}

// ComparePassAndHash for comparing hashPass and password
func (conf *AppConfig) ComparePassAndHash(password string) error {
	err := bcrypt.CompareHashAndPassword(conf.HashPassword, []byte(password))
	if err != nil {
		log.Println(err.Error())
		return err
	}

	fmt.Println("Hash and Password matches !")
	return nil
}
