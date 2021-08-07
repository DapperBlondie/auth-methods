package storage

import (
	"crypto/hmac"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
)

// KeyGenerator use for creating the key from bytes storage
func (conf *AppConfig) KeyGenerator() {
	for i := 0; i < conf.HmacConf.HashAlgorithm.Size(); i += 1 {
		j := conf.Rnd.Intn(2000)
		conf.Key = append(conf.Key, randomBytes[j])
	}

	return
}

// GenerateHash with bcrypt package
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

// HmacSigToken use for sign specific token and then return signed token
func (conf *AppConfig) HmacSigToken(token []byte) ([]byte, error) {
	conf.HmacConf.HmacSigner = hmac.New(conf.HmacConf.HashMethod, conf.Key)

	_, err := conf.HmacConf.HmacSigner.Write(token)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	return conf.HmacConf.HmacSigner.Sum(nil), nil
}

// CheckSignMsg use for checking the sign of received token with existing token
func (conf *AppConfig) CheckSignMsg(token, oldSign []byte) (bool, error) {
	newSign, err := conf.HmacSigToken(token)
	if err != nil {
		log.Println(err.Error())
		return false, err
	}

	identifier := hmac.Equal(oldSign, newSign)

	return identifier, nil
}
