# Authentication Methods
 A package for encrypting and decrypting tokens and messages with Golang.
 A layer at the top of other packages for encrypting and decrypting.

***

## HMAC/sha Method
 Have to function for using them for signing and checking the validation of token
 Also you can define your DAO layer everything you want.

## JWT Method
 Have two handlers for signing and parsing the signed token for getting the claims.
 Using Hmac/sha methods that I implemented for HMAC method section.
```
func (conf *AppConfig) CreateSignedToken(uc *UserClaims) (string, error)

func (conf *AppConfig) ParseSignedToken(signedToken string) (*UserClaims, error)
```
