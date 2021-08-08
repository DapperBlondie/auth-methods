# Authentication Methods
 A package for encrypting and decrypting tokens and messages with Golang.
 A layer at the top of other packages for encrypting and decrypting.

***

## HMAC/sha Method
 Have to function for using them for signing and checking the validation of token
 Also you can define your DataAccess layer everything you want.
***
## JWT Method
 Have two handlers for signing and parsing the signed token for getting the claims.
 Using Hmac/sha methods that I implemented for HMAC method section.
 With creating random key for every token maybe you do not need rotating key.
 You can store keys as long as its own expiration date.

```
func (conf *AppConfig) CreateSignedToken(uc *UserClaims) (string, error)

func (conf *AppConfig) ParseSignedToken(signedToken string) (*UserClaims, error)
```
***
## Base64 Method
 Use these functionalities for encoding may be URLs or Messages or even 
 use alongside of JWT method for creating keys or tokens.