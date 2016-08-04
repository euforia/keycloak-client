package keycloak

import (
	"fmt"
	"time"

	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
)

type TokenClass string

const (
	AccessTokenClass  TokenClass = "access_token"
	RefreshTokenClass TokenClass = "refresh_token"
	IdTokenClass      TokenClass = "id_token"
)

type TokenMetadata struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	IdToken          string `json:"id_token"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
}

// Get JWT for the specified token in TokenMetadata
func (tk *TokenMetadata) ParseJWT(tokenClass TokenClass) (j jwt.JWT, err error) {

	var field string
	switch tokenClass {
	case AccessTokenClass:
		field = tk.AccessToken
	case RefreshTokenClass:
		field = tk.RefreshToken
	case IdTokenClass:
		field = tk.IdToken
	default:
		err = fmt.Errorf("Invalid token class: %s", tokenClass)
		return
	}

	j, err = jws.ParseJWT([]byte(field))
	return
}

func (tk *TokenMetadata) IsExpired(tokenClass TokenClass, bufSec time.Duration) (bool, error) {
	if j, err := tk.ParseJWT(tokenClass); err == nil {
		if exp, ok := j.Claims().Expiration(); ok {
			return exp.Add(-bufSec * time.Second).Before(time.Now()), nil
		}
	}
	return true, fmt.Errorf("the token is invalid")
}
