package keycloak

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
)

const keycloakTokenHeader = "Authorization"

//
// Currently only supports Direct Grant Access
//
type ClientConfig struct {
	AuthServerUrl string `json:"auth-server-url"`
	PublicClient  bool   `json:"public-client"`
	Realm         string `json:"realm"`
	// RSA Public key
	RealmPublicKey string `json:"realm-public-key"`
	Resource       string `json:"resource"`
	SslRequired    string `json:"ssl-required"`

	// Parsed public key
	publicKey interface{}
}

// verify/parse  public key and load/reload into interface
func (cc *ClientConfig) LoadPublicKey() (err error) {
	block, _ := pem.Decode([]byte(cc.PublicKeyString()))
	cc.publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)
	return
}

func LoadClientConfig(cfgpath string) (occ *ClientConfig, err error) {
	var b []byte
	if b, err = ioutil.ReadFile(cfgpath); err == nil {
		occ = &ClientConfig{}
		if err = json.Unmarshal(b, occ); err == nil {
			err = occ.LoadPublicKey()
		}
	}
	return
}

func (occ *ClientConfig) PublicKeyString() string {
	return "-----BEGIN PUBLIC KEY-----\n" + occ.RealmPublicKey + "\n-----END PUBLIC KEY-----\n"
}

// Get resource role ids based on the resource specified in the config
func (occ *ClientConfig) GetResourceRoles(j *KeycloakJWT) (roleIds []string, err error) {
	return j.GetResourceRoles(occ.Resource)
}

func (occ *ClientConfig) ValidateToken(authToken string) (j *KeycloakJWT, err error) {

	var t jwt.JWT
	if t, err = jws.ParseJWT([]byte(authToken)); err == nil {
		if err = t.Validate(occ.publicKey, crypto.SigningMethodRS256); err == nil {
			j = NewKeycloakJWT(t)
		}
	}

	return
}

func (occ *ClientConfig) ValidateRequestToken(r *http.Request) (j *KeycloakJWT, err error) {
	tokenHeader := r.Header.Get(keycloakTokenHeader)
	if strings.HasPrefix(tokenHeader, "Bearer ") {
		j, err = occ.ValidateToken(tokenHeader[7:])
	} else {
		err = fmt.Errorf("Invalid 'Authorization' header")
	}
	return
}
