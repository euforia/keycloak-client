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

const KEYCLOAK_TOKEN_HEADER = "Authorization"

//
// Currently only supports Direct Grant Access
//
type KeycloakClientConfig struct {
	AuthServerUrl string `json:"auth-server-url"`
	PublicClient  bool   `json:"public-client"`
	Realm         string `json:"realm"`
	// RSA Public key
	RealmPublicKey string `json:"realm-public-key"`
	Resource       string `json:"resource"`
	SslRequired    string `json:"ssl-required"`
}

func (occ *KeycloakClientConfig) PublicKey() string {
	return "-----BEGIN PUBLIC KEY-----\n" + occ.RealmPublicKey + "\n-----END PUBLIC KEY-----\n"
}

func LoadKeycloakClientConfig(cfgpath string) (occ *KeycloakClientConfig, err error) {
	var b []byte
	if b, err = ioutil.ReadFile(cfgpath); err == nil {
		occ = &KeycloakClientConfig{}
		err = json.Unmarshal(b, occ)
	}
	return
}

type KeycloakClient struct {
	cfg *KeycloakClientConfig

	publicKey interface{}
}

func NewKeycloakClient(cfg *KeycloakClientConfig) (kc *KeycloakClient, err error) {
	kc = &KeycloakClient{cfg: cfg}

	block, _ := pem.Decode([]byte(kc.cfg.PublicKey()))
	kc.publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)

	return
}

func (kc *KeycloakClient) ValidateToken(authToken string) (j jwt.JWT, err error) {

	if j, err = jws.ParseJWT([]byte(authToken)); err == nil {
		err = j.Validate(kc.publicKey, crypto.SigningMethodRS256)
	}

	return
}

func (kc *KeycloakClient) ValidateRequestToken(r *http.Request) (j jwt.JWT, err error) {
	tokenHeader := r.Header.Get(KEYCLOAK_TOKEN_HEADER)
	if strings.HasPrefix(tokenHeader, "Bearer ") {
		j, err = kc.ValidateToken(tokenHeader[7:])
	} else {
		err = fmt.Errorf("Invalid 'Authorization' header")
	}
	return
}
