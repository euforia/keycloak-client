package keycloak

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/SermoDigital/jose/jws"
)

const (
	DefaultRealm     = "master"
	DefaultProtocol  = "openid-connect"
	DefaultGrantType = "password"
)

type Client struct {
	kcUrl    string
	realm    string
	protocol string
}

func NewClient(urlStr, realm, protocol string) *Client {
	return &Client{
		kcUrl:    urlStr,
		realm:    realm,
		protocol: protocol,
	}
}

func (kc *Client) getUrl() string {
	if kc.protocol != "" {
		return fmt.Sprintf("%s/realms/%s/protocol/%s/token", kc.kcUrl, kc.realm, kc.protocol)
	}
	// protocol is openid-connect
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", kc.kcUrl, kc.realm)

}

func (kc *Client) requestForToken(v url.Values) (tokenMeta *TokenMetadata, err error) {
	rsp, err := http.PostForm(kc.getUrl(), v)
	if err == nil && rsp.StatusCode >= 200 && rsp.StatusCode < 400 {
		var b []byte
		b, err = ioutil.ReadAll(rsp.Body)
		ioutil.WriteFile("token", b, 0644)
		var tokenMeta TokenMetadata
		if err = json.Unmarshal(b, &tokenMeta); err == nil {
			return &tokenMeta, nil
		}
	}
	return nil, err
}

func (kc *Client) TokenWithCreds(clientId, username, password string) (*TokenMetadata, error) {
	v := url.Values{
		"client_id":  []string{clientId},
		"grant_type": []string{"password"},
		"username":   []string{username},
		"password":   []string{password},
	}
	//https://auth-uswest.deluxe-dl3.com/auth/realms/master/protocol/openid-connect/token -d 'grant_type=password' -d 'client_id=asset-manager' -d 'username=<username>' -d 'password=<password>'
	return kc.requestForToken(v)
}

func (kc *Client) RefreshToken(clientId, refreshToken string) (*TokenMetadata, error) {
	v := url.Values{
		"client_id":     []string{clientId},
		"grant_type":    []string{"refresh_token"},
		"refresh_token": []string{refreshToken},
	}
	return kc.requestForToken(v)
}

func (kc *Client) GetToken(curToken *TokenMetadata, bufSec time.Duration, clientId string, username string, password string) (*TokenMetadata, error) {
	if curToken != nil {
		if t, err := jws.ParseJWT([]byte(curToken.AccessToken)); err == nil {
			if exp, ok := t.Claims().Expiration(); ok {
				n := time.Now()
				if exp.Add(-bufSec * time.Second).Before(n) {
					return kc.RefreshToken(clientId, curToken.RefreshToken)
				}
				return curToken, nil
			}
		}
	}
	return kc.TokenWithCreds(clientId, username, password)
}
