package keycloak

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
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

func (kc *Client) requestForToken(t *TokenMetadata, v url.Values) (err error) {
	rsp, err := http.PostForm(kc.getUrl(), v)
	if err == nil && rsp.StatusCode >= 200 && rsp.StatusCode < 400 {
		var b []byte
		b, err = ioutil.ReadAll(rsp.Body)
		ioutil.WriteFile("token", b, 0644)
		if err = json.Unmarshal(b, t); err == nil {
			return nil
		}
	}
	return err
}

func (kc *Client) TokenWithCreds(t *TokenMetadata, clientId, username, password string) error {
	v := url.Values{
		"client_id":  []string{clientId},
		"grant_type": []string{"password"},
		"username":   []string{username},
		"password":   []string{password},
	}
	//https://auth-uswest.deluxe-dl3.com/auth/realms/master/protocol/openid-connect/token -d 'grant_type=password' -d 'client_id=asset-manager' -d 'username=<username>' -d 'password=<password>'
	return kc.requestForToken(t, v)
}

func (kc *Client) RefreshToken(t *TokenMetadata, clientId string) error {
	v := url.Values{
		"client_id":     []string{clientId},
		"grant_type":    []string{"refresh_token"},
		"refresh_token": []string{t.RefreshToken},
	}
	return kc.requestForToken(t, v)
}

func (kc *Client) GetToken(t *TokenMetadata, bufSec time.Duration, clientId string, username string, password string) (err error) {
	if t != nil {
		if exp, err := t.IsExpired(AccessTokenClass, bufSec); err == nil {
			if exp {
				if err = kc.RefreshToken(t, clientId); err == nil {
					return nil
				}
			}
			return nil
		}
	}
	return kc.TokenWithCreds(t, clientId, username, password)
}
