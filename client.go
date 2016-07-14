package keycloak

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
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

func (kc *Client) doRequest(r *http.Request) (b []byte, err error) {
	var resp *http.Response
	if resp, err = http.DefaultClient.Do(r); err == nil {
		if b, err = ioutil.ReadAll(resp.Body); err == nil {
			defer resp.Body.Close()
		}
	}
	return
}

// In progress
func (kc *Client) TokenWithCreds(grantType, clientId, username, password string) (tokenMeta TokenMetadata, err error) {
	req, _ := http.NewRequest("POST", kc.getUrl(), nil)

	params := url.Values{
		"client_id":  []string{clientId},
		"grant_type": []string{grantType},
		"username":   []string{username},
		"password":   []string{password},
	}

	req.URL.RawQuery = params.Encode()

	var b []byte
	if b, err = kc.doRequest(req); err == nil {
		err = json.Unmarshal(b, &tokenMeta)
	}

	//https://auth-uswest.deluxe-dl3.com/auth/realms/master/protocol/openid-connect/token -d 'grant_type=password' -d 'client_id=asset-manager' -d 'username=<username>' -d 'password=<password>'
	return
}
