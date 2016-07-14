package keycloak

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/euforia/crud-rbac"
)

type HttpKeycloakAuthenticator struct {
	Config *ClientConfig
}

func NewHttpKeycloakAuthenticator(cfgfile string) (*HttpKeycloakAuthenticator, error) {

	cfg, err := LoadClientConfig(cfgfile)
	if err == nil {
		return NewHttpKeycloakAuthenticatorFromConfig(cfg)
	}

	return nil, err
}

func NewHttpKeycloakAuthenticatorFromConfig(cfg *ClientConfig) (*HttpKeycloakAuthenticator, error) {
	err := cfg.LoadPublicKey()
	return &HttpKeycloakAuthenticator{Config: cfg}, err
}

func (hka *HttpKeycloakAuthenticator) AuthenticateRequest(r *http.Request) (j *KeycloakJWT, roles interface{}, err error) {

	if j, err = hka.Config.ValidateRequestToken(r); err == nil {

		var roleIds []string
		if roleIds, err = hka.Config.GetResourceRoles(j); err == nil {

			rls := make([]crudrbac.Role, len(roleIds))
			for i, rid := range roleIds {
				// TODO: Get roles
				role := crudrbac.NewRole()
				role.Id = rid
				rls[i] = *role
			}

			// TODO: Build requested policy

			roles = rls
		}
	}

	return
}

func (hka *HttpKeycloakAuthenticator) ImplicitFlowURL(redirect string) string {
	rd := url.QueryEscape(redirect)

	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth?client_id=%s&response_type=code&state=&redirect_uri=%s",
		hka.Config.AuthServerUrl, hka.Config.Realm, hka.Config.Resource, rd)
	/*
		r, _ := http.NewRequest("GET", urlStr, nil)

		r.URL.Query().Set("client_id", hka.Config.Resource)
		r.URL.Query().Set("response_mode", "fragment")
		r.URL.Query().Set("response_type", "code")
		r.URL.Query().Set("state", "")
	*/
	//https://auth-uswest.deluxe-dl3.com/auth/realms/master/protocol/openid-connect/auth?client_id=asset-manager&redirect_uri=http://localhost:8000/&state=75201af9-c694-4136-8bca-aadd5efffc30&nonce=335f2867-3d54-4461-b6ad-62499dc1315b&response_mode=fragment&response_type=code
	//return r
}
