package keycloak

import (
	"fmt"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jwt"
)

type KeycloakJWT struct {
	j jwt.JWT
}

func NewKeycloakJWT(j jwt.JWT) *KeycloakJWT {
	return &KeycloakJWT{j}
}

func (kjwt *KeycloakJWT) GetUsername() string {
	username, _ := kjwt.j.Claims().Get("preferred_username").(string)
	return username
}

// Extract realm role ids from the claims
func (kjwt *KeycloakJWT) GetRealmRoles() (roleIds []string, err error) {
	if ra := kjwt.Get("realm_access"); ra != nil {
		if rv, ok := ra.(map[string]interface{}); ok {
			roleIds, err = getRolesFromMap(rv)
			return
		}
		err = fmt.Errorf("Realm access invalid type")
		return
	}

	err = fmt.Errorf("'realm_access' not found")
	return
}

// Extract resource role ids from jwt claims
func (kjwt *KeycloakJWT) GetResourceRoles(resource string) (roleIds []string, err error) {
	if ra := kjwt.Claims().Get("resource_access"); ra != nil {

		if rv, ok := ra.(map[string]interface{}); ok {

			var v map[string]interface{}
			if v, ok = rv[resource].(map[string]interface{}); ok {

				roleIds, err = getRolesFromMap(v)
				return
			}
			err = fmt.Errorf("No roles defined: %s", resource)
			return

		}
		err = fmt.Errorf("Resource access invalid type")
		return
	}

	err = fmt.Errorf("'%s' not found", resource)
	return
}

func (kjwt *KeycloakJWT) Get(key string) interface{} {
	return kjwt.j.Claims().Get(key)
}

func (kjwt *KeycloakJWT) Claims() jwt.Claims {
	//fmt.Println(kjwt.j.Claims())
	return kjwt.j.Claims()
}

// Validate returns an error describing any issues found while
// validating the JWT. For info on the fn parameter, see the
// comment on ValidateFunc.
func (kjwt *KeycloakJWT) Validate(key interface{}, method crypto.SigningMethod, v ...*jwt.Validator) error {
	return kjwt.j.Validate(key, method, v...)
}

// Serialize serializes the JWT into its on-the-wire
// representation.
func (kjwt *KeycloakJWT) Serialize(key interface{}) ([]byte, error) {
	return kjwt.j.Serialize(key)
}

// Get roles array from 'roles' key
func getRolesFromMap(ri map[string]interface{}) (roleIds []string, err error) {

	if roles, ok := ri["roles"].([]interface{}); ok && len(roles) > 0 {

		roleIds = make([]string, len(roles))

		for i, r := range roles {
			if rstr, ok := r.(string); ok {
				roleIds[i] = rstr
				continue
			}
			err = fmt.Errorf("Role id is not a string: %v", r)
			return
		}
		return
	}

	err = fmt.Errorf("No roles defined")
	return
}
