package keycloak

import (
	"fmt"

	"github.com/SermoDigital/jose/jwt"
)

func GetResourceRoles(j jwt.JWT, resource string) (roleIds []string, err error) {
	if ra := j.Claims().Get("resource_access"); ra != nil {

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

func GetRealmRoles(j jwt.JWT) (roleIds []string, err error) {
	if ra := j.Claims().Get("realm_access"); ra != nil {
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
