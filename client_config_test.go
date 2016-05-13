package keycloak

import (
	"net/http"
	"testing"

	"github.com/SermoDigital/jose/jws"
)

var (
	testCfgFile = "./etc/keycloak-config-sample.json"
	testConfig  *ClientConfig
	//testKCClient         *Client
	testExpiredAuthToken = "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJmMDQxZGQxMi04OWI1LTQ5MWQtYWQxNC00ZTg3OTE1NTFlN2IiLCJleHAiOjE0NjI1NTYxMjAsIm5iZiI6MCwiaWF0IjoxNDYyNTUyNTIwLCJpc3MiOiJodHRwczovL2F1dGgtdXN3ZXN0LmRlbHV4ZS1kbDMuY29tL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFzc2V0LW1hbmFnZXIiLCJzdWIiOiJmNDY1M2U2Zi03YmZkLTRhM2YtODcwMi1kZTIzNTE4MzQxMDMiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhc3NldC1tYW5hZ2VyIiwic2Vzc2lvbl9zdGF0ZSI6IjliY2NjZWM5LTVhMDctNGRjMi1iZDUwLWY1ZjFhNjhmNTc1YyIsImNsaWVudF9zZXNzaW9uIjoiMDg3OGVlZWYtMDI1Mi00YTA2LWFjMjYtYjRhNjQ4NjJkMTA4IiwiYWxsb3dlZC1vcmlnaW5zIjpbXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImNyZWF0ZS1yZWFsbSIsImFkbWluIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYXNzZXQtbWFuYWdlciI6eyJyb2xlcyI6WyJhZG1pbiJdfSwibWFzdGVyLXJlYWxtIjp7InJvbGVzIjpbInZpZXctaWRlbnRpdHktcHJvdmlkZXJzIiwidmlldy1yZWFsbSIsIm1hbmFnZS1ldmVudHMiLCJtYW5hZ2UtcmVhbG0iLCJtYW5hZ2UtaWRlbnRpdHktcHJvdmlkZXJzIiwiaW1wZXJzb25hdGlvbiIsInZpZXctZXZlbnRzIiwiY3JlYXRlLWNsaWVudCIsIm1hbmFnZS11c2VycyIsInZpZXctdXNlcnMiLCJ2aWV3LWNsaWVudHMiLCJtYW5hZ2UtY2xpZW50cyJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctcHJvZmlsZSJdfX0sIm5hbWUiOiJBYmhpc2hha2UgUGF0aGFrIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWJoaXNoYWtlLnBhdGhhayIsImdpdmVuX25hbWUiOiJBYmhpc2hha2UiLCJmYW1pbHlfbmFtZSI6IlBhdGhhayIsImVtYWlsIjoiYWJoaXNoYWtlLnBhdGhha0BieWRlbHV4ZS5jb20ifQ.HnhNYlr0cvm5ficWs9veOWs41cpM75tUGiw4KPLSOmg3AIMt0stATl0-GF4GbgqgUxIA64bv2eg8cwJbkQbCMpSBEpOgZ5_fGiDjsDFY7pD4PyYlCHNYzDfweaEmyZHH2c2xqr2YSDycMXqWhw-BU4V2AkXBmadQ7eoLguGGidZmbU3c40DDwjPNT3yNQSgTJ4M2y2TmW7g-b8Uxtwpyql6Vz3J_UX3umxmRoBqthgNv59W_PM8uRGIjYMKB1a9dLKT8kKT0adoAXfAl5r_m4MkfO8zhV4DPWzQIq3B-VX9yGmnr0ZqKaRkZy3Y3wx2t2fHKwLou6ep4g16p0kdXfA"
)

func Test_LoadClientConfig(t *testing.T) {
	var err error
	if testConfig, err = LoadClientConfig(testCfgFile); err != nil {
		t.Fatal(err)
	}
	//testKCClient = NewClient(testConfig)
}

func Test_KeycloakClient_ValidateRequestToken_Expired(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://localhost:8765/oauth/test", nil)
	req.Header.Set("Authorization", "Bearer "+testExpiredAuthToken)

	_, err := testConfig.ValidateRequestToken(req)
	if err.Error() != "token is expired" {
		t.Fatal("Token should be expired")
	}
}

/*
func Test_KeycloakClient_ValidateRequestToken_Valid(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://localhost:8765/oauth/test", nil)
	req.Header.Set("Authorization", "Bearer "+testValidAuthToken)

	j, err := testKCClient.ValidateRequestToken(req)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(j.Claims())
}
*/
func Test_GetResourceRoles(t *testing.T) {
	j, _ := jws.ParseJWT([]byte(testExpiredAuthToken))
	roles, err := testConfig.GetResourceRoles(NewKeycloakJWT(j))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Roles (resource): %#v\n", roles)
}

func Test_GetRealmRoles(t *testing.T) {
	j, _ := jws.ParseJWT([]byte(testExpiredAuthToken))
	roles, err := NewKeycloakJWT(j).GetRealmRoles()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Role (realm): %#v\n", roles)
}
