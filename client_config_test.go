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
	testExpiredAuthToken = "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiI1MDhlMGQ1Zi00MWM1LTQ0ZDUtYTczZS02ZWQyODc2YmEyN2UiLCJleHAiOjE0Njg0MzgxOTgsIm5iZiI6MCwiaWF0IjoxNDY4NDM0NTk4LCJpc3MiOiJodHRwczovL2F1dGgtdXN3ZXN0LmRlbHV4ZS1kbDMuY29tL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFzc2V0LW1hbmFnZXIiLCJzdWIiOiJkYjc2NGE5ZS05MzA2LTRhNmQtYWU2OC05MzRlYzk5YmQwMmUiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhc3NldC1tYW5hZ2VyIiwic2Vzc2lvbl9zdGF0ZSI6IjU3NmIxNmM3LTUwZWYtNGE4Yi1hZDBlLTkyY2Y5N2EzOGE5ZSIsImNsaWVudF9zZXNzaW9uIjoiOGJlNjc5YmYtMzg1OS00NGYxLTkwNTEtMzkyNGIyZmI1ZTQ1IiwiYWxsb3dlZC1vcmlnaW5zIjpbIioiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImNyZWF0ZS1yZWFsbSIsImFkbWluIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYXNzZXQtbWFuYWdlciI6eyJyb2xlcyI6WyJhZG1pbiJdfSwibWFzdGVyLXJlYWxtIjp7InJvbGVzIjpbInZpZXctcmVhbG0iLCJ2aWV3LWlkZW50aXR5LXByb3ZpZGVycyIsIm1hbmFnZS1ldmVudHMiLCJtYW5hZ2UtcmVhbG0iLCJtYW5hZ2UtaWRlbnRpdHktcHJvdmlkZXJzIiwiaW1wZXJzb25hdGlvbiIsInZpZXctZXZlbnRzIiwiY3JlYXRlLWNsaWVudCIsIm1hbmFnZS11c2VycyIsInZpZXctdXNlcnMiLCJ2aWV3LWNsaWVudHMiLCJtYW5hZ2UtY2xpZW50cyJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctcHJvZmlsZSJdfX0sIm5hbWUiOiIiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhZG1pbiJ9.WzODRfgIqWwkg57Bg2aj7mYqWiUyFra_fit47tMtN5oGWuNfGx0S0Z5XPUbVoWc1fQp5pETcoZViTXnp2-2vpxdIag7WDOzaBaUICAuohfjOY9nQR6EPg6gMcob5Pd8rlt9xU3Qm8hOl6zMp0r7M1QXdL3MpF8FSm3UiF0ST_u_u8xZxZ9GrDBWJX4uvNo1xYcfqkIw88ckF3CiRI3wQ82bAYCGvaD-ddk6TbSPqVTkAxCDOL4xJelTfmkPPLtBv77NBnZh5ItWpGbCUomr7h3CyN5ecMwdYsGXra04qYfeDgwxYG3lr1T1bMg2PPNHmsAeb3P3m-S5qbVfnrzTkIQ"
	testValidAuthToken   = "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiI4NmQwZDdhMS0zYjJjLTQzOTctYWE4Mi01MWRlMzllMTViMTMiLCJleHAiOjE0Njg0NjQzNzAsIm5iZiI6MCwiaWF0IjoxNDY4NDYwNzcwLCJpc3MiOiJodHRwczovL2F1dGgtdXN3ZXN0LmRlbHV4ZS1kbDMuY29tL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFzc2V0LW1hbmFnZXIiLCJzdWIiOiIyNjc1YmYwNS1hYTRiLTQ1NzAtYTVjMy04ZTk2MDY2MTBlMGEiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhc3NldC1tYW5hZ2VyIiwic2Vzc2lvbl9zdGF0ZSI6IjcyZmE5ODdhLTU4YmYtNDk4ZS1iMDhkLWRkOTFkYmM0OWNmYiIsImNsaWVudF9zZXNzaW9uIjoiOTJkNTE0NjAtOGRhOC00NWM0LTk0MzctOTQwMjBmMTg4YTAzIiwiYWxsb3dlZC1vcmlnaW5zIjpbIioiXSwicmVzb3VyY2VfYWNjZXNzIjp7ImFzc2V0LW1hbmFnZXIiOnsicm9sZXMiOlsicmVhZG9ubHkiLCJyZWFkd3JpdGUiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJ2aWV3LXByb2ZpbGUiXX19LCJuYW1lIjoiQWJoaXNoYWtlIFBhdGhhayIsInByZWZlcnJlZF91c2VybmFtZSI6ImFiaGlzaGFrZS5wYXRoYWsiLCJnaXZlbl9uYW1lIjoiQWJoaXNoYWtlIiwiZmFtaWx5X25hbWUiOiJQYXRoYWsiLCJlbWFpbCI6ImFiaGlzaGFrZS5wYXRoYWtAYnlkZWx1eGUuY29tIn0.dDymO7YBCGQyG0afLWYSGNg7xLuXZt7CfuvWOWmL1YXycyJ2E-4eFtLEzth_gwr4IhY-aYIBxS3mi13-98LmgPzxhvbcJLAwAzMOBWQXgAsKDLoFtgmHL_MXuDYZ-pFVkQKIQxfxm_HswEH0SUD5FiClLLg0Wnrulm0EL1Q745hdfdfJc8IvMQ2tqig3xJyQS-yPcZwLl_rMNtV9zda9cz5lEBvRBOk6mIajmtxslXe227Dh1rfBJkboP4a8ySfl4iZd64ixOiQAcQXGJjiEHj7wmmsHOurmmGl-Ne4xDxxphu6CGttcSjD_KwTxI3Dn0KV--2ts6xOc_Qh70Kt2_A"
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
	if err == nil {
		t.Fatal("Should have failed")
	} else if err.Error() != "token is expired" {
		t.Fatal("Token should be expired")
	}

}

func Test_KeycloakClient_ValidateRequestToken_Valid(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://localhost:8765/oauth/test", nil)
	req.Header.Set("Authorization", "Bearer "+testValidAuthToken)
	//j, err := testConfig.ValidateToken(testValidAuthToken)
	j, err := testConfig.ValidateRequestToken(req)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(j.Claims())
}

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
