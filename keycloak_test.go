package keycloak

import (
	"net/http"
	"testing"
)

var (
	testCfgFile          = "./keycloak-config.json"
	testConfig           *KeycloakClientConfig
	testKCClient         *KeycloakClient
	testExpiredAuthToken = "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJlMDliOTQwNS00ZDkyLTRiNWEtODY3NC0zMDZhMzcwMWUxN2IiLCJleHAiOjE0NjIzOTYyNTQsIm5iZiI6MCwiaWF0IjoxNDYyMzkyNjU0LCJpc3MiOiJodHRwczovL2F1dGgtdXN3ZXN0LmRlbHV4ZS1kbDMuY29tL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFzc2V0LW1hbmFnZXIiLCJzdWIiOiI0MzMzMzIyMC04YzMwLTQ2NjktYTczZi1kZDljNzE4ZTQ1ZmQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhc3NldC1tYW5hZ2VyIiwic2Vzc2lvbl9zdGF0ZSI6IjUwZTBhMTA2LTBjNDAtNGIyZi05YTFiLWExMTQyOWMzY2JlNCIsImNsaWVudF9zZXNzaW9uIjoiYzI1OTA0ODItMzYxOC00NmQ1LThlOTUtMzRiYjQ1OTlhNzVjIiwiYWxsb3dlZC1vcmlnaW5zIjpbXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImNyZWF0ZS1yZWFsbSIsImFkbWluIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsibWFzdGVyLXJlYWxtIjp7InJvbGVzIjpbInZpZXctaWRlbnRpdHktcHJvdmlkZXJzIiwidmlldy1yZWFsbSIsIm1hbmFnZS1ldmVudHMiLCJtYW5hZ2UtcmVhbG0iLCJtYW5hZ2UtaWRlbnRpdHktcHJvdmlkZXJzIiwiaW1wZXJzb25hdGlvbiIsInZpZXctZXZlbnRzIiwiY3JlYXRlLWNsaWVudCIsIm1hbmFnZS11c2VycyIsInZpZXctdXNlcnMiLCJ2aWV3LWNsaWVudHMiLCJtYW5hZ2UtY2xpZW50cyJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctcHJvZmlsZSJdfX0sIm5hbWUiOiIiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhZG1pbiJ9.VVNmPgAjuPurWRaWRXRRzQ_BYO4DvOJYMHwZlWqnfdqIeOv8B_mE2IP695n4EW78K0WERI0zWfoBjHMcwFZMEPMrXNQLeaDCDoAwTN8ua3a0jdzYGLcmA0JZFMC5IaIwUF1QgybGv04VJT9faPlPAMY0CZYY-gWf5S670Q8z3VcFibHnRi1NrHdgznYc7UMU1nCy-hAMRZpXqgzlJ3i9hKt1Cd5knDfDoPiJeig_wiuEV_woAzF6uo2Xsc67VzO19MdM6EGINXCKVrWyvCazzH7IsoQNJJuDWQhq8VuCFjt6aT4GGUDTskeD00yoWAxTIwMwA5BYvlqPiHnbQl6Wrg"

	testValidAuthToken = "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJhZWNiZTE1NC0xZTNhLTQ0MzMtOTZlZi1lOTdkOGY0YjdjZGUiLCJleHAiOjE0NjI0NzQzNzMsIm5iZiI6MCwiaWF0IjoxNDYyNDcwNzczLCJpc3MiOiJodHRwczovL2F1dGgtdXN3ZXN0LmRlbHV4ZS1kbDMuY29tL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFzc2V0LW1hbmFnZXIiLCJzdWIiOiJmNDY1M2U2Zi03YmZkLTRhM2YtODcwMi1kZTIzNTE4MzQxMDMiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhc3NldC1tYW5hZ2VyIiwic2Vzc2lvbl9zdGF0ZSI6ImJhNmNhOGE0LTU0NWYtNDQ1Ni1iZWExLWEzNzNiMjdmNzRjYSIsImNsaWVudF9zZXNzaW9uIjoiODQzOTkwMjgtNGNkYi00MDVlLTg4MTgtMWU1ODg3OGU5NjQwIiwiYWxsb3dlZC1vcmlnaW5zIjpbXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImNyZWF0ZS1yZWFsbSIsImFkbWluIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYXNzZXQtbWFuYWdlciI6eyJyb2xlcyI6WyJhZG1pbiJdfSwibWFzdGVyLXJlYWxtIjp7InJvbGVzIjpbInZpZXctaWRlbnRpdHktcHJvdmlkZXJzIiwidmlldy1yZWFsbSIsIm1hbmFnZS1ldmVudHMiLCJtYW5hZ2UtcmVhbG0iLCJtYW5hZ2UtaWRlbnRpdHktcHJvdmlkZXJzIiwiaW1wZXJzb25hdGlvbiIsInZpZXctZXZlbnRzIiwiY3JlYXRlLWNsaWVudCIsIm1hbmFnZS11c2VycyIsInZpZXctdXNlcnMiLCJ2aWV3LWNsaWVudHMiLCJtYW5hZ2UtY2xpZW50cyJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctcHJvZmlsZSJdfX0sIm5hbWUiOiJBYmhpc2hha2UgUGF0aGFrIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWJoaXNoYWtlLnBhdGhhayIsImdpdmVuX25hbWUiOiJBYmhpc2hha2UiLCJmYW1pbHlfbmFtZSI6IlBhdGhhayIsImVtYWlsIjoiYWJoaXNoYWtlLnBhdGhha0BieWRlbHV4ZS5jb20ifQ.ia2XMWaxrZWHitEEgfYH25p5AA-cR-5QHVkDBW2Rl_9ULFCccq_UzTIkfj1suO3T11tVUkcGReBsxi0-0m2wdNwiSNUZ-L9NphrY99c-03Ta_3OxB_VD156u3sT-8U9JlzaC-BoC27qYQLxfoL2wDgOtzyFfTiCJAHX3xhtSwXcU5rdpEAjU_NFyk9cJP8Y56dlWm5ZuW1eH7mZ58MlQah4btqBIFHuQSurZ34pK0s1Bh5JsfVfXzDq1-dqzOxJLADw9UdlJzzGjpenkVf_TngL-J9KrubRv-nIohtp9L8ORInxMbCrZF7to8QASVyrZSfH9i_2a8AvxDytJFhXvBg"
)

func Test_LoadKeycloakClientConfig(t *testing.T) {
	var err error
	if testConfig, err = LoadKeycloakClientConfig(testCfgFile); err != nil {
		t.Fatal(err)
	}
}

func Test_KeycloakClient(t *testing.T) {
	var err error
	if testKCClient, err = NewKeycloakClient(testConfig); err != nil {
		t.Fatal(err)
	}

}

func Test_KeycloakClient_ValidateRequestToken_Expired(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://localhost:8765/oauth/test", nil)
	req.Header.Set("Authorization", "Bearer "+testExpiredAuthToken)

	_, err := testKCClient.ValidateRequestToken(req)
	if err.Error() != "token is expired" {
		t.Fatal("Token should be expired")
	}
}

func Test_GetResourceRoles(t *testing.T) {
	j, _ := testKCClient.ValidateToken(testValidAuthToken)
	roles, err := GetResourceRoles(j, "asset-manager")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Roles (resource): %#v\n", roles)
}

func Test_GetRealmRoles(t *testing.T) {
	j, _ := testKCClient.ValidateToken(testValidAuthToken)
	roles, err := GetRealmRoles(j)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Role (realm): %#v\n", roles)
}

func Test_KeycloakClient_ValidateRequestToken_Valid(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://localhost:8765/oauth/test", nil)
	req.Header.Set("Authorization", "Bearer "+testValidAuthToken)

	j, err := testKCClient.ValidateRequestToken(req)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(j.Claims())
}
