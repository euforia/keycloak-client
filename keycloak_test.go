package keycloak

import (
	"net/http"
	"testing"
)

var (
	testCfgFile   = "./keycloak-config.json"
	testConfig    *KeycloakClientConfig
	testKCClient  *KeycloakClient
	testAuthToken = "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiI0NDJjNTliMy00N2NjLTQ1NDAtYjU5OC00MmUzMDIzNDY0YTYiLCJleHAiOjE0NTk2Njc3ODIsIm5iZiI6MCwiaWF0IjoxNDU5NjY0MTgyLCJpc3MiOiJodHRwOi8vaW50ZXJuYWwta2V5Y2xvYWstZWxiLTUwMDE4NjYwNi51cy13ZXN0LTIuZWxiLmFtYXpvbmF3cy5jb20vYXV0aC9yZWFsbXMvbWFzdGVyIiwiYXVkIjoiZGwzLWFwaSIsInN1YiI6IjBiMTIxYmU1LTI4MWQtNDY5Mi1iMTE1LWY4NTc1ZGEzNTY5ZiIsInR5cCI6IkJlYXJlciIsImF6cCI6ImRsMy1hcGkiLCJzZXNzaW9uX3N0YXRlIjoiNTVlMWRlNDAtYzMzMi00OGU2LWI2ZDMtZjc5NGY5MzIyYzk0IiwiY2xpZW50X3Nlc3Npb24iOiI3NDhkMDQ0MS1iMjAxLTQ2YmQtYTFmNy1kNzM5ODczNzg0ZGEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZXNvdXJjZV9hY2Nlc3MiOnt9LCJuYW1lIjoiIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWRtaW4ifQ.DAIcI2qB4KRkObHSM_YIm7LNtoEcDskx8-rgcq6FKEc4gd_HgHehhiSnjb-R-Zg-6k5w2S5bZAUYVfVEYyYrsnigC6Qbjk0VYkyW9Ewsx493yRJQ9uj8-Kwab1a55Y7b8OUWdOmmBhGDfi1m02RFtfT1S4vQRS4O5grSDNVWkdIfR0EZpzqsPn4O8R5Ne-Ns3CYm9xJT-jjeO0WN8NB84Isl7UeRPHsMgqY8dcpl3nWENK8FFLVjQh7imu-5eu7BUcxZJvY_ouQKNFx4e1ql_X87S6IeGINJiRd0zPUrVl7D3MY2GAKeX7d-JVZqj3kQJXsNHK9ThY-59Yq0l6isYg"
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

func Test_KeycloakClient_ValidateRequestToken(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://localhost:8765/oauth/test", nil)
	req.Header.Set("Authorization", "Bearer "+testAuthToken)

	j, err := testKCClient.ValidateRequestToken(req)
	if err == nil {
		t.Fatal("Should have failed (expired)")
	}

	t.Log(j.Claims())
}
