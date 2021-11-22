package firebase_verify_token

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type Config struct {
	ProjectID string `json:"project_id"`
}

type FirebaseJwtPlugin struct {
	next     http.Handler
	verifier *tokenVerifier
}

func CreateConfig() *Config {
	return &Config{}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.ProjectID) == 0 || strings.TrimSpace(config.ProjectID) == "" {
		return nil, fmt.Errorf("configuration incorrect, missing project_id")
	}

	idTokenVerifier, err := newIDTokenVerifier(context.Background(), config.ProjectID)
	if err != nil {
		return nil, err
	}

	plugin := &FirebaseJwtPlugin{
		next:     next,
		verifier: idTokenVerifier,
	}

	return plugin, nil
}

func (ctl *FirebaseJwtPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	tokenValid := false

	idToken, err := ctl.ExtractToken(req)
	if err == nil {
		token, err := ctl.verifier.VerifyToken(context.Background(), *idToken)
		if err == nil {
			req.Header.Set("fb-userid", token.UID)
			for key, value := range token.Claims {
				keyName := fmt.Sprintf("fbclaim-%s", key)
				newValue := fmt.Sprintf("%v", value)
				req.Header.Set(keyName, newValue)
			}

			tokenValid = true
		}
	}

	if tokenValid {
		ctl.next.ServeHTTP(rw, req)
	} else {
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
	}
}

func (ctl *FirebaseJwtPlugin) ExtractToken(req *http.Request) (*string, error) {
	authHeader, ok := req.Header["Authorization"]
	if !ok {
		return nil, errors.New("Token not found")
	}

	token := strings.Replace(authHeader[0], "Bearer ", "", -1)

	return &token, nil
}
