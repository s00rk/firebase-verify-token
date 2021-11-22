package firebaseverifytoken

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
)

type Config struct {
}

type FirebaseJwtPlugin struct {
	client *auth.Client
	next   http.Handler
	config *Config
}

func CreateConfig() *Config {
	return &Config{}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	firebase_config := &firebase.Config{
		ProjectID: "intsight-platform-323404",
	}

	app, err := firebase.NewApp(context.Background(), firebase_config)
	if err != nil {
		return nil, fmt.Errorf("Firebase init error %v", err)
	}

	client, err := app.Auth(context.Background())
	if err != nil {
		return nil, fmt.Errorf("Firebase auth error %v", err)
	}

	plugin := &FirebaseJwtPlugin{
		client: client,
		next:   next,
		config: config,
	}

	return plugin, nil
}

func (ctl *FirebaseJwtPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	tokenValid := false

	idToken, err := ctl.ExtractToken(req)
	if err == nil {
		token, err := ctl.client.VerifyIDToken(context.Background(), *idToken)
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
		http.Error(rw, "Not allowed", http.StatusForbidden)
	}
}

func (ctl *FirebaseJwtPlugin) ExtractToken(req *http.Request) (*string, error) {
	authHeader, ok := req.Header["Authorization"]
	if !ok {
		fmt.Println("No header token")
		return nil, errors.New("Token not found")
	}

	auth := strings.Replace(authHeader[0], "Bearer ", "", -1)
	return &auth, nil
}
