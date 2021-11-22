package firebase_verify_token

type FirebaseInfo struct {
	SignInProvider string                 `json:"sign_in_provider"`
	Tenant         string                 `json:"tenant"`
	Identities     map[string]interface{} `json:"identities"`
}

type Token struct {
	AuthTime int64                  `json:"auth_time"`
	Issuer   string                 `json:"iss"`
	Audience string                 `json:"aud"`
	Expires  int64                  `json:"exp"`
	IssuedAt int64                  `json:"iat"`
	Subject  string                 `json:"sub,omitempty"`
	UID      string                 `json:"uid,omitempty"`
	Firebase FirebaseInfo           `json:"firebase"`
	Claims   map[string]interface{} `json:"-"`
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid,omitempty"`
}
