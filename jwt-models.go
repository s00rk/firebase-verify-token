package firebaseverifytoken

import "encoding/json"

type FirebaseJwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type Claims struct {
	Iat      json.Number `json:"iat"`
	Exp      json.Number `json:"exp"`
	Aud      string      `json:"aud"`
	Iss      string      `json:"iss"`
	Sub      string      `json:"sub"`
	AuthTime json.Number `json:"auth_time"`
}

type FirebaseJwt struct {
	Header     FirebaseJwtHeader
	Payload    Claims
	Signature  []byte
	RawToken   []byte
	RawPayload []byte
}
