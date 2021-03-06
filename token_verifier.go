package firebase_verify_token

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	idTokenCertURL            = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
	idTokenIssuerPrefix       = "https://securetoken.google.com/"
	sessionCookieCertURL      = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/publicKeys"
	sessionCookieIssuerPrefix = "https://session.firebase.google.com/"
	clockSkewSeconds          = 300
	firebaseAudience          = "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
)

// tokenVerifier verifies different types of Firebase token strings, including ID tokens and
// session cookies.
type tokenVerifier struct {
	shortName         string
	articledShortName string
	docURL            string
	projectID         string
	issuerPrefix      string
	keySource         keySource
}

func newIDTokenVerifier(ctx context.Context, projectID string) (*tokenVerifier, error) {
	return &tokenVerifier{
		shortName:         "ID token",
		articledShortName: "an ID token",
		docURL:            "https://firebase.google.com/docs/auth/admin/verify-id-tokens",
		projectID:         projectID,
		issuerPrefix:      idTokenIssuerPrefix,
		keySource:         newHTTPKeySource(idTokenCertURL, &http.Client{}),
	}, nil
}

func newSessionCookieVerifier(ctx context.Context, projectID string) (*tokenVerifier, error) {
	return &tokenVerifier{
		shortName:         "session cookie",
		articledShortName: "a session cookie",
		docURL:            "https://firebase.google.com/docs/auth/admin/manage-cookies",
		projectID:         projectID,
		issuerPrefix:      sessionCookieIssuerPrefix,
		keySource:         newHTTPKeySource(sessionCookieCertURL, &http.Client{}),
	}, nil
}

// VerifyToken Verifies that the given token string is a valid Firebase JWT.
//
// VerifyToken considers a token string to be valid if all the following conditions are met:
//   - The token string is a valid RS256 JWT.
//   - The JWT contains a valid key ID (kid) claim.
//   - The JWT contains valid issuer (iss) and audience (aud) claims that match the issuerPrefix
//     and projectID of the tokenVerifier.
//   - The JWT contains a valid subject (sub) claim.
//   - The JWT is not expired, and it has been issued some time in the past.
//   - The JWT is signed by a Firebase Auth backend server as determined by the keySource.
//
// If any of the above conditions are not met, an error is returned. Otherwise a pointer to a
// decoded Token is returned.
func (tv *tokenVerifier) VerifyToken(ctx context.Context, token string) (*Token, error) {
	if tv.projectID == "" {
		return nil, errors.New("project id not available")
	}
	if token == "" {
		return nil, fmt.Errorf("%s must be a non-empty string", tv.shortName)
	}

	// Validate the token content first. This is fast and cheap.
	payload, err := tv.verifyContent(token)
	if err != nil {
		return nil, fmt.Errorf("%s; see %s for details on how to retrieve a valid %s",
			err.Error(), tv.docURL, tv.shortName)
	}

	if err := tv.verifyTimestamps(payload); err != nil {
		return nil, err
	}

	// Verifying the signature requires syncronized access to a key cache and
	// potentially issues an http request. Therefore we do it last.
	if err := tv.verifySignature(ctx, token); err != nil {
		return nil, err
	}
	return payload, nil
}

func (tv *tokenVerifier) verifyContent(token string) (*Token, error) {
	var (
		header  jwtHeader
		payload Token
	)

	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil, errors.New("incorrect number of segments")
	}

	if err := decode(segments[0], &header); err != nil {
		return nil, err
	}

	if err := decode(segments[1], &payload); err != nil {
		return nil, err
	}

	issuer := tv.issuerPrefix + tv.projectID
	if header.KeyID == "" {
		if payload.Audience == firebaseAudience {
			return nil, fmt.Errorf("expected %s but got a custom token", tv.articledShortName)
		}
		return nil, fmt.Errorf("%s has no 'kid' header", tv.shortName)
	}
	if header.Algorithm != "RS256" {
		return nil, fmt.Errorf("%s has invalid algorithm; expected 'RS256' but got %q",
			tv.shortName, header.Algorithm)
	}
	if payload.Audience != tv.projectID {
		return nil, fmt.Errorf("%s has invalid 'aud' (audience) claim; expected %q but got %q; %s",
			tv.shortName, tv.projectID, payload.Audience, tv.getProjectIDMatchMessage())
	}
	if payload.Issuer != issuer {
		return nil, fmt.Errorf("%s has invalid 'iss' (issuer) claim; expected %q but got %q; %s",
			tv.shortName, issuer, payload.Issuer, tv.getProjectIDMatchMessage())
	}
	if payload.Subject == "" {
		return nil, fmt.Errorf("%s has empty 'sub' (subject) claim", tv.shortName)
	}
	if len(payload.Subject) > 128 {
		return nil, fmt.Errorf("%s has a 'sub' (subject) claim longer than 128 characters",
			tv.shortName)
	}

	payload.UID = payload.Subject

	var customClaims map[string]interface{}
	if err := decode(segments[1], &customClaims); err != nil {
		return nil, err
	}
	for _, standardClaim := range []string{"iss", "aud", "exp", "iat", "sub", "uid"} {
		delete(customClaims, standardClaim)
	}
	payload.Claims = customClaims

	return &payload, nil
}

func (tv *tokenVerifier) verifyTimestamps(payload *Token) error {
	if (payload.IssuedAt - clockSkewSeconds) > time.Now().Unix() {
		return fmt.Errorf("%s issued at future timestamp: %d", tv.shortName, payload.IssuedAt)
	} else if (payload.Expires + clockSkewSeconds) < time.Now().Unix() {
		return fmt.Errorf("%s has expired at: %d", tv.shortName, payload.Expires)
	}
	return nil
}

func (tv *tokenVerifier) verifySignature(ctx context.Context, token string) error {
	segments := strings.Split(token, ".")

	var h jwtHeader
	if err := decode(segments[0], &h); err != nil {
		return err
	}

	keys, err := tv.keySource.Keys(ctx)
	if err != nil {
		return err
	}

	verified := false
	for _, k := range keys {
		if h.KeyID == "" || h.KeyID == k.Kid {
			if verifyJWTSignature(segments, k) == nil {
				verified = true
				break
			}
		}
	}
	if !verified {
		return errors.New("failed to verify token signature")
	}
	return nil
}

func (tv *tokenVerifier) getProjectIDMatchMessage() string {
	return fmt.Sprintf(
		"make sure the %s comes from the same Firebase project as the credential used to"+
			" authenticate this SDK", tv.shortName)
}

// decode accepts a JWT segment, and decodes it into the given interface.
func decode(segment string, i interface{}) error {
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.NewDecoder(bytes.NewBuffer(decoded)).Decode(i)
}

func verifyJWTSignature(parts []string, k *publicKey) error {
	content := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}

	h := sha256.New()
	h.Write([]byte(content))
	return rsa.VerifyPKCS1v15(k.Key, crypto.SHA256, h.Sum(nil), []byte(signature))
}

// publicKey represents a parsed RSA public key along with its unique key ID.
type publicKey struct {
	Kid string
	Key *rsa.PublicKey
}

// keySource is used to obtain a set of public keys, which can be used to verify cryptographic
// signatures.
type keySource interface {
	Keys(context.Context) ([]*publicKey, error)
}

// httpKeySource fetches RSA public keys from a remote HTTP server, and caches them in
// memory. It also handles cache! invalidation and refresh based on the standard HTTP
// cache-control headers.
type httpKeySource struct {
	KeyURI     string
	HTTPClient *http.Client
	CachedKeys []*publicKey
	ExpiryTime time.Time
	Mutex      *sync.Mutex
}

func newHTTPKeySource(uri string, hc *http.Client) *httpKeySource {
	return &httpKeySource{
		KeyURI:     uri,
		HTTPClient: hc,
		Mutex:      &sync.Mutex{},
	}
}

// Keys returns the RSA Public Keys hosted at this key source's URI. Refreshes the data if
// the cache is stale.
func (k *httpKeySource) Keys(ctx context.Context) ([]*publicKey, error) {
	k.Mutex.Lock()
	defer k.Mutex.Unlock()
	if len(k.CachedKeys) == 0 || k.hasExpired() {
		err := k.refreshKeys(ctx)
		if err != nil && len(k.CachedKeys) == 0 {
			return nil, err
		}
	}
	return k.CachedKeys, nil
}

// hasExpired indicates whether the cache has expired.
func (k *httpKeySource) hasExpired() bool {
	return time.Now().After(k.ExpiryTime)
}

func (k *httpKeySource) refreshKeys(ctx context.Context) error {
	k.CachedKeys = nil
	req, err := http.NewRequest("GET", k.KeyURI, nil)
	if err != nil {
		return err
	}

	resp, err := k.HTTPClient.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid response (%d) while retrieving public keys: %s",
			resp.StatusCode, string(contents))
	}
	newKeys, err := parsePublicKeys(contents)
	if err != nil {
		return err
	}
	maxAge, err := findMaxAge(resp)
	if err != nil {
		return err
	}
	k.CachedKeys = append([]*publicKey(nil), newKeys...)
	k.ExpiryTime = time.Now().Add(*maxAge)
	return nil
}

func parsePublicKeys(keys []byte) ([]*publicKey, error) {
	m := make(map[string]string)
	err := json.Unmarshal(keys, &m)
	if err != nil {
		return nil, err
	}

	var result []*publicKey
	for kid, key := range m {
		pubKey, err := parsePublicKey(kid, []byte(key))
		if err != nil {
			return nil, err
		}
		result = append(result, pubKey)
	}
	return result, nil
}

func parsePublicKey(kid string, key []byte) (*publicKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("failed to decode the certificate as PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("certificate is not an RSA key")
	}
	return &publicKey{kid, pk}, nil
}

func findMaxAge(resp *http.Response) (*time.Duration, error) {
	cc := resp.Header.Get("cache-control")
	for _, value := range strings.Split(cc, ",") {
		value = strings.TrimSpace(value)
		if strings.HasPrefix(value, "max-age=") {
			sep := strings.Index(value, "=")
			seconds, err := strconv.ParseInt(value[sep+1:], 10, 64)
			if err != nil {
				return nil, err
			}
			duration := time.Duration(seconds) * time.Second
			return &duration, nil
		}
	}
	return nil, errors.New("Could not find expiry time from HTTP headers")
}
