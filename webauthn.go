package main

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/fxamacker/cbor/v2"
	"github.com/fxamacker/webauthn"
)

type AttestationObject struct {
	Format    string               `json:"fmt"`
	Statement AttestationStatement `json:"attStmt"`
	AuthData  []byte               `json:"authData"`
}

type AttestationStatement struct {
	Algorithm int    `json:"alg"`
	Signature []byte `json:"sig"`
}

type AttestationStatementClean struct {
	Algorithm int    `json:"alg"`
	Signature string `json:"sig"`
	R         string `json:"r"`
	S         string `json:"s"`
}

type AuthDataDecoded struct {
	RpIdHash            string `json:"rpIdHash"`
	Flags               string `json:"flags"`
	SignCount           string `json:"signCount"`
	Aaguid              string `json:"aaguid"`
	CredentialIdLength  uint16 `json:"credentialIdLength"`
	CredentialId        string `json:"credentialId"`
	CredentialPublicKey string `json:"credentialPublicKey"`
	PubKeyX             string `json:"pubKeyX"`
	PubKeyY             string `json:"pubKeyY"`
}

type ECDSASignature struct {
	R, S *big.Int
}

type FullAttestationObject struct {
	Raw64     string                    `json:"raw64"`
	Format    string                    `json:"fmt"`
	Statement AttestationStatementClean `json:"attStmt"`
	AuthData  AuthDataDecoded           `json:"authData"`
}

type FullClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

type User struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type WebauthnAttestation struct {
	User      *webauthn.User
	Challenge []byte
	Options   string
}

type WebAuthnChallenge struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	RawId    string `json:"rawId"`
	Response struct {
		AuthenticatorData string `json:"authenticatorData"`
		ClientDataJSON    string `json:"clientDataJSON"`
		Signature         string `json:"signature"`
	}
}

type WebAuthnRegister struct {
	WebauthnUser             User                                `json:"user"`
	WebauthnConfig           webauthn.Config                     `json:"config"`
	WebauthnOptions          *virtualwebauthn.AttestationOptions `json:"options"`
	WebauthnResponseComplete WebauthnResponseComplete            `json:"responseDecoded"`
	WebAuthnResponseRaw      WebAuthnResponseRaw                 `json:"response"`
}

type WebauthnResponse struct {
	Id       string `json:"id"`
	RawId    string `json:"rawId"`
	Response struct {
		AttestationObject string `json:"attestationObject"`
		ClientDataJSON    string `json:"clientDataJSON"`
	}
}

type WebauthnResponseComplete struct {
	Id                string `json:"id"`
	RawId             string `json:"rawId"`
	AttestationObject FullAttestationObject
	ClientDataJSON    FullClientData
}

type WebAuthnResponseRaw struct {
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthData          string `json:"authData,omitempty"`
}

type WebauthnAssertion struct {
	User         *webauthn.User
	CredentialID []byte
	Challenge    []byte
	Options      string
}

type RP struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type PubKeyCredParams struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

type AuthenticatorSelection struct {
	ResidentKey      string `json:"residentKey"`
	UserVerification string `json:"userVerification"`
}

type AuthnParamsPublicKey struct {
	Challenge              string                 `json:"challenge"`
	Timeout                int                    `json:"timeout"`
	RP                     RP                     `json:"rp"`
	PubKeyCredParams       []PubKeyCredParams     `json:"pubKeyCredParams"`
	AuthenticatorSelection AuthenticatorSelection `json:"authenticatorSelection"`
	User                   User                   `json:"user"`
}

func createAttestationOptions(attestation *WebauthnAttestation) (*virtualwebauthn.AttestationOptions, error) {
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(attestation.Options)
	if err != nil {
		return nil, err
	}
	return attestationOptions, nil
}

func webauthnUser(username string, userId string) *webauthn.User {
	currentTime := time.Now().Format("02/01/2006 15:04:05")
	user := &webauthn.User{
		ID:          []byte(userId),
		Name:        username,
		DisplayName: fmt.Sprintf("%s -- %s", username, currentTime),
	}
	return user
}

func encodeToHex(data []byte) string {
	return "0x" + hex.EncodeToString(data)
}

func decodeAuthData(authData []byte) (*AuthDataDecoded, error) {
	if len(authData) < 37 {
		return nil, errors.New("authData is too short")
	}

	// Parse rpIdHash
	rpIdHash := authData[:32]

	// Parse flags
	flags := authData[32]

	// Parse signCount
	signCount := authData[33:37]

	// Offset where attestedCredentialData starts
	offset := 37

	// AAGUID is the next 16 bytes
	aaguid := authData[offset : offset+16]
	offset += 16

	// credentialIdLength is the next 2 bytes
	credentialIdLength := binary.BigEndian.Uint16(authData[offset : offset+2])
	offset += 2

	// credentialId is the next credentialIdLength bytes
	credentialId := authData[offset : offset+int(credentialIdLength)]
	offset += int(credentialIdLength)

	// The remaining bytes are for credentialPublicKey which is COSE-encoded.
	// Its parsing is more involved and depends on your needs.
	credentialPublicKey := authData[offset:]

	// Decode the credentialPublicKey
	var coseMap map[int]interface{}
	if err := cbor.Unmarshal(credentialPublicKey, &coseMap); err != nil {
		return nil, err
	}

	// Extract the x and y coordinates of the public key and convert them to big.Int
	// The publicKey variable is CBOR-encoded (not regular PEM string), which after decoding it in publicKeyObject should give an output like this:
	//		 1: 2,              -> Ellipic Curve key type
	//		 3: -7,             -> ES256 signature algorithm
	//		-1: 1,              -> P-256 curve
	//		-2: 0x7885DB484..., -> X value
	//		-3: 0x814F3DD31...  -> Y value
	xBytes := coseMap[-2].([]byte)
	yBytes := coseMap[-3].([]byte)

	return &AuthDataDecoded{
		RpIdHash:            encodeToHex(rpIdHash),
		Flags:               fmt.Sprintf("%08b", flags),
		SignCount:           encodeToHex(signCount),
		Aaguid:              encodeToHex(aaguid),
		CredentialIdLength:  credentialIdLength,
		CredentialId:        encodeToHex(credentialId),
		CredentialPublicKey: encodeToHex(credentialPublicKey),
		PubKeyX:             encodeToHex(xBytes),
		PubKeyY:             encodeToHex(yBytes),
	}, nil
}

/**
 * Register
 */
func startWebauthnRegister(webauthnConfig webauthn.Config, challenge []byte, username string, userId string) *WebauthnAttestation {
	user := webauthnUser(username, userId)
	if len(challenge) > 0 {
		webauthnConfig.ChallengeLength = len(challenge)
	}
	options, _ := webauthn.NewAttestationOptions(&webauthnConfig, user)
	if len(challenge) > 0 {
		options.Challenge = challenge
	}
	optionsJSON, _ := json.Marshal(options)
	return &WebauthnAttestation{User: user, Challenge: options.Challenge, Options: string(optionsJSON)}
}

func executeWebauthnRegister(domain string, registerResponse RegisterResponse, debug bool) (*WebAuthnRegister, error) {
	rp := virtualwebauthn.RelyingParty{Name: "Native Passkeys Dev", ID: domain, Origin: fmt.Sprintf("https://%s", domain)}

	authenticator := virtualwebauthn.NewAuthenticator()

	privateKey, keyType, err := parsePrivateKey()
	if err != nil {
		return nil, err
	}

	credential := virtualwebauthn.NewCredentialWithImportedKey(keyType, privateKey)

	challenge, err := base64.RawURLEncoding.DecodeString(registerResponse.AuthnParamsPublicKey.Challenge)
	if err != nil {
		return nil, err
	}

	var webauthnConfig = webauthn.Config{
		RPID:                    rp.ID,
		RPName:                  rp.Name,
		Timeout:                 uint64(60000),
		ChallengeLength:         64,
		UserVerification:        webauthn.UserVerificationRequired,
		Attestation:             webauthn.AttestationNone,
		CredentialAlgs:          []int{webauthn.COSEAlgES256},
		AuthenticatorAttachment: webauthn.AuthenticatorPlatform,
	}

	username := registerResponse.AuthnParamsPublicKey.User.Name
	userId := registerResponse.AuthnParamsPublicKey.User.ID

	attestation := startWebauthnRegister(webauthnConfig, challenge, username, userId)
	attestationOptions, err := createAttestationOptions(attestation)
	if err != nil {
		return nil, err
	}
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *attestationOptions)

	authenticator.Options.UserHandle = []byte(userId)
	authenticator.AddCredential(credential)

	var webauthnResponse WebauthnResponse
	json.Unmarshal([]byte(attestationResponse), &webauthnResponse)

	decodedClientDataBytes, err := base64.RawURLEncoding.DecodeString(webauthnResponse.Response.ClientDataJSON)
	if err != nil {
		return nil, err
	}

	var clientData FullClientData
	err = json.Unmarshal(decodedClientDataBytes, &clientData)
	if err != nil {
		return nil, err
	}

	decodedBytes, err := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	if err != nil {
		return nil, err
	}
	clientData.Challenge = encodeToHex(decodedBytes)

	decodedAttestationObjectBytes, err := base64.RawURLEncoding.DecodeString(webauthnResponse.Response.AttestationObject)
	if err != nil {
		return nil, err
	}

	var result AttestationObject
	err = cbor.Unmarshal(decodedAttestationObjectBytes, &result)
	if err != nil {
		return nil, err
	}

	WebauthnResponseIdByte, err := base64.RawURLEncoding.DecodeString(webauthnResponse.Id)
	if err != nil {
		return nil, err
	}

	decodedAuthData, err := decodeAuthData(result.AuthData)
	if err != nil {
		return nil, err
	}

	var sig ECDSASignature
	asn1.Unmarshal(result.Statement.Signature, &sig)

	webauthnRegister := WebAuthnRegister{
		User{
			ID:          attestationOptions.UserID,
			Name:        attestationOptions.UserName,
			DisplayName: attestationOptions.UserDisplayName,
		},
		webauthnConfig,
		attestationOptions,
		WebauthnResponseComplete{
			Id:    base64.RawURLEncoding.EncodeToString(WebauthnResponseIdByte),
			RawId: webauthnResponse.RawId,
			AttestationObject: FullAttestationObject{
				Format: result.Format,
				Statement: AttestationStatementClean{
					Algorithm: result.Statement.Algorithm,
					Signature: base64.RawURLEncoding.EncodeToString(result.Statement.Signature),
					R:         "0x" + sig.R.Text(16),
					S:         "0x" + sig.S.Text(16),
				},
				AuthData: *decodedAuthData,
			},
			ClientDataJSON: clientData,
		},
		WebAuthnResponseRaw{
			AttestationObject: base64.RawURLEncoding.EncodeToString(decodedAttestationObjectBytes),
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(decodedClientDataBytes),
			AuthData:          base64.RawURLEncoding.EncodeToString(result.AuthData),
		},
	}

	if debug {
		jsonData, err := json.Marshal(webauthnRegister)
		if err != nil {
			return nil, err
		}
		prettyLog("Response from Webauthn APIs:", jsonData)
	}

	return &webauthnRegister, nil
}

/**
 * Challenge
 */
func startWebauthnChallenge(webauthnConfig *webauthn.Config, challenge []byte, user *webauthn.User, credentialID []byte) (*WebauthnAssertion, error) {
	options, err := webauthn.NewAssertionOptions(webauthnConfig, user)
	if err != nil {
		return nil, err
	}

	options.Challenge = challenge

	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}

	return &WebauthnAssertion{User: user, CredentialID: credentialID, Challenge: options.Challenge, Options: string(optionsJSON)}, nil
}

func executeWebauthnChallenge(domain string, challengeResponse ChallengeResponse, user UserDetails, debug bool) (*WebAuthnChallenge, error) {
	username := user.Name
	userId := user.ID
	credentialID := []byte(user.CredentialID)

	rp := virtualwebauthn.RelyingParty{Name: "Native Passkeys Dev", ID: domain, Origin: fmt.Sprintf("https://%s", domain)}

	privateKey, keyType, err := parsePrivateKey()
	if err != nil {
		return nil, err
	}

	credential := virtualwebauthn.NewCredentialWithImportedKey(keyType, privateKey)
	credential.ID = credentialID

	challenge, err := base64.RawURLEncoding.DecodeString(challengeResponse.AuthnParamsPublicKey.Challenge)
	if err != nil {
		return nil, err
	}

	var webauthnConfig = webauthn.Config{
		RPID:                    rp.ID,
		RPName:                  rp.Name,
		Timeout:                 uint64(60000),
		ChallengeLength:         64,
		UserVerification:        webauthn.UserVerificationRequired,
		Attestation:             webauthn.AttestationNone,
		CredentialAlgs:          []int{webauthn.COSEAlgES256},
		AuthenticatorAttachment: webauthn.AuthenticatorPlatform,
	}

	webauthnUser := webauthnUser(username, userId)
	webauthnUser.CredentialIDs = append(webauthnUser.CredentialIDs, credential.ID)

	authenticator := virtualwebauthn.NewAuthenticator()
	authenticator.AddCredential(credential)
	authenticator.Options.UserHandle = []byte(userId)

	webauthnAssertion, err := startWebauthnChallenge(&webauthnConfig, challenge, webauthnUser, credential.ID)
	if err != nil {
		return nil, err
	}

	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(webauthnAssertion.Options)
	if err != nil {
		return nil, err
	}

	foundCredential := authenticator.FindAllowedCredential(*assertionOptions)
	if !bytes.Equal(foundCredential.ID, credential.ID) {
		return nil, errors.New("credential not found")
	}

	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, credential, *assertionOptions)

	if debug {
		prettyLog("Response from Webauthn APIs:", []byte(assertionResponse))
	}

	var webAuthnChallenge WebAuthnChallenge
	json.Unmarshal([]byte(assertionResponse), &webAuthnChallenge)

	return &webAuthnChallenge, nil

}
