package main

import (
	"encoding/json"
	"errors"
)

type TokenRequestAuthnResponseResponse struct {
	AttestationObject string `json:"attestationObject,omitempty"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData,omitempty"`
	Signature         string `json:"signature,omitempty"`
	UserHandle        string `json:"userHandle,omitempty"`
}

type TokenRequestAuthnResponse struct {
	ID                      string                            `json:"id"`
	RawID                   string                            `json:"rawId"`
	ClientExtensionResults  interface{}                       `json:"clientExtensionResults"`
	Type                    string                            `json:"type"`
	AuthenticatorAttachment string                            `json:"authenticatorAttachment"`
	Response                TokenRequestAuthnResponseResponse `json:"response"`
}

type TokenRequestData struct {
	GrantType     string                    `json:"grant_type"`
	ClientID      string                    `json:"client_id"`
	Realm         string                    `json:"realm"`
	Scope         string                    `json:"scope"`
	AuthSession   string                    `json:"auth_session"`
	AuthnResponse TokenRequestAuthnResponse `json:"authn_response"`
	Organization  string                    `json:"organization,omitempty"`
}

type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token"`
	Scope            string `json:"scope"`
	ExpiresIn        int    `json:"expires_in"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type TokenWebAuthnDetails struct {
	ID                string `json:"id,omitempty"`
	RawId             string `json:"rawId,omitempty"`
	AttestationObject string `json:"attestationObject,omitempty"`
	ClientDataJSON    string `json:"clientDataJSON,omitempty"`
	AuthenticatorData string `json:"authenticatorData,omitempty"`
	Signature         string `json:"signature,omitempty"`
}

func executeTokenRequest(config Config, requestData TokenRequestData, debug bool) (*TokenResponse, error) {
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return nil, err
	}

	if debug {
		prettyLog("Sending request /oauth/token with:", jsonData)
	}

	tokenRes, err := executeRequest(config.Domain, "oauth/token", jsonData)
	if err != nil {
		return nil, err
	}

	prettyLog("Response from /oauth/token:", tokenRes)

	var tokenResponse TokenResponse
	err = json.Unmarshal(tokenRes, &tokenResponse)
	if err != nil {
		return nil, err
	}
	if tokenResponse.Error != "" {
		return nil, errors.New(tokenResponse.ErrorDescription)
	}

	return &tokenResponse, nil
}
