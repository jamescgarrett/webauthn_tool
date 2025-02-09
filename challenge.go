package main

import (
	"encoding/json"
	"errors"
)

type ChallengeRequestUserProfile struct {
	Email       string `json:"email,omitempty"`
	Username    string `json:"username,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
}

type ChallengeRequestData struct {
	ClientID     string `json:"client_id"`
	Realm        string `json:"realm"`
	Organization string `json:"organization,omitempty"`
}

type ChallengeResponse struct {
	Error                string               `json:"error,omitempty"`
	ErrorDescription     string               `json:"error_description,omitempty"`
	AuthnParamsPublicKey AuthnParamsPublicKey `json:"authn_params_public_key"`
	AuthSession          string               `json:"auth_session"`
}

func handleChallenge(config Config, debug bool) error {
	user, err := findUser(config)
	if err != nil {
		return err
	}

	requestData := ChallengeRequestData{
		ClientID: config.ClientID,
		Realm:    config.Realm,
	}
	if config.UseOrganization {
		requestData.Organization = config.Organization
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return err
	}

	if debug {
		prettyLog("Sending request /passkey/challenge with:", jsonData)
	}

	challengeRes, err := executeRequest(config.Domain, "passkey/challenge", jsonData)
	if err != nil {
		return err
	}

	prettyLog("Response from /passkey/challenge:", challengeRes)

	var challengeResponse ChallengeResponse
	err = json.Unmarshal(challengeRes, &challengeResponse)
	if err != nil {
		return err
	}
	if challengeResponse.Error != "" {
		return errors.New(challengeResponse.ErrorDescription)
	}

	// START Webauthn Register
	webauthnChallenge, err := executeWebauthnChallenge(config.Domain, challengeResponse, *user, debug)
	if err != nil {
		return err
	}
	// END Webauthn Register

	tokenRequestData := TokenRequestData{
		GrantType:   "urn:okta:params:oauth:grant-type:webauthn",
		ClientID:    config.ClientID,
		Realm:       config.Realm,
		Scope:       "openid profile email username phone_number offline_access",
		AuthSession: challengeResponse.AuthSession,
		AuthnResponse: TokenRequestAuthnResponse{
			ID:                      user.CredentialID,
			RawID:                   user.CredentialID,
			ClientExtensionResults:  struct{}{},
			Type:                    "public-key",
			AuthenticatorAttachment: "platform",
			Response: TokenRequestAuthnResponseResponse{
				AuthenticatorData: webauthnChallenge.Response.AuthenticatorData,
				ClientDataJSON:    webauthnChallenge.Response.ClientDataJSON,
				Signature:         webauthnChallenge.Response.Signature,
				UserHandle:        user.ID,
			},
		},
	}
	if config.UseOrganization {
		tokenRequestData.Organization = config.Organization
	}

	executeTokenRequest(config, tokenRequestData, debug)

	return nil
}
