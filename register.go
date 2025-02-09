package main

import (
	"encoding/json"
	"errors"
)

type RegisterRequestUserProfile struct {
	Email       string `json:"email,omitempty"`
	Username    string `json:"username,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
}

type RegisterRequestData struct {
	ClientID     string                     `json:"client_id"`
	Realm        string                     `json:"realm"`
	Organization string                     `json:"organization,omitempty"`
	UserProfile  RegisterRequestUserProfile `json:"user_profile"`
}

type RegisterResponse struct {
	Error                string               `json:"error,omitempty"`
	ErrorDescription     string               `json:"error_description,omitempty"`
	AuthnParamsPublicKey AuthnParamsPublicKey `json:"authn_params_public_key"`
	AuthSession          string               `json:"auth_session"`
}

func handleRegister(config Config, debug bool) error {
	userProfile := RegisterRequestUserProfile{}
	if config.Email != "" {
		userProfile.Email = config.Email
	}
	if config.Username != "" {
		userProfile.Email = config.Username
	}
	if config.PhoneNumber != "" {
		userProfile.PhoneNumber = config.PhoneNumber
	}

	requestData := RegisterRequestData{
		ClientID:    config.ClientID,
		Realm:       config.Realm,
		UserProfile: userProfile,
	}
	if config.UseOrganization {
		requestData.Organization = config.Organization
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return err
	}

	if debug {
		prettyLog("Sending request /passkey/register with:", jsonData)
	}

	registerRes, err := executeRequest(config.Domain, "passkey/register", jsonData)
	if err != nil {
		return err
	}

	prettyLog("Response from /passkey/register:", registerRes)

	var registerResponse RegisterResponse
	err = json.Unmarshal(registerRes, &registerResponse)
	if err != nil {
		return err
	}
	if registerResponse.Error != "" {
		return errors.New(registerResponse.ErrorDescription)
	}

	// START Webauthn Register
	webAuthnRegister, err := executeWebauthnRegister(config.Domain, registerResponse, debug)
	if err != nil {
		return err
	}
	// END Webauthn Register

	// write data to a file so we can keep track of what we have available
	err = writeDetailsToJSON(&registerResponse.AuthnParamsPublicKey.User, webAuthnRegister.WebauthnResponseComplete.Id)
	if err != nil {
		return err
	}

	tokenRequestData := TokenRequestData{
		GrantType:   "urn:okta:params:oauth:grant-type:webauthn",
		ClientID:    config.ClientID,
		Realm:       config.Realm,
		Scope:       "openid profile email username phone_number offline_access",
		AuthSession: registerResponse.AuthSession,
		AuthnResponse: TokenRequestAuthnResponse{
			ID:                      webAuthnRegister.WebauthnResponseComplete.Id,
			RawID:                   webAuthnRegister.WebauthnResponseComplete.RawId,
			ClientExtensionResults:  struct{}{},
			Type:                    "public-key",
			AuthenticatorAttachment: "platform",
			Response: TokenRequestAuthnResponseResponse{
				AttestationObject: webAuthnRegister.WebAuthnResponseRaw.AttestationObject,
				ClientDataJSON:    webAuthnRegister.WebAuthnResponseRaw.ClientDataJSON,
			},
		},
	}
	if config.UseOrganization {
		tokenRequestData.Organization = config.Organization
	}

	executeTokenRequest(config, tokenRequestData, debug)

	return nil
}
