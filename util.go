package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/charmbracelet/log"
	"github.com/descope/virtualwebauthn"
)

type UserDetails struct {
	ID           string `json:"id"`
	DisplayName  string `json:"display_name"`
	Name         string `json:"name"`
	CredentialID string `json:"credential_id"`
}

func logError(description string, err error) {
	log.Error(description, "Error", err)
}

func logInfo(description string) {
	log.Info(description)
}

func prettyLog(description string, details []byte) {
	var prettyJSON bytes.Buffer

	err := json.Indent(&prettyJSON, details, "", "   ")

	if err != nil {
		log.Error("JSON parse error:", "Error", err)
	}

	log.Info(description, "Response", prettyJSON.String())
}

func writeDetailsToJSON(user *User, credentialID string) error {
	file, err := os.OpenFile("users.json", os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	existingData := []interface{}{}

	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	if fileInfo.Size() > 0 {
		byteValue, _ := io.ReadAll(file)
		err = json.Unmarshal(byteValue, &existingData)
		if err != nil {
			return err
		}
	}

	var data UserDetails
	data.ID = user.ID
	data.DisplayName = user.DisplayName
	data.Name = user.Name
	data.CredentialID = credentialID

	existingData = append(existingData, data)

	jsonData, err := json.MarshalIndent(existingData, "", "    ")
	if err != nil {
		return err
	}
	err = os.Truncate("users.json", 0)

	if err != nil {
		return err
	}
	_, err = file.WriteAt(jsonData, 0)
	if err != nil {
		return err
	}

	return nil
}

func getUserFromJSON(identifier string) (*UserDetails, error) {
	file, err := os.Open("users.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var users []UserDetails
	decoder := json.NewDecoder(file)

	err = decoder.Decode(&users)
	if err != nil {
		return nil, err
	}

	var foundUser UserDetails
	for _, user := range users {
		if user.Name == identifier {
			foundUser = user

		}
	}

	return &foundUser, nil
}

func findUser(config Config) (*UserDetails, error) {
	var user *UserDetails
	for _, identifier := range [...]string{config.Email, config.Username, config.PhoneNumber} {
		foundUser, err := getUserFromJSON(identifier)

		if err != nil {
			return nil, err
		}

		if foundUser != nil {
			user = foundUser
			break
		}
	}

	return user, nil
}

func parsePrivateKey() ([]byte, virtualwebauthn.KeyType, error) {
	// Read the private key file
	keyData, err := os.ReadFile("private-key.pem")
	if err != nil {
		return nil, "", err
	}

	// Decode the PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, "", fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Parse the private key based on the type
	var parsedKey interface{}
	var keyType virtualwebauthn.KeyType
	switch block.Type {
	case "PRIVATE KEY": // PKCS#8 format
		parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
	case "RSA PRIVATE KEY": // PKCS#1 format
		parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse PKCS#1 private key: %w", err)
		}
		keyType = "RSA"
	case "EC PRIVATE KEY": // EC key in PEM format
		parsedKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse EC private key: %w", err)
		}
		keyType = "EC"
	default:
		return nil, "", fmt.Errorf("unsupported key type: %s", block.Type)
	}

	// Detect key type if not already set
	switch parsedKey.(type) {
	case *rsa.PrivateKey:
		keyType = virtualwebauthn.KeyTypeRSA
	case *ecdsa.PrivateKey:
		keyType = virtualwebauthn.KeyTypeEC2
	default:
		return nil, "", fmt.Errorf("unknown key type")
	}

	// Marshal the private key into PKCS#8 format
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(parsedKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal private key to PKCS#8: %w", err)
	}

	return privateKeyBytes, keyType, nil
}
