package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	_ "github.com/fxamacker/webauthn/packed"
)

type Config struct {
	Domain          string `json:"domain"`
	Realm           string `json:"realm"`
	ClientID        string `json:"clientID"`
	Organization    string `json:"organization"`
	UseOrganization bool   `json:"useOrganization"`
	Email           string `json:"email"`
	Username        string `json:"username"`
	PhoneNumber     string `json:"phoneNumber"`
}

func getFlags() (Config, string, bool) {
	configFile := flag.String("config", "config.json", "JSON file containing config")
	purpose := flag.String("purpose", "purpose", "register, challenge or enroll")
	debug := flag.Bool("debug", false, "Enable debug logs")
	email := flag.String("email", "", "Email of user")
	username := flag.String("username", "", "Username of user")
	phoneNumber := flag.String("phoneNumber", "", "Phone number of user")

	flag.Parse()

	file, err := os.Open(*configFile)
	if err != nil {
		panic(fmt.Sprintf("Error reading config file: %v", err))
	}
	defer file.Close()

	var config Config

	decoder := json.NewDecoder(file)

	err = decoder.Decode(&config)
	if err != nil {
		panic(fmt.Sprintf("Error reading config file: %v", err))
	}

	if *email != "" {
		config.Email = *email
	}
	if *username != "" {
		config.Username = *username
	}
	if *phoneNumber != "" {
		config.PhoneNumber = *phoneNumber
	}

	if config.Domain == "" {
		panic("Domain is required and is missing from config")
	}
	if config.ClientID == "" {
		panic("ClientID is required and is missing from config")
	}
	if config.Realm == "" {
		panic("Realm is required and is missing from config")
	}
	if config.UseOrganization && config.Organization == "" {
		panic("Organization ID or Name is required and is missing configured to be used.")
	}
	if config.Email == "" && config.Username == "" && config.PhoneNumber == "" {
		panic("One Email, Username or PhoneNumber is required and is missing from config")
	}

	return config, *purpose, *debug
}

func main() {
	config, purpose, debug := getFlags()

	switch purpose {
	case "register":
		err := handleRegister(config, debug)
		if err != nil {
			logError("Error with register", err)
			return
		}

		logInfo("Successfully registered!")
	case "challenge":
		err := handleChallenge(config, debug)
		if err != nil {
			logError("Error with challenge", err)
			return
		}

		logInfo("Successfully challenged!")
	default:
		panic("Unknown purpose")
	}
}
