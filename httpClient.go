package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

func executeRequest(domain string, path string, payload []byte) ([]byte, error) {
	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("https://%s/%s", domain, path),
		bytes.NewBuffer(payload),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	response, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return response, nil
}
