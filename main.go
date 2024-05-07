package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	bls "github.com/herumi/bls-eth-go-binary/bls"
)

type ResponseData struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type DecodedPayload struct {
	Platform  string `json:"platform"`
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
}

var pubkey = "a410f6e8284c84e68fb4fef78ed947177c4f18d3106b148f6e558d0cdc8fd7a2bf7c44caceb2847b974134d4fd87c259"

func main() {
	// Define the URL
	url := "http://172.33.0.36:9000/api/v1/eth2/ext/sign/0xa410f6e8284c84e68fb4fef78ed947177c4f18d3106b148f6e558d0cdc8fd7a2bf7c44caceb2847b974134d4fd87c259"

	// Define the DecodedPayload
	requestPayload := DecodedPayload{
		Platform:  "dappnode",
		Timestamp: "1711338489397",
		Type:      "PROOF_OF_VALIDATION",
	}

	// Marshal the DecodedPayload to JSON
	requestBodyBytes, err := json.Marshal(requestPayload)
	if err != nil {
		fmt.Println("Error marshaling DecodedPayload:", err)
		return
	}

	// Convert the JSON bytes to string
	requestBody := string(requestBodyBytes)

	// Make the HTTP request with application/json content type
	client := &http.Client{}
	fmt.Println("Sending request to:", url)
	req, err := http.NewRequest("POST", url, strings.NewReader(requestBody))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	// Parse the JSON response
	var responseData ResponseData
	if err := json.Unmarshal(body, &responseData); err != nil {
		fmt.Println("Error parsing JSON:", err)
		return
	} else {
		fmt.Println("\nAPI response parsed successfully:", responseData)
	}

	// Decode the base64 payload
	decodedBytes, err := base64.StdEncoding.DecodeString(responseData.Payload)
	if err != nil {
		fmt.Println("Error decoding base64:", err)
		return
	}

	var decodedResponsePayload DecodedPayload
	if err := json.Unmarshal(decodedBytes, &decodedResponsePayload); err != nil {
		fmt.Println("Error parsing JSON:", err)
		return
	}
	fmt.Println("Payload parsed and decoded successfully: ", decodedResponsePayload)
	// Verify the signature

	fmt.Println(" \nNow verifying the signature:")
	fmt.Println("Payload:", decodedResponsePayload)
	fmt.Println("Signature:", responseData.Signature)
	fmt.Println("Pubkey:", pubkey)
	verifySignature(decodedResponsePayload, pubkey, responseData.Signature)

}

func verifySignature(decPayload DecodedPayload, pubkey string, signature string) bool {
	// Initialize BLS
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)

	// Decode the public key from hex
	pubkeyBytes, err := hex.DecodeString(pubkey)
	if err != nil {
		fmt.Println("Error decoding public key:", err)
		return false
	}
	var pubkeyDes bls.PublicKey
	if err := pubkeyDes.Deserialize(pubkeyBytes); err != nil {
		fmt.Println("Error deserializing public key:", err)
		return false
	}

	// Remove "0x" prefix from the signature and decode from hex
	signature = strings.TrimPrefix(signature, "0x")
	signature = strings.TrimSpace(signature)
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		fmt.Println("Error decoding signature:", err)
		return false
	}
	var sig bls.Sign
	if err := sig.Deserialize(sigBytes); err != nil {
		fmt.Println("Error deserializing signature:", err)
		return false
	}

	// Serialize payload to string (assuming it's what was signed)
	payloadBytes, err := json.Marshal(decPayload)
	if err != nil {
		fmt.Println("Error marshaling payload:", err)
		return false
	}

	// Verify the signature
	if !sig.VerifyByte(&pubkeyDes, payloadBytes) {
		fmt.Println("Signature verification failed")
		return false
	} else {
		fmt.Println("Signature verification successful")
		return true
	}
}
