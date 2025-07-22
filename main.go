package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	"github.com/wapc/wapc-go"
	"github.com/wapc/wapc-go/engines/wazero"
)

func main() {
	// Define command line flags
	requestFile := flag.String("r", "", "Path to the JSON file containing the Kubernetes request payload")
	settingsJSON := flag.String("settings-json", "{}", "Settings JSON as a string")

	flag.Parse()

	ctx := context.Background()
	guest, err := os.ReadFile("policy.wasm")
	if err != nil {
		panic(err)
	}

	engine := wazero.Engine()
	module, err := engine.New(ctx, host, guest, &wapc.ModuleConfig{
		Logger: wapc.PrintlnLogger,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	})
	if err != nil {
		panic(err)
	}
	defer module.Close(ctx)

	instance, err := module.Instantiate(ctx)
	if err != nil {
		panic(err)
	}
	defer instance.Close(ctx)

	// Initialize validation request structure
	kreq := kubewarden_protocol.ValidationRequest{}

	// Read Kubernetes admission-style request JSON into kreq.Request
	if *requestFile != "" {
		fileContent, err := os.ReadFile(*requestFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file %s: %v\n", *requestFile, err)
			os.Exit(1)
		}
		// Unmarshal directly into the Request field
		if err := json.Unmarshal(fileContent, &kreq.Request); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing request JSON: %v\n", err)
			os.Exit(1)
		}
	}

	// Parse settings JSON
	var settings json.RawMessage
	if err := json.Unmarshal([]byte(*settingsJSON), &settings); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing settings JSON: %v\n", err)
		os.Exit(1)
	}
	kreq.Settings = settings

	reqBytes, err := json.Marshal(kreq)
	if err != nil {
		panic(err)
	}

	// Invoke guest
	result, err := instance.Invoke(ctx, "validate", reqBytes)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(result))
}

func host(ctx context.Context, binding, namespace, operation string, payload []byte) ([]byte, error) {
	// Minimal stub: ignore host calls
	return []byte{}, nil
}
