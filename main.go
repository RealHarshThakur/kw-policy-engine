package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	"github.com/wapc/wapc-go"
	"github.com/wapc/wapc-go/engines/wazero"
)

func main() {
	// Define command line flags
	requestFile := flag.String("r", "", "Path to the JSON file containing the validation request object")
	settingsJSON := flag.String("settings-json", "{}", "Settings JSON as a string")

	// Parse command line flags
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

	// Initialize validation request
	kreq := kubewarden_protocol.ValidationRequest{}

	// Read validation request from file if specified
	if *requestFile != "" {
		fileContent, err := os.ReadFile(*requestFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file %s: %v\n", *requestFile, err)
			os.Exit(1)
		}

		var req json.RawMessage
		// Parse the JSON directly into the ValidationRequest
		if err := json.Unmarshal(fileContent, &req); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing JSON from file: %v\n", err)
			os.Exit(1)
		}
		kreq.Request.Object = req
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

	fmt.Printf("%v\n", string(reqBytes))

	result, err := instance.Invoke(ctx, "validate", reqBytes)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(result))
}

func host(ctx context.Context, binding, namespace, operation string, payload []byte) ([]byte, error) {
	// Route the payload to any custom functionality accordingly.
	// You can even route to other waPC modules!!!
	switch namespace {
	case "example":
		switch operation {
		case "capitalize":
			name := string(payload)
			name = strings.Title(name)
			return []byte(name), nil
		}
	}
	return []byte("default"), nil
}
