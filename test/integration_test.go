//go:build integration

package test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestIntegration(t *testing.T) {
	// Ensure the plugin binary is built and in PATH
	pluginPath, err := exec.LookPath("age-plugin-keystore")
	if err != nil {
		t.Skip("plugin not found, skipping integration test")
	}
	t.Logf("Using plugin: %s", pluginPath)

	// Check that age is available
	if _, err := exec.LookPath("age"); err != nil {
		t.Skip("age not found in PATH, skipping integration test")
	}

	// Create a temp directory for test files
	tmpDir, err := os.MkdirTemp("", "age-keystore-separate-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Test data
	testContent := []byte("Hello, this is a test for separate identity mode!\nLine 2\nLine 3\n")

	// Write test file
	plaintextFile := filepath.Join(tmpDir, "plaintext.txt")
	if err := os.WriteFile(plaintextFile, testContent, 0644); err != nil {
		t.Fatalf("Failed to write plaintext file: %v", err)
	}

	// Generate a new key pair with separate identity flag
	identityFile := filepath.Join(tmpDir, "identity.txt")
	cmd := exec.Command(pluginPath, "-g")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to generate key: %v\nstderr: %s", err, stderr.String())
	}

	// Parse the output to get identity and recipient
	identityStr := strings.TrimSpace(stdout.String())
	if !strings.HasPrefix(identityStr, "AGE-PLUGIN-KEYSTORE-") {
		t.Fatalf("Unexpected identity format: %s", identityStr)
	}

	// Extract public key from stderr (second line after "# key ID: ...") - should be standard age1... format
	stderrStr := stderr.String()
	var recipient string
	for _, line := range strings.Split(stderrStr, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "age1") {
			recipient = line
			break
		}
	}
	if recipient == "" {
		t.Fatalf("Could not find public key in output:\n%s", stderrStr)
	}

	// Verify the public key is a standard age public key (not age1keystore1...)
	if !strings.HasPrefix(recipient, "age1") || strings.HasPrefix(recipient, "age1keystore") {
		t.Fatalf("Expected standard age1... public key, got: %s", recipient)
	}

	// Extract key ID for cleanup
	var keyID string
	for _, line := range strings.Split(stderrStr, "\n") {
		if strings.HasPrefix(line, "# key ID: ") {
			keyID = strings.TrimPrefix(line, "# key ID: ")
			break
		}
	}

	t.Logf("Generated identity: %s", identityStr)
	t.Logf("Public key (standard age format): %s", recipient)
	t.Logf("Key ID: %s", keyID)

	// Save identity to file
	if err := os.WriteFile(identityFile, []byte(identityStr+"\n"), 0600); err != nil {
		t.Fatalf("Failed to write identity file: %v", err)
	}

	// Encrypt the file using standard age recipient
	encryptedFile := filepath.Join(tmpDir, "encrypted.age")
	cmd = exec.Command("age", "-r", recipient, "-o", encryptedFile, plaintextFile)
	cmd.Stderr = &stderr
	stderr.Reset()
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to encrypt file: %v\nstderr: %s", err, stderr.String())
	}

	// Verify encrypted file exists and is different from plaintext
	encryptedContent, err := os.ReadFile(encryptedFile)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}
	if bytes.Equal(encryptedContent, testContent) {
		t.Fatal("Encrypted content is the same as plaintext!")
	}
	t.Logf("Encrypted file size: %d bytes", len(encryptedContent))

	// Decrypt the file using keystore identity
	decryptedFile := filepath.Join(tmpDir, "decrypted.txt")
	cmd = exec.Command("age", "-d", "-i", identityFile, "-o", decryptedFile, encryptedFile)
	stderr.Reset()
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to decrypt file: %v\nstderr: %s", err, stderr.String())
	}

	// Verify decrypted content matches original
	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(decryptedContent, testContent) {
		t.Errorf("Decrypted content doesn't match original!\nExpected: %q\nGot: %q",
			testContent, decryptedContent)
	}

	// List keys and verify the generated key is present
	cmd = exec.Command(pluginPath, "-l")
	stdout.Reset()
	stderr.Reset()
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to list keys: %v\nstderr: %s", err, stderr.String())
	}
	listOutput := stdout.String()
	stderrOutput := stderr.String()
	t.Logf("Key list output:\n%s", listOutput)
	if stderrOutput != "" {
		t.Logf("Key list stderr:\n%s", stderrOutput)
	}
	if !strings.Contains(listOutput, keyID) && !strings.Contains(stderrOutput, keyID) {
		t.Errorf("Key ID %s not found in list output or stderr", keyID)
	}

	// Delete the generated key
	if keyID != "" {
		cmd = exec.Command(pluginPath, "-d", keyID)
		var delStdout, delStderr bytes.Buffer
		cmd.Stdout = &delStdout
		cmd.Stderr = &delStderr
		if err := cmd.Run(); err != nil {
			t.Errorf("Failed to delete key: %v\nstderr: %s", err, delStderr.String())
		} else {
			t.Logf("Successfully deleted key %s", keyID)
		}
	} else {
		t.Error("Key ID was not extracted, cannot verify or cleanup")
	}

	t.Log("Integration test passed: separate identity encrypt/decrypt roundtrip successful")
}
