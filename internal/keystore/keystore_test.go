package keystore

import (
	"errors"
	"strings"
	"testing"
)

// skipIfLocked skips the test if the keystore is locked or unavailable
func skipIfLocked(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "locked collection") ||
			strings.Contains(errStr, "disconnected") ||
			strings.Contains(errStr, "unavailable") {
			t.Skipf("Keystore locked or unavailable: %v", err)
		}
	}
}

func TestStoreAndLookup(t *testing.T) {
	secret := "AGE-PLUGIN-KEYSTORE-1TESTKEYTESTKEYTESTKEYTEST"

	k := New()
	defer k.Close()

	// Store the secret
	keyID, err := k.Store(secret)
	skipIfLocked(t, err)
	if err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	// Ensure cleanup after test
	defer k.Delete(keyID)

	// Lookup the secret
	retrieved, err := k.Lookup(keyID)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}

	if string(retrieved) != string(secret) {
		t.Errorf("Lookup() = %q, want %q", retrieved, secret)
	}
}

func TestLookupNotFound(t *testing.T) {
	k := New()
	defer k.Close()

	_, err := k.Lookup("nonexistent-key-id-12345")
	if err != ErrKeyNotFound {
		t.Errorf("Lookup() error = %v, want ErrKeyNotFound", err)
	}
}

func TestDelete(t *testing.T) {
	secret := "test-secret-to-delete"

	k := New()
	defer k.Close()

	// Store a secret first
	keyID, err := k.Store(secret)
	skipIfLocked(t, err)
	if err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	// Delete the secret
	err = k.Delete(keyID)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify it's gone
	_, err = k.Lookup(keyID)
	if err != ErrKeyNotFound {
		t.Errorf("Lookup() after Delete() error = %v, want ErrKeyNotFound", err)
	}
}

func TestDeleteNonexistent(t *testing.T) {
	k := New()
	defer k.Close()

	// Delete should error on nonexistent keys
	err := k.Delete("nonexistent-key-to-delete")
	if err != ErrKeyNotFound {
		t.Errorf("Delete() on nonexistent key error = %v, want ErrKeyNotFound", err)
	}
}

func TestList(t *testing.T) {
	k := New()
	defer k.Close()

	// Store test secrets
	keyID1, err := k.Store("secret1")
	skipIfLocked(t, err)
	if err != nil {
		t.Fatalf("Store() key1 error = %v", err)
	}
	defer k.Delete(keyID1)

	keyID2, err := k.Store("secret2")
	if err != nil {
		t.Fatalf("Store() key2 error = %v", err)
	}
	defer k.Delete(keyID2)

	// List keys
	keyIDs, err := k.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	// Check that our keys are in the list
	found1, found2 := false, false
	for _, id := range keyIDs {
		if id == keyID1 {
			found1 = true
		}
		if id == keyID2 {
			found2 = true
		}
	}

	if !found1 {
		t.Errorf("List() did not return %q", keyID1)
	}
	if !found2 {
		t.Errorf("List() did not return %q", keyID2)
	}
}

// TestStoreEmptySecret tests storing an empty secret
func TestStoreEmptySecret(t *testing.T) {
	secret := ""

	k := New()
	defer k.Close()

	// Store empty secret
	_, err := k.Store(secret)
	skipIfLocked(t, err)
	if !errors.Is(err, ErrSecretEmpty) {
		t.Errorf("Store() error = %v, want ErrSecretEmpty", err)
	}
}

// TestLookupEmptyKeyID tests looking up with an empty key ID
func TestLookupEmptyKeyID(t *testing.T) {
	k := New()
	defer k.Close()

	_, err := k.Lookup("")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Lookup(\"\") error = %v, want ErrKeyNotFound", err)
	}
}

// TestListEmpty tests listing when no keys exist
func TestListEmpty(t *testing.T) {
	k := New()
	defer k.Close()

	// First, delete any test keys that might exist
	keyIDs, err := k.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	for _, id := range keyIDs {
		if len(id) > 5 && id[:5] == "test-" {
			_ = k.Delete(id)
		}
	}

	// Now list should return no test keys
	// (but might return other keys from other tests)
	keyIDs, err = k.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	for _, id := range keyIDs {
		if len(id) > 5 && id[:5] == "test-" {
			t.Errorf("List() returned test key that should have been deleted: %q", id)
		}
	}
}

// TestErrorTypes tests that error types are correctly identified
func TestErrorTypes(t *testing.T) {
	// Test that ErrKeyNotFound is a proper error
	if ErrKeyNotFound.Error() == "" {
		t.Error("ErrKeyNotFound.Error() should not be empty")
	}

	if ErrSecretEmpty.Error() == "" {
		t.Error("ErrSecretEmpty.Error() should not be empty")
	}
}
