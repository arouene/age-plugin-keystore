// Package keystore provides an interface to the GNOME Keyring via the
// Secret Service D-Bus API using native D-Bus communication.
package keystore

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	// AttributeKeyApplication is the attribute that identity the type of keys
	// in the keystore.
	AttributeKeyApplication = "age-plugin-keystore"
	// AttributeKeyID is the attribute name used to identify keys.
	AttributeKeyID = "age-keystore-id"

	// D-Bus constants for Secret Service API
	SecretServiceName           = "org.freedesktop.secrets"
	ObjectPathService           = "/org/freedesktop/secrets"
	ObjectPathDefaultCollection = "/org/freedesktop/secrets/aliases/default"

	// D-Bus constants for Secret Service Errors
	SecretErrorIsLocked = "org.freedesktop.Secret.Error.IsLocked"

	// Content type for stored secrets
	contentType = "text/plain; charset=utf8"
)

// ErrKeyNotFound is returned when a key is not found in the keystore.
var ErrKeyNotFound = errors.New("key not found in keystore")
var ErrSecretEmpty = errors.New("Secret is empty")

// Secret represents the Secret structure used by the Secret Service API.
type Secret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

type Secrets map[dbus.ObjectPath]Secret

type Keystore struct {
	conn *dbus.Conn
}

func New() Keystore {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to connect to session bus:", err)
		os.Exit(1)
	}

	return Keystore{
		conn: conn,
	}
}

func (k *Keystore) Close() error {
	return k.conn.Close()
}

func (k *Keystore) Obj(path dbus.ObjectPath) dbus.BusObject {
	return k.conn.Object(SecretServiceName, path)
}

func (k *Keystore) Signal() chan *dbus.Signal {
	dbusSignal := make(chan *dbus.Signal, 10)
	k.conn.Signal(dbusSignal)

	return dbusSignal
}

type SessionAlgo string

// Session Algo modes used when opening sessions
const (
	SessionAlgoPlain SessionAlgo = "plain"
	SessionAlgoDH    SessionAlgo = "dh-ietf1024-sha256-aes128-cbc-pkcs7"
)

type Session struct {
	keystore *Keystore
	Path     dbus.ObjectPath
}

func (k *Keystore) openSession(mode SessionAlgo) (Session, error) {
	switch mode {
	case SessionAlgoDH:
		panic("DH Session Algo is not implemented")
	case SessionAlgoPlain:
		break
	default:
		panic("unknown Session Algo")
	}

	var output dbus.Variant
	var session dbus.ObjectPath

	input := dbus.MakeVariant("")

	obj := k.Obj(ObjectPathService)
	err := obj.Call("org.freedesktop.Secret.Service.OpenSession", 0, mode, input).Store(&output, &session)
	if err != nil {
		return Session{}, fmt.Errorf("failed to open session: %w", err)
	}

	return Session{keystore: k, Path: session}, nil
}

func (s *Session) closeSession() {
	obj := s.keystore.Obj(s.Path)
	obj.Call("org.freedesktop.Secret.Session.Close", 0)
}

type (
	Prompt dbus.ObjectPath
	Item   dbus.ObjectPath
	Items  []dbus.ObjectPath
)

func (k Keystore) unlock(locked Items) (Items, error) {
	var unlocked Items
	var prompt Prompt

	obj := k.Obj(ObjectPathService)
	err := obj.Call("org.freedesktop.Secret.Service.Unlock", 0, locked).Store(&unlocked, &prompt)
	if err != nil {
		return nil, fmt.Errorf("failed to call service unlock: %w", err)
	}

	obj = k.Obj(dbus.ObjectPath(prompt))
	call := obj.Call("org.freedesktop.Secret.Prompt.Prompt", 0, "Keyring Prompt")
	if call.Err != nil {
		return nil, fmt.Errorf("failed to prompt: %w", call.Err)
	}
	signal := k.Signal()
	items, err := handleUnlockSignal(signal)
	if err != nil {
		return nil, err
	}

	return items, nil
}

func handleUnlockSignal(signal <-chan *dbus.Signal) ([]dbus.ObjectPath, error) {
	var result dbus.Variant
loop:
	for {
		select {
		case sig, ok := <-signal:
			if !ok {
				return nil, fmt.Errorf("prompt unexpectedly closed")
			}

			if sig == nil {
				continue
			}

			if sig.Name != "org.freedesktop.Secret.Prompt.Completed" {
				continue
			}

			var dismissed bool
			err := dbus.Store(sig.Body, &dismissed, &result)
			if err != nil {
				return nil, fmt.Errorf("could not store prompt result: %w", err)
			}

			if dismissed {
				return nil, fmt.Errorf("prompt was dismissed")
			}

			break loop

		case <-time.After(60 * time.Second):
			return nil, fmt.Errorf("prompt timed out")
		}
	}

	return result.Value().([]dbus.ObjectPath), nil
}

type Attributes map[string]string

func (k Keystore) searchItems(attributes Attributes) (Items, Items, error) {
	var unlocked, locked Items

	obj := k.Obj(ObjectPathService)
	err := obj.Call("org.freedesktop.Secret.Service.SearchItems", 0, attributes).Store(&unlocked, &locked)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to search items: %w", err)
	}

	return unlocked, locked, nil
}

func (k Keystore) getItemsSecrets(items Items) (Secrets, error) {
	var secrets Secrets

	session, err := k.openSession(SessionAlgoPlain)
	if err != nil {
		return nil, err
	}
	defer session.closeSession()

	obj := k.Obj(ObjectPathService)
	err = obj.Call("org.freedesktop.Secret.Service.GetSecrets", 0, items, session.Path).Store(&secrets)
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets: %w", err)
	}

	return secrets, nil
}

// List returns all key IDs stored in the keyring.
func (k Keystore) List() ([]string, error) {
	attributes := Attributes{
		"application": AttributeKeyApplication,
	}

	unlocked, locked, err := k.searchItems(attributes)
	if err != nil {
		return nil, fmt.Errorf("cannot list keystore items: %w", err)
	}

	if len(locked) > 0 {
		items, err := k.unlock(locked)
		if err != nil {
			return nil, fmt.Errorf("cannot unlock keystore: %w", err)
		}
		unlocked = append(unlocked, items...)
	}

	// Get the key ID attribute from each item
	var keyIDs []string
	for _, item := range unlocked {
		obj := k.Obj(dbus.ObjectPath(item))
		variant, err := obj.GetProperty("org.freedesktop.Secret.Item.Attributes")
		if err != nil {
			fmt.Printf("warning: cannot get properties of %s: %v\n", item, err)
			continue
		}

		attrs, ok := variant.Value().(map[string]string)
		if !ok {
			fmt.Printf("warning: cannot get property values of %s\n", item)
			continue
		}

		if keyID, ok := attrs[AttributeKeyID]; ok {
			keyIDs = append(keyIDs, keyID)
		}
	}

	return keyIDs, nil
}

// Lookup retrieves a secret key from the keyring.
func (k Keystore) Lookup(keyID string) (string, error) {
	attributes := Attributes{
		AttributeKeyID: keyID,
	}

	unlocked, locked, err := k.searchItems(attributes)
	if err != nil {
		return "", fmt.Errorf("cannot list keystore items: %w", err)
	}

	if len(locked) > 0 {
		items, err := k.unlock(locked)
		if err != nil {
			return "", fmt.Errorf("cannot unlock keystore: %w", err)
		}
		unlocked = append(unlocked, items...)
	}

	if len(unlocked) == 0 {
		return "", ErrKeyNotFound
	}

	if len(unlocked) > 1 {
		fmt.Println("warning: more than one secret is matching, taking the first one")
	}
	itemPath := unlocked[0]

	secrets, err := k.getItemsSecrets(unlocked)
	if err != nil {
		return "", err
	}
	secret, ok := secrets[dbus.ObjectPath(itemPath)]
	if !ok {
		return "", ErrKeyNotFound
	}

	return string(secret.Value), nil
}

// Store stores a secret key in the keyring. It returns a keyID that is used to
// identify the key for later retrieval.
func (k Keystore) Store(secretKey string) (string, error) {
	if secretKey == "" {
		return "", ErrSecretEmpty
	}

	// Generate a new random KeyID
	keyIDBytes := make([]byte, 8)
	if _, err := rand.Read(keyIDBytes); err != nil {
		return "", fmt.Errorf("failed to generate key ID: %w", err)
	}
	keyID := fmt.Sprintf("%x", keyIDBytes)

	session, err := k.openSession(SessionAlgoPlain)
	if err != nil {
		return "", fmt.Errorf("could not open a session: %w", err)
	}
	defer session.closeSession()

	secret := Secret{
		Session:     session.Path,
		Parameters:  []byte{},
		Value:       []byte(secretKey),
		ContentType: contentType,
	}

	// item properties
	label := fmt.Sprintf("%s: %s", AttributeKeyApplication, keyID)
	attributes := Attributes{
		AttributeKeyID: keyID,
		"application":  AttributeKeyApplication,
	}

	properties := map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label":      dbus.MakeVariant(label),
		"org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(attributes),
	}

	var item Item
	var prompt Prompt

	obj := k.Obj(ObjectPathDefaultCollection)
	err = obj.Call("org.freedesktop.Secret.Collection.CreateItem", 0, properties, secret, true).Store(&item, &prompt)
	if err != nil {
		var dBusError dbus.Error
		if errors.As(err, &dBusError) && dBusError.Name == SecretErrorIsLocked {
			_, err := k.unlock([]dbus.ObjectPath{ObjectPathDefaultCollection})
			if err != nil {
				return "", fmt.Errorf("unlocking failed: %w", err)
			}
			// retry creating item after unlocking the collection
			err = obj.Call("org.freedesktop.Secret.Collection.CreateItem", 0, properties, secret, true).Store(&item, &prompt)
			if err == nil {
				return keyID, nil
			}
		}
		return "", fmt.Errorf("cannot create item: %w", err)
	}

	return keyID, nil
}

// Delete removes a secret key from the keyring. Returns ErrKeyNotFound if the
// key does not exist.
func (k Keystore) Delete(keyID string) error {
	attributes := map[string]string{
		AttributeKeyID: keyID,
	}

	unlocked, locked, err := k.searchItems(attributes)
	if err != nil {
		return fmt.Errorf("cannot list keystore items: %w", err)
	}

	if len(locked) > 0 {
		items, err := k.unlock(locked)
		if err != nil {
			return fmt.Errorf("cannot unlock keystore: %w", err)
		}
		unlocked = append(unlocked, items...)
	}

	if len(unlocked) == 0 {
		return ErrKeyNotFound
	}

	// Delete all matching items
	for _, item := range unlocked {
		var prompt Prompt

		obj := k.Obj(dbus.ObjectPath(item))
		err = obj.Call("org.freedesktop.Secret.Item.Delete", 0).Store(&prompt)
		if err != nil {
			return fmt.Errorf("failed to delete item: %w", err)
		}

		if prompt != "/" && prompt != "" {
			return fmt.Errorf("deletion requires interactive confirmation")
		}
	}

	return nil
}
