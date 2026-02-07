package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/arouene/age-plugin-keystore/internal/keystore"
)

const pluginName = "keystore"

var (
	generateFlag    bool
	postquantumFlag bool
	listFlag        bool
	deleteFlag      string
	versionFlag     bool
	ks              keystore.Keystore
)

type KeyType string

const KeyTypeX25519 KeyType = "X25519"
const KeyTypeHybrid KeyType = "Hybrid"

func printUsage() {
	fmt.Fprintf(os.Stderr, `age-plugin-keystore

An age plugin that stores X25519 private keys in GNOME Keyring.

Usage:
    age-plugin-keystore -g, --generate [-pq] Generate a new key pair (-pq for post-quantum key)
    age-plugin-keystore -l, --list           List stored keys
    age-plugin-keystore -d, --delete KEYID   Delete a key by ID
    age-plugin-keystore -v, --version        Show version
    age-plugin-keystore -h, --help           Show this help

The plugin is normally invoked by age automatically when decypting with an
identity: AGE-PLUGIN-KEYSTORE-1...

Note: The -j flag is not supported. Use -i with an identity file instead.

Examples:
    # Generate a new key with separate identity (standard age public key) This
    # outputs a standard age1... public key The public key can be shared
    # independently and used without the plugin for encryption (only decryption
    # requires the plugin)
    age-plugin-keystore -g > identity.txt 2> recipient.txt

    # Generate a post-quantom hybrid key instead of X25519
    age-plugin-keystore -g -pq > identity.txt 2> recipient.txt

    # List all stored keys
    age-plugin-keystore -l

    # Delete a key from the keystore
    age-plugin-keystore -d 1234567890abcdef

    # Encrypt a file (using the public key printed by -g)
    age -r age1... file.txt > file.txt.age

    # Decrypt a file (using the identity file)
    age -d -i identity.txt file.txt.age > file.txt
`)
}

func main() {
	// Create the plugin first to register its flags
	p, err := plugin.New(pluginName)
	if err != nil {
		log.Fatalf("Could not register plugin: %v", err)
	}
	p.RegisterFlags(nil)

	flag.BoolVar(&generateFlag, "g", false, "Generate a new key pair (pq: post-quantum)")
	flag.BoolVar(&generateFlag, "generate", false, "Generate a new key pair (pq: post-quantum)")
	flag.BoolVar(&postquantumFlag, "pq", false, "Generate a post-quantum key pair")
	flag.BoolVar(&listFlag, "l", false, "List stored keys")
	flag.BoolVar(&listFlag, "list", false, "List stored keys")
	flag.StringVar(&deleteFlag, "d", "", "Delete a key by ID")
	flag.StringVar(&deleteFlag, "delete", "", "Delete a key by ID")
	flag.BoolVar(&versionFlag, "v", false, "Show version")
	flag.BoolVar(&versionFlag, "version", false, "Show version")

	flag.Usage = printUsage
	flag.Parse()

	ks = keystore.New()
	defer ks.Close()

	if generateFlag {
		if postquantumFlag {
			os.Exit(keygen(KeyTypeHybrid))
		}
		os.Exit(keygen(KeyTypeX25519))
	}
	if postquantumFlag {
		fmt.Println("error: invalid use of option -pq, it must be use as an option of -g / --generate")
		fmt.Println()
		printUsage()
		os.Exit(0)
	}
	if listFlag {
		os.Exit(list())
	}
	if deleteFlag != "" {
		os.Exit(deleteKey(deleteFlag))
	}
	if versionFlag {
		os.Exit(version())
	}

	// If no flags provided and not running as plugin, show help
	if flag.NFlag() == 0 {
		printUsage()
		os.Exit(0)
	}

	p.HandleRecipient(func(data []byte) (age.Recipient, error) {
		arg := string(data)

		switch {
		case strings.HasPrefix(arg, "age1pq1"):
			return age.ParseHybridRecipient(arg)
		case strings.HasPrefix(arg, "age1"):
			return age.ParseX25519Recipient(arg)
		default:
			return nil, fmt.Errorf("unknown recipient type: %q", arg)
		}
	})

	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		keyID := string(data)

		secret, err := ks.Lookup(keyID)
		if err != nil {
			return nil, fmt.Errorf("could not get the secret of key %s: %w", keyID, err)
		}

		switch {
		case strings.HasPrefix(secret, "AGE-SECRET-KEY-1"):
			return age.ParseX25519Identity(secret)
		case strings.HasPrefix(secret, "AGE-SECRET-KEY-PQ-1"):
			return age.ParseHybridIdentity(secret)
		default:
			return nil, fmt.Errorf("unknown identity type: %q", secret)
		}
	})

	os.Exit(p.Main())
}

func keygen(key KeyType) int {
	var recipient string
	var privatekey string

	switch key {
	case KeyTypeX25519:
		i, err := age.GenerateX25519Identity()
		if err != nil {
			log.Fatalf("failed to generate key pair: %v", err)
		}
		recipient = i.Recipient().String()
		privatekey = i.String()

	case KeyTypeHybrid:
		i, err := age.GenerateHybridIdentity()
		if err != nil {
			log.Fatalf("failed to generate key pair: %v", err)
		}
		recipient = i.Recipient().String()
		privatekey = i.String()

	default:
		panic("unsupported key type")
	}

	keyID, err := ks.Store(privatekey)
	if err != nil {
		log.Fatalf("failed to store key in keystore: %v", err)
	}

	identityStr := plugin.EncodeIdentity(pluginName, []byte(keyID))

	fmt.Fprintf(os.Stderr, "# key ID: %s\n", keyID)
	fmt.Fprintf(os.Stderr, "%s\n", recipient)
	fmt.Printf("%s\n", strings.ToUpper(identityStr))

	return 0
}

func list() int {
	keyIDs, err := ks.List()
	if err != nil {
		log.Fatalf("error listing keys: %v", err)
	}

	if len(keyIDs) == 0 {
		fmt.Fprintln(os.Stderr, "No keys stored in keystore")
		return 0
	}

	fmt.Fprintf(os.Stderr, "Found %d key(s) in keystore:\n", len(keyIDs))
	for _, keyID := range keyIDs {
		secret, err := ks.Lookup(keyID)
		if err != nil {
			fmt.Printf("could not get the secret of key %q: %s", keyID, err)
			continue
		}

		var recipient string
		switch {
		case strings.HasPrefix(secret, "AGE-SECRET-KEY-1"):
			identity, err := age.ParseX25519Identity(secret)
			if err != nil {
				fmt.Println(err)
				continue
			}
			recipient = identity.Recipient().String()
		case strings.HasPrefix(secret, "AGE-SECRET-KEY-PQ-1"):
			identity, err := age.ParseHybridIdentity(secret)
			if err != nil {
				fmt.Println(err)
				continue
			}
			recipient = identity.Recipient().String()
		default:
			fmt.Printf("unknown identity type: %q", secret)
		}

		// Rebuild the identity string from the keyID instead of the secret
		// as what is exposed is the keyID not the secret key.
		identityStr := plugin.EncodeIdentity(pluginName, []byte(keyID))

		fmt.Fprintf(os.Stderr, "  Key ID: %s\n", keyID)
		fmt.Fprintf(os.Stderr, "    Public key: %s\n", recipient)
		fmt.Fprintf(os.Stderr, "    Identity:   %s\n", identityStr)
	}
	return 0
}

func deleteKey(keyID string) int {
	if err := ks.Delete(keyID); err != nil {
		fmt.Fprintf(os.Stderr, "Error deleting key: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "Deleted key: %s\n", keyID)
	return 0
}

func version() int {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		fmt.Fprintln(os.Stderr, "version: unknown")
		return 1
	}
	fmt.Println(info.Main.Version)
	return 0
}
