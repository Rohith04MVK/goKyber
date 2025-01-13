package main

import (
	"crypto/subtle"
	"fmt"

	gokyber "github.com/Rohith04MVK/goKyber/goKyber"
)

func main() {
	// Kyber-768 Example: Simulating Communication Between Two Parties (Alice and Bob)

	fmt.Println("Kyber-768 Key Exchange Between Alice and Bob")
	fmt.Println("---------------------------------------------")

	// --- Alice's Side ---
	fmt.Println("\nAlice:")

	// Alice generates a Kyber-768 key pair
	alicePrivateKey, alicePublicKey, err := gokyber.KemKeypair(768)
	if err != nil {
		fmt.Println("  Error: Alice failed to generate key pair:", err)
		return
	}
	fmt.Println("  1. Generates a key pair.")

	// Alice sends her public key to Bob (in a real scenario, this would be over a network)
	fmt.Println("  2. Sends her public key to Bob.")

	// --- Bob's Side ---
	fmt.Println("\nBob:")

	// Bob receives Alice's public key
	fmt.Println("  1. Receives Alice's public key.")

	// Bob encrypts a message (using Alice's public key) to generate a ciphertext and a shared secret
	ciphertext, sharedSecretBob, err := gokyber.KemEncrypt(alicePublicKey, 768)
	if err != nil {
		fmt.Println("  Error: Bob failed to encrypt:", err)
		return
	}
	fmt.Println("  2. Encrypts a message using Alice's public key, generating a ciphertext and a shared secret.")

	// Bob sends the ciphertext to Alice
	fmt.Println("  3. Sends the ciphertext to Alice.")
	fmt.Printf("     Ciphertext (truncated): %x...\n", ciphertext[:25]) // Show a truncated ciphertext

	// --- Alice's Side ---
	fmt.Println("\nAlice:")

	// Alice receives the ciphertext from Bob
	fmt.Println("  3. Receives the ciphertext from Bob.")

	// Alice decrypts the ciphertext using her private key to get the shared secret
	sharedSecretAlice, err := gokyber.KemDecrypt(ciphertext, alicePrivateKey, 768)
	if err != nil {
		fmt.Println("  Error: Alice failed to decrypt:", err)
		return
	}
	fmt.Println("  4. Decrypts the ciphertext using her private key to obtain the shared secret.")

	// --- Verification ---
	fmt.Println("\nVerification:")

	fmt.Printf("  Alice's shared secret: %x\n", sharedSecretAlice)
	fmt.Printf("  Bob's shared secret : %x\n", sharedSecretBob)

	if subtle.ConstantTimeCompare(sharedSecretAlice, sharedSecretBob) == 1 {
		fmt.Println("  Shared secrets match! Secure communication established.")
	} else {
		fmt.Println("  Shared secrets do not match! Something went wrong.")
	}
}
