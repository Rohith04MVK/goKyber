package main

import (
	"crypto/subtle"
	"fmt"
	"time"

	gokyber "github.com/Rohith04MVK/goKyber/goKyber"
)

// BenchmarkKyber tests the total time for key generation, encryption, and decryption
func BenchmarkKyber(securityLevel int) {
	fmt.Printf("\nBenchmarking Kyber-%d:\n", securityLevel)

	totalStart := time.Now()

	start := time.Now()
	privateKey, publicKey, err := gokyber.KemKeypair(securityLevel)
	if err != nil {
		fmt.Println("  Error: Failed to generate key pair:", err)
		return
	}
	keyGenTime := time.Since(start)

	start = time.Now()
	ciphertext, sharedSecretBob, err := gokyber.KemEncrypt(publicKey, securityLevel)
	if err != nil {
		fmt.Println("  Error: Failed to encrypt:", err)
		return
	}
	encryptTime := time.Since(start)

	start = time.Now()
	sharedSecretAlice, err := gokyber.KemDecrypt(ciphertext, privateKey, securityLevel)
	if err != nil {
		fmt.Println("  Error: Failed to decrypt:", err)
		return
	}
	decryptTime := time.Since(start)

	totalTime := time.Since(totalStart)

	if subtle.ConstantTimeCompare(sharedSecretAlice, sharedSecretBob) == 1 {
		fmt.Printf("  Total time: %v (KeyGen: %v, Encrypt: %v, Decrypt: %v) - Success\n", totalTime, keyGenTime, encryptTime, decryptTime)
	} else {
		fmt.Printf("  Total time: %v (KeyGen: %v, Encrypt: %v, Decrypt: %v) - Failure\n", totalTime, keyGenTime, encryptTime, decryptTime)
	}
}

func main() {
	BenchmarkKyber(512)
	BenchmarkKyber(768)
	BenchmarkKyber(1024)
}
