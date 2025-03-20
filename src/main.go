package main

import (
	"crypto/subtle"
	"fmt"
	"time"

	gokyber "github.com/Rohith04MVK/goKyber/goKyber"
)

// BenchmarkKyber runs the Kyber benchmark over multiple iterations and averages the results
func BenchmarkKyber(securityLevel int, iterations int) {
	fmt.Printf("\nBenchmarking Kyber-%d over %d runs:\n", securityLevel, iterations)

	var totalKeyGenTime, totalEncryptTime, totalDecryptTime, totalRunTime time.Duration
	successCount := 0
	totalStart := time.Now()

	for i := 0; i < iterations; i++ {
		runStart := time.Now()

		start := time.Now()
		privateKey, publicKey, err := gokyber.KemKeypair(securityLevel)
		if err != nil {
			fmt.Println("  Error: Failed to generate key pair:", err)
			return
		}
		keyGenTime := time.Since(start)
		totalKeyGenTime += keyGenTime

		start = time.Now()
		ciphertext, sharedSecretBob, err := gokyber.KemEncrypt(publicKey, securityLevel)
		if err != nil {
			fmt.Println("  Error: Failed to encrypt:", err)
			return
		}
		encryptTime := time.Since(start)
		totalEncryptTime += encryptTime

		start = time.Now()
		sharedSecretAlice, err := gokyber.KemDecrypt(ciphertext, privateKey, securityLevel)
		if err != nil {
			fmt.Println("  Error: Failed to decrypt:", err)
			return
		}
		decryptTime := time.Since(start)
		totalDecryptTime += decryptTime

		if subtle.ConstantTimeCompare(sharedSecretAlice, sharedSecretBob) == 1 {
			successCount++
		}

		// Track total run time for a single iteration
		singleRunTime := time.Since(runStart)
		totalRunTime += singleRunTime
	}

	totalTime := time.Since(totalStart)

	fmt.Printf("  Average KeyGen Time: %v\n", totalKeyGenTime/time.Duration(iterations))
	fmt.Printf("  Average Encrypt Time: %v\n", totalEncryptTime/time.Duration(iterations))
	fmt.Printf("  Average Decrypt Time: %v\n", totalDecryptTime/time.Duration(iterations))
	fmt.Printf("  Average Total Time per Run: %v\n", totalRunTime/time.Duration(iterations))
	fmt.Printf("  Total Benchmark Time: %v\n", totalTime)
	fmt.Printf("  Success Rate: %.2f%%\n", float64(successCount)/float64(iterations)*100)
}

func main() {
	iterations := 1000
	BenchmarkKyber(512, iterations)
	BenchmarkKyber(768, iterations)
	BenchmarkKyber(1024, iterations)
}
