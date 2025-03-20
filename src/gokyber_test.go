package main

import (
	"crypto/subtle"
	"testing"

	gokyber "github.com/Rohith04MVK/goKyber/goKyber"
)

func benchmarkKyber(b *testing.B, securityLevel int) {
	for i := 0; i < b.N; i++ {
		privateKey, publicKey, err := gokyber.KemKeypair(securityLevel)
		if err != nil {
			b.Fatalf("Failed to generate key pair: %v", err)
		}

		ciphertext, sharedSecretBob, err := gokyber.KemEncrypt(publicKey, securityLevel)
		if err != nil {
			b.Fatalf("Failed to encrypt: %v", err)
		}

		sharedSecretAlice, err := gokyber.KemDecrypt(ciphertext, privateKey, securityLevel)
		if err != nil {
			b.Fatalf("Failed to decrypt: %v", err)
		}

		if subtle.ConstantTimeCompare(sharedSecretAlice, sharedSecretBob) != 1 {
			b.Fatalf("Shared secrets do not match")
		}
	}
}

func BenchmarkKyber512(b *testing.B)  { benchmarkKyber(b, 512) }
func BenchmarkKyber768(b *testing.B)  { benchmarkKyber(b, 768) }
func BenchmarkKyber1024(b *testing.B) { benchmarkKyber(b, 1024) }
