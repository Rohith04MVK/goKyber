package gokyber

import (
	"crypto/rand"

	"golang.org/x/crypto/sha3"
)

// IndcpaPackPublicKey serializes the public key as a concatenation of the
// serialized vector of polynomials of the public key, and the public seed
// used to generate the matrix `A`.
func IndcpaPackPublicKey(publicKeyVector PolynomialVector, seed []byte, kVariant int) []byte {
	return append(PolyvecToBytes(publicKeyVector, kVariant), seed...)
}

// IndcpaUnpackPublicKey de-serializes the public key from a byte array
// and represents the approximate inverse of IndcpaPackPublicKey.
func IndcpaUnpackPublicKey(inputBytes []byte, kVariant int) (PolynomialVector, []byte) {
	switch kVariant {
	case 2:
		publicKeyVector := PolyvecFromBytes(inputBytes[:paramsPolyvecBytesK512], kVariant)
		seed := inputBytes[paramsPolyvecBytesK512:]
		return publicKeyVector, seed
	case 3:
		publicKeyVector := PolyvecFromBytes(inputBytes[:paramsPolyvecBytesK768], kVariant)
		seed := inputBytes[paramsPolyvecBytesK768:]
		return publicKeyVector, seed
	default:
		publicKeyVector := PolyvecFromBytes(inputBytes[:paramsPolyvecBytesK1024], kVariant)
		seed := inputBytes[paramsPolyvecBytesK1024:]
		return publicKeyVector, seed
	}
}

// IndcpaPackPrivateKey serializes the private key.
func IndcpaPackPrivateKey(privateKeyVector PolynomialVector, kVariant int) []byte {
	return PolyvecToBytes(privateKeyVector, kVariant)
}

// IndcpaUnpackPrivateKey de-serializes the private key and represents
// the inverse of IndcpaPackPrivateKey.
func IndcpaUnpackPrivateKey(inputBytes []byte, kVariant int) PolynomialVector {
	return PolyvecFromBytes(inputBytes, kVariant)
}

// IndcpaPackCiphertext serializes the ciphertext as a concatenation of
// the compressed and serialized vector of polynomials `b` and the
// compressed and serialized polynomial `v`.
func IndcpaPackCiphertext(bVector PolynomialVector, v Polynomial, kVariant int) []byte {
	return append(PolyvecCompress(bVector, kVariant), PolyCompress(v, kVariant)...)
}

// IndcpaUnpackCiphertext de-serializes and decompresses the ciphertext
// from a byte array, and represents the approximate inverse of
// IndcpaPackCiphertext.
func IndcpaUnpackCiphertext(inputBytes []byte, kVariant int) (PolynomialVector, Polynomial) {
	switch kVariant {
	case 2:
		bVector := PolyvecDecompress(inputBytes[:paramsPolyvecCompressedBytesK512], kVariant)
		vPolynomial := PolyDecompress(inputBytes[paramsPolyvecCompressedBytesK512:], kVariant)
		return bVector, vPolynomial
	case 3:
		bVector := PolyvecDecompress(inputBytes[:paramsPolyvecCompressedBytesK768], kVariant)
		vPolynomial := PolyDecompress(inputBytes[paramsPolyvecCompressedBytesK768:], kVariant)
		return bVector, vPolynomial
	default:
		bVector := PolyvecDecompress(inputBytes[:paramsPolyvecCompressedBytesK1024], kVariant)
		vPolynomial := PolyDecompress(inputBytes[paramsPolyvecCompressedBytesK1024:], kVariant)
		return bVector, vPolynomial
	}
}

// IndcpaRejUniform runs rejection sampling on uniform random bytes
// to generate uniform random integers modulo `Q`.
func IndcpaRejUniform(inputBytes []byte, inputLength int, numCoefficients int) (Polynomial, int) {
	var resultPoly Polynomial
	var d1, d2 uint16
	i := 0
	j := 0
	for i < numCoefficients && j+3 <= inputLength {
		// Combine 3 bytes into 2 12-bit integers.
		d1 = (uint16((inputBytes[j])>>0) | (uint16(inputBytes[j+1]) << 8)) & 0xFFF
		d2 = (uint16((inputBytes[j+1])>>4) | (uint16(inputBytes[j+2]) << 4)) & 0xFFF
		j = j + 3

		// If d1 is in [0, Q-1], set r[i] = d1
		if d1 < uint16(paramsQ) {
			resultPoly[i] = int16(d1)
			i = i + 1
		}
		// If d2 is in [0, Q-1] and r has space, set r[i] = d2
		if i < numCoefficients && d2 < uint16(paramsQ) {
			resultPoly[i] = int16(d2)
			i = i + 1
		}
	}
	return resultPoly, i
}

// IndcpaGenMatrix deterministically generates a matrix `A` (or the transpose of `A`)
// from a seed. Entries of the matrix are polynomials that look uniformly random.
// Performs rejection sampling on the output of an extendable-output function (XOF).
func IndcpaGenMatrix(seed []byte, transposed bool, kVariant int) ([]PolynomialVector, error) {
	resultMatrix := make([]PolynomialVector, kVariant)
	buffer := make([]byte, 672)
	xof := sha3.NewShake128()
	seedWithIndex := make([]byte, len(seed)+2) // Allocate once and reuse

	for i := 0; i < kVariant; i++ {
		resultMatrix[i] = PolyvecNew(kVariant)
		for j := 0; j < kVariant; j++ {
			xof.Reset()
			copy(seedWithIndex, seed) // Reset seed prefix

			if transposed {
				seedWithIndex[len(seed)] = byte(i)
				seedWithIndex[len(seed)+1] = byte(j)
			} else {
				seedWithIndex[len(seed)] = byte(j)
				seedWithIndex[len(seed)+1] = byte(i)
			}

			_, err := xof.Write(seedWithIndex)
			if err != nil {
				return []PolynomialVector{}, err
			}
			_, err = xof.Read(buffer)
			if err != nil {
				return []PolynomialVector{}, err
			}

			ctr := 0
			poly, sampled := IndcpaRejUniform(buffer[:504], 504, paramsN)
			resultMatrix[i][j] = poly
			ctr = sampled

			if ctr < paramsN {
				missingCoefficients, numSampled := IndcpaRejUniform(buffer[504:672], 168, paramsN-ctr)
				for k := 0; k < numSampled; k++ { // Optimized copy loop
					resultMatrix[i][j][ctr+k] = missingCoefficients[k]
				}
				ctr += numSampled
			}
			// No need for the second loop and manual copy if IndcpaRejUniform handles the count correctly
			// Original code's second loop was overly complex and potentially inefficient.
			// Simplified logic based on the assumption that IndcpaRejUniform correctly samples up to the requested count.
			// We've already sampled 'sampled' coefficients in the first call.
			// If more are needed, the second call samples up to the remaining amount.
		}
	}
	return resultMatrix, nil
}

// IndcpaPrf provides a pseudo-random function (PRF) which returns
// a byte array of length `l`, using the provided key and nonce
// to instantiate the PRF's underlying hash function.
func IndcpaPrf(outputLength int, key []byte, nonce byte) []byte {
	hash := make([]byte, outputLength)
	keyNonce := make([]byte, len(key)+1)
	copy(keyNonce, key)
	keyNonce[len(key)] = nonce
	sha3.ShakeSum256(hash, keyNonce)
	return hash
}

// IndcpaKeypair generates a key pair for the IND-CPA secure encryption scheme.
//
// Parameters:
//   - kVariant: An integer representing the variant of the scheme, which determines
//     the size of the key vectors and other parameters.
//
// Returns:
//   - A byte slice representing the private key.
//   - A byte slice representing the public key.
//   - An error if any occurs during key generation.
//
// The function performs the following steps:
//  1. Initializes private key, public key, and error vectors based on the given variant.
//  2. Generates random bytes and splits them into a public seed and a noise seed.
//  3. Uses the public seed to generate a matrix A.
//  4. Samples the private key and error vectors from the noise seed.
//  5. Converts the private key and error vectors to the Number Theoretic Transform (NTT) domain.
//  6. Computes the public key as A*s + e, where s is the private key vector and e is the error vector.
//
// The function involves mathematical operations such as NTT, point-wise multiplication, and modular reduction.
//
// Example usage:
//
//	 privateKey, publicKey, err := IndcpaKeypair(3)
//	 if err != nil {
//		log.Fatal(err)
//	 }
//
//	fmt.Printf("Private Key: %x\n", privateKey)
//	fmt.Printf("Public Key: %x\n", publicKey)
func IndcpaKeypair(kVariant int) ([]byte, []byte, error) {
	privateKeyVector := PolyvecNew(kVariant)
	publicKeyVector := PolyvecNew(kVariant)
	errorVector := PolyvecNew(kVariant)
	randomBytes := make([]byte, 2*paramsSymBytes) // Allocate once

	_, err := rand.Read(randomBytes[:paramsSymBytes])
	if err != nil {
		return []byte{}, []byte{}, err
	}

	hash := sha3.New512()
	_, err = hash.Write(randomBytes[:paramsSymBytes])
	if err != nil {
		return []byte{}, []byte{}, err
	}

	// Reuse randomBytes buffer for hash sum
	randomBytes = randomBytes[:0] // Reset the slice length to reuse the buffer
	randomBytes = hash.Sum(randomBytes)

	publicSeed := make([]byte, paramsSymBytes)
	noiseSeed := make([]byte, paramsSymBytes)
	copy(publicSeed, randomBytes[:paramsSymBytes])
	copy(noiseSeed, randomBytes[paramsSymBytes:])

	// Generate matrix A from public seed.
	matrixA, err := IndcpaGenMatrix(publicSeed, false, kVariant)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	var nonce byte
	// Sample private key and error vector from noise seed in combined loop.
	for i := 0; i < kVariant; i++ {
		privateKeyVector[i] = PolyGetNoise(noiseSeed, nonce, kVariant)
		nonce++ // Increment nonce after private key
		errorVector[i] = PolyGetNoise(noiseSeed, nonce, kVariant)
		nonce++ // Increment nonce after error vector
	}

	// Convert private key and error vector to NTT domain.
	PolyvecNtt(privateKeyVector, kVariant)
	PolyvecReduce(privateKeyVector, kVariant) // Reduce private key modulo q.
	PolyvecNtt(errorVector, kVariant)

	// Calculate public key: A*s + e.
	for i := 0; i < kVariant; i++ {
		publicKeyVector[i] = PolyToMont(PolyvecPointWiseAccMontgomery(matrixA[i], privateKeyVector, kVariant))
	}
	PolyvecAdd(publicKeyVector, errorVector, kVariant)
	PolyvecReduce(publicKeyVector, kVariant) // Reduce public key modulo q.

	return IndcpaPackPrivateKey(privateKeyVector, kVariant), IndcpaPackPublicKey(publicKeyVector, publicSeed, kVariant), nil
}

// IndcpaEncrypt encrypts a given message using the provided public key and coins.
// The encryption process involves several steps including generating noise vectors,
// converting polynomials to the Number Theoretic Transform (NTT) domain, and performing
// polynomial arithmetic.
//
// Parameters:
//   - message: The plaintext message to be encrypted.
//   - publicKey: The public key used for encryption.
//   - coins: Random bytes used for generating noise vectors.
//   - kVariant: A parameter that determines the variant of the algorithm to use.
//
// The function performs the following steps:
//  1. Unpacks the public key to obtain the public key vector and seed.
//  2. Generates a transposed matrix A from the seed.
//  3. Samples noise vectors s' and e' from the coins.
//  4. Samples an additional noise polynomial e”.
//  5. Converts the noise vector s' to the NTT domain.
//  6. Calculates the vector b' as A^T * s' + e'.
//  7. Calculates the polynomial v as p^T * s' + e” + K, where K is the polynomial
//     representation of the message.
//  8. Converts b' and v back to the standard domain.
//  9. Adds the error vectors and message to b' and v.
//  10. Packs the ciphertext and returns it.
//
// Returns:
// - A byte slice containing the ciphertext.
// - An error if any step in the encryption process fails.
func IndcpaEncrypt(message []byte, publicKey []byte, coins []byte, kVariant int) ([]byte, error) {
	sPrimeVector := PolyvecNew(kVariant)
	ePrimeVector := PolyvecNew(kVariant)
	bPrimeVector := PolyvecNew(kVariant)

	publicKeyVector, seed := IndcpaUnpackPublicKey(publicKey, kVariant)
	kPolynomial := PolyFromMsg(message)

	// Generate transposed matrix A from seed.
	matrixATransposed, err := IndcpaGenMatrix(seed[:paramsSymBytes], true, kVariant)
	if err != nil {
		return []byte{}, err
	}

	// Sample s' and e' from coins in a combined loop.
	for i := 0; i < kVariant; i++ {
		sPrimeVector[i] = PolyGetNoise(coins, byte(i), kVariant)
		ePrimeVector[i] = PolyGetNoise(coins, byte(i+kVariant), 3)
	}

	// Sample e''.
	ePrimePrimePolynomial := PolyGetNoise(coins, byte(kVariant*2), 3)

	// Convert s' to NTT domain.
	PolyvecNtt(sPrimeVector, kVariant)
	PolyvecReduce(sPrimeVector, kVariant)

	// Calculate b' = A^T * s' + e'.
	for i := 0; i < kVariant; i++ {
		bPrimeVector[i] = PolyvecPointWiseAccMontgomery(matrixATransposed[i], sPrimeVector, kVariant)
	}
	// Calculate v = p^T * s' + e'' + K.
	vPolynomial := PolyvecPointWiseAccMontgomery(publicKeyVector, sPrimeVector, kVariant)

	// Convert b' and v to standard domain.
	PolyvecInvNttToMont(bPrimeVector, kVariant)
	vPolynomial = PolyInvNttToMont(vPolynomial)

	// Add error vectors and message to b' and v.
	PolyvecAdd(bPrimeVector, ePrimeVector, kVariant)
	vPolynomial = PolyAdd(PolyAdd(vPolynomial, ePrimePrimePolynomial), kPolynomial)

	PolyvecReduce(bPrimeVector, kVariant)
	return IndcpaPackCiphertext(bPrimeVector, PolyReduce(vPolynomial), kVariant), nil
}

// IndcpaDecrypt decrypts the given ciphertext using the provided private key and Kyber variant.
//
// Parameters:
//   - ciphertext: The encrypted data to be decrypted.
//   - privateKey: The private key used for decryption.
//   - kVariant: The Kyber variant (e.g., 2, 3, or 4) which determines the security level and parameters.
//
// The function performs the following steps:
//  1. Unpacks the ciphertext into a vector and polynomial.
//  2. Unpacks the private key into a vector.
//  3. Converts the vector to the Number Theoretic Transform (NTT) domain.
//  4. Computes the polynomial m' by performing point-wise multiplication and subtraction operations.
//  5. Converts the polynomial back from the NTT domain and reduces it.
//  6. Converts the resulting polynomial to the original message.
//
// Example usage:
//
//	decryptedMessage := IndcpaDecrypt(ciphertext, privateKey, 3)
func IndcpaDecrypt(ciphertext []byte, privateKey []byte, kVariant int) []byte {
	bPrimeVector, vPolynomial := IndcpaUnpackCiphertext(ciphertext, kVariant)
	privateKeyVector := IndcpaUnpackPrivateKey(privateKey, kVariant)

	// Convert b' to NTT domain.
	PolyvecNtt(bPrimeVector, kVariant)

	// Calculate m' = v - b' * s.
	mPrimePolynomial := PolyvecPointWiseAccMontgomery(privateKeyVector, bPrimeVector, kVariant)
	mPrimePolynomial = PolyInvNttToMont(mPrimePolynomial)
	mPrimePolynomial = PolySub(vPolynomial, mPrimePolynomial)
	mPrimePolynomial = PolyReduce(mPrimePolynomial)

	return PolyToMsg(mPrimePolynomial)
}
