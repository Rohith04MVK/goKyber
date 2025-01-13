package gokyber

import (
	"crypto/rand"

	"golang.org/x/crypto/sha3"
)

// indcpaPackPublicKey serializes the public key as a concatenation of the
// serialized vector of polynomials of the public key, and the public seed
// used to generate the matrix `A`.
func indcpaPackPublicKey(publicKeyVector polyvec, seed []byte, kVariant int) []byte {
	return append(polyvecToBytes(publicKeyVector, kVariant), seed...)
}

// indcpaUnpackPublicKey de-serializes the public key from a byte array
// and represents the approximate inverse of indcpaPackPublicKey.
func indcpaUnpackPublicKey(inputBytes []byte, kVariant int) (polyvec, []byte) {
	switch kVariant {
	case 2:
		publicKeyVector := polyvecFromBytes(inputBytes[:paramsPolyvecBytesK512], kVariant)
		seed := inputBytes[paramsPolyvecBytesK512:]
		return publicKeyVector, seed
	case 3:
		publicKeyVector := polyvecFromBytes(inputBytes[:paramsPolyvecBytesK768], kVariant)
		seed := inputBytes[paramsPolyvecBytesK768:]
		return publicKeyVector, seed
	default:
		publicKeyVector := polyvecFromBytes(inputBytes[:paramsPolyvecBytesK1024], kVariant)
		seed := inputBytes[paramsPolyvecBytesK1024:]
		return publicKeyVector, seed
	}
}

// indcpaPackPrivateKey serializes the private key.
func indcpaPackPrivateKey(privateKeyVector polyvec, kVariant int) []byte {
	return polyvecToBytes(privateKeyVector, kVariant)
}

// indcpaUnpackPrivateKey de-serializes the private key and represents
// the inverse of indcpaPackPrivateKey.
func indcpaUnpackPrivateKey(inputBytes []byte, kVariant int) polyvec {
	return polyvecFromBytes(inputBytes, kVariant)
}

// indcpaPackCiphertext serializes the ciphertext as a concatenation of
// the compressed and serialized vector of polynomials `b` and the
// compressed and serialized polynomial `v`.
func indcpaPackCiphertext(bVector polyvec, v poly, kVariant int) []byte {
	return append(polyvecCompress(bVector, kVariant), polyCompress(v, kVariant)...)
}

// indcpaUnpackCiphertext de-serializes and decompresses the ciphertext
// from a byte array, and represents the approximate inverse of
// indcpaPackCiphertext.
func indcpaUnpackCiphertext(inputBytes []byte, kVariant int) (polyvec, poly) {
	switch kVariant {
	case 2:
		bVector := polyvecDecompress(inputBytes[:paramsPolyvecCompressedBytesK512], kVariant)
		vPolynomial := polyDecompress(inputBytes[paramsPolyvecCompressedBytesK512:], kVariant)
		return bVector, vPolynomial
	case 3:
		bVector := polyvecDecompress(inputBytes[:paramsPolyvecCompressedBytesK768], kVariant)
		vPolynomial := polyDecompress(inputBytes[paramsPolyvecCompressedBytesK768:], kVariant)
		return bVector, vPolynomial
	default:
		bVector := polyvecDecompress(inputBytes[:paramsPolyvecCompressedBytesK1024], kVariant)
		vPolynomial := polyDecompress(inputBytes[paramsPolyvecCompressedBytesK1024:], kVariant)
		return bVector, vPolynomial
	}
}

// indcpaRejUniform runs rejection sampling on uniform random bytes
// to generate uniform random integers modulo `Q`.
func indcpaRejUniform(inputBytes []byte, inputLength int, numCoefficients int) (poly, int) {
	var resultPoly poly
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

// indcpaGenMatrix deterministically generates a matrix `A` (or the transpose of `A`)
// from a seed. Entries of the matrix are polynomials that look uniformly random.
// Performs rejection sampling on the output of an extendable-output function (XOF).
func indcpaGenMatrix(seed []byte, transposed bool, kVariant int) ([]polyvec, error) {
	resultMatrix := make([]polyvec, kVariant)
	buffer := make([]byte, 672)
	xof := sha3.NewShake128()
	ctr := 0
	for i := 0; i < kVariant; i++ {
		resultMatrix[i] = polyvecNew(kVariant)
		for j := 0; j < kVariant; j++ {
			xof.Reset()
			var err error
			if transposed {
				// Use seed concatenated with i and j for transposed A.
				_, err = xof.Write(append(seed, byte(i), byte(j)))
			} else {
				// Use seed concatenated with j and i for A.
				_, err = xof.Write(append(seed, byte(j), byte(i)))
			}
			if err != nil {
				return []polyvec{}, err
			}
			_, err = xof.Read(buffer)
			if err != nil {
				return []polyvec{}, err
			}
			// Sample 504 coefficients into resultMatrix[i][j].
			resultMatrix[i][j], ctr = indcpaRejUniform(buffer[:504], 504, paramsN)
			// Sample remaining coefficients using the last 168 bytes of the buffer.
			for ctr < paramsN {
				var missingCoefficients poly
				var numSampled int
				missingCoefficients, numSampled = indcpaRejUniform(buffer[504:672], 168, paramsN-ctr)
				for k := ctr; k < paramsN; k++ {
					resultMatrix[i][j][k] = missingCoefficients[k-ctr]
				}
				ctr = ctr + numSampled
			}
		}
	}
	return resultMatrix, nil
}

// indcpaPrf provides a pseudo-random function (PRF) which returns
// a byte array of length `l`, using the provided key and nonce
// to instantiate the PRF's underlying hash function.
func indcpaPrf(outputLength int, key []byte, nonce byte) []byte {
	hash := make([]byte, outputLength)
	sha3.ShakeSum256(hash, append(key, nonce))
	return hash
}

// indcpaKeypair generates a key pair for the IND-CPA secure encryption scheme.
//
// Parameters:
//   - kVariant: An integer representing the variant of the scheme, which determines
//     the size of the key vectors and other parameters.
//
// Returns:
// - A byte slice representing the private key.
// - A byte slice representing the public key.
// - An error if any occurs during key generation.
//
// The function performs the following steps:
// 1. Initializes private key, public key, and error vectors based on the given variant.
// 2. Generates random bytes and splits them into a public seed and a noise seed.
// 3. Uses the public seed to generate a matrix A.
// 4. Samples the private key and error vectors from the noise seed.
// 5. Converts the private key and error vectors to the Number Theoretic Transform (NTT) domain.
// 6. Computes the public key as A*s + e, where s is the private key vector and e is the error vector.
//
// The function involves mathematical operations such as NTT, point-wise multiplication, and modular reduction.
//
// Example usage:
//
//	 privateKey, publicKey, err := indcpaKeypair(3)
//	 if err != nil {
//		log.Fatal(err)
//	 }
//
// fmt.Printf("Private Key: %x\n", privateKey)
// fmt.Printf("Public Key: %x\n", publicKey)
func indcpaKeypair(kVariant int) ([]byte, []byte, error) {
	privateKeyVector := polyvecNew(kVariant)
	publicKeyVector := polyvecNew(kVariant)
	errorVector := polyvecNew(kVariant)
	randomBytes := make([]byte, 2*paramsSymBytes)
	hash := sha3.New512()

	_, err := rand.Read(randomBytes[:paramsSymBytes])
	if err != nil {
		return []byte{}, []byte{}, err
	}

	// Split hash of random bytes into public seed and noise seed.
	_, err = hash.Write(randomBytes[:paramsSymBytes])
	if err != nil {
		return []byte{}, []byte{}, err
	}
	randomBytes = randomBytes[:0]
	randomBytes = hash.Sum(randomBytes)
	publicSeed := make([]byte, paramsSymBytes)
	noiseSeed := make([]byte, paramsSymBytes)
	copy(publicSeed, randomBytes[:paramsSymBytes])
	copy(noiseSeed, randomBytes[paramsSymBytes:])

	// Generate matrix A from public seed.
	matrixA, err := indcpaGenMatrix(publicSeed, false, kVariant)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	var nonce byte
	// Sample private key from noise seed.
	for i := 0; i < kVariant; i++ {
		privateKeyVector[i] = polyGetNoise(noiseSeed, nonce, kVariant)
		nonce = nonce + 1
	}
	// Sample error vector from noise seed.
	for i := 0; i < kVariant; i++ {
		errorVector[i] = polyGetNoise(noiseSeed, nonce, kVariant)
		nonce = nonce + 1
	}

	// Convert private key and error vector to NTT domain.
	polyvecNtt(privateKeyVector, kVariant)
	polyvecReduce(privateKeyVector, kVariant) // Reduce private key modulo q.
	polyvecNtt(errorVector, kVariant)

	// Calculate public key: A*s + e.
	for i := 0; i < kVariant; i++ {
		publicKeyVector[i] = polyToMont(polyvecPointWiseAccMontgomery(matrixA[i], privateKeyVector, kVariant))
	}
	polyvecAdd(publicKeyVector, errorVector, kVariant)
	polyvecReduce(publicKeyVector, kVariant) // Reduce public key modulo q.

	return indcpaPackPrivateKey(privateKeyVector, kVariant), indcpaPackPublicKey(publicKeyVector, publicSeed, kVariant), nil
}

// indcpaEncrypt encrypts a given message using the provided public key and coins.
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
func indcpaEncrypt(message []byte, publicKey []byte, coins []byte, kVariant int) ([]byte, error) {
	sPrimeVector := polyvecNew(kVariant)
	ePrimeVector := polyvecNew(kVariant)
	bPrimeVector := polyvecNew(kVariant)

	publicKeyVector, seed := indcpaUnpackPublicKey(publicKey, kVariant)
	kPolynomial := polyFromMsg(message)

	// Generate transposed matrix A from seed.
	matrixATransposed, err := indcpaGenMatrix(seed[:paramsSymBytes], true, kVariant)
	if err != nil {
		return []byte{}, err
	}

	// Sample s' from coins.
	for i := 0; i < kVariant; i++ {
		sPrimeVector[i] = polyGetNoise(coins, byte(i), kVariant)
		ePrimeVector[i] = polyGetNoise(coins, byte(i+kVariant), 3)
	}
	// Sample e''.
	ePrimePrimePolynomial := polyGetNoise(coins, byte(kVariant*2), 3)

	// Convert s' to NTT domain.
	polyvecNtt(sPrimeVector, kVariant)
	polyvecReduce(sPrimeVector, kVariant)

	// Calculate b' = A^T * s' + e'.
	for i := 0; i < kVariant; i++ {
		bPrimeVector[i] = polyvecPointWiseAccMontgomery(matrixATransposed[i], sPrimeVector, kVariant)
	}
	// Calculate v = p^T * s' + e'' + K.
	vPolynomial := polyvecPointWiseAccMontgomery(publicKeyVector, sPrimeVector, kVariant)

	// Convert b' and v to standard domain.
	polyvecInvNttToMont(bPrimeVector, kVariant)
	vPolynomial = polyInvNttToMont(vPolynomial)

	// Add error vectors and message to b' and v.
	polyvecAdd(bPrimeVector, ePrimeVector, kVariant)
	vPolynomial = polyAdd(polyAdd(vPolynomial, ePrimePrimePolynomial), kPolynomial)

	polyvecReduce(bPrimeVector, kVariant)
	return indcpaPackCiphertext(bPrimeVector, polyReduce(vPolynomial), kVariant), nil
}

// indcpaDecrypt decrypts the given ciphertext using the provided private key and Kyber variant.
//
// Parameters:
//   - ciphertext: The encrypted data to be decrypted.
//   - privateKey: The private key used for decryption.
//   - kVariant: The Kyber variant (e.g., 2, 3, or 4) which determines the security level and parameters.
//
// The function performs the following steps:
// 1. Unpacks the ciphertext into a vector and polynomial.
// 2. Unpacks the private key into a vector.
// 3. Converts the vector to the Number Theoretic Transform (NTT) domain.
// 4. Computes the polynomial m' by performing point-wise multiplication and subtraction operations.
// 5. Converts the polynomial back from the NTT domain and reduces it.
// 6. Converts the resulting polynomial to the original message.
//
// Example usage:
//
//	decryptedMessage := indcpaDecrypt(ciphertext, privateKey, 3)
func indcpaDecrypt(ciphertext []byte, privateKey []byte, kVariant int) []byte {
	bPrimeVector, vPolynomial := indcpaUnpackCiphertext(ciphertext, kVariant)
	privateKeyVector := indcpaUnpackPrivateKey(privateKey, kVariant)

	// Convert b' to NTT domain.
	polyvecNtt(bPrimeVector, kVariant)

	// Calculate m' = v - b' * s.
	mPrimePolynomial := polyvecPointWiseAccMontgomery(privateKeyVector, bPrimeVector, kVariant)
	mPrimePolynomial = polyInvNttToMont(mPrimePolynomial)
	mPrimePolynomial = polySub(vPolynomial, mPrimePolynomial)
	mPrimePolynomial = polyReduce(mPrimePolynomial)

	return polyToMsg(mPrimePolynomial)
}
