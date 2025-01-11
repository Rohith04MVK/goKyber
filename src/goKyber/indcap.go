package gokyber

import (
	"crypto/rand"

	"golang.org/x/crypto/sha3"
)

// SerializePublicKey serializes the public key into a byte array.
// The output is a concatenation of the serialized polynomial vector and the seed.
func SerializePublicKey(publicKeyVector PolynomialVector, seed []byte, kVariant int) []byte {
	return append(SerializePolyVector(publicKeyVector, kVariant), seed...)
}

// DeserializePublicKey deserializes the public key from a byte array.
// It's the inverse of SerializePublicKey.
func DeserializePublicKey(inputBytes []byte, kVariant int) (PolynomialVector, []byte) {
	switch kVariant {
	case 2:
		publicKeyVector := DeserializePolyVector(inputBytes[:paramsPolyvecBytesK512], kVariant)
		seed := inputBytes[paramsPolyvecBytesK512:]
		return publicKeyVector, seed
	case 3:
		publicKeyVector := DeserializePolyVector(inputBytes[:paramsPolyvecBytesK768], kVariant)
		seed := inputBytes[paramsPolyvecBytesK768:]
		return publicKeyVector, seed
	default:
		publicKeyVector := DeserializePolyVector(inputBytes[:paramsPolyvecBytesK1024], kVariant)
		seed := inputBytes[paramsPolyvecBytesK1024:]
		return publicKeyVector, seed
	}
}

// SerializePrivateKey serializes the private key into a byte array.
func SerializePrivateKey(privateKeyVector PolynomialVector, kVariant int) []byte {
	return SerializePolyVector(privateKeyVector, kVariant)
}

// DeserializePrivateKey deserializes the private key from a byte array.
// It's the inverse of SerializePrivateKey.
func DeserializePrivateKey(inputBytes []byte, kVariant int) PolynomialVector {
	return DeserializePolyVector(inputBytes, kVariant)
}

// SerializeCiphertext serializes the ciphertext into a byte array.
// The output is a concatenation of the compressed polynomial vector `b` and the compressed polynomial `v`.
func SerializeCiphertext(bVector PolynomialVector, v Polynomial, kVariant int) []byte {
	return append(CompressPolyVector(bVector, kVariant), CompressPolynomial(v, kVariant)...)
}

// DeserializeCiphertext deserializes and decompresses the ciphertext from a byte array.
// It's the inverse of SerializeCiphertext.
func DeserializeCiphertext(inputBytes []byte, kVariant int) (PolynomialVector, Polynomial) {
	switch kVariant {
	case 2:
		bVector := DecompressPolyVector(inputBytes[:paramsPolyvecCompressedBytesK512], kVariant)
		vPolynomial := DecompressPolynomial(inputBytes[paramsPolyvecCompressedBytesK512:], kVariant)
		return bVector, vPolynomial
	case 3:
		bVector := DecompressPolyVector(inputBytes[:paramsPolyvecCompressedBytesK768], kVariant)
		vPolynomial := DecompressPolynomial(inputBytes[paramsPolyvecCompressedBytesK768:], kVariant)
		return bVector, vPolynomial
	default:
		bVector := DecompressPolyVector(inputBytes[:paramsPolyvecCompressedBytesK1024], kVariant)
		vPolynomial := DecompressPolynomial(inputBytes[paramsPolyvecCompressedBytesK1024:], kVariant)
		return bVector, vPolynomial
	}
}

// RejectionSampleUniform samples uniform random integers modulo `Q` using rejection sampling.
// The output values will be in the range [0, Q-1].
func RejectionSampleUniform(inputBytes []byte, inputLength int, numCoefficients int) (Polynomial, int) {
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

// GenerateMatrix deterministically generates a matrix `A` (or the transpose of `A`) from a seed.
// The matrix entries are polynomials uniformly random in the range [0, Q-1].
func GenerateMatrix(seed []byte, transposed bool, kVariant int) ([]PolynomialVector, error) {
	resultMatrix := make([]PolynomialVector, kVariant)
	buffer := make([]byte, 672)
	xof := sha3.NewShake128()
	ctr := 0
	for i := 0; i < kVariant; i++ {
		resultMatrix[i] = NewPolyVector(kVariant)
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
				return []PolynomialVector{}, err
			}
			_, err = xof.Read(buffer)
			if err != nil {
				return []PolynomialVector{}, err
			}
			// Sample 504 coefficients into resultMatrix[i][j].
			resultMatrix[i][j], ctr = RejectionSampleUniform(buffer[:504], 504, paramsN)
			// Sample remaining coefficients using the last 168 bytes of the buffer.
			for ctr < paramsN {
				var missingCoefficients Polynomial
				var numSampled int
				missingCoefficients, numSampled = RejectionSampleUniform(buffer[504:672], 168, paramsN-ctr)
				for k := ctr; k < paramsN; k++ {
					resultMatrix[i][j][k] = missingCoefficients[k-ctr]
				}
				ctr = ctr + numSampled
			}
		}
	}
	return resultMatrix, nil
}

// PseudoRandomFunction provides a pseudo-random function (PRF) which returns
// a byte array of length `outputLength`, using the provided key and nonce.
func PseudoRandomFunction(outputLength int, key []byte, nonce byte) []byte {
	hash := make([]byte, outputLength)
	sha3.ShakeSum256(hash, append(key, nonce))
	return hash
}

// GenerateKeyPair generates a key pair for the CPA-secure public-key encryption scheme.
func GenerateKeyPair(kVariant int) ([]byte, []byte, error) {
	privateKeyVector := NewPolyVector(kVariant)
	publicKeyVector := NewPolyVector(kVariant)
	errorVector := NewPolyVector(kVariant)
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
	matrixA, err := GenerateMatrix(publicSeed, false, kVariant)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	var nonce byte
	// Sample private key from noise seed.
	for i := 0; i < kVariant; i++ {
		privateKeyVector[i] = SamplePolyFromSeed(noiseSeed, nonce, kVariant)
		nonce = nonce + 1
	}
	// Sample error vector from noise seed.
	for i := 0; i < kVariant; i++ {
		errorVector[i] = SamplePolyFromSeed(noiseSeed, nonce, kVariant)
		nonce = nonce + 1
	}

	// Convert private key and error vector to NTT domain.
	PolyVecNTT(privateKeyVector, kVariant)
	PolyVecReduce(privateKeyVector, kVariant) // Reduce private key modulo q.
	PolyVecNTT(errorVector, kVariant)

	// Calculate public key: A*s + e.
	for i := 0; i < kVariant; i++ {
		publicKeyVector[i] = PolyToMont(PolyVecPointWiseAccMontgomery(matrixA[i], privateKeyVector, kVariant))
	}
	PolyVecAdd(publicKeyVector, errorVector, kVariant)
	PolyVecReduce(publicKeyVector, kVariant) // Reduce public key modulo q.

	return SerializePrivateKey(privateKeyVector, kVariant), SerializePublicKey(publicKeyVector, publicSeed, kVariant), nil
}

// Encrypt encrypts a message using the public key and coins.
func Encrypt(message []byte, publicKey []byte, coins []byte, kVariant int) ([]byte, error) {
	sPrimeVector := NewPolyVector(kVariant)
	ePrimeVector := NewPolyVector(kVariant)
	bPrimeVector := NewPolyVector(kVariant)

	publicKeyVector, seed := DeserializePublicKey(publicKey, kVariant)
	kPolynomial := ConvertMsgToPoly(message)

	// Generate transposed matrix A from seed.
	matrixATransposed, err := GenerateMatrix(seed[:paramsSymBytes], true, kVariant)
	if err != nil {
		return []byte{}, err
	}

	// Sample s' from coins.
	for i := 0; i < kVariant; i++ {
		sPrimeVector[i] = SamplePolyFromSeed(coins, byte(i), kVariant)
		ePrimeVector[i] = SamplePolyFromSeed(coins, byte(i+kVariant), 3)
	}
	// Sample e''.
	ePrimePrimePolynomial := SamplePolyFromSeed(coins, byte(kVariant*2), 3)

	// Convert s' to NTT domain.
	PolyVecNTT(sPrimeVector, kVariant)
	PolyVecReduce(sPrimeVector, kVariant)

	// Calculate b' = A^T * s' + e'.
	for i := 0; i < kVariant; i++ {
		bPrimeVector[i] = PolyVecPointWiseAccMontgomery(matrixATransposed[i], sPrimeVector, kVariant)
	}
	// Calculate v = p^T * s' + e'' + K.
	vPolynomial := PolyVecPointWiseAccMontgomery(publicKeyVector, sPrimeVector, kVariant)

	// Convert b' and v to standard domain.
	PolyVecInvNTTToMont(bPrimeVector, kVariant)
	vPolynomial = PolyInvNTTToMont(vPolynomial)

	// Add error vectors and message to b' and v.
	PolyVecAdd(bPrimeVector, ePrimeVector, kVariant)
	vPolynomial = PolyAdd(PolyAdd(vPolynomial, ePrimePrimePolynomial), kPolynomial)

	PolyVecReduce(bPrimeVector, kVariant)
	return SerializeCiphertext(bPrimeVector, PolyReduce(vPolynomial), kVariant), nil
}

// Decrypt decrypts a ciphertext using the private key.
func Decrypt(ciphertext []byte, privateKey []byte, kVariant int) []byte {
	bPrimeVector, vPolynomial := DeserializeCiphertext(ciphertext, kVariant)
	privateKeyVector := DeserializePrivateKey(privateKey, kVariant)

	// Convert b' to NTT domain.
	PolyVecNTT(bPrimeVector, kVariant)

	// Calculate m' = v - b' * s.
	mPrimePolynomial := PolyVecPointWiseAccMontgomery(privateKeyVector, bPrimeVector, kVariant)
	mPrimePolynomial = PolyInvNTTToMont(mPrimePolynomial)
	mPrimePolynomial = PolySub(vPolynomial, mPrimePolynomial)
	mPrimePolynomial = PolyReduce(mPrimePolynomial)

	return ConvertPolyToMsg(mPrimePolynomial)
}
