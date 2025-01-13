package gokyber

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"

	"golang.org/x/crypto/sha3"
)

// KemKeypair generates a key pair for the Kyber KEM (Key Encapsulation Mechanism) based on the specified variant.
//
// Parameters:
//   - kyberVariant: An integer representing the Kyber variant. It can be one of the following:
//   - 512: For Kyber512 mode
//   - 768: For Kyber768 mode
//   - 1024: For Kyber1024 mode
//
// Returns:
//   - privateKey: A byte slice containing the generated private key.
//   - publicKey: A byte slice containing the generated public key.
//   - error: An error if the key generation fails or if an invalid Kyber variant is provided.
//
// The function initializes the key pair based on the Kyber variant, generates the IND-CPA key pair,
// computes the hash of the public key, and combines these components to form the private key.
func KemKeypair(kyberVariant int) ([]byte, []byte, error) {
	var privateKey, publicKey []byte
	var paramsK int
	var indcpaPrivateKey, indcpaPublicKey []byte

	switch kyberVariant {
	case 512:
		paramsK = 2
		privateKey = make([]byte, Kyber512SKBytes)
		publicKey = make([]byte, Kyber512PKBytes)
	case 768:
		paramsK = 3
		privateKey = make([]byte, Kyber768SKBytes)
		publicKey = make([]byte, Kyber768PKBytes)
	case 1024:
		paramsK = 4
		privateKey = make([]byte, Kyber1024SKBytes)
		publicKey = make([]byte, Kyber1024PKBytes)
	default:
		return nil, nil, errors.New("invalid Kyber variant")
	}

	var err error
	indcpaPrivateKey, indcpaPublicKey, err = IndcpaKeypair(paramsK)
	if err != nil {
		return nil, nil, err
	}

	pkh := sha3.Sum256(indcpaPublicKey)
	rnd := make([]byte, paramsSymBytes)
	if _, err = rand.Read(rnd); err != nil {
		return nil, nil, err
	}

	copy(privateKey, indcpaPrivateKey)
	copy(privateKey[len(indcpaPrivateKey):], indcpaPublicKey)
	copy(privateKey[len(indcpaPrivateKey)+len(indcpaPublicKey):], pkh[:])
	copy(privateKey[len(indcpaPrivateKey)+len(indcpaPublicKey)+len(pkh):], rnd)

	copy(publicKey, indcpaPublicKey)

	return privateKey, publicKey, nil
}

// KemEncrypt encrypts a message using the Kyber KEM (Key Encapsulation Mechanism) algorithm.
// It takes a public key and a Kyber variant as input and returns the ciphertext, shared secret, and an error if any.
//
// Parameters:
//   - publicKey: A byte slice representing the public key used for encryption.
//   - kyberVariant: An integer representing the Kyber variant. It can be one of the following:
//   - 512: Uses Kyber512 parameters.
//   - 768: Uses Kyber768 parameters.
//   - 1024: Uses Kyber1024 parameters.
//
// Returns:
//   - ciphertext: A byte slice containing the encrypted message.
//   - sharedSecret: A byte slice containing the shared secret generated during encryption.
//   - error: An error if the encryption process fails or if an invalid Kyber variant is provided.
//
// The function performs the following steps:
//  1. Initializes parameters based on the Kyber variant.
//  2. Generates a random buffer and computes its hash.
//  3. Computes the hash of the public key.
//  4. Concatenates the hashes and computes a new hash (kr).
//  5. Encrypts the buffer using the public key and the kr hash.
//  6. Computes the hash of the ciphertext and generates the shared secret.
//  7. Returns the ciphertext and shared secret.
func KemEncrypt(publicKey []byte, kyberVariant int) ([]byte, []byte, error) {
	var ciphertext []byte
	var paramsK int

	switch kyberVariant {
	case 512:
		paramsK = 2
		ciphertext = make([]byte, Kyber512CTBytes)
	case 768:
		paramsK = 3
		ciphertext = make([]byte, Kyber768CTBytes)
	case 1024:
		paramsK = 4
		ciphertext = make([]byte, Kyber1024CTBytes)
	default:
		return nil, nil, errors.New("invalid Kyber variant")
	}

	sharedSecret := make([]byte, KyberSSBytes)
	buf := make([]byte, 2*paramsSymBytes)
	if _, err := rand.Read(buf[:paramsSymBytes]); err != nil {
		return nil, nil, err
	}

	buf1 := sha3.Sum256(buf[:paramsSymBytes])
	buf2 := sha3.Sum256(publicKey)
	kr := sha3.Sum512(append(buf1[:], buf2[:]...))

	ct, err := IndcpaEncrypt(buf1[:], publicKey, kr[paramsSymBytes:], paramsK)
	if err != nil {
		return nil, nil, err
	}

	krc := sha3.Sum256(ct)
	sha3.ShakeSum256(sharedSecret, append(kr[:paramsSymBytes], krc[:]...))

	copy(ciphertext, ct)
	return ciphertext, sharedSecret, nil
}

// KemDecrypt decrypts a given ciphertext using the provided private key and Kyber variant.
// It returns the shared secret or an error if decryption fails.
//
// Parameters:
//   - ciphertext: The encrypted data to be decrypted.
//   - privateKey: The private key used for decryption.
//   - kyberVariant: The Kyber variant to use, which can be one of the following:
//   - 512: Uses Kyber512 parameters.
//   - 768: Uses Kyber768 parameters.
//   - 1024: Uses Kyber1024 parameters.
//
// Returns:
//   - []byte: The decrypted shared secret.
//   - error: An error if decryption fails, otherwise nil.
//
// The function performs the following steps:
//  1. Sets parameters based on the Kyber variant.
//  2. Extracts the IND-CPA private key and public key from the provided private key.
//  3. Decrypts the ciphertext using the IND-CPA private key.
//  4. Generates a key recovery value (kr) using SHA3-512.
//  5. Encrypts the decrypted buffer to compare with the original ciphertext.
//  6. Uses constant-time comparison to check for decryption failure.
//  7. Adjusts the key recovery value based on the comparison result.
//  8. Computes the shared secret using SHAKE-256.
func KemDecrypt(ciphertext, privateKey []byte, kyberVariant int) ([]byte, error) {
	var paramsK, paramsIndcpaSecretKeyBytes, paramsIndcpaPublicKeyBytes int
	var err error

	switch kyberVariant {
	case 512:
		paramsK = 2
		paramsIndcpaSecretKeyBytes = paramsIndcpaSecretKeyBytesK512
		paramsIndcpaPublicKeyBytes = paramsIndcpaPublicKeyBytesK512
	case 768:
		paramsK = 3
		paramsIndcpaSecretKeyBytes = paramsIndcpaSecretKeyBytesK768
		paramsIndcpaPublicKeyBytes = paramsIndcpaPublicKeyBytesK768
	case 1024:
		paramsK = 4
		paramsIndcpaSecretKeyBytes = paramsIndcpaSecretKeyBytesK1024
		paramsIndcpaPublicKeyBytes = paramsIndcpaPublicKeyBytesK1024
	default:
		return nil, errors.New("invalid Kyber variant")
	}
	sharedSecret := make([]byte, KyberSSBytes)
	indcpaPrivateKey := privateKey[:paramsIndcpaSecretKeyBytes]
	publicKey := privateKey[paramsIndcpaSecretKeyBytes : paramsIndcpaSecretKeyBytes+paramsIndcpaPublicKeyBytes]

	buf := IndcpaDecrypt(ciphertext, indcpaPrivateKey, paramsK)

	var privateKeyEnd int
	switch kyberVariant {
	case 512:
		privateKeyEnd = Kyber512SKBytes
	case 768:
		privateKeyEnd = Kyber768SKBytes
	case 1024:
		privateKeyEnd = Kyber1024SKBytes
	}

	kr := sha3.Sum512(append(buf, privateKey[privateKeyEnd-2*paramsSymBytes:privateKeyEnd-paramsSymBytes]...))
	cmp, err := IndcpaEncrypt(buf, publicKey, kr[paramsSymBytes:], paramsK)
	if err != nil {
		return nil, err
	}

	fail := byte(subtle.ConstantTimeCompare(ciphertext, cmp) - 1)
	krh := sha3.Sum256(ciphertext)

	for i := 0; i < paramsSymBytes; i++ {
		kr[i] = kr[i] ^ (fail & (kr[i] ^ privateKey[privateKeyEnd-paramsSymBytes+i]))
	}

	sha3.ShakeSum256(sharedSecret, append(kr[:paramsSymBytes], krh[:]...))

	return sharedSecret, nil
}
