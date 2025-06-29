package gokyber

// ByteopsLoad32 converts a slice of 4 bytes into a single uint32 value.
// It takes the first 4 bytes from the input slice and combines them into a uint32.
// The bytes are combined in little-endian order, meaning the first byte is the least significant byte.
//
// Example:
//
//	inputBytes := []byte{0x01, 0x02, 0x03, 0x04}
//	result := ByteopsLoad32(inputBytes) // result will be 0x04030201
func ByteopsLoad32(inputBytes []byte) uint32 {
	var result uint32
	result = uint32(inputBytes[0])
	result = result | (uint32(inputBytes[1]) << 8)
	result = result | (uint32(inputBytes[2]) << 16)
	result = result | (uint32(inputBytes[3]) << 24)
	return result
}

// ByteopsLoad24 loads 3 bytes from the inputBytes slice and combines them into a single uint32 value.
// It takes the first byte as the least significant byte, the second byte shifted left by 8 bits,
// and the third byte shifted left by 16 bits, then combines them using bitwise OR operations.
//
// Example:
//
//	inputBytes := []byte{0x01, 0x02, 0x03}
//	result := ByteopsLoad24(inputBytes) // result will be 0x00030201
//
// Parameters:
//
//	inputBytes - a slice of bytes from which the first 3 bytes will be read and combined.
//
// Returns:
//
//	A uint32 value representing the combined result of the first 3 bytes.
func ByteopsLoad24(inputBytes []byte) uint32 {
	var result uint32
	result = uint32(inputBytes[0])
	result = result | (uint32(inputBytes[1]) << 8)
	result = result | (uint32(inputBytes[2]) << 16)
	return result
}

// ByteopsCbd processes a byte array and generates a polynomial based on the kVariant parameter.
// The function supports two modes determined by kVariant: 2 and other values.
//
// For kVariant = 2:
// - Processes the input bytes in chunks of 3.
// - Loads 24 bits from the input bytes and performs bitwise operations to compute intermediate values.
// - Extracts two 3-bit values (a and b) from the intermediate value and computes their difference.
// - Stores the result in the polynomial.
//
// For other kVariant values:
// - Processes the input bytes in chunks of 4.
// - Loads 32 bits from the input bytes and performs bitwise operations to compute intermediate values.
// - Extracts two 2-bit values (a and b) from the intermediate value and computes their difference.
// - Stores the result in the polynomial.
//
// The function uses bitwise operations and shifts to manipulate the input bytes and compute the polynomial coefficients.
func ByteopsCbd(uniformBytes []byte, kVariant int) Polynomial {
	var t, d uint32
	var a, b int16
	var resultPoly Polynomial
	switch kVariant {
	case 2:
		for i := 0; i < paramsN/4; i++ {
			// $t = x_0 | x_1 << 8 | x_2 << 16$
			t = ByteopsLoad24(uniformBytes[3*i:])
			// $d = t \mod 2^6 + (t \gg 1 \mod 2^6) + (t \gg 2 \mod 2^6)$
			d = t & 0x00249249
			d = d + ((t >> 1) & 0x00249249)
			d = d + ((t >> 2) & 0x00249249)
			for j := 0; j < 4; j++ {
				// $a = d \mod 2^{\eta}$
				a = int16((d >> (6*j + 0)) & 0x7)
				// $b = d \gg \eta \mod 2^{\eta}$
				b = int16((d >> (6*j + paramsETAK512)) & 0x7)
				// $r_{i+j} = a - b$
				resultPoly[4*i+j] = a - b
			}
		}
	default:
		for i := 0; i < paramsN/8; i++ {
			// $t = x_0 | x_1 << 8 | x_2 << 16 | x_3 << 24$
			t = ByteopsLoad32(uniformBytes[4*i:])
			// $d = t \mod 2^4 + (t \gg 1 \mod 2^4)$
			d = t & 0x55555555
			d = d + ((t >> 1) & 0x55555555)
			for j := 0; j < 8; j++ {
				// $a = d \mod 2^{\eta}$
				a = int16((d >> (4*j + 0)) & 0x3)
				// $b = d \gg \eta \mod 2^{\eta}$
				b = int16((d >> (4*j + paramsETAK768K1024)) & 0x3)
				// $r_{i+j} = a - b$
				resultPoly[8*i+j] = a - b
			}
		}
	}
	return resultPoly
}

// ByteopsMontgomeryReduce reduces a 32-bit integer 'a' using Montgomery reduction.
// This function performs the reduction by multiplying 'a' with a constant 'paramsQInv',
// then subtracting the product from 'a' after converting it to a 32-bit integer.
// The result is then right-shifted by 16 bits and returned as a 16-bit integer.
//
// The function avoids direct conversion of the product to int16 due to potential
// issues with sign extension in Go. Instead, it ensures the correct reduction
// by handling the intermediate values properly.
//
// Example:
// If 'a' is 1 and 'paramsQInv' is -12287, the function will correctly compute
// the reduced value without sign extension issues.
func ByteopsMontgomeryReduce(a int32) int16 {
	// Compute u directly without intermediate conversion to int16
	u := a * int32(paramsQInv)

	// Compute t in a single step
	t := a - (u&0xFFFF)*int32(paramsQ)

	// Return the high 16 bits of t
	return int16(t >> 16)
}

// ByteopsBarrettReduce computes a Barrett reduction; given
// a 16-bit integer `a`, returns a 16-bit integer congruent to
// `a mod Q` in {0,...,Q}.
func ByteopsBarrettReduce(a int16) int16 {
	var t int16
	// `v` is a constant value pre-computed in `params.go`.
	var v int16 = int16(((uint32(1) << 26) + uint32(paramsQ/2)) / uint32(paramsQ))
	// $t = (v * a) >> 26$
	t = int16(int32(v) * int32(a) >> 26)
	// $t = t * Q$
	t = t * int16(paramsQ)
	// $r = a - t$
	return a - t
}

// ByteopsCSubQ conditionally subtracts Q from a.
func ByteopsCSubQ(a int16) int16 {
	// $a = a - Q$
	a = a - int16(paramsQ)
	// $a = a + ((a >> 15) & Q)$
	// If `a` is negative, then `a >> 15` is -1 in two's complement, or all 1 bits.
	// If `a` is positive, then `a >> 15` is 0.
	a = a + ((a >> 15) & int16(paramsQ))
	return a
}
