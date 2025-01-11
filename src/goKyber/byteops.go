package gokyber

// LoadLittleEndian32 loads a 32-bit unsigned integer from a byte slice in little-endian order.
func LoadLittleEndian32(inputBytes []byte) uint32 {
	var result uint32
	result = uint32(inputBytes[0])
	result = result | (uint32(inputBytes[1]) << 8)
	result = result | (uint32(inputBytes[2]) << 16)
	result = result | (uint32(inputBytes[3]) << 24)
	return result
}

// LoadLittleEndian24 loads a 24-bit unsigned integer from a byte slice in little-endian order.
func LoadLittleEndian24(inputBytes []byte) uint32 {
	var result uint32
	result = uint32(inputBytes[0])
	result = result | (uint32(inputBytes[1]) << 8)
	result = result | (uint32(inputBytes[2]) << 16)
	return result
}

// CenteredBinomialFromUniform computes a polynomial with coefficients distributed
// according to a centered binomial distribution with parameter $\eta$,
// given an array of uniformly random bytes.
func CenteredBinomialFromUniform(uniformBytes []byte, kVariant int) Polynomial {
	var t, d uint32
	var a, b int16
	var resultPoly Polynomial
	switch kVariant {
	case 2:
		for i := 0; i < paramsN/4; i++ {
			// $t = x_0 | x_1 << 8 | x_2 << 16$
			t = LoadLittleEndian24(uniformBytes[3*i:])
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
			t = LoadLittleEndian32(uniformBytes[4*i:])
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

// MontgomeryReduce computes a Montgomery reduction; given a 32-bit integer `a`,
// returns `a * R^-1 mod Q` where `R=2^16`.
func MontgomeryReduce(a int32) int16 {
	// The original expression is:
	// `u := int16(a * paramsQInv)`
	// `t := a - int32(u) * int32(paramsQ)`
	// `return int16(t >> 16)`
	//
	// However, because `paramsQInv` is negative, Go won't convert it to
	// int16 correctly. The expression `a * paramsQInv` is sign-extended
	// to 64 bits, then truncated to 32 bits, and only then truncated to 16
	// bits.
	//
	// e.g. if `a == 1`, then `a * paramsQInv == -12287`. Go sign-extends it to
	// 0xFFFFFFFFFFFFC801. Then it's truncated to 0xFFFFFFFFFFFFC801, and
	// then truncated to 0xC801. If it was just truncated to 16 bits,
	// then we would get 0xC801, or -14335 in decimal.
	//
	// The fix is to not convert `a * paramsQInv` to int16.
	return int16((a - int32(int16(a*int32(paramsQInv)))*int32(paramsQ)) >> 16)
}

// BarrettReduce computes a Barrett reduction; given a 16-bit integer `a`,
// returns a 16-bit integer congruent to `a mod Q` in {0,...,Q}.
func BarrettReduce(a int16) int16 {
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

// ConditionalSubQ conditionally subtracts Q from a.
// Returns r such that r = a - Q if a >= Q, and r = a otherwise.
func ConditionalSubQ(a int16) int16 {
	// $a = a - Q$
	a = a - int16(paramsQ)
	// $a = a + ((a >> 15) & Q)$
	// If `a` is negative, then `a >> 15` is -1 in two's complement, or all 1 bits.
	// If `a` is positive, then `a >> 15` is 0.
	a = a + ((a >> 15) & int16(paramsQ))
	return a
}
