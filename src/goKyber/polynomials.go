package gokyber

// Polynomial represents a polynomial with coefficients in /{Z_q}.
type Polynomial [384]int16

// PolynomialVector represents a vector of polynomials.
type PolynomialVector []Polynomial

// CompressPolynomial compresses and serializes a polynomial.
func CompressPolynomial(inputPoly Polynomial, kVariant int) []byte {
	temp := make([]byte, 8)
	inputPoly = PolyConditionalSubQ(inputPoly)
	outputByteIndex := 0
	switch kVariant {
	case 2, 3:
		outputBytes := make([]byte, paramsPolyCompressedBytesK768) // 128
		for i := 0; i < paramsN/8; i++ {
			for j := 0; j < 8; j++ {
				temp[j] = byte((((uint32(inputPoly[8*i+j]) << 4) + paramsQDivBy2Ceil) * params2Pow28DivByQ) >> 28)
			}
			outputBytes[outputByteIndex+0] = temp[0] | (temp[1] << 4)
			outputBytes[outputByteIndex+1] = temp[2] | (temp[3] << 4)
			outputBytes[outputByteIndex+2] = temp[4] | (temp[5] << 4)
			outputBytes[outputByteIndex+3] = temp[6] | (temp[7] << 4)
			outputByteIndex = outputByteIndex + 4
		}
		return outputBytes
	default:
		outputBytes := make([]byte, paramsPolyCompressedBytesK1024) // 160
		for i := 0; i < paramsN/8; i++ {
			for j := 0; j < 8; j++ {
				temp[j] = byte((((uint32(inputPoly[8*i+j]) << 5) + (paramsQDivBy2Ceil - 1)) * params2Pow27DivByQ) >> 27)
			}
			outputBytes[outputByteIndex+0] = (temp[0] >> 0) | (temp[1] << 5)
			outputBytes[outputByteIndex+1] = (temp[1] >> 3) | (temp[2] << 2) | (temp[3] << 7)
			outputBytes[outputByteIndex+2] = (temp[3] >> 1) | (temp[4] << 4)
			outputBytes[outputByteIndex+3] = (temp[4] >> 4) | (temp[5] << 1) | (temp[6] << 6)
			outputBytes[outputByteIndex+4] = (temp[6] >> 2) | (temp[7] << 3)
			outputByteIndex = outputByteIndex + 5
		}
		return outputBytes
	}
}

// DecompressPolynomial decompresses and de-serializes a polynomial.
func DecompressPolynomial(inputBytes []byte, kVariant int) Polynomial {
	var resultPoly Polynomial
	temp := make([]byte, 8)
	inputByteIndex := 0
	switch kVariant {
	case 2, 3:
		for i := 0; i < paramsN/2; i++ {
			resultPoly[2*i+0] = int16(((uint16(inputBytes[inputByteIndex]&15) * uint16(paramsQ)) + 8) >> 4)
			resultPoly[2*i+1] = int16(((uint16(inputBytes[inputByteIndex]>>4) * uint16(paramsQ)) + 8) >> 4)
			inputByteIndex = inputByteIndex + 1
		}
	case 4:
		for i := 0; i < paramsN/8; i++ {
			temp[0] = (inputBytes[inputByteIndex+0] >> 0)
			temp[1] = (inputBytes[inputByteIndex+0] >> 5) | (inputBytes[inputByteIndex+1] << 3)
			temp[2] = (inputBytes[inputByteIndex+1] >> 2)
			temp[3] = (inputBytes[inputByteIndex+1] >> 7) | (inputBytes[inputByteIndex+2] << 1)
			temp[4] = (inputBytes[inputByteIndex+2] >> 4) | (inputBytes[inputByteIndex+3] << 4)
			temp[5] = (inputBytes[inputByteIndex+3] >> 1)
			temp[6] = (inputBytes[inputByteIndex+3] >> 6) | (inputBytes[inputByteIndex+4] << 2)
			temp[7] = (inputBytes[inputByteIndex+4] >> 3)
			inputByteIndex = inputByteIndex + 5
			for j := 0; j < 8; j++ {
				resultPoly[8*i+j] = int16(((uint32(temp[j]&31) * uint32(paramsQ)) + 16) >> 5)
			}
		}
	}
	return resultPoly
}

// SerializePolynomial serializes a polynomial into an array of bytes.
func SerializePolynomial(inputPoly Polynomial) []byte {
	var t0, t1 uint16
	outputBytes := make([]byte, paramsPolyBytes)
	inputPoly = PolyConditionalSubQ(inputPoly)
	for i := 0; i < paramsN/2; i++ {
		t0 = uint16(inputPoly[2*i])
		t1 = uint16(inputPoly[2*i+1])
		outputBytes[3*i+0] = byte(t0 >> 0)
		outputBytes[3*i+1] = byte(t0>>8) | byte(t1<<4)
		outputBytes[3*i+2] = byte(t1 >> 4)
	}
	return outputBytes
}

// DeserializePolynomial de-serializes an array of bytes into a polynomial.
func DeserializePolynomial(inputBytes []byte) Polynomial {
	var resultPoly Polynomial
	for i := 0; i < paramsN/2; i++ {
		resultPoly[2*i] = int16(((uint16(inputBytes[3*i+0]) >> 0) | (uint16(inputBytes[3*i+1]) << 8)) & 0xFFF)
		resultPoly[2*i+1] = int16(((uint16(inputBytes[3*i+1]) >> 4) | (uint16(inputBytes[3*i+2]) << 4)) & 0xFFF)
	}
	return resultPoly
}

// ConvertMsgToPoly converts a 32-byte message to a polynomial.
func ConvertMsgToPoly(msg []byte) Polynomial {
	var resultPoly Polynomial
	var mask int16
	for i := 0; i < paramsN/8; i++ {
		for j := 0; j < 8; j++ {
			mask = -int16((msg[i] >> j) & 1)
			resultPoly[8*i+j] = mask & int16((paramsQ+1)/2)
		}
	}
	return resultPoly
}

// ConvertPolyToMsg converts a polynomial to a 32-byte message.
func ConvertPolyToMsg(inputPoly Polynomial) []byte {
	msg := make([]byte, paramsSymBytes)
	var t uint32
	inputPoly = PolyConditionalSubQ(inputPoly)
	for i := 0; i < paramsN/8; i++ {
		msg[i] = 0
		for j := 0; j < 8; j++ {
			t = (uint32(inputPoly[8*i+j]) << 1) + paramsQDivBy2Ceil
			t = ((t * params2Pow28DivByQ) >> 28) & 1
			msg[i] |= byte(t << j)
		}
	}
	return msg
}

// SamplePolyFromSeed samples a polynomial deterministically from a seed and nonce.
func SamplePolyFromSeed(seed []byte, nonce byte, kVariant int) Polynomial {
	switch kVariant {
	case 2:
		l := paramsETAK512 * paramsN / 4
		p := indcpaPrf(l, seed, nonce)
		return CenteredBinomialFromUniform(p, kVariant)
	default:
		l := paramsETAK768K1024 * paramsN / 4
		p := indcpaPrf(l, seed, nonce)
		return CenteredBinomialFromUniform(p, kVariant)
	}
}

// PolyNTT computes a negacyclic number-theoretic transform (NTT) of a polynomial.
func PolyNTT(inputPoly Polynomial) Polynomial {
	return ForwardNTT(inputPoly)
}

// PolyInvNTTToMont computes the inverse of a negacyclic number-theoretic transform (NTT) of a polynomial.
func PolyInvNTTToMont(inputPoly Polynomial) Polynomial {
	return InverseNTT(inputPoly)
}

// PolyBaseMul performs the multiplication of two polynomials in the NTT domain.
func PolyBaseMul(aPoly Polynomial, bPoly Polynomial) Polynomial {
	for i := 0; i < paramsN/4; i++ {
		aPoly[4*i+0], aPoly[4*i+1] = BaseMul(
			aPoly[4*i+0], aPoly[4*i+1],
			bPoly[4*i+0], bPoly[4*i+1],
			nttTwiddleFactors[64+i],
		)
		aPoly[4*i+2], aPoly[4*i+3] = BaseMul(
			aPoly[4*i+2], aPoly[4*i+3],
			bPoly[4*i+2], bPoly[4*i+3],
			-nttTwiddleFactors[64+i],
		)
	}
	return aPoly
}

// PolyToMont converts all coefficients of a polynomial from normal domain to Montgomery domain.
func PolyToMont(inputPoly Polynomial) Polynomial {
	var f int16 = int16((uint64(1) << 32) % uint64(paramsQ))
	for i := 0; i < paramsN; i++ {
		inputPoly[i] = MontgomeryReduce(int32(inputPoly[i]) * int32(f))
	}
	return inputPoly
}

// PolyReduce applies Barrett reduction to all coefficients of a polynomial.
func PolyReduce(inputPoly Polynomial) Polynomial {
	for i := 0; i < paramsN; i++ {
		inputPoly[i] = BarrettReduce(inputPoly[i])
	}
	return inputPoly
}

// PolyConditionalSubQ applies the conditional subtraction of Q to each coefficient of a polynomial.
func PolyConditionalSubQ(inputPoly Polynomial) Polynomial {
	for i := 0; i < paramsN; i++ {
		inputPoly[i] = ConditionalSubQ(inputPoly[i])
	}
	return inputPoly
}

// PolyAdd adds two polynomials.
func PolyAdd(aPoly Polynomial, bPoly Polynomial) Polynomial {
	for i := 0; i < paramsN; i++ {
		aPoly[i] = aPoly[i] + bPoly[i]
	}
	return aPoly
}

// PolySub subtracts two polynomials.
func PolySub(aPoly Polynomial, bPoly Polynomial) Polynomial {
	for i := 0; i < paramsN; i++ {
		aPoly[i] = aPoly[i] - bPoly[i]
	}
	return aPoly
}

// NewPolyVector instantiates a new vector of polynomials.
func NewPolyVector(kVariant int) PolynomialVector {
	var pv PolynomialVector = make([]Polynomial, kVariant)
	return pv
}

// CompressPolyVector compresses and serializes a vector of polynomials.
func CompressPolyVector(polyVec PolynomialVector, kVariant int) []byte {
	var resultBytes []byte
	PolyVecConditionalSubQ(polyVec, kVariant)
	resultByteIndex := 0
	switch kVariant {
	case 2:
		resultBytes = make([]byte, paramsPolyvecCompressedBytesK512)
	case 3:
		resultBytes = make([]byte, paramsPolyvecCompressedBytesK768)
	case 4:
		resultBytes = make([]byte, paramsPolyvecCompressedBytesK1024)
	}
	switch kVariant {
	case 2, 3:
		temp := make([]uint16, 4)
		for i := 0; i < kVariant; i++ {
			for j := 0; j < paramsN/4; j++ {
				for k := 0; k < 4; k++ {
					temp[k] = uint16(((((uint64(polyVec[i][4*j+k]) << 10) + uint64(paramsQDivBy2Ceil)) * params2Pow32DivByQ) >> 32) & 0x3ff)
				}
				resultBytes[resultByteIndex+0] = byte(temp[0] >> 0)
				resultBytes[resultByteIndex+1] = byte((temp[0] >> 8) | (temp[1] << 2))
				resultBytes[resultByteIndex+2] = byte((temp[1] >> 6) | (temp[2] << 4))
				resultBytes[resultByteIndex+3] = byte((temp[2] >> 4) | (temp[3] << 6))
				resultBytes[resultByteIndex+4] = byte((temp[3] >> 2))
				resultByteIndex = resultByteIndex + 5
			}
		}
		return resultBytes
	default:
		temp := make([]uint16, 8)
		for i := 0; i < kVariant; i++ {
			for j := 0; j < paramsN/8; j++ {
				for k := 0; k < 8; k++ {
					temp[k] = uint16(((((uint64(polyVec[i][8*j+k]) << 11) + uint64(paramsQDivBy2Ceil-1)) * params2Pow31DivByQ) >> 31) & 0x7ff)
				}
				resultBytes[resultByteIndex+0] = byte((temp[0] >> 0))
				resultBytes[resultByteIndex+1] = byte((temp[0] >> 8) | (temp[1] << 3))
				resultBytes[resultByteIndex+2] = byte((temp[1] >> 5) | (temp[2] << 6))
				resultBytes[resultByteIndex+3] = byte((temp[2] >> 2))
				resultBytes[resultByteIndex+4] = byte((temp[2] >> 10) | (temp[3] << 1))
				resultBytes[resultByteIndex+5] = byte((temp[3] >> 7) | (temp[4] << 4))
				resultBytes[resultByteIndex+6] = byte((temp[4] >> 4) | (temp[5] << 7))
				resultBytes[resultByteIndex+7] = byte((temp[5] >> 1))
				resultBytes[resultByteIndex+8] = byte((temp[5] >> 9) | (temp[6] << 2))
				resultBytes[resultByteIndex+9] = byte((temp[6] >> 6) | (temp[7] << 5))
				resultBytes[resultByteIndex+10] = byte((temp[7] >> 3))
				resultByteIndex = resultByteIndex + 11
			}
		}
		return resultBytes
	}
}

// DecompressPolyVector de-serializes and decompresses a vector of polynomials.
func DecompressPolyVector(inputBytes []byte, kVariant int) PolynomialVector {
	resultPolyVec := NewPolyVector(kVariant)
	inputByteIndex := 0
	switch kVariant {
	case 2, 3:
		temp := make([]uint16, 4)
		for i := 0; i < kVariant; i++ {
			for j := 0; j < paramsN/4; j++ {
				temp[0] = (uint16(inputBytes[inputByteIndex+0]) >> 0) | (uint16(inputBytes[inputByteIndex+1]) << 8)
				temp[1] = (uint16(inputBytes[inputByteIndex+1]) >> 2) | (uint16(inputBytes[inputByteIndex+2]) << 6)
				temp[2] = (uint16(inputBytes[inputByteIndex+2]) >> 4) | (uint16(inputBytes[inputByteIndex+3]) << 4)
				temp[3] = (uint16(inputBytes[inputByteIndex+3]) >> 6) | (uint16(inputBytes[inputByteIndex+4]) << 2)
				inputByteIndex = inputByteIndex + 5
				for k := 0; k < 4; k++ {
					resultPolyVec[i][4*j+k] = int16((uint32(temp[k]&0x3FF)*uint32(paramsQ) + 512) >> 10)
				}
			}
		}
	case 4:
		temp := make([]uint16, 8)
		for i := 0; i < kVariant; i++ {
			for j := 0; j < paramsN/8; j++ {
				temp[0] = (uint16(inputBytes[inputByteIndex+0]) >> 0) | (uint16(inputBytes[inputByteIndex+1]) << 8)
				temp[1] = (uint16(inputBytes[inputByteIndex+1]) >> 3) | (uint16(inputBytes[inputByteIndex+2]) << 5)
				temp[2] = (uint16(inputBytes[inputByteIndex+2]) >> 6) | (uint16(inputBytes[inputByteIndex+3]) << 2) | (uint16(inputBytes[inputByteIndex+4]) << 10)
				temp[3] = (uint16(inputBytes[inputByteIndex+4]) >> 1) | (uint16(inputBytes[inputByteIndex+5]) << 7)
				temp[4] = (uint16(inputBytes[inputByteIndex+5]) >> 4) | (uint16(inputBytes[inputByteIndex+6]) << 4)
				temp[5] = (uint16(inputBytes[inputByteIndex+6]) >> 7) | (uint16(inputBytes[inputByteIndex+7]) << 1) | (uint16(inputBytes[inputByteIndex+8]) << 9)
				temp[6] = (uint16(inputBytes[inputByteIndex+8]) >> 2) | (uint16(inputBytes[inputByteIndex+9]) << 6)
				temp[7] = (uint16(inputBytes[inputByteIndex+9]) >> 5) | (uint16(inputBytes[inputByteIndex+10]) << 3)
				inputByteIndex = inputByteIndex + 11
				for k := 0; k < 8; k++ {
					resultPolyVec[i][8*j+k] = int16((uint32(temp[k]&0x7FF)*uint32(paramsQ) + 1024) >> 11)
				}
			}
		}
	}
	return resultPolyVec
}

// SerializePolyVector serializes a vector of polynomials.
func SerializePolyVector(polyVec PolynomialVector, kVariant int) []byte {
	resultBytes := []byte{}
	for i := 0; i < kVariant; i++ {
		resultBytes = append(resultBytes, SerializePolynomial(polyVec[i])...)
	}
	return resultBytes
}

// DeserializePolyVector deserializes a vector of polynomials.
func DeserializePolyVector(inputBytes []byte, kVariant int) PolynomialVector {
	resultPolyVec := NewPolyVector(kVariant)
	for i := 0; i < kVariant; i++ {
		startIndex := (i * paramsPolyBytes)
		endIndex := (i + 1) * paramsPolyBytes
		resultPolyVec[i] = DeserializePolynomial(inputBytes[startIndex:endIndex])
	}
	return resultPolyVec
}

// PolyVecNTT applies forward number-theoretic transforms (NTT) to all elements of a vector of polynomials.
func PolyVecNTT(polyVec PolynomialVector, kVariant int) {
	for i := 0; i < kVariant; i++ {
		polyVec[i] = PolyNTT(polyVec[i])
	}
}

// PolyVecInvNTTToMont applies inverse number-theoretic transforms (NTT) to all elements of a vector of polynomials.
func PolyVecInvNTTToMont(polyVec PolynomialVector, kVariant int) {
	for i := 0; i < kVariant; i++ {
		polyVec[i] = PolyInvNTTToMont(polyVec[i])
	}
}

// PolyVecPointWiseAccMontgomery pointwise multiplies elements of polynomial vectors a and b, accumulates the results.
func PolyVecPointWiseAccMontgomery(aVec PolynomialVector, bVec PolynomialVector, kVariant int) Polynomial {
	resultPoly := PolyBaseMul(aVec[0], bVec[0])
	for i := 1; i < kVariant; i++ {
		tempPoly := PolyBaseMul(aVec[i], bVec[i])
		resultPoly = PolyAdd(resultPoly, tempPoly)
	}
	return PolyReduce(resultPoly)
}

// PolyVecReduce applies Barrett reduction to each coefficient of each element of a vector of polynomials.
func PolyVecReduce(polyVec PolynomialVector, kVariant int) {
	for i := 0; i < kVariant; i++ {
		polyVec[i] = PolyReduce(polyVec[i])
	}
}

// PolyVecConditionalSubQ applies conditional subtraction of Q to each coefficient of each element of a vector of polynomials.
func PolyVecConditionalSubQ(polyVec PolynomialVector, kVariant int) {
	for i := 0; i < kVariant; i++ {
		polyVec[i] = PolyConditionalSubQ(polyVec[i])
	}
}

// PolyVecAdd adds two vectors of polynomials.
func PolyVecAdd(aVec PolynomialVector, bVec PolynomialVector, kVariant int) {
	for i := 0; i < kVariant; i++ {
		aVec[i] = PolyAdd(aVec[i], bVec[i])
	}
}
