package gokyber

type poly [paramsPolyBytes]int16
type polyvec []poly

// CompressPolynomial compresses a given polynomial based on the specified kVariant.
//
// Parameters:
// - inputPoly: The polynomial to be compressed.
// - kVariant: Determines the compression mode. It can be either 2, 3, or any other value.
//
// Returns:
// - A byte slice containing the compressed polynomial.
//
// Compression Modes:
// - If kVariant is 2 or 3: The polynomial is compressed into 128 bytes.
// - For any other kVariant: The polynomial is compressed into 160 bytes.
//
// The function first conditionally reduces the polynomial and then compresses it
// by iterating over its coefficients and applying bitwise operations to pack them
// into the output byte slice.
func polyCompress(inputPoly poly, kVariant int) []byte {
	temp := make([]byte, 8)
	inputPoly = polyCSubQ(inputPoly)
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

// polyDecompress de-serializes and subsequently decompresses a polynomial,
// representing the approximate inverse of polyCompress.
// Note that compression is lossy, and thus decompression will not match the
// original input.
func polyDecompress(inputBytes []byte, kVariant int) poly {
	var resultPoly poly
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

// SerializePolynomial converts a Polynomial into a byte array representation.
// This function processes the input polynomial by first conditionally reducing
// its coefficients and then serializing them into a byte array. The serialization
// is done by packing two 16-bit coefficients into three bytes.
//
// Parameters:
// - inputPoly: The Polynomial to be serialized.
//
// Returns:
// - A byte array representing the serialized polynomial.
//
// Modes:
//   - The function operates in a mode where it processes pairs of coefficients
//     from the input polynomial, packs them into three bytes, and stores them
//     in the output byte array.
func polyToBytes(inputPoly poly) []byte {
	var t0, t1 uint16
	outputBytes := make([]byte, paramsPolyBytes)
	inputPoly = polyCSubQ(inputPoly)
	for i := 0; i < paramsN/2; i++ {
		t0 = uint16(inputPoly[2*i])
		t1 = uint16(inputPoly[2*i+1])
		outputBytes[3*i+0] = byte(t0 >> 0)
		outputBytes[3*i+1] = byte(t0>>8) | byte(t1<<4)
		outputBytes[3*i+2] = byte(t1 >> 4)
	}
	return outputBytes
}

// DeserializePolynomial converts a byte array into a Polynomial structure.
//
// The function takes an input byte slice and processes it to extract polynomial coefficients.
// Each coefficient is represented using 12 bits, and the function extracts these coefficients
// from the byte array in a specific manner. The coefficients are stored in the resultPoly array.
//
// The function assumes that the input byte slice is of appropriate length to represent
// the polynomial coefficients. The length of the input byte slice should be paramsN/2 * 3.
//
// Modes:
//   - The function operates in a straightforward mode where it processes the input bytes
//     sequentially to extract the polynomial coefficients.
//
// Parameters:
// - inputBytes: A byte slice containing the serialized polynomial data.
//
// Returns:
// - A Polynomial structure with the deserialized coefficients.
func polyFromBytes(inputBytes []byte) poly {
	var resultPoly poly
	for i := 0; i < paramsN/2; i++ {
		resultPoly[2*i] = int16(((uint16(inputBytes[3*i+0]) >> 0) | (uint16(inputBytes[3*i+1]) << 8)) & 0xFFF)
		resultPoly[2*i+1] = int16(((uint16(inputBytes[3*i+1]) >> 4) | (uint16(inputBytes[3*i+2]) << 4)) & 0xFFF)
	}
	return resultPoly
}

// ConvertMsgToPoly converts a given message (byte array) into a polynomial.
// The function iterates over each bit of the message and maps it to a polynomial coefficient.
// If the bit is 1, the corresponding coefficient is set to (paramsQ+1)/2, otherwise it is set to 0.
//
// Parameters:
// - msg: A byte array representing the message to be converted.
//
// Returns:
// - Polynomial: A polynomial representation of the input message.
//
// Modes:
// - The function processes the message in chunks of 8 bits (1 byte) at a time.
// - For each bit in the byte, it calculates a mask and sets the corresponding polynomial coefficient.
func polyFromMsg(msg []byte) poly {
	var resultPoly poly
	var mask int16
	for i := 0; i < paramsN/8; i++ {
		for j := 0; j < 8; j++ {
			mask = -int16((msg[i] >> j) & 1)
			resultPoly[8*i+j] = mask & int16((paramsQ+1)/2)
		}
	}
	return resultPoly
}

// ConvertPolyToMsg converts a polynomial to a message byte array.
//
// This function takes an input polynomial and processes it to produce a byte array
// representation of the message. The polynomial is first conditionally reduced
// using PolyConditionalSubQ. Then, for each group of 8 coefficients, it calculates
// a corresponding byte in the message array.
//
// The function operates in the following modes:
// - Normal Mode: Converts each coefficient of the polynomial to a bit in the message byte.
// - Conditional Subtraction Mode: Ensures the polynomial coefficients are within a certain range before conversion.
//
// Parameters:
// - inputPoly: The polynomial to be converted.
//
// Returns:
// - A byte array representing the message.
func polyToMsg(inputPoly poly) []byte {
	msg := make([]byte, paramsSymBytes)
	var t uint32
	inputPoly = polyCSubQ(inputPoly)
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

// polyGetNoise samples a polynomial deterministically from a seed
// and nonce, with the output polynomial being close to a centered
// binomial distribution.
func polyGetNoise(seed []byte, nonce byte, kVariant int) poly {
	switch kVariant {
	case 2:
		l := paramsETAK512 * paramsN / 4
		p := indcpaPrf(l, seed, nonce)
		return byteopsCbd(p, kVariant)
	default:
		l := paramsETAK768K1024 * paramsN / 4
		p := indcpaPrf(l, seed, nonce)
		return byteopsCbd(p, kVariant)
	}
}

// polyNtt computes a negacyclic number-theoretic transform (NTT) of
// a polynomial in-place; the input is assumed to be in normal order,
// while the output is in bit-reversed order.
func polyNtt(inputPoly poly) poly {
	return ntt(inputPoly)
}

// polyInvNttToMont computes the inverse of a negacyclic number-theoretic
// transform (NTT) of a polynomial in-place; the input is assumed to be in
// bit-reversed order, while the output is in normal order.
func polyInvNttToMont(inputPoly poly) poly {
	return nttInv(inputPoly)
}

// PolyBaseMul performs element-wise multiplication of two polynomials
// in the NTT (Number Theoretic Transform) domain using base multiplication.
//
// Parameters:
// - aPoly: The first input polynomial.
// - bPoly: The second input polynomial.
//
// Returns:
// - A new polynomial resulting from the element-wise multiplication of aPoly and bPoly.
//
// The function iterates over the polynomials in chunks of 4 elements and applies
// the BaseMul function to each pair of elements from aPoly and bPoly. The twiddle
// factors used in the multiplication are taken from the nttTwiddleFactors array.
//
// Modes:
// - The first two elements in each chunk are multiplied using a positive twiddle factor.
// - The last two elements in each chunk are multiplied using a negative twiddle factor.
func polyBaseMulMontgomery(aPoly poly, bPoly poly) poly {
	for i := 0; i < paramsN/4; i++ {
		aPoly[4*i+0], aPoly[4*i+1] = nttBaseMul(
			aPoly[4*i+0], aPoly[4*i+1],
			bPoly[4*i+0], bPoly[4*i+1],
			nttZetas[64+i],
		)
		aPoly[4*i+2], aPoly[4*i+3] = nttBaseMul(
			aPoly[4*i+2], aPoly[4*i+3],
			bPoly[4*i+2], bPoly[4*i+3],
			-nttZetas[64+i],
		)
	}
	return aPoly
}

// polyToMont performs the in-place conversion of all coefficients
// of a polynomial from the normal domain to the Montgomery domain.
func polyToMont(inputPoly poly) poly {
	var f int16 = int16((uint64(1) << 32) % uint64(paramsQ))
	for i := 0; i < paramsN; i++ {
		inputPoly[i] = byteopsMontgomeryReduce(int32(inputPoly[i]) * int32(f))
	}
	return inputPoly
}

// polyReduce applies Barrett reduction to all coefficients of a polynomial.
func polyReduce(inputPoly poly) poly {
	for i := 0; i < paramsN; i++ {
		inputPoly[i] = byteopsBarrettReduce(inputPoly[i])
	}
	return inputPoly
}

// polyCSubQ applies the conditional subtraction of `Q` to each coefficient
// of a polynomial.
func polyCSubQ(inputPoly poly) poly {
	for i := 0; i < paramsN; i++ {
		inputPoly[i] = byteopsCSubQ(inputPoly[i])
	}
	return inputPoly
}

// polyAdd adds two polynomials.
func polyAdd(aPoly poly, bPoly poly) poly {
	for i := 0; i < paramsN; i++ {
		aPoly[i] = aPoly[i] + bPoly[i]
	}
	return aPoly
}

// polySub subtracts two polynomials.
func polySub(aPoly poly, bPoly poly) poly {
	for i := 0; i < paramsN; i++ {
		aPoly[i] = aPoly[i] - bPoly[i]
	}
	return aPoly
}

// polyvecNew instantiates a new vector of polynomials.
func polyvecNew(kVariant int) polyvec {
	var pv polyvec = make([]poly, kVariant)
	return pv
}

// CompressPolyVector compresses a polynomial vector into a byte array based on the given kVariant.
// The function first conditionally reduces the polynomial coefficients and then compresses them
// into a byte array. The compression method varies depending on the kVariant value.
//
// Parameters:
// - polyVec: The polynomial vector to be compressed.
// - kVariant: Determines the compression mode and the size of the resulting byte array.
//   - 2: Uses paramsPolyvecCompressedBytesK512 for the byte array size and compresses in chunks of 4.
//   - 3: Uses paramsPolyvecCompressedBytesK768 for the byte array size and compresses in chunks of 4.
//   - 4: Uses paramsPolyvecCompressedBytesK1024 for the byte array size and compresses in chunks of 8.
//
// Returns:
// - A byte array containing the compressed polynomial vector.
func polyvecCompress(polyVec polyvec, kVariant int) []byte {
	var resultBytes []byte
	polyvecCSubQ(polyVec, kVariant)
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

// DecompressPolyVector decompresses a byte array into a PolynomialVector based on the given kVariant.
//
// Parameters:
// - inputBytes: A byte array containing the compressed polynomial vector data.
// - kVariant: An integer indicating the mode of decompression. It can be 2, 3, or 4.
//
// Returns:
// - A PolynomialVector that has been decompressed from the input byte array.
//
// The function supports three modes of decompression based on the value of kVariant:
// - kVariant 2 or 3: Decompresses the inputBytes into a PolynomialVector with 2 or 3 polynomials respectively.
// - kVariant 4: Decompresses the inputBytes into a PolynomialVector with 4 polynomials.
//
// The decompression process involves reading specific bits from the inputBytes and converting them into polynomial coefficients.
func polyvecDecompress(inputBytes []byte, kVariant int) polyvec {
	resultPolyVec := polyvecNew(kVariant)
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

// SerializePolyVector takes a PolynomialVector and an integer kVariant, and returns a byte slice.
// It serializes each polynomial in the vector up to the kVariant length.
//
// Parameters:
// - polyVec: The PolynomialVector to be serialized.
// - kVariant: The number of polynomials to serialize from the vector.
//
// Returns:
// - A byte slice containing the serialized polynomials.
//
// Modes:
// - kVariant determines how many polynomials from the vector will be serialized.
func polyvecToBytes(polyVec polyvec, kVariant int) []byte {
	resultBytes := []byte{}
	for i := 0; i < kVariant; i++ {
		resultBytes = append(resultBytes, polyToBytes(polyVec[i])...)
	}
	return resultBytes
}

// DeserializePolyVector takes a byte array and an integer kVariant as input,
// and returns a PolynomialVector. The function processes the input byte array
// by dividing it into segments based on the kVariant value. Each segment is
// then deserialized into a Polynomial and stored in the resulting PolynomialVector.
//
// Parameters:
// - inputBytes: A byte array containing the serialized polynomial data.
// - kVariant: An integer representing the number of polynomials to deserialize.
//
// The function operates in different modes based on the value of kVariant:
// - If kVariant is 2, it processes the inputBytes into 2 polynomials.
// - If kVariant is 3, it processes the inputBytes into 3 polynomials.
// - If kVariant is 4, it processes the inputBytes into 4 polynomials.
//
// Returns:
// - A PolynomialVector containing the deserialized polynomials.
func polyvecFromBytes(inputBytes []byte, kVariant int) polyvec {
	resultPolyVec := polyvecNew(kVariant)
	for i := 0; i < kVariant; i++ {
		startIndex := (i * paramsPolyBytes)
		endIndex := (i + 1) * paramsPolyBytes
		resultPolyVec[i] = polyFromBytes(inputBytes[startIndex:endIndex])
	}
	return resultPolyVec
}

// polyvecNtt applies forward number-theoretic transforms (NTT)
// to all elements of a vector of polynomials.
func polyvecNtt(polyVec polyvec, kVariant int) {
	for i := 0; i < kVariant; i++ {
		polyVec[i] = polyNtt(polyVec[i])
	}
}

// polyvecInvNttToMont applies the inverse number-theoretic transform (NTT)
// to all elements of a vector of polynomials and multiplies by Montgomery
// factor `2^16`.
func polyvecInvNttToMont(polyVec polyvec, kVariant int) {
	for i := 0; i < kVariant; i++ {
		polyVec[i] = polyInvNttToMont(polyVec[i])
	}
}

// polyvecPointWiseAccMontgomery pointwise-multiplies elements of polynomial-vectors
// `a` and `b`, accumulates the results into `r`, and then multiplies by `2^-16`.
func polyvecPointWiseAccMontgomery(aVec polyvec, bVec polyvec, kVariant int) poly {
	resultPoly := polyBaseMulMontgomery(aVec[0], bVec[0])
	for i := 1; i < kVariant; i++ {
		tempPoly := polyBaseMulMontgomery(aVec[i], bVec[i])
		resultPoly = polyAdd(resultPoly, tempPoly)
	}
	return polyReduce(resultPoly)
}

// polyvecReduce applies Barrett reduction to each coefficient of each element
// of a vector of polynomials.
func polyvecReduce(polyVec polyvec, kVariant int) {
	for i := 0; i < kVariant; i++ {
		polyVec[i] = polyReduce(polyVec[i])
	}
}

// polyvecCSubQ applies the conditional subtraction of `Q` to each coefficient
// of each element of a vector of polynomials.
func polyvecCSubQ(polyVec polyvec, kVariant int) {
	for i := 0; i < kVariant; i++ {
		polyVec[i] = polyCSubQ(polyVec[i])
	}
}

// polyvecAdd adds two vectors of polynomials.
func polyvecAdd(aVec polyvec, bVec polyvec, kVariant int) {
	for i := 0; i < kVariant; i++ {
		aVec[i] = polyAdd(aVec[i], bVec[i])
	}
}
