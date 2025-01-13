package gokyber

var nttZetas [128]int16 = [128]int16{
	2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,
	2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,
	732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,
	1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,
	107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,
	430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,
	1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
	418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
	1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459,
	478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628,
}

var nttZetasInv [128]int16 = [128]int16{
	1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535,
	1278, 1530, 1185, 1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465,
	1285, 2007, 2719, 2726, 2232, 2512, 75, 156, 3000, 2911, 2980, 872, 2685,
	1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676, 1755, 460, 291, 235,
	3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275, 2652,
	1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853,
	1860, 3203, 1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552,
	2677, 2106, 1571, 205, 2918, 1542, 2721, 2597, 2312, 681, 130, 1602, 1871,
	829, 2946, 3065, 1325, 2756, 1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
	3127, 3042, 1907, 1836, 1517, 359, 758, 1441,
}

// nttFqMul performs multiplication followed by Montgomery reduction
// and returns a 16-bit integer congruent to `a*b*R^{-1} mod Q`.
func nttFqMul(a int16, b int16) int16 {
	return byteopsMontgomeryReduce(int32(a) * int32(b))
}

// ntt performs the Number Theoretic Transform (NTT) on a polynomial.
//
// The NTT is a specialized version of the Fast Fourier Transform (FFT)
// that operates in a finite field, making it suitable for cryptographic
// applications. This function transforms the input polynomial `r` into
// its NTT representation.
//
// The function iterates through different stages of the transformation,
// progressively combining elements of the polynomial using modular
// arithmetic and precomputed roots of unity (stored in `nttZetas`).
//
// Modes:
//   - Forward NTT: Converts the polynomial from its coefficient form to
//     its NTT form.
//   - Inverse NTT: Converts the polynomial from its NTT form back to its
//     coefficient form (not implemented in this function).
//
// Parameters:
// - r: The input polynomial to be transformed.
//
// Returns:
// - The transformed polynomial in its NTT representation.
func ntt(r poly) poly {
	j := 0
	k := 1
	for l := 128; l >= 2; l >>= 1 {
		for start := 0; start < 256; start = j + l {
			zeta := nttZetas[k]
			k = k + 1
			for j = start; j < start+l; j++ {
				t := nttFqMul(zeta, r[j+l])
				r[j+l] = r[j] - t
				r[j] = r[j] + t
			}
		}
	}
	return r
}

// nttInv performs the inverse Number Theoretic Transform (NTT) on a polynomial.
// This function is used to convert data from the frequency domain back to the time domain.
// The input is in bit-reversed order, the output is in standard order.
//
// The function operates in two main modes:
//  1. Iterative Mode: It iterates over the polynomial in stages, reducing the size of the problem
//     by half in each stage until the entire polynomial is transformed.
//  2. Final Multiplication Mode: After the iterative stages, each element of the polynomial is
//     multiplied by a specific constant to complete the inverse transformation.
//
// Parameters:
// - r: The input polynomial to be transformed.
//
// Returns:
// - The transformed polynomial in the time domain.
func nttInv(r poly) poly {
	j := 0
	k := 0
	for l := 2; l <= 128; l <<= 1 {
		for start := 0; start < 256; start = j + l {
			zeta := nttZetasInv[k]
			k = k + 1
			for j = start; j < start+l; j++ {
				t := r[j]
				r[j] = byteopsBarrettReduce(t + r[j+l])
				r[j+l] = t - r[j+l]
				r[j+l] = nttFqMul(zeta, r[j+l])
			}
		}
	}
	for j := 0; j < 256; j++ {
		r[j] = nttFqMul(r[j], nttZetasInv[127])
	}
	return r
}

// nttBaseMul performs a base multiplication operation used in the Number Theoretic Transform (NTT).
// It takes two pairs of int16 values (a0, a1) and (b0, b1), and a zeta value.
// The function returns a pair of int16 values resulting from the NTT base multiplication.
// The operation involves modular arithmetic and multiplication of the inputs with the zeta value.
func nttBaseMul(
	a0 int16, a1 int16,
	b0 int16, b1 int16,
	zeta int16,
) (int16, int16) {
	return nttFqMul(nttFqMul(a1, b1), zeta) + nttFqMul(a0, b0),
		nttFqMul(a0, b1) + nttFqMul(a1, b0)
}
