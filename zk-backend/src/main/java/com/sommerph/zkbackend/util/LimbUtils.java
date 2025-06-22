package com.sommerph.zkbackend.util;

import java.math.BigInteger;

public class LimbUtils {

    /**
     * Converts a BigInteger scalar to limbs.
     *
     * @param scalar  The BigInteger input.
     * @param limbSizeBits  The bit size per limb.
     * @param numLimbs  The number of limbs.
     * @return String array of limbs (decimal strings, for JSON output)
     */
    public static String[] scalarToLimbs(BigInteger scalar, int limbSizeBits, int numLimbs) {
        String[] limbs = new String[numLimbs];
        BigInteger mask = BigInteger.ONE.shiftLeft(limbSizeBits).subtract(BigInteger.ONE);
        for (int i = 0; i < numLimbs; i++) {
            BigInteger limb = scalar.shiftRight(i * limbSizeBits).and(mask);
            limbs[i] = limb.toString();
        }
        return limbs;
    }

    /**
     * Converts EC Point coordinates (BigInteger x and y) to limbs.
     *
     * @param x  The x-coordinate.
     * @param y  The y-coordinate.
     * @param limbSizeBits  The bit size per limb.
     * @param numLimbs  The number of limbs.
     * @return 2D String array: [2][numLimbs] → [x limbs][y limbs]
     */
    public static String[][] pointToLimbs(BigInteger x, BigInteger y, int limbSizeBits, int numLimbs) {
        String[] xLimbs = scalarToLimbs(x, limbSizeBits, numLimbs);
        String[] yLimbs = scalarToLimbs(y, limbSizeBits, numLimbs);
        return new String[][] { xLimbs, yLimbs };
    }

    // Convenience helpers for secp256r1 and secp256k1:

    public static String[] scalarToLimbsR1(BigInteger scalar) {
        return scalarToLimbs(scalar, 43, 6);
    }

    public static String[][] pointToLimbsR1(BigInteger x, BigInteger y) {
        return pointToLimbs(x, y, 43, 6);
    }

    public static String[] scalarToLimbsK1(BigInteger scalar) {
        return scalarToLimbs(scalar, 64, 4);
    }

    public static String[][] pointToLimbsK1(BigInteger x, BigInteger y) {
        return pointToLimbs(x, y, 64, 4);
    }

}
