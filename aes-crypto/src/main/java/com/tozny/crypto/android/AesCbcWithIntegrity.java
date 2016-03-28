/*
 * Copyright (c) 2014-2015 Tozny LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Created by Isaac Potoczny-Jones on 11/12/14.
 */

package com.tozny.crypto.android;

import android.util.Base64;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Simple library for the "right" defaults for AES key generation, encryption,
 * and decryption using 128-bit AES, CBC, PKCS5 padding, and a random 16-byte IV
 * with SHA1PRNG. Integrity with HmacSHA256.
 */
public class AesCbcWithIntegrity {

    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String CIPHER = "AES";
    private static final String RANDOM_ALGORITHM = "SHA1PRNG";
    private static final int AES_KEY_LENGTH_BITS = 256;
    private static final int IV_LENGTH_BYTES = 16;
    private static final int PBE_ITERATION_COUNT = 10000;
    private static final int PBE_SALT_LENGTH_BITS = AES_KEY_LENGTH_BITS; // same size as key output
    private static final String PBE_ALGORITHM = "PBKDF2WithHmacSHA1";

    //Made BASE_64_FLAGS public as it's useful to know for compatibility.
    private static final int BASE64_FLAGS = Base64.NO_WRAP;

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int HMAC_KEY_LENGTH_BITS = 256;

    /**
     * Converts the given AES/HMAC keys into a base64 encoded string suitable for
     * storage. Sister function of keys.
     *
     * @param keys The combined aes and hmac keys
     * @return a base 64 encoded AES string & hmac key as base64(aesKey) : base64(hmacKey)
     */
    public static String keyString(final SecretKeys keys) {
        return keys.toString();
    }

    /**
     * An aes key derived from a base64 encoded key. This does not generate the
     * key. It's not random or a PBE key.
     *
     * @param keysStr a base64 encoded AES key / hmac key as base64(aesKey) : base64(hmacKey).
     * @return an AES & HMAC key set suitable for other functions.
     */
    public static SecretKeys keys(String keysStr) throws InvalidKeyException {
        final String[] keysArr = keysStr.split(":");

        if (keysArr.length != 2) {
            throw new IllegalArgumentException("Cannot parse aesKey:hmacKey");

        } else {
            final byte[] confidentialityKey = Base64.decode(keysArr[0], BASE64_FLAGS);
            if (confidentialityKey.length != AES_KEY_LENGTH_BITS / 8) {
                throw new InvalidKeyException(String.format("Base64 decoded key is not %s bytes", AES_KEY_LENGTH_BITS));
            }
            final byte[] integrityKey = Base64.decode(keysArr[1], BASE64_FLAGS);
            if (integrityKey.length != HMAC_KEY_LENGTH_BITS / 8) {
                throw new InvalidKeyException(String.format("Base64 decoded key is not %s bytes", HMAC_KEY_LENGTH_BITS));// "Base64 decoded key is not " + HMAC_KEY_LENGTH_BITS + " bytes");
            }

            return new SecretKeys(
                    new SecretKeySpec(confidentialityKey, 0, confidentialityKey.length, CIPHER),
                    new SecretKeySpec(integrityKey, HMAC_ALGORITHM));
        }
    }

    /**
     * A function that generates random AES & HMAC keys and prints out exceptions but
     * doesn't throw them since none should be encountered. If they are
     * encountered, the return value is null.
     *
     * @return The AES & HMAC keys.
     * @throws GeneralSecurityException if AES is not implemented on this system,
     *                                  or a suitable RNG is not available
     */
    public static SecretKeys generateKey() throws GeneralSecurityException {
        final KeyGenerator keyGen = KeyGenerator.getInstance(CIPHER);
        // No need to provide a SecureRandom or set a seed since that will
        // happen automatically.
        keyGen.init(AES_KEY_LENGTH_BITS);
        final SecretKey confidentialityKey = keyGen.generateKey();

        //Now make the HMAC key
        final byte[] integrityKeyBytes = randomBytes(HMAC_KEY_LENGTH_BITS / 8);//to get bytes
        final SecretKey integrityKey = new SecretKeySpec(integrityKeyBytes, HMAC_ALGORITHM);

        return new SecretKeys(confidentialityKey, integrityKey);
    }

    /**
     * A function that generates password-based AES & HMAC keys. It prints out exceptions but
     * doesn't throw them since none should be encountered. If they are
     * encountered, the return value is null.
     *
     * @param password The password to derive the keys from.
     * @return The AES & HMAC keys.
     * @throws GeneralSecurityException if AES is not implemented on this system,
     *                                  or a suitable RNG is not available
     */
    public static SecretKeys generateKeyFromPassword(String password, byte[] salt) throws GeneralSecurityException {
        //Get enough random bytes for both the AES key and the HMAC key:
        final KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt,
                PBE_ITERATION_COUNT, AES_KEY_LENGTH_BITS + HMAC_KEY_LENGTH_BITS);
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        final byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();

        // Split the random bytes into two parts:
        final byte[] confidentialityKeyBytes = Arrays.copyOfRange(keyBytes, 0, AES_KEY_LENGTH_BITS / 8);
        final byte[] integrityKeyBytes = Arrays.copyOfRange(keyBytes, AES_KEY_LENGTH_BITS / 8, AES_KEY_LENGTH_BITS / 8 + HMAC_KEY_LENGTH_BITS / 8);

        //Generate the AES key
        final SecretKey confidentialityKey = new SecretKeySpec(confidentialityKeyBytes, CIPHER);

        //Generate the HMAC key
        final SecretKey integrityKey = new SecretKeySpec(integrityKeyBytes, HMAC_ALGORITHM);

        return new SecretKeys(confidentialityKey, integrityKey);
    }

    /**
     * A function that generates password-based AES & HMAC keys. See generateKeyFromPassword.
     *
     * @param password The password to derive the AES/HMAC keys from
     * @param salt     A string version of the salt; base64 encoded.
     * @return The AES & HMAC keys.
     * @throws GeneralSecurityException
     */
    public static SecretKeys generateKeyFromPassword(final String password, final String salt) throws GeneralSecurityException {
        return generateKeyFromPassword(password, Base64.decode(salt, BASE64_FLAGS));
    }

    /**
     * Generates a random salt.
     *
     * @return The random salt suitable for generateKeyFromPassword.
     */
    public static byte[] generateSalt() throws GeneralSecurityException {
        return randomBytes(PBE_SALT_LENGTH_BITS);
    }

    /**
     * Converts the given salt into a base64 encoded string suitable for
     * storage.
     *
     * @param salt
     * @return a base 64 encoded salt string suitable to pass into generateKeyFromPassword.
     */
    public static String saltString(final byte[] salt) {
        return Base64.encodeToString(salt, BASE64_FLAGS);
    }


    /**
     * Creates a random Initialization Vector (IV) of IV_LENGTH_BYTES.
     *
     * @return The byte array of this IV
     * @throws GeneralSecurityException if a suitable RNG is not available
     */
    public static byte[] generateIv() throws GeneralSecurityException {
        return randomBytes(IV_LENGTH_BYTES);
    }

    private static byte[] randomBytes(final int length) throws GeneralSecurityException {
        final SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
        final byte[] b = new byte[length];
        random.nextBytes(b);
        return b;
    }

    /*
     * -----------------------------------------------------------------
     * Encryption
     * -----------------------------------------------------------------
     */

    /**
     * Generates a random IV and encrypts this plain text with the given key. Then attaches
     * a hashed MAC, which is contained in the CipherTextIvMac class.
     *
     * @param plaintext  The text that will be encrypted, which
     *                   will be serialized with UTF-8
     * @param secretKeys The AES & HMAC keys with which to encrypt
     * @return a tuple of the IV, ciphertext, mac
     * @throws GeneralSecurityException     if AES is not implemented on this system
     * @throws UnsupportedEncodingException if UTF-8 is not supported in this system
     */
    public static CipherTextIvMac encrypt(final String plaintext, final SecretKeys secretKeys)
            throws UnsupportedEncodingException, GeneralSecurityException {
        return encrypt(plaintext, secretKeys, "UTF-8");
    }

    /**
     * Generates a random IV and encrypts this plain text with the given key. Then attaches
     * a hashed MAC, which is contained in the CipherTextIvMac class.
     *
     * @param plaintext  The bytes that will be encrypted
     * @param secretKeys The AES & HMAC keys with which to encrypt
     * @return a tuple of the IV, ciphertext, mac
     * @throws GeneralSecurityException     if AES is not implemented on this system
     * @throws UnsupportedEncodingException if the specified encoding is invalid
     */
    public static CipherTextIvMac encrypt(final String plaintext, final SecretKeys secretKeys, String encoding)
            throws UnsupportedEncodingException, GeneralSecurityException {
        return encrypt(plaintext.getBytes(encoding), secretKeys);
    }

    /**
     * Generates a random IV and encrypts this plain text with the given key. Then attaches
     * a hashed MAC, which is contained in the CipherTextIvMac class.
     *
     * @param plaintext  The text that will be encrypted
     * @param secretKeys The combined AES & HMAC keys with which to encrypt
     * @return a tuple of the IV, ciphertext, mac
     * @throws GeneralSecurityException if AES is not implemented on this system
     */
    public static CipherTextIvMac encrypt(final byte[] plaintext, final SecretKeys secretKeys)
            throws GeneralSecurityException {
        byte[] iv = generateIv();
        Cipher aesCipherForEncryption = Cipher.getInstance(CIPHER_TRANSFORMATION);
        aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, secretKeys.getConfidentialityKey(), new IvParameterSpec(iv));

        /*
         * Now we get back the IV that will actually be used. Some Android
         * versions do funny stuff w/ the IV, so this is to work around bugs:
         */
        iv = aesCipherForEncryption.getIV();
        byte[] byteCipherText = aesCipherForEncryption.doFinal(plaintext);
        byte[] ivCipherConcat = CipherTextIvMac.ivCipherConcat(iv, byteCipherText);

        byte[] integrityMac = generateMac(ivCipherConcat, secretKeys.getIntegrityKey());
        return new CipherTextIvMac(byteCipherText, iv, integrityMac);
    }



    /*
     * -----------------------------------------------------------------
     * Decryption
     * -----------------------------------------------------------------
     */

    /**
     * AES CBC decrypt.
     *
     * @param civ        The cipher text, IV, and mac
     * @param secretKeys The AES & HMAC keys
     * @param encoding   The string encoding to use to decode the bytes after decryption
     * @return A string derived from the decrypted bytes (not base64 encoded)
     * @throws GeneralSecurityException     if AES is not implemented on this system
     * @throws UnsupportedEncodingException if the encoding is unsupported
     */
    public static String decryptString(final CipherTextIvMac civ, final SecretKeys secretKeys, final String encoding)
            throws UnsupportedEncodingException, GeneralSecurityException {
        return new String(decrypt(civ, secretKeys), encoding);
    }

    /**
     * AES CBC decrypt.
     *
     * @param civ        The cipher text, IV, and mac
     * @param secretKeys The AES & HMAC keys
     * @return A string derived from the decrypted bytes, which are interpreted
     * as a UTF-8 String
     * @throws GeneralSecurityException     if AES is not implemented on this system
     * @throws UnsupportedEncodingException if UTF-8 is not supported
     */
    public static String decryptString(final CipherTextIvMac civ, final SecretKeys secretKeys)
            throws UnsupportedEncodingException, GeneralSecurityException {
        return decryptString(civ, secretKeys, "UTF-8");
    }

    /**
     * AES CBC decrypt.
     *
     * @param civ        the cipher text, iv, and mac
     * @param secretKeys the AES & HMAC keys
     * @return The raw decrypted bytes
     * @throws GeneralSecurityException if MACs don't match or AES is not implemented
     */
    public static byte[] decrypt(final CipherTextIvMac civ, final SecretKeys secretKeys)
            throws GeneralSecurityException {

        final byte[] ivCipherConcat = CipherTextIvMac.ivCipherConcat(civ.getIv(), civ.getCipherText());
        final byte[] computedMac = generateMac(ivCipherConcat, secretKeys.getIntegrityKey());
        if (constantTimeEq(computedMac, civ.getMac())) {
            final Cipher aesCipherForDecryption = Cipher.getInstance(CIPHER_TRANSFORMATION);
            aesCipherForDecryption.init(Cipher.DECRYPT_MODE, secretKeys.getConfidentialityKey(),
                    new IvParameterSpec(civ.getIv()));
            return aesCipherForDecryption.doFinal(civ.getCipherText());
        } else {
            throw new GeneralSecurityException("MAC stored in civ does not match computed MAC.");
        }
    }

    /*
     * -----------------------------------------------------------------
     * Helper Code
     * -----------------------------------------------------------------
     */

    /**
     * Generate the mac based on HMAC_ALGORITHM
     *
     * @param integrityKey   The key used for hmac
     * @param byteCipherText the cipher text
     * @return A byte array of the HMAC for the given key & ciphertext
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static byte[] generateMac(byte[] byteCipherText, SecretKey integrityKey) throws NoSuchAlgorithmException, InvalidKeyException {
        //Now compute the mac for later integrity checking
        final Mac sha256_HMAC = Mac.getInstance(HMAC_ALGORITHM);
        sha256_HMAC.init(integrityKey);
        return sha256_HMAC.doFinal(byteCipherText);
    }

    /**
     * Holder class that has both the secret AES key for encryption (confidentiality)
     * and the secret HMAC key for integrity.
     */

    public static class SecretKeys implements Serializable {
        private final SecretKey confidentialityKey;
        private final SecretKey integrityKey;

        /**
         * Construct the secret keys container.
         *
         * @param confidentialityKeyIn The AES key
         * @param integrityKeyIn       the HMAC key
         */
        public SecretKeys(SecretKey confidentialityKeyIn, SecretKey integrityKeyIn) {
            confidentialityKey = confidentialityKeyIn;
            integrityKey = integrityKeyIn;
        }

        public SecretKey getConfidentialityKey() {
            return confidentialityKey;
        }


        public SecretKey getIntegrityKey() {
            return integrityKey;
        }


        /**
         * Encodes the two keys as a string
         *
         * @return base64(confidentialityKey):base64(integrityKey)
         */
        @Override
        public String toString() {
            return String.format("%s:%s", Base64.encodeToString(getConfidentialityKey().getEncoded(), BASE64_FLAGS), Base64.encodeToString(getIntegrityKey().getEncoded(), BASE64_FLAGS));
        }

        @Override
        public int hashCode() {
            return Objects.hash(confidentialityKey, integrityKey);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null || getClass() != obj.getClass())
                return false;
            final SecretKeys other = (SecretKeys) obj;
            if (!Objects.equals(integrityKey, other.integrityKey)
                    || !Objects.equals(confidentialityKey, other.confidentialityKey))
                return false;
            return true;
        }
    }


    /**
     * Simple constant-time equality of two byte arrays. Used for security to avoid timing attacks.
     *
     * @param a
     * @param b
     * @return true iff the arrays are exactly equal.
     */
    public static boolean constantTimeEq(final byte[] a, final byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    /**
     * Holder class that allows us to bundle ciphertext and IV together.
     */
    public static class CipherTextIvMac {
        private final byte[] cipherText;
        private final byte[] iv;
        private final byte[] mac;

        public byte[] getCipherText() {
            return cipherText;
        }

        public byte[] getIv() {
            return iv;
        }

        public byte[] getMac() {
            return mac;
        }

        /**
         * Construct a new bundle of ciphertext and IV.
         *
         * @param c The ciphertext
         * @param i The IV
         * @param h The mac
         */
        public CipherTextIvMac(final byte[] c, final byte[] i, final byte[] h) {
            cipherText = Arrays.copyOf(c, c.length);
            iv = Arrays.copyOf(i, i.length);
            mac = Arrays.copyOf(h, h.length);
        }

        /**
         * Constructs a new bundle of ciphertext and IV from a string of the
         * format <code>base64(iv):base64(ciphertext)</code>.
         *
         * @param base64IvAndCiphertext A string of the format
         *                              <code>iv:ciphertext</code> The IV and ciphertext must each
         *                              be base64-encoded.
         */
        public CipherTextIvMac(final String base64IvAndCiphertext) {
            final String[] civArray = base64IvAndCiphertext.split(":");
            if (civArray.length != 3) {
                throw new IllegalArgumentException("Cannot parse iv:ciphertext:mac");
            } else {
                iv = Base64.decode(civArray[0], BASE64_FLAGS);
                mac = Base64.decode(civArray[1], BASE64_FLAGS);
                cipherText = Base64.decode(civArray[2], BASE64_FLAGS);
            }
        }

        /**
         * Concatinate the IV to the cipherText using array copy.
         * This is used e.g. before computing mac.
         *
         * @param iv         The IV to prepend
         * @param cipherText the cipherText to append
         * @return iv:cipherText, a new byte array.
         */
        public static byte[] ivCipherConcat(final byte[] iv, final byte[] cipherText) {
            final byte[] combined = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);
            return combined;
        }

        /**
         * Encodes this ciphertext, IV, mac as a string.
         *
         * @return base64(iv) : base64(mac) : base64(ciphertext).
         * The iv and mac go first because they're fixed length.
         */
        @Override
        public String toString() {
            String ivString = Base64.encodeToString(iv, BASE64_FLAGS);
            String cipherTextString = Base64.encodeToString(cipherText, BASE64_FLAGS);
            String macString = Base64.encodeToString(mac, BASE64_FLAGS);
            return String.format("%s:%s:%s", ivString, macString, cipherTextString);
        }

        @Override
        public int hashCode() {
            return Objects.hash(Arrays.hashCode(cipherText), Arrays.hashCode(iv), Arrays.hashCode(mac));
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null || getClass() != obj.getClass())
                return false;
            final CipherTextIvMac other = (CipherTextIvMac) obj;

            if (!Objects.equals(cipherText, other.cipherText)
                    || !Objects.equals(iv, other.iv)
                    || !Objects.equals(mac, other.mac)
                    ) {
                return false;
            }

            return true;
        }
    }


}
