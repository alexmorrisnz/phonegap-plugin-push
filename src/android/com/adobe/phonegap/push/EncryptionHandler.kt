package com.adobe.phonegap.push

import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.math.BigInteger
import java.security.AlgorithmParameterGenerator
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.security.auth.x500.X500Principal

class EncryptionHandler(private val context: Context) {
    companion object {
        private const val TAG: String = "${PushPlugin.PREFIX_TAG} (EncryptionHandler)"
        const val ALIAS: String = "moodlemobile"
        const val KEYSTORE_NAME = "AndroidKeyStore"
        const val CIPHER = "RSA/ECB/PKCS1Padding"
        const val DIGEST = "SHA-512"

        /**
         * Decrypt with private key
         */
        fun decrypt(cipherText: ByteArray): ByteArray {
            val privateKey: PrivateKey? = getPrivateKey()

            val cipher = Cipher.getInstance(CIPHER)
            val parameterSpec = OAEPParameterSpec(
                DIGEST,
                OAEPParameterSpec.DEFAULT.mgfAlgorithm,
                OAEPParameterSpec.DEFAULT.mgfParameters,
                OAEPParameterSpec.DEFAULT.pSource
            )
            cipher.init(Cipher.DECRYPT_MODE, privateKey)

            return cipher.doFinal(cipherText)
        }

        /**
         * Encrypt with public key
         */
        fun encrypt(plainText: ByteArray): ByteArray {
            val publicKey: PublicKey? = getPublicKey()

            val cipher = Cipher.getInstance(CIPHER)
            val parameterSpec = OAEPParameterSpec(
                DIGEST,
                OAEPParameterSpec.DEFAULT.mgfAlgorithm,
                OAEPParameterSpec.DEFAULT.mgfParameters,
                OAEPParameterSpec.DEFAULT.pSource
            )
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, parameterSpec)

            return cipher.doFinal(plainText)
        }

        fun deleteKey() {
            val keyStore = KeyStore.getInstance(KEYSTORE_NAME)
            keyStore.load(null)
            keyStore.deleteEntry(ALIAS)
        }

        /**
         * Check if our key exists
         */
        fun keyExists(): Boolean {
            val keyStore = KeyStore.getInstance(KEYSTORE_NAME)
            keyStore.load(null);
            return keyStore.containsAlias(ALIAS);
        }

        fun getPublicKey(): PublicKey? {
            val keyStore: KeyStore = KeyStore.getInstance(KEYSTORE_NAME);
            keyStore.load(null);
            if (!keyStore.containsAlias(ALIAS)) {
                return null
            }

            val keypair: KeyStore.PrivateKeyEntry =
                keyStore.getEntry(ALIAS, null) as KeyStore.PrivateKeyEntry
            return keypair.certificate.publicKey
        }

        private fun getPrivateKey(): PrivateKey? {
            val keyStore: KeyStore = KeyStore.getInstance(KEYSTORE_NAME);
            keyStore.load(null);
            if (!keyStore.containsAlias(ALIAS)) {
                return null
            }

            val entry: KeyStore.PrivateKeyEntry =
                keyStore.getEntry(ALIAS, null) as KeyStore.PrivateKeyEntry
            return entry.privateKey
        }
    }

    fun getPublicKeyString(): String? {
        val publicKey: PublicKey = if (!keyExists()) {
            val keyPair = generateKeyPair()
            keyPair.public
        } else {
            val tempKey = getPublicKey() ?: return null
            tempKey
        }
        val publicKeyString =
            android.util.Base64.encodeToString(publicKey.encoded, android.util.Base64.DEFAULT)
        return "-----BEGIN PUBLIC KEY-----\n$publicKeyString-----END PUBLIC KEY-----"
    }

    /**
     * Generates new RSA key pair stored in Android key store.
     *
     * @return Public key
     */
    fun generateKeyPair(): KeyPair {
        val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance("RSA", KEYSTORE_NAME)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            keyPairGenerator
                .apply {
                    initialize(
                        KeyGenParameterSpec.Builder(
                            ALIAS,
                            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                        ).run {
                            setKeySize(2048)
                            setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                            setDigests(
                                KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512
                            )
                            build()
                        }
                    )
                }
            return keyPairGenerator.generateKeyPair()
        } else {
//            var start: Calendar = Calendar.getInstance()
//            var end: Calendar = Calendar.getInstance()
//            end.add(Calendar.YEAR, 30)
            val spec: KeyPairGeneratorSpec = KeyPairGeneratorSpec.Builder(context).run {
                setAlias(ALIAS)
                setSubject(X500Principal("CN=$ALIAS"))
                setSerialNumber(BigInteger.TEN)
//                setStartDate(start.time)
//                setEndDate(end.time)
                build()
            }

            keyPairGenerator.initialize(spec)
            return keyPairGenerator.generateKeyPair()
        }
    }
}
