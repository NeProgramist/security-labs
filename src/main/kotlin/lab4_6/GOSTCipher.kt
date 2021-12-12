package lab4_6

import java.nio.charset.StandardCharsets
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class GOSTCipher {
    private val algorithm = "GOST"
    private val provider = "BC"
    private val transformation = "GOST/CBC/PKCS5Padding"

    private val keyGenerator = KeyGenerator.getInstance(algorithm, provider)
    fun getNewSecret(): SecretKey = keyGenerator.generateKey()

    fun encrypt(message: String, secret: SecretKey): String {
        val cipher = getCipher(secret, Cipher.ENCRYPT_MODE)
        val original = message.toByteArray(StandardCharsets.UTF_8)
        val encrypted = cipher.doFinal(original)
        val iv = cipher.iv

        val result = ByteArray(encrypted.size + iv.size)
        System.arraycopy(iv, 0, result, 0, iv.size)
        System.arraycopy(encrypted, 0, result, iv.size, encrypted.size)

        return Base64.getEncoder().encodeToString(result)
    }

    fun decrypt(message: String, secret: SecretKey): String {
        val encrypted = Base64.getDecoder().decode(message)

        val iv = ByteArray(8)
        val msg = ByteArray(encrypted.size - 8)
        System.arraycopy(encrypted, 0, iv, 0, iv.size)
        System.arraycopy(encrypted, iv.size, msg, 0, msg.size)

        val cipher = getCipher(secret, Cipher.DECRYPT_MODE, iv)

        val decrypted = cipher.doFinal(msg)
        return String(decrypted, StandardCharsets.UTF_8)
    }

    private fun getCipher(secret: SecretKey, mode: Int, iv: ByteArray? = null): Cipher {
        val cipher =  Cipher.getInstance(transformation, provider)
        when {
            mode == Cipher.DECRYPT_MODE && iv != null -> cipher.init(mode, secret, IvParameterSpec(iv))
            mode == Cipher.ENCRYPT_MODE -> cipher.init(mode, secret)
        }

        return cipher
    }
}
