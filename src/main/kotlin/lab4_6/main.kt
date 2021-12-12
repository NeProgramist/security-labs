package lab4_6

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

fun main() {
    Security.addProvider(BouncyCastleProvider())
    val algorithm = GOSTCipher()
    val secret = algorithm.getNewSecret()

    val msg = "abcd"
    val encrypted = algorithm.encrypt(msg, secret)
    val decrypted = algorithm.decrypt(encrypted, secret)

    println("""
        msg      : $msg
        encrypted: $encrypted
        decrypted: $decrypted
    """.trimIndent())
}
