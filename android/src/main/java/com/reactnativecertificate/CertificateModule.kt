package com.reactnativecertificate

import android.R.attr
import android.util.Base64
import android.util.Log
import com.facebook.react.bridge.*
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import android.R.attr.publicKey
import java.io.InputStream
import java.security.KeyFactory

import java.security.spec.X509EncodedKeySpec

const val ALGORITHM = "AES"
const val PADDING_MODE = "/CBC/PKCS7Padding"
const val RSA_ALGORITHM = "RSA/ECB/PKCS1Padding"

fun byteArrayOfInts(vararg ints: Int) = ByteArray(ints.size) { pos -> ints[pos].toByte() }
fun String.hexStringToByteArray() = ByteArray(this.length / 2) {
    this.substring(
        it * 2,
        it * 2 + 2
    ).toInt(16).toByte()
}

private val HEX_CHARS = "0123456789ABCDEF".toCharArray()
fun ByteArray.toHex() : String{
    val result = StringBuffer()

    forEach {
        val octet = it.toInt()
        val firstIndex = (octet and 0xF0).ushr(4)
        val secondIndex = octet and 0x0F
        result.append(HEX_CHARS[firstIndex])
        result.append(HEX_CHARS[secondIndex])
    }

    return result.toString()
}

class CertificateModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {
    private var rsa:RSA? = null
    private var aes:AES256Util? = null

    override fun getName(): String {
        return "Certificate"
    }

    @ReactMethod
    fun saveCertificate(filepath: String, hexString: String, promise: Promise) {
      try {
        val e1 = hexString.hexStringToByteArray()
        val derOut = FileOutputStream(filepath)
        derOut.write(e1)
        derOut.close()
      } catch (ex: java.lang.Exception) {
        promise.reject(ex)
      }

      promise.resolve("")
    }

    @ReactMethod
    fun getCertificate(filepath: String, promise: Promise) {
      val map = Arguments.createMap()
      val dateFormat = SimpleDateFormat("yyyy.MM.dd")
      val derFile = File(filepath)
      try {
        val cf: CertificateFactory = CertificateFactory.getInstance("X.509")
        val cert: X509Certificate =
          cf.generateCertificate(FileInputStream(derFile)) as X509Certificate


        //cn
        val dn: String = cert.getSubjectDN().toString()
        Log.wtf("DN: ", dn)

        val split = dn.split(",".toRegex()).toTypedArray()
        for (x in split) {
          if (x.contains("CN=")) {
            var cn = x.trim { it <= ' ' }.replace("CN=", "")
            println("CN is $cn")
            cn = cn.replace("\\p{Punct}|\\p{Digit}|[A-Za-z]".toRegex(), "")
            map.putString("cn", cn)
          }
        }


        //valid date
        val validFrom: String = dateFormat.format(cert.notBefore)
        val validTo: String = dateFormat.format(cert.notAfter)
        println("Valid Date = $validFrom - $validTo")
        map.putString("validDate", "$validFrom - $validTo")
        map.putString("path", filepath)

      } catch (ex: java.lang.Exception) {
        ex.printStackTrace()
        promise.reject(ex)
      }

      promise.resolve(map)
    }

    @ReactMethod
    fun generateKeys() {
      rsa = RSA()
      rsa!!.generatorKey()
    }

    @ReactMethod
    fun getPublicKey(promise: Promise) {
      return promise.resolve(Base64.encodeToString(rsa!!.publicKey.encoded, 0))
    }

    @ReactMethod
      fun getPrivateKey(promise: Promise) {
        return promise.resolve(Base64.encodeToString(rsa!!.privateKey.encoded, 0))
    }

    @ReactMethod
    fun decrypt(encryptedAesKey: String, encryptedPublicKey: String, encryptedPrivateKey: String, subjectDN: String, sessionId: String, promise: Promise) {
      val hexAesKeyByteArray = encryptedAesKey.hexStringToByteArray()
      val decryptedAesKey = decryptWithRSA(hexAesKeyByteArray, rsa!!.privateKey)!!

      val iv = byteArrayOfInts(
        123,
        140,
        56,
        128,
        22,
        11,
        170,
        121,
        33,
        113,
        73,
        28,
        208,
        42,
        247,
        134
      )
      Log.d("decryptedAesKey: ", "$decryptedAesKey")
      val decryptedPublicBytes = decryptWithAES(
        decryptedAesKey,
        iv,
        encryptedPublicKey.hexStringToByteArray()
      )!!
      val decryptedPrivateBytes = decryptWithAES(
        decryptedAesKey,
        iv,
        encryptedPrivateKey.hexStringToByteArray()
      )!!


      val e1 = String(decryptedPublicBytes)
      val e2 = String(decryptedPrivateBytes)

      var issuedBy = ""
      val dnList = subjectDN.split(",")
      dnList.forEach {

        Log.wtf("dn: ", it)

        val dn = it.split("=")
        if (dn[0] == "O") {
          issuedBy = dn[1]
          Log.wtf("Issued By:", issuedBy)
        }
      }

      val map = Arguments.createMap()

      map.putString("der", e1)
      map.putString("key", e2)
      map.putString("issuedBy", issuedBy)

      promise.resolve(map)
    }

    private fun decryptWithAES(
      aesKey: ByteArray, aesIV: ByteArray,
      encryptedData: ByteArray
    ): ByteArray? {
      val skeySpec = SecretKeySpec(aesKey, ALGORITHM)
      val aesCipher = Cipher.getInstance(
        ALGORITHM + PADDING_MODE
      )

      aesCipher.init(
        Cipher.DECRYPT_MODE, skeySpec,
        IvParameterSpec(aesIV)
      )

      return aesCipher.doFinal(encryptedData)
    }

    private fun decryptWithRSA(encryptedAesKey: ByteArray, privKey: PrivateKey): ByteArray? {
      val rsaCipher = Cipher.getInstance(RSA_ALGORITHM)
      rsaCipher.init(Cipher.DECRYPT_MODE, privKey)
      return rsaCipher.doFinal(encryptedAesKey)
    }

    @ReactMethod
    fun encryptWithRSA(key: String, publicKey: PublicKey): String {
      val bytes: ByteArray = key.toByteArray(Charsets.UTF_8)
      val cipher = Cipher.getInstance(RSA_ALGORITHM)
      cipher.init(Cipher.ENCRYPT_MODE, publicKey)
      val cipherData = cipher.doFinal(bytes)
      return Base64.encodeToString(cipherData, 0)
    }

  @ReactMethod
  fun getAesKey(key: String, publicKey: String, promise: Promise) {
    if (this.aes == null) {
      this.aes = AES256Util(key);
    }

    val byteKey: ByteArray = Base64.decode(publicKey.toByteArray(), Base64.DEFAULT)
    val x509publicKey = X509EncodedKeySpec(byteKey)
    val kf = KeyFactory.getInstance("RSA")

    val encryptAesKey = encryptWithRSA(key, kf.generatePublic(x509publicKey));

    return promise.resolve(encryptAesKey)
  }

  @ReactMethod
  fun getEncryptedCert(filepath: String, promise: Promise) {
    val file = File(filepath).readBytes()
    return promise.resolve(this.aes?.encodeBytes(file))
  }

  @ReactMethod
  fun getEncryptedWithAES(str: String, promise: Promise) {
    return promise.resolve(this.aes?.encode(str))
  }
}
