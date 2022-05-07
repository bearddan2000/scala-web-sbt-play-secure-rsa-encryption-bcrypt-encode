package security

import org.mindrot.jbcrypt.BCrypt;
import java.io.IOException;
import java.security.KeyPair;
import javax.xml.bind.DatatypeConverter;

object Encode {

  @throws(classOf[IOException])
  def compress(hash: String): Array[Byte] = {
    val compress: Array[Byte] = GZIPCompression.compress(hash);
    return compress
  }

  @throws(classOf[Exception])
  def encrypt(keypair: KeyPair, hash: String): Array[Byte] = {

    val cipherText: Array[Byte] = Encryption.do_RSAEncryption(hash, keypair);

    val newHash: String = DatatypeConverter.printHexBinary(cipherText);

    return compress(newHash);
  }

  @throws(classOf[Exception])
  def decompress(hash: Array[Byte]) = GZIPCompression.decompress(hash);

  @throws(classOf[Exception])
  def decrypt(keypair: KeyPair, hash: Array[Byte]): String = {

      val dcompress = decompress(hash);

      return Encryption.do_RSADecryption(DatatypeConverter.parseHexBinary(dcompress), keypair);
  }

  def hashpw(keypair: KeyPair, pass: String): String = {

    val stored: String = BCrypt.hashpw(pass, BCrypt.gensalt());

    try {

      val newHash: Array[Byte] = encrypt(keypair, stored);

      return DatatypeConverter.printHexBinary(newHash);

    } catch {
      case e: Exception => {

      return "";
      }
    }

  }

  def verify(keypair: KeyPair, pass :String, hash: String): Boolean = {

      val hashArray = DatatypeConverter.parseHexBinary(hash);

      try{

        val newHash = decrypt(keypair, hashArray);

        return BCrypt.checkpw(pass, newHash);

    } catch {
      case e: Exception => {
        return false;
      }
    }
  }
}
