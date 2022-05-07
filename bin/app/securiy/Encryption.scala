package security;

// Java program to perform the
// encryption and decryption
// using asymmetric key
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

object Encryption{
  def RSA: String = "RSA"
  //def keypair: KeyPair = generateRSAKkeyPair()

  @throws(classOf[Exception])
  def generateRSAKeyPair(): KeyPair =
  {
      val secureRandom: SecureRandom = new SecureRandom();
      val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(RSA);

      keyPairGenerator.initialize(2048, secureRandom);

      return keyPairGenerator.generateKeyPair();
  }

  // Encryption function which converts
  // the plainText into a cipherText
  // using private Key.
  @throws(classOf[Exception])
  def do_RSAEncryption( plainText: String, keypair: KeyPair): Array[Byte] =
  {
      val cipher: Cipher = Cipher.getInstance(RSA);

      cipher.init(Cipher.ENCRYPT_MODE, keypair.getPrivate() );

      val encrypted: Array[Byte] = cipher.doFinal(plainText.getBytes());

      print("The Encrypted Text is: ");

      val rsaText: String = DatatypeConverter.printHexBinary(encrypted);

      println(rsaText);

      println("The Encrypted Text length is: %d".format(rsaText.length));

      return encrypted
  }

  @throws(classOf[Exception])
  def do_RSADecryption( hash: Array[Byte], keypair: KeyPair): String =
  {
      val cipher: Cipher = Cipher.getInstance(RSA);

      cipher.init(Cipher.DECRYPT_MODE, keypair.getPublic() );

      val decrypted: Array[Byte] = cipher.doFinal(hash);

      print("The Decrypted Text is: ");

      val rsaText: String = new String(decrypted);

      println(rsaText);

      println("The Decrypted Text length is: %d".format(rsaText.length));

      return rsaText
  }
}
