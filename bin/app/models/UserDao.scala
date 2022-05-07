package models

import javax.inject.Inject
import java.security.KeyPair;

import security.{Encode, Encryption};

@javax.inject.Singleton
class UserDao @Inject()() {

  def lookupUser(u: User): Boolean = {
    val keypair: KeyPair = Encryption.generateRSAKeyPair();

    val hash: String = Encode.hashpw(keypair, u.password);

    val isMatch: Boolean = Encode.verify(keypair, "pass", hash);

    if (u.username == "user" && isMatch) true else false
  }

}
