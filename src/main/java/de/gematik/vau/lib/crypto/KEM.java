/*
 * Copyright 2024 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.vau.lib.crypto;


import de.gematik.vau.lib.data.*;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

@Slf4j
@NoArgsConstructor(access = lombok.AccessLevel.PRIVATE)
public class KEM {
  private static final int GCM_IV_LENGTH = 12; //A_24628
  private static final int GCM_TAG_LENGTH = 16; //A_24628
  private static final SecureRandom RANDOM = new SecureRandom();

  /**
   * Generates the Shared secrets using own Private and the remote ciphertexts of VauMessage2
   * @param ciphertext a VauMessage2, containing the ciphertexts
   * @param privateKeys own PrivateKey
   * @return The ECDH and Kyber Shared Secrets
   */
  public static KdfMessage decapsulateMessages(VauMessage2 ciphertext, EccKyberKeyPair privateKeys) {
    ECPublicKey ecdhPublicKeySender = cborDecodeEcdhPublicKey(ciphertext.getEcdhCt());
    byte[] ecdhSharedSecret = EllipticCurve.getSharedSecret(ecdhPublicKeySender, privateKeys.getEccKeyPair()
      .getPrivate());

    byte[] sharedSecretClient = KyberEncoding.pqcGenerateDecryptionKey(privateKeys.getKyberKeyPair().getPrivate(),
      ciphertext.getKyberCt());

    return new KdfMessage(null, ecdhSharedSecret, null, sharedSecretClient);
  }

  /**
   * Generates the Shared secrets using own Private, the remote Kyber ciphertext and the remote ECDH PublicKey of VauMessage3InnerLayer
   * @param ciphertext a VauMessage3InnerLayer, containing the Kyber ciphertext and the remote ECDH PublicKey
   * @param privateKeys own PrivateKey
   * @return The ECDH and Kyber Shared Secrets
   */
  public static KdfMessage decapsulateMessages(VauMessage3InnerLayer ciphertext, EccKyberKeyPair privateKeys) {
    ECPublicKey ecdhPublicKeySender = cborDecodeEcdhPublicKey(ciphertext.getEcdhCt());
    byte[] ecdhSharedSecret = EllipticCurve.getSharedSecret(ecdhPublicKeySender, privateKeys.getEccKeyPair().getPrivate());

    byte[] sharedSecretClient = KyberEncoding.pqcGenerateDecryptionKey(privateKeys.getKyberKeyPair().getPrivate(),
            ciphertext.getKyberCt());
    return new KdfMessage(null, ecdhSharedSecret, null, sharedSecretClient);
  }

  /**
   * Generates the ECDH and Kyber Shared Secrets and Ciphertexts
   * @param remoteEcdhPublicKey remote ECDH PublicKey
   * @param kyberPublicKey remote Kyber PublicKey
   * @return KdfMessage containing both secrets and ciphertexts
   */
  public static KdfMessage encapsulateMessage(ECPublicKey remoteEcdhPublicKey, PublicKey kyberPublicKey) {
    KeyPair temporaryEcdhKeyPair = EllipticCurve.generateKeyPair();
    byte[] ecdhSharedSecret = EllipticCurve.getSharedSecret(remoteEcdhPublicKey,
      (ECPrivateKey) temporaryEcdhKeyPair.getPrivate());
    SecretKeyWithEncapsulation kyberSecretWithEncapsulation = KyberEncoding.pqcGenerateEncryptionKey(kyberPublicKey);

    return new KdfMessage(new VauEccPublicKey((ECPublicKey) temporaryEcdhKeyPair.getPublic()), temporaryEcdhKeyPair.getPrivate(),
      ecdhSharedSecret,
      kyberSecretWithEncapsulation.getEncapsulation(),
      kyberSecretWithEncapsulation.getEncoded());
  }

  /**
   * Generates the KdfKey1 using the ECDH and Kyber Shared secrets of a KdfMessage
   * @param message the KdfMessage containing the ECDH and Kyber Shared secrets
   * @return KdfKey1
   */
  public static KdfKey1 kdf(KdfMessage message) {
    if(message == null) {
      throw new IllegalArgumentException("Kdf Message was null.");
    }
    else if(message.getEcdhSharedSecret() == null) {
      throw new IllegalArgumentException("Ecdh Shared Secret was null.");
    }
    else if(message.getKyberSharedSecret() == null) {
      throw new IllegalArgumentException("Kyber Shared Secret was null.");
    }
    else {
      List<byte[]> byteArrays = kdf(ArrayUtils.addAll(message.getEcdhSharedSecret(), message.getKyberSharedSecret()), 2);
      return new KdfKey1(byteArrays.get(0), byteArrays.get(1));
    }
  }

  /**
   * Generates the KdfKey2 using the ECDH and Kyber Shared secrets of the two KdfMessages
   * @param message1 KdfMessage 1 containing the ECDH and Kyber Shared secrets
   * @param message2 KdfMessage 2 containing the ECDH and Kyber Shared secrets
   * @return KdfKey2
   */
  public static KdfKey2 kdf(KdfMessage message1, KdfMessage message2) {
    if (message1 == null) {
      throw new IllegalArgumentException("Kdf Message 1 was null.");
    } else if (message1.getEcdhSharedSecret() == null) {
      throw new IllegalArgumentException("Ecdh Shared Secret of Message 1 was null.");
    } else if (message1.getEcdhSharedSecret().length != 32) {
      throw new IllegalArgumentException("Length of Ecdh Shared Secret of Message 1 must be 32.");
    } else if (message1.getKyberSharedSecret() == null) {
      throw new IllegalArgumentException("Kyber Shared Secret of Message 1 was null.");
    } else if (message2 == null) {
      throw new IllegalArgumentException("Kdf Message 2 was null.");
    } else if (message2.getEcdhSharedSecret() == null) {
      throw new IllegalArgumentException("Ecdh Shared Secret of Message 2 was null.");
    } else if (message2.getEcdhSharedSecret().length != 32) {
      throw new IllegalArgumentException("Length of Ecdh Shared Secret of Message 2 must be 32.");
    } else if (message2.getKyberSharedSecret() == null) {
      throw new IllegalArgumentException("Kyber Shared Secret of Message 2 was null.");
    }
    List<byte[]> byteArrays = kdf(
      ArrayUtils.addAll(ArrayUtils.addAll(message1.getEcdhSharedSecret(), message1.getKyberSharedSecret()),
        ArrayUtils.addAll(message2.getEcdhSharedSecret(), message2.getKyberSharedSecret())), 5);
    return new KdfKey2(byteArrays.get(0), byteArrays.get(1), byteArrays.get(2), byteArrays.get(3), byteArrays.get(4));
  }

  private static List<byte[]> kdf(byte[] sharedSecret, int numSegments) {
    List<byte[]> encodedKeys = new ArrayList<>();
    int sequenceLength = 32;
    Digest digest = new SHA256Digest();
    HKDFBytesGenerator hkdfBytesGenerator = new HKDFBytesGenerator(digest);
    hkdfBytesGenerator.init(new HKDFParameters(sharedSecret, null, null));

    byte[] out = new byte[numSegments * sequenceLength];
    hkdfBytesGenerator.generateBytes(out, 0, out.length);
    for (int i = 0; i < numSegments; i++) {
      byte[] newEntry = new byte[sequenceLength];
      System.arraycopy(out, i * sequenceLength, newEntry, 0, sequenceLength);
      encodedKeys.add(newEntry);
    }

    return encodedKeys;
  }

  /**
   * Generates an AEAD ciphertext of a plaintext using a given key; AES/GCM is used as Cipher
   * @param key the key (client to server, when using on client; server to client, when using on server)
   * @param plaintext text to be encrypted
   * @return resulting ciphertext
   */
  public static byte[] encryptAead(byte[] key, byte[] plaintext) {
    try {
      if (key.length != 32) {
        throw new IllegalArgumentException("Key length must be 32 bytes");
      }
      byte[] iv = new byte[GCM_IV_LENGTH];
      RANDOM.nextBytes(iv);
      GCMParameterSpec ivParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);

      SecretKey secretKey = new SecretKeySpec(key, "AES");
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

      byte[] ciphertext = cipher.doFinal(plaintext);
      return ArrayUtils.addAll(iv, ciphertext);
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException("Error while encrypting plaintext: " + e.getMessage(), e);
    }
  }

  /**
   * Deciphers an AEAD ciphertext back to a plaintext using a given key; AES/GCM is used as Cipher
   * @param key the key (client to server, when using on server; server to client, when using on client)
   * @param cipherText ciphertext to be decrypted
   * @return the resulting plaintext
   */
  public static byte[] decryptAead(byte[] key, byte[] cipherText) {
    try {
      if (key.length != 32) {
        throw new AssertionError();
      }
      byte[] iv = ArrayUtils.subarray(cipherText, 0, GCM_IV_LENGTH);
      byte[] ct = ArrayUtils.subarray(cipherText, GCM_IV_LENGTH, cipherText.length);

      GCMParameterSpec ivParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);
      SecretKey secretKey = new SecretKeySpec(key, "AES");

      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
      return cipher.doFinal(ct);
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException("Error while decrypting AEAD ciphertext: " + e.getMessage(), e);
    }
  }

  /**
   * reconstructs the ECDH PublicKey using the given key information in encodedPublicKeyParameters
   * @param encodedPublicKeyParameters contains key information
   * @return the reconstructed PublicKey
   */
  public static ECPublicKey cborDecodeEcdhPublicKey(VauEccPublicKey encodedPublicKeyParameters) {
    return encodedPublicKeyParameters.toEcPublicKey();
  }
}

