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

import de.gematik.vau.lib.exceptions.VauKyberCryptoException;
import java.security.*;
import javax.crypto.KeyGenerator;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

public class KyberEncoding {
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final String BC_PQC_PROVIDER = BouncyCastlePQCProvider.PROVIDER_NAME;
  private static final String ALGORITHM = "KYBER";

  private KyberEncoding() {
    // Prevent instantiation by making the constructor private
  }

  /**
   * Generate a Kyber KeyPair
   * @return the KeyPair
   */
  public static KeyPair generateKeyPair() {
    try {
      KyberParameterSpec kyberParameterSpec = KyberParameterSpec.kyber768;
      KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM, BC_PQC_PROVIDER);
      kpg.initialize(kyberParameterSpec, SECURE_RANDOM);
      return kpg.generateKeyPair();
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
      throw new VauKyberCryptoException("Error while generating Kyber KeyPair", e);
    }
  }

  /**
   * Creates a Kyber Secret with encapsulation for a Kyber PublicKey
   * @param publicKey the PublicKey
   * @return the secret with encapsulation
   */
  public static SecretKeyWithEncapsulation pqcGenerateEncryptionKey(PublicKey publicKey) {
    try {
      var keyGen = KeyGenerator.getInstance(ALGORITHM, BC_PQC_PROVIDER);
      keyGen.init(new KEMGenerateSpec(publicKey, "AES"), SECURE_RANDOM);
      return (SecretKeyWithEncapsulation) keyGen.generateKey();
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
      throw new VauKyberCryptoException("Error while generating kyber encryption key", e);
    }
  }

  /**
   * Generates a shared secret using a Kyber PrivateKey and a binary encapsulated key
   * @param privateKey the private key
   * @param encapsulatedKey the encapsulated key
   * @return the shared secret
   */
  public static byte[] pqcGenerateDecryptionKey(PrivateKey privateKey, byte[] encapsulatedKey) {
    try {
      var keyGen = KeyGenerator.getInstance(ALGORITHM, BC_PQC_PROVIDER);
      keyGen.init(new KEMExtractSpec(privateKey, encapsulatedKey, "AES"), SECURE_RANDOM);
      SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation) keyGen.generateKey();
      return secEnc2.getEncoded();
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
      throw new VauKyberCryptoException("Error while generating kyber decryption key", e);
    }
  }
}
