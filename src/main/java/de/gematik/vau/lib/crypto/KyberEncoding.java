/*-
 * #%L
 * lib-vau
 * %%
 * Copyright (C) 2025 gematik GmbH
 * %%
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
 * 
 * *******
 * 
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */


package de.gematik.vau.lib.crypto;

import de.gematik.vau.lib.exceptions.VauKyberCryptoException;
import java.security.*;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class KyberEncoding {
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final String BC_PQC_PROVIDER = BouncyCastlePQCProvider.PROVIDER_NAME;
  private static final String ALGORITHM = "KYBER";

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

      final var bcResult = (SecretKeyWithEncapsulation) keyGen.generateKey();
      byte[] ct = bcResult.getEncapsulation();
      byte[] sharedSecret = bcResult.getEncoded();

      // This trick is necessary since BouncyCastle does not implement Kyber versio 3.0.2, but rather the current draft
      // The trick is derived from https://words.filippo.io/dispatches/mlkem768/#bonus-track-using-a-ml-kem-implementation-as-kyber-v3
      byte[] resultSecret = ArrayUtils.subarray(shake256(ArrayUtils.addAll(sharedSecret, shaThree256(ct))), 0, 32);

      return new SecretKeyWithEncapsulation(new SecretKeySpec(resultSecret, bcResult.getAlgorithm()), ct);
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
      throw new VauKyberCryptoException("Error while generating kyber encryption key", e);
    }
  }

  /**
   * Generates a shared secret using a Kyber PrivateKey and a binary encapsulated key
   * @param privateKey the private key
   * @param ct the encapsulated key
   * @return the shared secret
   */
  public static byte[] pqcGenerateDecryptionKey(PrivateKey privateKey, byte[] ct) {
    try {
      var keyGen = KeyGenerator.getInstance(ALGORITHM, BC_PQC_PROVIDER);
      keyGen.init(new KEMExtractSpec(privateKey, ct, "AES"), SECURE_RANDOM);
      SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation) keyGen.generateKey();

      // This trick is necessary since BouncyCastle does not implement Kyber versio 3.0.2, but rather the current draft
      // The trick is derived from https://words.filippo.io/dispatches/mlkem768/#bonus-track-using-a-ml-kem-implementation-as-kyber-v3
      return ArrayUtils.subarray(shake256(ArrayUtils.addAll(secEnc2.getEncoded(), shaThree256(ct))), 0, 32);
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
      throw new VauKyberCryptoException("Error while generating kyber decryption key", e);
    }
  }

  private static byte[] shake256(byte[] input) {
    byte[] result = new byte[64];
    final SHAKEDigest digest = new SHAKEDigest(256);
    digest.update(input, 0, input.length);
    digest.doFinal(result, 0, 64);
    return result;
  }

  private static byte[] shaThree256(byte[] input) {
    byte[] result = new byte[32];
    final SHA3Digest digest = new SHA3Digest(256);
    digest.update(input, 0, input.length);
    digest.doFinal(result, 0);
    return result;
  }
}
