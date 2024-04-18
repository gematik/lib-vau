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

import java.math.BigInteger;
import java.security.*;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.SneakyThrows;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class EllipticCurve {

  private static final ECNamedCurveParameterSpec SEC_P256_CURVE_SPEC = ECNamedCurveTable.getParameterSpec("secp256r1");
  private static final String BC_PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

  /**
   * Generates a ECDH KeyPair
   * @return the KeyPair
   */
  public static KeyPair generateKeyPair() {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", BC_PROVIDER);
      keyPairGenerator.initialize(SEC_P256_CURVE_SPEC, new SecureRandom());
      return keyPairGenerator.generateKeyPair();
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Generates the public key from the transferred X and Y public coordinates
   * @param x X coordinate
   * @param y Y coordinate
   * @return the ECDH PublicKey
   */
  @SneakyThrows
  public static ECPublicKey getPublicKeyFromCoordinates(BigInteger x, BigInteger y) {
    ECPoint ecPoint = SEC_P256_CURVE_SPEC.getCurve().createPoint(x, y);

    ECPublicKeySpec ecKeySpec = new ECPublicKeySpec(ecPoint, SEC_P256_CURVE_SPEC);
    KeyFactory keyFactory = KeyFactory.getInstance("ECDH", BC_PROVIDER);
    return (ECPublicKey) keyFactory.generatePublic(ecKeySpec);
  }

  /**
   * Generates the shared secret using the local PrivateKey and the remote PublicKey
   * @param remoteEcdhPublicKey remote PublicKey
   * @param localEcdhPrivateKey own PrivateKey
   * @throws IllegalArgumentException, if localEcdhPrivateKey is not of instance ECPrivateKey
   * @return the shared secret in bytes
   */
  public static byte[] getSharedSecret(ECPublicKey remoteEcdhPublicKey, PrivateKey localEcdhPrivateKey) {
    if (localEcdhPrivateKey instanceof ECPrivateKey ecPrivateKey) {
      return getSharedSecret(remoteEcdhPublicKey, ecPrivateKey);
    } else {
      throw new IllegalArgumentException("Unsupported private key type " + localEcdhPrivateKey.getClass().getName());
    }
  }

  /**
   * Generates the shared secret using the local PrivateKey and the remote PublicKey
   * @param remoteEcdhPublicKey remote PublicKey
   * @param localEcdhPrivateKey own PrivateKey
   * @return the shared secret in bytes
   */
  public static byte[] getSharedSecret(ECPublicKey remoteEcdhPublicKey, ECPrivateKey localEcdhPrivateKey) {
    ECDHBasicAgreement ecdhBasicAgreement = new ECDHBasicAgreement();

    ECDomainParameters domainParams = new ECDomainParameters(SEC_P256_CURVE_SPEC.getCurve(), SEC_P256_CURVE_SPEC.getG(),
      SEC_P256_CURVE_SPEC.getN(), SEC_P256_CURVE_SPEC.getH(),
      SEC_P256_CURVE_SPEC.getSeed());

    ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(localEcdhPrivateKey.getD(), domainParams);
    ecdhBasicAgreement.init(privateKeyParameters);

    ECPoint ecPoint = SEC_P256_CURVE_SPEC.getCurve().createPoint(remoteEcdhPublicKey.getQ().getXCoord().toBigInteger(),
      remoteEcdhPublicKey.getQ().getYCoord().toBigInteger());

    ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(ecPoint, domainParams);

    BigInteger sharedSecret = ecdhBasicAgreement.calculateAgreement(publicKeyParameters);
    return sharedSecret.toByteArray();
  }
}
