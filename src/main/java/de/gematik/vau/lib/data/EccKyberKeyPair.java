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


package de.gematik.vau.lib.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import de.gematik.vau.lib.crypto.EllipticCurve;
import de.gematik.vau.lib.crypto.KyberEncoding;
import de.gematik.vau.lib.util.ArrayUtils;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import lombok.*;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.encoders.Hex;

@Data
public class EccKyberKeyPair {

  private static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

  protected static final byte[] KYBER_PUBLIC_KEY_ENCODING_HEADER = Hex.decode(
       "308204B2300B0609608648016503040402038204A100");
  
  protected static final byte[] KYBER_PRIVATE_KEY_ENCODING_HEADER = Hex.decode(
      "30820978020100300B06096086480165030404020482096404820960");

  @JsonIgnore
  private final KeyPair eccKeyPair;
  @JsonIgnore
  private final KeyPair kyberKeyPair;

  /**
   * Generates a random ECDH key pair and a random Kyber-768 key pair
   *
   * @return EccKyberKeyPair, which is the object containing both key pairs
   */
  @SneakyThrows
  public static EccKyberKeyPair generateRandom() {
    KeyPair ecdhKeyPair = EllipticCurve.generateKeyPair();
    KeyPair kybKeyPair = KyberEncoding.generateKeyPair();

    return new EccKyberKeyPair(ecdhKeyPair, kybKeyPair);
  }

  @SneakyThrows
  public static EccKyberKeyPair readFromFile(Path file) {
    final CBORMapper cborMapper = new CBORMapper();
    final JsonNode tree = cborMapper.readTree(Files.readAllBytes(file));

    final byte[] eccPrivateKeyData = tree.get("ECDH_PrivKey").binaryValue();
    final byte[] kyberPublicKeyData = tree.get("Kyber768_PK").binaryValue();
    final byte[] kyberPrivateKeyData = tree.get("Kyber768_PrivKey").binaryValue();
    var eccKeyPair = readEcdsaKeypairFromPkcs8Pem(eccPrivateKeyData);
    var kyberKeyPair = readKyberKeypairFromPkcs8Pem(kyberPrivateKeyData, kyberPublicKeyData);
    return new EccKyberKeyPair(eccKeyPair, kyberKeyPair);
  }

  @SneakyThrows
  private static KeyPair readKyberKeypairFromPkcs8Pem(byte[] kyberPrivateKeyData, byte[] kyberPublicKeyData) {
    final String keyType = "KYBER";
    KeyFactory keyFactory = KeyFactory.getInstance(keyType, new BouncyCastlePQCProvider());

    X509EncodedKeySpec kyberPubKey = new X509EncodedKeySpec(
      ArrayUtils.unionByteArrays(KYBER_PUBLIC_KEY_ENCODING_HEADER, kyberPublicKeyData),
      keyType);
    PKCS8EncodedKeySpec kyberPrivKey = new PKCS8EncodedKeySpec(
      ArrayUtils.unionByteArrays(KYBER_PRIVATE_KEY_ENCODING_HEADER, kyberPrivateKeyData),
      keyType);

    return new KeyPair(
      keyFactory.generatePublic(kyberPubKey),
      keyFactory.generatePrivate(kyberPrivKey)
    );
  }

  @SneakyThrows
  public static KeyPair readEcdsaKeypairFromPkcs8Pem(byte[] eccPrivateKeyData) {
    KeyFactory factory = KeyFactory.getInstance("ECDSA", BOUNCY_CASTLE_PROVIDER);
    PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(eccPrivateKeyData);
    final BCECPrivateKey privateKey = (BCECPrivateKey) factory.generatePrivate(privKeySpec);
    KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", BOUNCY_CASTLE_PROVIDER);

    ECParameterSpec ecSpec = privateKey.getParameters();
    ECPoint q = ecSpec.getG().multiply(privateKey.getD());

    ECPublicKeySpec pubSpec = new ECPublicKeySpec(q, ecSpec);
    return new KeyPair(keyFactory.generatePublic(pubSpec), privateKey);
  }
}
