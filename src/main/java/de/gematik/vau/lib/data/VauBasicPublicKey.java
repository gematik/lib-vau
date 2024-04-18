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

package de.gematik.vau.lib.data;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

@Data
@AllArgsConstructor
@Slf4j
public class VauBasicPublicKey {

  @JsonProperty("ECDH_PK")
  private final VauEccPublicKey ecdhPublicKey;
  @JsonProperty("Kyber768_PK")
  private final byte[] kyberPublicKeyBytes;

  @SneakyThrows
  public VauBasicPublicKey(EccKyberKeyPair keyPair) {
    this.ecdhPublicKey = new VauEccPublicKey((ECPublicKey) keyPair.getEccKeyPair().getPublic());
    this.kyberPublicKeyBytes = keyPair.getKyberKeyPair().getPublic().getEncoded();
  }

  public PublicKey toKyberPublicKey() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
    X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(kyberPublicKeyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("KYBER", "BCPQC");
    return keyFactory.generatePublic(x509EncodedKeySpec);
  }
}
