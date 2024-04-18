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
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import java.security.PrivateKey;
import java.security.Signature;
import lombok.*;
import org.apache.commons.codec.digest.DigestUtils;

@Value
@NoArgsConstructor(force = true, access = AccessLevel.PRIVATE)
@AllArgsConstructor
@Builder
public class SignedPublicVauKeys {

  private static final CBORMapper CBOR_MAPPER = new CBORMapper();

  @JsonProperty("signed_pub_keys")
  byte[] signedPubKeys;
  @JsonProperty("signature-ES256")
  byte[] signatureEs256;
  @JsonProperty("cert_hash")
  byte[] certHash;
  @JsonProperty("cdv")
  int cdv;
  @JsonProperty("ocsp_response")
  byte[] ocspResponse;

  /**
   * Builds the SignedPublicVauKeys using the input
   * @param serverAutCertificate decrypted server certificate in bytes
   * @param privateKey corresponding private key
   * @param ocspResponseAutCertificate decrypted OCSP response authorization certificate of client in bytes
   * @param cdv Cert-Data-Version (natural number, starting at 1)
   * @param vauServerKeys public keys of server
   * @return the SignedPublicVauKeys
   */
  @SneakyThrows
  public static SignedPublicVauKeys sign(byte[] serverAutCertificate, PrivateKey privateKey,
    byte[] ocspResponseAutCertificate, int cdv, VauPublicKeys vauServerKeys) {

    final byte[] keyBytes = CBOR_MAPPER.writeValueAsBytes(vauServerKeys);
    return SignedPublicVauKeys.builder()
      .signedPubKeys(keyBytes)
      .certHash(DigestUtils.sha256(serverAutCertificate))
      .cdv(cdv)
      .ocspResponse(ocspResponseAutCertificate)
      .signatureEs256(generateEccSignature(keyBytes, privateKey))
      .build();
  }

  private static byte[] generateEccSignature(byte[] tbsData, PrivateKey privateKey) {
    try {
      Signature ecdsaSignature = Signature.getInstance("SHA256withECDSA");
      ecdsaSignature.initSign(privateKey);
      ecdsaSignature.update(tbsData);
      return ecdsaSignature.sign();
    } catch (Exception e) {
      throw new RuntimeException("Error while generating signature", e);
    }
  }

  public VauPublicKeys extractVauKeys() {
    try {
      return CBOR_MAPPER.readValue(signedPubKeys, VauPublicKeys.class);
    } catch (Exception e) {
      throw new RuntimeException("Error while extracting VauKeys", e);
    }
  }
}
