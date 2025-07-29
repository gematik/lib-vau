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

import static de.gematik.vau.lib.data.EccKyberKeyPair.KYBER_PUBLIC_KEY_ENCODING_HEADER;
import com.fasterxml.jackson.annotation.JsonProperty;
import de.gematik.vau.lib.exceptions.VauKeyConversionException;
import de.gematik.vau.lib.util.ArrayUtils;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.jce.interfaces.ECPublicKey;

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
    this.kyberPublicKeyBytes = extractCompactKyberPublicKey(keyPair.getKyberKeyPair());
  }

  private byte[] extractCompactKyberPublicKey(KeyPair kyberKeyPair) {
    try {
      final byte[] verbosePublicKey = kyberKeyPair.getPublic().getEncoded();
      final ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(verbosePublicKey));
      return ((DERBitString) ((DLSequence) asn1InputStream.readObject()).getObjectAt(1)).getBytes();
    } catch (IOException e) {
      throw new VauKeyConversionException("Error during key extraction for Kyber-key", e);
    }
  }

  public PublicKey toKyberPublicKey()
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
    X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
      ArrayUtils.unionByteArrays(KYBER_PUBLIC_KEY_ENCODING_HEADER, kyberPublicKeyBytes));
    KeyFactory keyFactory = KeyFactory.getInstance("KYBER", "BCPQC");
    return keyFactory.generatePublic(x509EncodedKeySpec);
  }
}
