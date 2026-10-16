/*-
 * #%L
 * lib-vau
 * %%
 * Copyright (C) 2025 - 2026 gematik GmbH
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
 * For additional notes and disclaimer from gematik and in case of changes
 * by gematik, find details in the "Readme" file.
 * #L%
 */

package de.gematik.vau.lib.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import de.gematik.vau.lib.data.EccKyberKeyPair;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.Security;
import lombok.SneakyThrows;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.Test;

class KyberEncodingTest {

  static {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new BouncyCastleProvider());
  }

  /**
   * The VAU server speaks Kyber-768 round 3 (v3.0.2), not ML-KEM. The ciphertext and shared secret
   * in kyber768_v3_kat.cbor were produced by a Kyber v3.0.2 reference implementation against the
   * Kyber768_PK of vau_server_keys.cbor.
   */
  @SneakyThrows
  @Test
  void decapsulatesReferenceKyberV3Ciphertext() {
    KeyPair kyberKeyPair =
        EccKyberKeyPair.readFromFile(Path.of("src/test/resources/vau_server_keys.cbor"))
            .getKyberKeyPair();
    JsonNode kat =
        new CBORMapper()
            .readTree(Files.readAllBytes(Path.of("src/test/resources/kyber768_v3_kat.cbor")));

    byte[] sharedSecret =
        KyberEncoding.pqcGenerateDecryptionKey(
            kyberKeyPair.getPrivate(), kat.get("Kyber768_ct").binaryValue());

    assertThat(sharedSecret).isEqualTo(kat.get("SharedSecret").binaryValue());
  }

  @Test
  void encapsulationRoundTrip() {
    KeyPair kyberKeyPair = KyberEncoding.generateKeyPair();

    var secretWithEncapsulation =
        KyberEncoding.pqcGenerateEncryptionKey(kyberKeyPair.getPublic());

    assertThat(secretWithEncapsulation.getEncapsulation()).hasSize(1088);
    assertThat(
            KyberEncoding.pqcGenerateDecryptionKey(
                kyberKeyPair.getPrivate(), secretWithEncapsulation.getEncapsulation()))
        .isEqualTo(secretWithEncapsulation.getEncoded());
  }
}
