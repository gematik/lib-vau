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

import com.fasterxml.jackson.annotation.JsonIgnore;
import de.gematik.vau.lib.crypto.EllipticCurve;
import de.gematik.vau.lib.crypto.KyberEncoding;
import java.security.KeyPair;
import lombok.*;

@Data
public class EccKyberKeyPair {

  @JsonIgnore
  private final KeyPair eccKeyPair;
  @JsonIgnore
  private final KeyPair kyberKeyPair;

  /**
   * Generates a random ECDH key pair and a random Kyber-768 key pair
   * @return EccKyberKeyPair, which is the object containing both key pairs
   */
  @SneakyThrows
  public static EccKyberKeyPair generateRandom() {
    KeyPair ecdhKeyPair = EllipticCurve.generateKeyPair();
    KeyPair kybKeyPair = KyberEncoding.generateKeyPair();

    return new EccKyberKeyPair(ecdhKeyPair, kybKeyPair);
  }
}
