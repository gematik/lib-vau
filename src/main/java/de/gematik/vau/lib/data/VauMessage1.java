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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.SneakyThrows;

@Getter
public class VauMessage1 extends VauBasicPublicKey {

  @JsonProperty("MessageType")
  private final String messageType;

  @SneakyThrows
  public VauMessage1(EccKyberKeyPair clientKey1) {
    super(clientKey1);
    messageType = "M1";
  }

  @JsonCreator(mode = JsonCreator.Mode.PROPERTIES)
  public VauMessage1(@JsonProperty("ECDH_PK") VauEccPublicKey ecdhPublicKey,
    @JsonProperty("Kyber768_PK") byte[] kyberPublicKey, @JsonProperty("MessageType") String messageType) {
    super(ecdhPublicKey, kyberPublicKey);
    this.messageType = messageType;
  }
}
