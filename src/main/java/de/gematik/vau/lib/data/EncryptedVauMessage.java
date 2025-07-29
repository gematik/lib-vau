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

import static de.gematik.vau.lib.util.ArrayUtils.unionByteArrays;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.util.encoders.Hex;

@Getter
@Slf4j
// A_24628 - encrypted VAU messsage with user data
public class EncryptedVauMessage {

  private final byte[] message;

  private final byte[] header;
  private final byte   version;
  private final byte   pu;
  private final byte   request;
  private final byte[] requestCounter;
  private final byte[] keyId;

  private final byte[] iv;
  private final byte[] ct;

  private final boolean isPu;
  private static final int MINIMUM_CIPHERTEXT_LENGTH = 1 + 1 + 1 + 8 + 32 + 12 + 1 + 16; //A_24628

  public EncryptedVauMessage(byte[] message, boolean isPu) {
    this.isPu = isPu;
    if (message.length < MINIMUM_CIPHERTEXT_LENGTH) {
      throw new IllegalArgumentException(
          "Invalid ciphertext length. Needs to be at least " + MINIMUM_CIPHERTEXT_LENGTH +
              " bytes, but we received " + message.length + " bytes!");
    }

    this.message = message;
    this.header = ArrayUtils.subarray(message, 0, 43);
    this.version = header[0];
    this.pu = header[1];
    this.request = header[2];
    this.requestCounter = ArrayUtils.subarray(header, 3, 3 + 8);
    this.keyId = ArrayUtils.subarray(header, 11, header.length);
    this.iv = ArrayUtils.subarray(message, 43, 43 + 12);
    this.ct = ArrayUtils.subarray(message, 55, message.length);
  }

  public void checkCommonMessageParameters() {
    if (version != 0x02) {
      throw new IllegalArgumentException(
          "Invalid version byte. Expected 2, got %s".formatted(version));
    }
    int expectedPu = isPu ? 0x01 : 0x00;
    if (pu != (byte) (expectedPu)) {
      throw new IllegalArgumentException(
          "Invalid PU byte. Expected %s, but got %s".formatted(expectedPu, pu));
    }
  }

  public void logAsTrace(byte[] serverSecretKey) {
    log.trace(
        """
        trying to decrypt:
              Complete message     : {}
              Message size (Bytes) : {}
              Complete header      : {}
              Key to decrypt (K2_c2s_app_data): {}
              -------------------------------
              Version  (1 Byte): {}
              PU       (1 Byte): {}
              Request  (1 Byte): {}
              Counter  (8 Byte): {}
              KeyId   (32 Byte): {}
              IV      (12 Byte): {}
              CT + GMAC        : {}
        """,
        Hex.toHexString(message),
        message.length,
        Hex.toHexString(header),
        Hex.toHexString(serverSecretKey),

        Hex.toHexString(unionByteArrays(version)),
        Hex.toHexString(unionByteArrays(pu)),
        Hex.toHexString(unionByteArrays(request)),
        Hex.toHexString(requestCounter),
        Hex.toHexString(keyId),

        Hex.toHexString(iv),
        Hex.toHexString(ct));
  }
}
