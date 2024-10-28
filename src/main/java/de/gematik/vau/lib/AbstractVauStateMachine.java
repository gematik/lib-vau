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

package de.gematik.vau.lib;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import de.gematik.vau.lib.data.*;
import de.gematik.vau.lib.exceptions.VauDecryptionException;
import de.gematik.vau.lib.exceptions.VauEncryptionException;
import java.security.GeneralSecurityException;
import java.time.*;
import lombok.Getter;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Date;

import static de.gematik.vau.lib.util.ArrayUtils.unionByteArrays;

@Setter
@Getter
@Slf4j
public abstract class AbstractVauStateMachine {

  private static final CBORMapper cborMapper = CBORMapper.builder()
    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
    .build();
  private static final ObjectMapper objectMapper = new ObjectMapper()
    .enable(SerializationFeature.INDENT_OUTPUT);
  private static final String MESSAGE_TYPE = "MessageType";
  private static final int AUTHENTICATION_TAG_BIT_SIZE = 128; //A_24628
  private byte[] keyId;
  private EncryptionVauKey encryptionVauKey;
  private byte[] decryptionVauKey;
  private final boolean isPu;

  AbstractVauStateMachine(boolean isPu) {
    this.isPu = isPu;
  }

  @SneakyThrows
  byte[] encodeUsingCbor(Object value) {
    final byte[] bytes = cborMapper.writeValueAsBytes(value);
    if (log.isDebugEnabled()) {
      log.debug("Encoding message \n{}\nto\n{}", objectMapper.writeValueAsString(value), Hex.toHexString(bytes));
    }
    return bytes;
  }

  @SneakyThrows
  <T> T decodeCborMessageToClass(byte[] encodedMessage) {
    final JsonNode tree = cborMapper.readTree(encodedMessage);
    if (!tree.has(MESSAGE_TYPE) || !tree.get(MESSAGE_TYPE).isTextual()) {
      throw new UnsupportedOperationException("Message type not recognized");
    }
    return switch (tree.get(MESSAGE_TYPE).textValue()) {
      case "M1" -> cborMapper.readerFor(VauMessage1.class).readValue(encodedMessage);
      case "M2" -> cborMapper.readerFor(VauMessage2.class).readValue(encodedMessage);
      case "M3" -> cborMapper.readerFor(VauMessage3.class).readValue(encodedMessage);
      case "M4" -> cborMapper.readerFor(VauMessage4.class).readValue(encodedMessage);
      default -> throw new UnsupportedOperationException(
        "Message type " + tree.get(MESSAGE_TYPE).textValue() + "not supported");
    };
  }

  @SneakyThrows
  <T> T decodeCborMessageToClass(byte[] encodedMessage, Class<T> clazz) {
    return cborMapper.readerFor(clazz).readValue(encodedMessage);
  }

  /**
   * encrypts a message to be sent; handshake has to be completed successfully; described in detail in gemSpec_Krypt
   * A_24628
   *
   * @param cleartext text be encrypted
   * @return the ciphertext
   */
  public byte[] encryptVauMessage(byte[] cleartext) {
    byte versionByte = 2;
    byte puByte = 0;
    byte reqByte = getRequestByte();
    byte[] reqCtrBytes = ByteBuffer.allocate(8).putLong(getRequestCounter()).array();
    byte[] header = unionByteArrays(versionByte, puByte, reqByte, reqCtrBytes, getKeyId());

    byte[] a = new byte[4];
    new SecureRandom().nextBytes(a);

    byte[] iv = unionByteArrays(a, reqCtrBytes);

    byte[] ciphertext = encryptWithAesGcm(encryptionVauKey.getAppData(), iv, cleartext, header);

    final byte[] bytes = unionByteArrays(header, iv, ciphertext);
    if (log.isTraceEnabled()) {
      log.trace("Encoded message: {} with key {} with iv {} with header {}", Hex.toHexString(bytes),
        Hex.toHexString(encryptionVauKey.getAppData()),
        Hex.toHexString(iv), Hex.toHexString(header));
    }
    return bytes;
  }

  protected abstract long getRequestCounter();

  protected abstract byte getRequestByte();

  @SneakyThrows
  private byte[] encryptWithAesGcm(byte[] vauKey, byte[] iv, byte[] cleartext, byte[] associatedData) {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); // NOSONAR
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(vauKey, "AES"),
      new GCMParameterSpec(AUTHENTICATION_TAG_BIT_SIZE, iv));
    cipher.updateAAD(associatedData);
    byte[] ciphertext = cipher.doFinal(cleartext);
    if (ciphertext.length != cleartext.length + AUTHENTICATION_TAG_BIT_SIZE / Byte.SIZE) {
      throw new VauEncryptionException(
        String.format("Calculated Authentication tag must be %s Bytes, but it was %s Bytes.",
          AUTHENTICATION_TAG_BIT_SIZE / Byte.SIZE, ciphertext.length - cleartext.length));
    }
    return ciphertext;
  }

  private byte[] decryptWithAesGcm(byte[] secretKey, byte[] iv, byte[] cipherText, byte[] header)
    throws GeneralSecurityException {
    if (iv.length != 12) {
      throw new IllegalArgumentException("Length of IV must be 12 Bytes.");
    }

    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); // NOSONAR
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(secretKey, "AES"),
      new GCMParameterSpec(AUTHENTICATION_TAG_BIT_SIZE, iv));
    cipher.updateAAD(header);
    return cipher.doFinal(cipherText);
  }

  /**
   * Decrypts a received message; handshake has to be completed successfully; described in detail in gemSpec_Krypt
   * A_24628
   *
   * @param ciphertext the to be decrypted message
   * @return the resulting plaintext
   */
  public byte[] decryptVauMessage(byte[] ciphertext) {
    var message = new EncryptedVauMessage(ciphertext, isPu);

    // trace all
    if (log.isTraceEnabled()) {
      message.logAsTrace(decryptionVauKey);
    }

    // check VAU header information
    message.checkCommonMessageParameters();
    checkRequestByte(message.getRequest());
    checkRequestCounter(ByteBuffer.wrap(message.getRequestCounter()).getLong());
    checkRequestKeyId(message.getKeyId());

    try {
      var cleartext = decryptWithAesGcm(decryptionVauKey, message.getIv(), message.getCt(), message.getHeader());
      if (log.isTraceEnabled()) {
        log.trace("Successful decrypted ct as: \n {}", new String(cleartext));
      }
      return cleartext;
    } catch (GeneralSecurityException e) {
      throw new VauDecryptionException("Exception thrown whilst trying to decrypt VAU message: " + e.getMessage(), e);
    }
  }

  protected abstract void checkRequestCounter(long reqCtr);

  protected abstract void checkRequestByte(byte reqByte);

  protected abstract void checkRequestKeyId(byte[] keyId);

  protected static void checkCertificateExpired(int exp) throws CertificateException {
    Instant now = new Date().toInstant();
    if (exp < now.getEpochSecond()) {
      throw new CertificateException("The server certificate has expired. (exp: "
                                     + ZonedDateTime.ofInstant(Instant.ofEpochSecond(exp), ZoneId.systemDefault())
                                     + ")");
    }
  }

  protected void verifyEccPublicKey(VauEccPublicKey eccPublicKey) {
    if (!eccPublicKey.getCrv().equals("P-256")) {
      throw new IllegalArgumentException(
        "CRV Value of ECDH Public Key in VAU Message 1 must be 'P-256'. Actual value is '" + eccPublicKey.getCrv()
        + "'");
    }
    if (eccPublicKey.getX().length != 32) {
      throw new IllegalArgumentException(
        "Length of X Value of ECDH Public Key in VAU Message 1 must be 32. Actual length is '"
        + eccPublicKey.getX().length + "'");
    }
    if (eccPublicKey.getY().length != 32) {
      throw new IllegalArgumentException(
        "Length of Y Value of ECDH Public Key in VAU Message 1 must be 32. Actual length is '%s'"
        + eccPublicKey.getY().length + "'");
    }
  }
}
