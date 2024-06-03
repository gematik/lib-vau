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

import de.gematik.vau.lib.crypto.KEM;
import de.gematik.vau.lib.data.*;
import de.gematik.vau.lib.exceptions.VauServerException;
import lombok.Getter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.util.encoders.Hex;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * State machine for the VauServer. An instance of this class is created for each connection. It handles the handshake
 * phase and can then be used to send and receive encrytped messages.
 */
@Slf4j
@Getter
public class VauServerStateMachine extends AbstractVauStateMachine {

  private final SignedPublicVauKeys signedPublicVauKeys;
  private final EccKyberKeyPair serverVauKeys;
  private byte[] c2s; //S_K1_c2s
  private byte[] s2c; //S_K1_s2c
  private KdfMessage kemResult1;
  private KdfMessage kemResult2;
  private byte[] serverTranscript;
  private KdfKey2 serverKey2;
  private long clientRequestCounter;
  private static final int EXPIRATION_DAYS = 30;

  public VauServerStateMachine(SignedPublicVauKeys signedPublicVauKeys, EccKyberKeyPair serverVauKeys) {
    super();

    int iat = signedPublicVauKeys.extractVauKeys().getIat();
    int exp = signedPublicVauKeys.extractVauKeys().getExp();
    if(exp - iat > EXPIRATION_DAYS * 60 * 60 * 24) {
      throw new IllegalArgumentException("Dates of initialization and expiration of server keys can be only up to 30 days apart.");
    }

    this.signedPublicVauKeys = signedPublicVauKeys;
    this.serverVauKeys = serverVauKeys;
  }

  /**
   * Uses decoded Message to create Handshake Message 2 or 4
   * @param encodedMessage CBOR decoded Message 1 or 3
   * @return CBOR decoded Message 2 or 4
   */
  @SneakyThrows
  public byte[] receiveMessage(byte[] encodedMessage) {
    checkCertificateExpired(signedPublicVauKeys.extractVauKeys().getExp());

    Object message = decodeCborMessageToClass(encodedMessage);
    if (message instanceof VauMessage1 message1) {
      return receiveMessage1(message1, encodedMessage);
    } else if (message instanceof VauMessage3 message3) {
      return receiveMessage3(message3, encodedMessage);
    } else {
      throw new UnsupportedOperationException("Message type not supported");
    }
  }

  /**
   * Handshake Message 2: takes public keys from Message 1 and calculates shared secrets in order to generate
   * server-to-client and client-to-server keys; creates Message 2 with aead encrypted public key and
   * the ciphertexts, which are generated using the client PublicKeys
   * @param vauMessage1 Message 1 from Client with the remote PublicKeys
   * @param message1Encoded CBOR encoded Message 1
   * @return Message 2 with aead encrypted publicKey and the ciphertexts
   */
  @SneakyThrows
  private byte[] receiveMessage1(VauMessage1 vauMessage1, byte[] message1Encoded) {
    serverTranscript = message1Encoded;
    verifyClientMessageIsWellFormed(vauMessage1);

    kemResult1 = KEM.encapsulateMessage(vauMessage1.getEcdhPublicKey().toEcPublicKey(),
      vauMessage1.toKyberPublicKey());
    if (log.isTraceEnabled()) {
      log.trace("ecdh_shared_secret: (hexdump) {}", Hex.toHexString(kemResult1.getEcdhSharedSecret()));
      log.trace("Kyber768_shared_secret: (hexdump) {}", Hex.toHexString(kemResult1.getKyberSharedSecret()));
    }
    KdfKey1 kdfServerKey1 = KEM.kdf(kemResult1);
    c2s = kdfServerKey1.getClientToServer();
    s2c = kdfServerKey1.getServerToClient();

    byte[] encodedSignedPublicVauKeys = encodeUsingCbor(signedPublicVauKeys);
    byte[] aeadCiphertextMessage2 = KEM.encryptAead(kdfServerKey1.getServerToClient(),
            encodedSignedPublicVauKeys);
    VauMessage2 message2 = new VauMessage2(kemResult1.getEcdhCt(), kemResult1.getKyberCt(), aeadCiphertextMessage2);
    log.debug("Generated message1: {}", Hex.toHexString(message1Encoded));
    byte[] message2Encoded = encodeUsingCbor(message2);
    serverTranscript = ArrayUtils.addAll(serverTranscript, message2Encoded);
    return message2Encoded;
  }

  /**
   * Handshake Message 4: uses Message3 from Client; aead decrypts the kem certificates; these are then used to
   * create the same KdfKey2 as the client did when receiving message 2. In order to verify that both keys are identical,
   * the client hash is deciphered with the newly generated key and compared with the hashed server transcript.
   * The aead encrypted server hash is then returned in Message 4
   * @param vauMessage3 Message 3 from client, containing aead encrypted kem certificates and client hash
   * @param message3Encoded Message 3 CBOR encoded
   * @return CBOR decoded Message 4 containing the aead encrypted server hash
   */
  @SneakyThrows
  private byte[] receiveMessage3(VauMessage3 vauMessage3, byte[] message3Encoded) {
    try {
      byte[] transcriptServerToCheck = ArrayUtils.addAll(serverTranscript, vauMessage3.getAeadCt());
      serverTranscript = ArrayUtils.addAll(serverTranscript, message3Encoded);

      byte[] kemCertificatesEncoded = KEM.decryptAead(c2s, vauMessage3.getAeadCt());

      VauMessage3InnerLayer kemCertificates;
      try {
        kemCertificates = decodeCborMessageToClass(kemCertificatesEncoded, VauMessage3InnerLayer.class);
      } catch (Exception e) {
        throw new IllegalArgumentException("Could not CBOR decode KEM certificates (inner layer of message 3) when receiving it at client. " + e.getMessage());
      }

      kemResult2 = KEM.decapsulateMessages(kemCertificates, serverVauKeys);
      serverKey2 = KEM.kdf(kemResult1, kemResult2);
      setEncryptionVauKey(new EncryptionVauKey(serverKey2.getServerToClientAppData()));
      setDecryptionVauKey(serverKey2.getClientToServerAppData());
      setKeyId(serverKey2.getKeyId());
      byte[] clientTranscriptHash = KEM.decryptAead(serverKey2.getClientToServerKeyConfirmation(), vauMessage3.getAeadCtKeyKonfirmation());

      byte[] clientVauHashCalculation = DigestUtils.sha256(transcriptServerToCheck);

      if (!Arrays.equals(clientTranscriptHash, clientVauHashCalculation)) {
        throw new InvalidKeyException("Client transcript hash and vau calculation do not equal.");
      }
      byte[] transcriptServerHash = DigestUtils.sha256(serverTranscript);
      byte[] aeadCiphertextMessage4KeyKonfirmation = KEM.encryptAead(serverKey2.getServerToClientKeyConfirmation(), transcriptServerHash);
      VauMessage4 message4 = new VauMessage4("M4", aeadCiphertextMessage4KeyKonfirmation);
      return encodeUsingCbor(message4);
    }
    catch (Exception e) {
      throw new VauServerException(e);
    }
  }

  @Override
  protected long getRequestCounter() {
    return clientRequestCounter;
  }

  @Override
  public byte getRequestByte() {
    return 2;
  }

  @Override
  protected void checkRequestCounter(long reqCtr) {
    this.clientRequestCounter = reqCtr;
  }

  @Override
  protected void checkRequestByte(byte reqByte) {
    if (reqByte != 1) {
      throw new UnsupportedOperationException("Request byte was unexpected. Expected 1, but got " + reqByte);
    }
  }

  @Override
  protected boolean validateKeyId(byte[] keyId) {
    return Arrays.equals(serverKey2.getKeyId(), keyId);
  }

  private void verifyClientMessageIsWellFormed(VauMessage1 vauMessage1) {
    verifyEccPublicKey(vauMessage1.getEcdhPublicKey());
    try {
      vauMessage1.toKyberPublicKey();
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
      throw new IllegalArgumentException("Kyber Public Key Bytes in VAU Message 1 are not well formed.", e);
    }
  }
}
