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

package de.gematik.vau;


import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import de.gematik.vau.lib.VauClientStateMachine;
import de.gematik.vau.lib.VauServerStateMachine;
import de.gematik.vau.lib.data.EccKyberKeyPair;
import de.gematik.vau.lib.data.SignedPublicVauKeys;
import de.gematik.vau.lib.data.VauPublicKeys;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.kyber.BCKyberPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.kyber.BCKyberPublicKey;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

@Slf4j
class VauHandshakeTest {

  private static final int KYBER_768_BYTE_LENGTH = 1184;
  private static final String TGR_FILENAME = "target/vau3traffic.tgr";

  static {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new BouncyCastleProvider());
  }

  private int msgNumber = 0;

  @BeforeEach
  public void setUp() {
    final Logger logger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    logger.setLevel(Level.TRACE);
  }

  @SneakyThrows
  @Test
  void testHandshake() {
    Files.deleteIfExists(Path.of(TGR_FILENAME));

    KeyFactory keyFactory = KeyFactory.getInstance("EC");
    PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(
      Files.readAllBytes(Path.of("src/test/resources/vau-sig-key.der")));
    PrivateKey serverAutPrivateKey = keyFactory.generatePrivate(privateSpec);
    final EccKyberKeyPair serverVauKeyPair = EccKyberKeyPair.readFromFile(
      Path.of("src/test/resources/vau_server_keys.cbor"));
    final VauPublicKeys serverVauKeys = new VauPublicKeys(serverVauKeyPair, "VAU Server Keys", Duration.ofDays(30));
    var signedPublicVauKeys = SignedPublicVauKeys.sign(
      Files.readAllBytes(Path.of("src/test/resources/vau_sig_cert.der")), serverAutPrivateKey,
      Files.readAllBytes(Path.of("src/test/resources/ocsp-response-vau-sig.der")),
      1, serverVauKeys);

    assertThat(serverVauKeyPair.getEccKeyPair().getPublic().getAlgorithm()).startsWith("EC");
    assertThat(serverVauKeyPair.getEccKeyPair().getPrivate().getAlgorithm()).startsWith("EC");

    assertThat(assertPublicKeyAlgorithm(serverVauKeyPair.getEccKeyPair().getPublic())).isTrue();
    assertThat(assertPrivateKeyAlgorithm(serverVauKeyPair.getEccKeyPair().getPrivate())).isTrue();

    assertThat(serverVauKeyPair.getKyberKeyPair().getPublic().getAlgorithm()).isEqualTo("KYBER768");
    assertThat(serverVauKeyPair.getKyberKeyPair().getPrivate().getAlgorithm()).isEqualTo("KYBER768");
    assertThat(
      ((BCKyberPublicKey) serverVauKeyPair.getKyberKeyPair().getPublic()).getParameterSpec().getName()).isEqualTo(
      "KYBER768");
    assertThat(
      ((BCKyberPrivateKey) serverVauKeyPair.getKyberKeyPair().getPrivate()).getParameterSpec().getName()).isEqualTo(
      "KYBER768");

    VauServerStateMachine server = new VauServerStateMachine(signedPublicVauKeys, serverVauKeyPair);
    VauClientStateMachine client = new VauClientStateMachine();

    final byte[] message1Encoded = client.generateMessage1();
    final JsonNode message1Tree = new CBORMapper().readTree(message1Encoded);
    assertThat(message1Tree.get("MessageType").textValue()).isEqualTo("M1");
    assertThat(containsKyberEncodedOfLength(message1Tree.get("Kyber768_PK").binaryValue())).isTrue();

    final byte[] message2Encoded = server.receiveMessage(message1Encoded);
    final JsonNode message2Tree = new CBORMapper().readTree(message2Encoded);
    assertThat(message2Tree.get("MessageType").textValue()).isEqualTo("M2");
    assertThat(message2Tree.get("Kyber768_ct").binaryValue()).hasSize(1088);
    log.debug("AEAD_ct length: {}", message2Tree.get("AEAD_ct").binaryValue().length);
    assertThat(message2Tree.get("AEAD_ct").binaryValue()).hasSizeBetween(1550, 1557);
    log.debug("x: {}", Hex.toHexString(message1Tree.get("ECDH_PK").get("x").binaryValue()));
    log.debug("y: {}", Hex.toHexString(message1Tree.get("ECDH_PK").get("y").binaryValue()));

    final byte[] message3Encoded = client.receiveMessage2(message2Encoded);

    assertThat(client.getKdfClientKey1().getServerToClient())
      .isEqualTo(server.getS2c());
    assertThat(client.getKdfClientKey1().getClientToServer())
      .isEqualTo(server.getC2s());

    byte[] message4Encoded = server.receiveMessage(message3Encoded);
    client.receiveMessage4(message4Encoded);

    final byte[] encryptedClientVauMessage = client.encryptVauMessage("Hello World".getBytes());
    final byte[] decryptedClientVauMessage = server.decryptVauMessage(encryptedClientVauMessage);
    assertThat(decryptedClientVauMessage).isEqualTo("Hello World".getBytes());

    final byte[] encryptedServerVauMessage = server.encryptVauMessage("Right back at ya!".getBytes());
    final byte[] decryptedServerVauMessage = client.decryptVauMessage(encryptedServerVauMessage);
    assertThat(encryptedClientVauMessage[0]).isEqualTo((byte) 2);
    assertThat(encryptedClientVauMessage[1]).isEqualTo((byte) 0);
    assertThat(encryptedClientVauMessage[2]).isEqualTo((byte) 1);
    assertThat(ArrayUtils.subarray(encryptedClientVauMessage, 3, 3 +
                                                                 8))
      .isEqualTo(new byte[]{0, 0, 0, 0, 0, 0, 0, 1});
    assertThat(ArrayUtils.subarray(encryptedClientVauMessage, 11, 11 + 32))
      .isEqualTo(client.getKeyId());

    assertThat(decryptedServerVauMessage).isEqualTo("Right back at ya!".getBytes());

    bundleInHttpRequestAndWriteToFile("/vau", message1Encoded);
    final String vauCid = "/vau/URL-von-der-VAU-waehrend-des-Handshakes-gewaehlt-abcdefghij1234567890";
    bundleInHttpResponseAndWriteToFile(message2Encoded, Pair.of("VAU-DEBUG-S_K1_s2c",
        java.util.Base64.getEncoder().encodeToString(server.getS2c())),
      Pair.of("VAU-DEBUG-S_K1_c2s",
        java.util.Base64.getEncoder().encodeToString(server.getC2s())),
      Pair.of("VAU-CID", vauCid));
    bundleInHttpRequestAndWriteToFile(vauCid, message3Encoded);
    bundleInHttpResponseAndWriteToFile(message4Encoded);
    bundleInHttpRequestAndWriteToFile(vauCid, encryptedClientVauMessage, Pair.of("VAU-nonPU-Tracing",
      Base64.toBase64String(server.getServerKey2().getClientToServerAppData()) + " " + Base64.toBase64String(
        server.getServerKey2().getServerToClientAppData()) + "\n"));
    bundleInHttpResponseAndWriteToFile(encryptedServerVauMessage);

    Files.write(Path.of("target/serverEcc.pem"), writeKeyPair(serverVauKeyPair.getEccKeyPair()).getBytes());
    Files.write(Path.of("target/serverKyber.pem"), writeKeyPair(serverVauKeyPair.getKyberKeyPair()).getBytes());
  }

  @SneakyThrows
  private static boolean containsKyberEncodedOfLength(byte[] encoded) {
    return encoded.length == KYBER_768_BYTE_LENGTH;
  }

  private static boolean assertPublicKeyAlgorithm(PublicKey key) {
    byte[] encoded = key.getEncoded();
    ASN1Sequence asn1 = ASN1Sequence.getInstance(encoded);
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(asn1);
    return publicKeyInfo.getAlgorithm().getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey);
  }

  private static boolean assertPrivateKeyAlgorithm(PrivateKey key) {
    byte[] encoded = key.getEncoded();
    ASN1Sequence asn1 = ASN1Sequence.getInstance(encoded);
    PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(asn1);
    return privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey);
  }

  private static String writeKeyPair(KeyPair keyPair) throws IOException {
    final StringWriter printer = new StringWriter();
    JcaPEMWriter writer = new JcaPEMWriter(printer);
    PemObject obj = new org.bouncycastle.openssl.PKCS8Generator(
      PrivateKeyInfo.getInstance(keyPair.getPrivate().getEncoded()), null).generate();
    writer.writeObject(obj);
    writer.writeObject(keyPair.getPublic());
    writer.flush();
    writer.close();

    return printer.toString();
  }

  @SneakyThrows
  private void bundleInHttpRequestAndWriteToFile(String path, byte[] payload,
    Pair<String, String>... additionalHeader) {
    String additionalHeaders = Stream.of(additionalHeader)
      .map(p -> p.getLeft() + ": " + p.getRight())
      .collect(Collectors.joining("\r\n"));
    if (!additionalHeaders.isBlank()) {
      additionalHeaders += "\r\n";
    }
    byte[] httpRequest = ("POST " + path + " HTTP/1.1\r\n"
                          + "Host: vau.gematik.de\r\n"
                          + additionalHeaders
                          + "Content-Type: application/cbor\r\n"
                          + "Content-Length: " + payload.length + "\r\n\r\n").getBytes();

    Files.write(Path.of(TGR_FILENAME), makeTgr(ArrayUtils.addAll(httpRequest, payload)),
      StandardOpenOption.CREATE, StandardOpenOption.APPEND);
  }

  @SneakyThrows
  private void bundleInHttpResponseAndWriteToFile(byte[] payload, Pair<String, String>... additionalHeader) {
    String additionalHeaders = Stream.of(additionalHeader)
      .map(p -> p.getLeft() + ": " + p.getRight())
      .collect(Collectors.joining("\r\n"));
    if (!additionalHeaders.isEmpty()) {
      additionalHeaders += "\r\n";
    }
    byte[] httpRequest = ("HTTP/1.1 200 OK\r\n"
                          + additionalHeaders
                          + "Content-Type: application/cbor\r\n"
                          + "Content-Length: " + payload.length + "\r\n\r\n").getBytes();
    Files.write(Path.of(TGR_FILENAME),
      makeTgr(ArrayUtils.addAll(httpRequest, payload)),
      StandardOpenOption.CREATE, StandardOpenOption.APPEND);
  }

  private byte[] makeTgr(byte[] content) {
    String rec, sen;
    if (msgNumber % 2 == 0) {
      rec = "vau.gematik.de";
      sen = "";
    } else {
      rec = "";
      sen = "vau.gematik.de";
    }
    String result =
      "{\"receiverHostname\":\"" + rec + "\","
      + "\"sequenceNumber\":\"" + msgNumber++ + "\","
      + "\"senderHostname\":\"" + sen + "\","
      + "\"uuid\":\"" + UUID.randomUUID() + "\","
      + "\"rawMessageContent\":\"" + Base64.toBase64String(content) + "\"}\n";
    return result.getBytes();
  }
}
