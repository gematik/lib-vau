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

package de.gematik.vau.exception;

import de.gematik.vau.lib.VauClientStateMachine;
import de.gematik.vau.lib.VauServerStateMachine;
import de.gematik.vau.lib.data.EccKyberKeyPair;
import de.gematik.vau.lib.data.EncryptionVauKey;
import de.gematik.vau.lib.data.SignedPublicVauKeys;
import de.gematik.vau.lib.data.VauPublicKeys;
import de.gematik.vau.lib.exceptions.VauDecryptionException;
import de.gematik.vau.lib.exceptions.VauEncryptionException;
import javax.crypto.AEADBadTagException;
import lombok.SneakyThrows;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DecryptVauMessageExceptionTest {

    private VauServerStateMachine server;
    private VauClientStateMachine client;

    @SneakyThrows
    @BeforeEach
    public void doHandShake() {
        Security.addProvider(new BouncyCastlePQCProvider());
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyFactory keyFactory = KeyFactory.getInstance("EC", "SunEC");
        PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(
                Files.readAllBytes(Path.of("src/test/resources/vau-sig-key.der")));
        PrivateKey serverAutPrivateKey = keyFactory.generatePrivate(privateSpec);
        final EccKyberKeyPair serverVauKeyPair = EccKyberKeyPair.generateRandom();
        final VauPublicKeys serverVauKeys = new VauPublicKeys(serverVauKeyPair, "VAU Server Keys", Duration.ofDays(30));
        var signedPublicVauKeys = SignedPublicVauKeys.sign(
                Files.readAllBytes(Path.of("src/test/resources/vau_sig_cert.der")), serverAutPrivateKey,
                Files.readAllBytes(Path.of("src/test/resources/ocsp-response-vau-sig.der")),
                1, serverVauKeys);

        server = new VauServerStateMachine(signedPublicVauKeys, serverVauKeyPair);
        client = new VauClientStateMachine();
        final byte[] message1Encoded = client.generateMessage1();
        final byte[] message2Encoded = server.receiveMessage(message1Encoded);
        final byte[] message3Encoded = client.receiveMessage2(message2Encoded);
        byte[] message4Encoded = server.receiveMessage(message3Encoded);
        client.receiveMessage4(message4Encoded);
    }

    @SneakyThrows
    @Test
    void testClientEncryptionException() {
        byte[] invalidAppData = new byte[0];
        byte[] test = "test".getBytes();
        client.setEncryptionVauKey(new EncryptionVauKey(invalidAppData));
        assertThatThrownBy(() -> client.encryptVauMessage(test)).isInstanceOf(VauEncryptionException.class);
    }

    @Test
    void testIllegalLengthException() {
        byte[] sizeNotLongEnough = new byte[4];
        assertThatThrownBy(() -> server.decryptVauMessage(sizeNotLongEnough))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Invalid ciphertext length");
    }

    @Test
    void testIllegalVersionByteException() {
        byte[] wrongHeaderByte = new byte[72];
        assertThatThrownBy(() -> server.decryptVauMessage(wrongHeaderByte))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Invalid version byte");
    }

    @Test
    void testIllegalPUByteException() {
        byte[] wrongPUByte = new byte[72];
        wrongPUByte[0] = 2;
        wrongPUByte[1] = 1;
        assertThatThrownBy(() -> server.decryptVauMessage(wrongPUByte))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Invalid PU byte");
    }

    @Test
    void testInvalidKeyException() {
        byte[] simplyNotAValidCiphertext = new byte[72];
        simplyNotAValidCiphertext[0] = 2;
        simplyNotAValidCiphertext[2] = 1;

        assertThatThrownBy(() -> server.decryptVauMessage(simplyNotAValidCiphertext))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Key ID in the header")
            .hasMessageContaining("does not equals");
    }

    @Test
    void testDecryptWithAesGcmException() {
        byte[] onlyHeaderValid = new byte[72];
        onlyHeaderValid[0] = 2;
        onlyHeaderValid[2] = 1;
        byte[] clientKeyId = client.getClientKey2().getKeyId();

        System.arraycopy(clientKeyId, 0, onlyHeaderValid, 11, 32);
        assertThatThrownBy(() -> server.decryptVauMessage(onlyHeaderValid))
          .isInstanceOf(VauDecryptionException.class)
          .hasMessageContaining("Exception thrown whilst trying to decrypt VAU message")
            .hasMessageContaining( "Tag mismatch");
    }
}
