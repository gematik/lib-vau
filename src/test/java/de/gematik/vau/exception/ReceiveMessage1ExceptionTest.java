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

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import de.gematik.vau.lib.VauClientStateMachine;
import de.gematik.vau.lib.VauServerStateMachine;
import de.gematik.vau.lib.data.*;
import lombok.SneakyThrows;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReceiveMessage1ExceptionTest {

    private VauServerStateMachine server;
    private VauClientStateMachine client;

    @BeforeEach
    @SneakyThrows
    void prepareStateMachines() {
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

        server = new VauServerStateMachine(signedPublicVauKeys, serverVauKeyPair, (byte) 0);
        client = new VauClientStateMachine();
    }

    @SneakyThrows
    @Test
    void testWrongMessageException() {
        final byte[] message1Encoded = client.generateMessage1();
        final byte[] message2Encoded = server.receiveMessage(message1Encoded);
        assertThatThrownBy(() -> server.receiveMessage(message2Encoded)).isInstanceOf(UnsupportedOperationException.class);
    }

    @SneakyThrows
    @Test
    void testWrongCrvException() {
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        VauEccPublicKey eccPublicKey = new VauEccPublicKey("not P-256", x, y);
        VauMessage1 vauMessage1 = setVauMessage1EccPublicKey(eccPublicKey);
        CBORMapper cborMapper = new CBORMapper();
        byte[] message1Encoded = cborMapper.writeValueAsBytes(vauMessage1);
        assertThatThrownBy(() -> server.receiveMessage(message1Encoded)).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("CRV Value of ECDH Public Key in VAU Message 1 must be 'P-256'. Actual value is ");
    }

    @SneakyThrows
    @Test
    void testWrongXLengthException() {
        byte[] x = new byte[20];
        byte[] y = new byte[32];
        VauEccPublicKey eccPublicKey = new VauEccPublicKey("P-256", x, y);
        VauMessage1 vauMessage1 = setVauMessage1EccPublicKey(eccPublicKey);
        CBORMapper cborMapper = new CBORMapper();
        byte[] message1Encoded = cborMapper.writeValueAsBytes(vauMessage1);
        assertThatThrownBy(() -> server.receiveMessage(message1Encoded)).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Length of X Value of ECDH Public Key in VAU Message 1 must be 32. Actual length is ");
    }

    @SneakyThrows
    @Test
    void testWrongYLengthException() {
        byte[] x = new byte[32];
        byte[] y = new byte[20];
        VauEccPublicKey eccPublicKey = new VauEccPublicKey("P-256", x, y);
        VauMessage1 vauMessage1 = setVauMessage1EccPublicKey(eccPublicKey);
        CBORMapper cborMapper = new CBORMapper();
        byte[] message1Encoded = cborMapper.writeValueAsBytes(vauMessage1);
        assertThatThrownBy(() -> server.receiveMessage(message1Encoded)).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Length of Y Value of ECDH Public Key in VAU Message 1 must be 32. Actual length is ");
    }

    @SneakyThrows
    @Test
    void testWrongKyberException() {
        byte[] invalidKyberBytes = new byte[10];
        EccKyberKeyPair clientKey1 = EccKyberKeyPair.generateRandom();
        Class<?> vauMessage1Class = Class.forName("de.gematik.vau.lib.data.VauMessage1");
        VauMessage1 vauMessage1 = (VauMessage1) vauMessage1Class.getDeclaredConstructor(EccKyberKeyPair.class).newInstance(clientKey1);
        Field field = vauMessage1Class.getSuperclass().getDeclaredField("kyberPublicKeyBytes");
        field.setAccessible(true);
        field.set(vauMessage1, invalidKyberBytes);

        CBORMapper cborMapper = new CBORMapper();
        byte[] message1Encoded = cborMapper.writeValueAsBytes(vauMessage1);
        assertThatThrownBy(() -> server.receiveMessage(message1Encoded))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Kyber Public Key Bytes in VAU Message 1 are not well formed.");
    }

    private static VauMessage1 setVauMessage1EccPublicKey(VauEccPublicKey eccPublicKey)
            throws ReflectiveOperationException {
        Class<?> vauMessage1Class = Class.forName("de.gematik.vau.lib.data.VauMessage1");
        EccKyberKeyPair clientKey1 = EccKyberKeyPair.generateRandom();
        VauMessage1 vauMessage1 = (VauMessage1) vauMessage1Class.getDeclaredConstructor(EccKyberKeyPair.class).newInstance(clientKey1);
        Field field = vauMessage1Class.getSuperclass().getDeclaredField("ecdhPublicKey");
        field.setAccessible(true);
        field.set(vauMessage1, eccPublicKey);
        return vauMessage1;
    }
}
