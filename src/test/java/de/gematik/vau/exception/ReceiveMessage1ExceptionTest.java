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
import java.io.IOException;
import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
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

        server = new VauServerStateMachine(signedPublicVauKeys, serverVauKeyPair);
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

    @SneakyThrows
    @Test
    void testTextInsteadOfBinaryEccKeyFormats() {
        final byte[] message1Encoded = Base64.decodeBase64("o2tNZXNzYWdlVHlwZWJNMWdFQ0RIX1BLo2NjcnZlUC0yNTZheHgsNHRxWkk2Ry9rRVBJY3k5ODBsVEJPc0pBZ2gzR0Z0WmxYM2E1V3NqNjJ6Yz1heXgsS3VKWTVKSjdKSkQ4VFZNWHZDTGFINXB2NnFSbklHMzBkck4wZDAzNU96VT1rS3liZXI3NjhfUEt5Biwvall0b3lJcExtaENuSFcrZmd0ejIwcHQxeUoxZ2Z3T3YvWS92eUMrd2drOVA1d2JBa09acHZ4TldvcHlZU2xJYlNHUTVacWtJeUc3WDBBL1l5UUVBR2VnaGVBK0tNS05scFZ6Yjd1MGQ0bkk1R1k2bmtRc3AvSEVXY21CNTJpK2IrR08wMUV5NGxiREpDUENockEzLytRKzRkTzhjeXVGTjVaRXhmdG5aQW05VE1FYUdWbEQ1dUtqaDNrRUpuRVpSN2c0WHZNTDQ3VXZMd09PN01oYmtnaGFuYktEd0lqTk1HR3lpTWVSTXBDN3dTVXp2UE5tUDFKcWVuUmxEYXRvWC9nUEV6eE8zdnBFZmlGQW44dHZiU292NWZDcVNUQzRxcHdObmpxL0FYVkFOOGFtWFpXS0lMVVdneEpBcWxjek5ESitXZndXWHFHYkdvY1c1V2MrOGxFOFdLbXFRQVZQdXNRT0pBdGF4UW9LRDhaSEZ1WVdhRGdNS1NzQ2JhZEg2TVBKQkNoNTNqT3U1UGlMQm10NEI3S2t0bENJTm5GOWpFbXlBNFp5a29sYkdzWVBwVEExTitjYVRyUTJaYnQxdUZOMStteThHZmtMOUtrUVdLUXJpcXdkcndBckJObEh2WkJlR29vendaeVRRMWQ3QlpFa0ROVWFMK1M4akpJQkJ0dElLUmxPZVFkRnFqaVN4WXZPUmtiT2p6UXJMUEkyQ01SRG5uYUF6b2V6L1J1VDdwd2J0YWRLblBBemg0Uk9nRWRBQUFtb1dkWVc3SnluQk9RMTNyTWRsc01Qam9zcWliU0FwMEdQVDNOcTlpWm5JcWdVaDhvWUZNSTlpdU5HY2JsWFpXTkJRY0dZUnFTcUliWisxU3NOR1hwM290SXNMWlU5c1hTVGVLUWRiTkF4RFNtS29vQTNlVEI2bk54NDdxU3NqWko5NDdBREdXZDFPUldTT1Vkc21rRllLU1ZNaGlFTG5XVTRLaE9BUm1pbnEyQzIxN0t1b2Z5d1l0aXFWOUc5YWhBZERNcVAwSU1NZm1DdE0rcFk2Wm1uLzhoUTNGaU1uS1NERE1rTGtEVnl5a1FqRm5wSEJoeGNOblMycnpVSjVGYkRvQ09ySmNBOWgvaTNRUmh0NXRNeE1paGxOemhyWWJzZFlOd1pXcldpbjVLQ1NDTnlaNmdHcXREQ01iTWRYdHNGVm9ESXFNZVJMVnhqNHhSS2RXVlFyN2ljTXpnS2tIcHZMeFZ2aTRDV290YzRTQ2tHUEtaY1hSSVJ5Z1NIN3hrOUR0YWVhZ3dla3ZJZXlQSW9Eb2s5VjdDcllpeE1hTFpPcVhHT2F5UE13amF6S2p0MEd6R2VMd0ZTUHdBbGQyZU0yOFNUT3dNUmoxU1habEJ0UVlQR3Rxa3lhSXdiR1phY3BjWldaMGZBRWtReFFyaHBDVU40ME5sSmJuVXFDRkk1MlViT1UzRUtlK3dkY0N3aFdWT21iT2UyNi9LRTA4aW9ndnVxeVR3eVBSa1RiREZtWnl0VWVySmxIM2tmaFlRUkZEY0ZUMll2V3ltRkQzbk83aWxQMkF1VDFWSEFSc0M0Q3VGdkg5Qmh0alFCeWlSeDhXcTd1enA1U05TS2diTXhzR0VpZ29ZRUtsV1hheHRlKzlZaTh6ZFBNN2R3blZhV1AzUlUzN3M1TmVObjZrTzZOZlBKZUtwbmxwcWlwQklxSTVPMXpxU00vQ2toU2NheTdHcDRzTnFHNHF2TzloSTMvK3gvTEJXVVR1dW4wMkMyb1JOTVdmUVBYR2lzY2tZSXdBdUdKRmxoUy9lKzQ3eFdteG9RUEZkeGFNU0QwUnlpV09DcU1lQnNsbFhMQ0xTVHZtdUdBUW9IUXZYTzVXdWFEUHhiQnJOWGtYY3dBc040MmdxeU9wQmtBWlNIMnJkL1c2VnN5VWtiZHhjT3VzWlhxYkxISEllVjhBWjl0ZnkvaU1FWXQ3eWkwZ0lpMDNzWWNOYU1oRFNKZzFIR1RzeHg4eEpmREFvaU1JZGIrbmxLdUFCWm5QWEJ2bmdER1M0UjdVejQwK1lUSWVTNkZQQmc3Z1BPekI1RXkrRVJLbWdRU1M4PQ==");
        assertThatThrownBy(() -> server.receiveMessage(message1Encoded)).isInstanceOf(IOException.class);
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
