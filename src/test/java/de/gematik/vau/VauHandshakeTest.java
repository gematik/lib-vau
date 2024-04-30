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


import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import de.gematik.vau.lib.VauClientStateMachine;
import de.gematik.vau.lib.VauServerStateMachine;
import de.gematik.vau.lib.crypto.KyberEncoding;
import de.gematik.vau.lib.data.EccKyberKeyPair;
import de.gematik.vau.lib.data.SignedPublicVauKeys;
import de.gematik.vau.lib.data.VauPublicKeys;
import lombok.SneakyThrows;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DLSequence;
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
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class VauHandshakeTest {

  private static final int KYBER_768_BYTE_LENGTH = 1184;
  private static final String TGR_FILENAME = "target/vau3traffic.tgr";

  static {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new BouncyCastleProvider());
  }

  private int msgNumber = 0;

  @SneakyThrows
  @Test
  void testHandshake() {
    Files.deleteIfExists(Path.of(TGR_FILENAME));

    KeyFactory keyFactory = KeyFactory.getInstance("EC");
    PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(
      Files.readAllBytes(Path.of("src/test/resources/vau-sig-key.der")));
    PrivateKey serverAutPrivateKey = keyFactory.generatePrivate(privateSpec);
    final EccKyberKeyPair serverVauKeyPair = EccKyberKeyPair.generateRandom();
    final VauPublicKeys serverVauKeys = new VauPublicKeys(serverVauKeyPair, "VAU Server Keys", Duration.ofDays(30));
    var signedPublicVauKeys = SignedPublicVauKeys.sign(
      Files.readAllBytes(Path.of("src/test/resources/vau_sig_cert.der")), serverAutPrivateKey,
      Files.readAllBytes(Path.of("src/test/resources/ocsp-response-vau-sig.der")),
      1, serverVauKeys);

    assertThat(serverVauKeyPair.getEccKeyPair().getPublic().getAlgorithm()).isEqualTo("ECDH");
    assertThat(serverVauKeyPair.getEccKeyPair().getPrivate().getAlgorithm()).isEqualTo("ECDH");

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
    assertThat(message2Tree.get("AEAD_ct").binaryValue()).hasSizeBetween(1000, 2000);

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

  String KyberPublicKeyEncodingHeader = "308204B4300D060B2B0601040181B01A050602038204A100";
  String KyberPrivateKeyEncodingHeader = "3082097A020100300D060B2B0601040181B01A0506020482096404820960";

  // replace with self generated values for reference
  String KyberPublicKey = "e816935144418bfb9940eb80d386b43af0ca7329a1d729c915603e13d63bb24ac80f13873b736f25a31064595aeba85d089a7a2e657db5a876a4e49ccf77ba0e05321b235d63a06ed6c0460d9c3085804bf0606437e96e771725b5a23b706281f2ab751575032fcb96016265b3d80e075738e74354ef5abf349076dcf5b863c18b6d748edfa8c99a4863b1e26b027caeca59463a90bfd4790ca1a792bad037edd98728458e0d67b805e0b2a5d8299b84ca610041a1468a89ebcbe6f05026c24ea52a44a0b42c473275cbf875e26478734b6350ecb257451f2aa0c1f0b554204029c97584f8cb4068fb2b00dc650f7a67e23035d5c8bad3d15a791443ac7861e720b0ffab1f58733bf9108bec0abf5d0460c3fb768559c35641b85308311da83b8e8aac023105712322a72873ff289285051ca372854129cbce962674664c781b0f21a02a9da6a9884b72db5c3251b85bf44871a0ca53793525ebc539de1683e748b7397a9458c788ed8b5dd787b7cdbb5d7cca163a5222283b5aff570b6f27661b2a14e75b11e7402f21911207c08db4478630eb87020a19bb6b790fb572cdbb3cea27a5e846ae63fbadc66361331223ac3a105ca80d5de2339a026f8b0c9898d14856c44b588a6bd7c241bd149345bb292b5c75937c1d5532aea9260e51e5b8e8916fdd857278a45b03a6b79e35a4b155324f4479aed51fdb8685316245afe719b4b26d2945943d727602aaabd8d9446807417ee7ae84907e4b2a847b1289a191a7f0b5a0f47899430534ebd66524560fde4035975076cf8ccbdb082355d87998cbbc875092d1fa9384709f1b64bcbe626134e84373c5123c9261e3d71311e47c9db455b8c815c3d840d44b008c003147d41f87ea169b3c18db44a382284dacb6420b794e0ce23822fa6932cbbf453a2bdebc1f07e103760189822888e2323bb296b088216c10ec5b60a64abf92c51336bc1f06a3308b426233af5d396f6164719fc796ba46c013740fcba8499b27acffb71210c94e246221ebf6b546a1af4dfc9f6db6482e9168dd0b0df0639128dc729c6b3f154c56ca70c022d3962fd2c8df7b6f15ab49d570a1eea921b7b9897c6bb494068ac9439446426602d60f98b98eebd5095b646e01d1571eca12105259cc04508e725e1814b4b9a67b935744d3b834f376beda531f4da645ace10c92275a754b04f06412f19a4888c66f7f4c6ad0bc7526c3778e42340697642f3c5850326854ac3aff1c01fcdc487b17c6f0e691811910e9824ae264b96e7b277894656060a6eff85385110427e8c2f6e5aabbaa2d1287621843a6c8b62893a1c41935952b8ba4ab51ab3bc49c20d129d9b828eda4894628c528d80c996892ea27737c3726e501cff30195b6043beedb66c1951f7621ca1d952ebe477b2659437f351d65cb2cfbf49a35e19bb2ba81b20123706a4c14f346209c27169956f1d139826aada72216c3760df4e2a9e80101eaf842e6b392c490b59274c0b1bb6ad1d067d1910210a32f523738f0521364c47510b0be0c16b4eb53c15a64cf8ce33a19f244b250c754330c6f376dad425653b86d98abc35a51889dd1936db3a70c3a9a9865c967e8861b82912e6925e12892a82a8c480f3a4bf854ca00d45421e2372feafacffbcd39c227d44e7ec66f31c791ba1f";
  String KyberPrivateKey = "f54c794105c65e1794b3586dc3d9bd4c88a5884b8efba3330932898a0266f7dcb222b3c8fd011a478a47ac65a728b91a90a8422a3929c72b8df875c3c33a1af361ab0376519f8c7fa124c92a03a6136422d220368bac633a20ae53fc61eb58760c8140f8360caa7b462c59781414b5445c3ef798cfbb9abb15a964642aa23d076d51215a1d16a575b8370eac9fdf1282dda4014decbf03d34872a55c350133c40b0ce215443732b32138c47a4b92708cbb4f181215e7144c7456bc386890acc0f69019add39142c87b6a532ed50b990c9313b1b7be72a24943eb09ac080f51f068a5d483d2ec00bbb70698541a3de64b98f991c8c824bc85b391345a66d995356003b149aaf0870bd3f99515c19fd6c4c6778637c2c6a1940b4b6849408b096eeecc9b2744bf5ab10ad19b752a9928ee2049eb8023131c37b9fb8cf586b7f72c891133049d4b67f363110d0998f7509fd7013ac5294bce555540f836ad48ce9070704e13bdb1f3aea5cb53b49213d0b716f9c41811225f19374cccf39a62b43db10b5d813c15688c04c78c906f45c9d95876be01a8c0e7764a552d1df9a1c881059a1889c252c678a75dcf868b8ba6a1aec019bda951a3c446ff3a27ef2527fa25049739cf14fa0ac55842ae018b86b0c9cdb94f1ac4324ba7c8bbd8b707791dcf48cc762900b86a967a7a19b0876718128ea4f79f3dd0c3da2363b78a453abb7d09b87661850a5053814c198943b871c3fa990fb821a6b134efc54f00b35742728699e7a6967aa240b3738da56d3b8824731075bfbcaf603c268c2320df1c86973b5e9895bdb1d21ba2576480c39b37e9601512be73c26c715595336798b719cc21f388926b15e648b5a5b6783465b9824b0347ec2916133717369d65b5716002b43bc1c41c3ca0c4835601a29643c8184d6b2d5c8689deea71ad57cc9c1b510e445829cb0c212c67c3955b91a376b8f62a0f20863c145c27c90272290f79673f964bba87a273abb84ecfe1763ab00af95a1425f98f866bca09156a5aca5a9364a614b499e57094e3d3bba8f205cec094c79cb18cb65689c19e54856dfab8193d8a352e4262da879fca4b3e5ce9309db4395ef85e93464db4a209a72bc92176b95afa7e5f5507223943599c32e2930347804b143aa4d9b92ffb8c9bba382f87537868f0442133332ee5bca037a9aea0597bf849371974fb27208c5b0da731c4bba69b90c10225db39f610865913ac3e6482c0d10b9ab91dace317cb4c7eda925f458881b48aa0ecb8aeabb3424935294616c2c4129e61a65b5ab296466a98c5c70b01127436d686491a3fdb17346f48c36aac0ff0a889cbe74a016b03013c6aebf256fdb8b16979993505168ae984e98971552b572080cdeda82437e7b1371b4cd2a95808f2a187911bc6367fc054847de19eb0351091c78c2415ad6c311da25abd2f4c273ed1b7438048f83bb7e19002a4a55abcaa8eea7a0d466789bfa545609b80897b2e6a990ab6dc0b55311e71157e668352911bb56bdcad043416ba270d777809a6472a2d261db808b83e69a4e933520fd280f374807225364e448c9d1236ad8cbac6d689bd279fdb007cdd2b94472a3bd5f52867816f884aae40bbade816935144418bfb9940eb80d386b43af0ca7329a1d729c915603e13d63bb24ac80f13873b736f25a31064595aeba85d089a7a2e657db5a876a4e49ccf77ba0e05321b235d63a06ed6c0460d9c3085804bf0606437e96e771725b5a23b706281f2ab751575032fcb96016265b3d80e075738e74354ef5abf349076dcf5b863c18b6d748edfa8c99a4863b1e26b027caeca59463a90bfd4790ca1a792bad037edd98728458e0d67b805e0b2a5d8299b84ca610041a1468a89ebcbe6f05026c24ea52a44a0b42c473275cbf875e26478734b6350ecb257451f2aa0c1f0b554204029c97584f8cb4068fb2b00dc650f7a67e23035d5c8bad3d15a791443ac7861e720b0ffab1f58733bf9108bec0abf5d0460c3fb768559c35641b85308311da83b8e8aac023105712322a72873ff289285051ca372854129cbce962674664c781b0f21a02a9da6a9884b72db5c3251b85bf44871a0ca53793525ebc539de1683e748b7397a9458c788ed8b5dd787b7cdbb5d7cca163a5222283b5aff570b6f27661b2a14e75b11e7402f21911207c08db4478630eb87020a19bb6b790fb572cdbb3cea27a5e846ae63fbadc66361331223ac3a105ca80d5de2339a026f8b0c9898d14856c44b588a6bd7c241bd149345bb292b5c75937c1d5532aea9260e51e5b8e8916fdd857278a45b03a6b79e35a4b155324f4479aed51fdb8685316245afe719b4b26d2945943d727602aaabd8d9446807417ee7ae84907e4b2a847b1289a191a7f0b5a0f47899430534ebd66524560fde4035975076cf8ccbdb082355d87998cbbc875092d1fa9384709f1b64bcbe626134e84373c5123c9261e3d71311e47c9db455b8c815c3d840d44b008c003147d41f87ea169b3c18db44a382284dacb6420b794e0ce23822fa6932cbbf453a2bdebc1f07e103760189822888e2323bb296b088216c10ec5b60a64abf92c51336bc1f06a3308b426233af5d396f6164719fc796ba46c013740fcba8499b27acffb71210c94e246221ebf6b546a1af4dfc9f6db6482e9168dd0b0df0639128dc729c6b3f154c56ca70c022d3962fd2c8df7b6f15ab49d570a1eea921b7b9897c6bb494068ac9439446426602d60f98b98eebd5095b646e01d1571eca12105259cc04508e725e1814b4b9a67b935744d3b834f376beda531f4da645ace10c92275a754b04f06412f19a4888c66f7f4c6ad0bc7526c3778e42340697642f3c5850326854ac3aff1c01fcdc487b17c6f0e691811910e9824ae264b96e7b277894656060a6eff85385110427e8c2f6e5aabbaa2d1287621843a6c8b62893a1c41935952b8ba4ab51ab3bc49c20d129d9b828eda4894628c528d80c996892ea27737c3726e501cff30195b6043beedb66c1951f7621ca1d952ebe477b2659437f351d65cb2cfbf49a35e19bb2ba81b20123706a4c14f346209c27169956f1d139826aada72216c3760df4e2a9e80101eaf842e6b392c490b59274c0b1bb6ad1d067d1910210a32f523738f0521364c47510b0be0c16b4eb53c15a64cf8ce33a19f244b250c754330c6f376dad425653b86d98abc35a51889dd1936db3a70c3a9a9865c967e8861b82912e6925e12892a82a8c480f3a4bf854ca00d45421e2372feafacffbcd39c227d44e7ec66f31c791ba1f7dc0927ee25beb6646a78e0793be8941ae730767162d89d5385fb5119cddb4bf077c2960a499ec8dc46b6a5cda2252daa27cf2c135de64a6299fbae7a2110439";
  String KyberKEMEncapsulation = "de650a12507a6ff89b308fde49a6343659f0266ebd66d50a44d418d4122fefff7eb9586c6c9b9a6485868b63b996e8ca73334f92a8f8e6547d4f4ec0fc1a0e6047f1fba5901ba2431dac3fb7a376743e22eee4026dd3fe1dc3291085c6cfb22f3d6240c8d86fccdd582295d2c6e9edf9478cf28cd970cf3657a63233ddc8ea68c1cb2d2f5b936fef53dea18d520e71c0dd38bca568a38f20a66104f0e2c1d5815443c851d9633df55956af8686c49b19b11c053bb0dcc3a073982b844a932f2e9c93dd1aaf005d6f4d2e47a3ba1841d167580564915d7ad2cc3eda2e10648dfc8371e23d3a1e2ec11bd62ad60b560c2bca9c28fddc62ac1d507eb2b6cf6c9732fe4d55370c4f3402bae76c2f04f9988ba97d67411ddcbf4941efdca3c64de4ba38bf56680cd4ea1b42c24236eb8d4950300455a9e8c6c61c2a4616d6cf366bf7f50fb508eea67d674116d6765d1280cacedd8381e0a0340aa3336c4b0442daa563b1cbc3e8406aae2cde479f1c6170fdac792a01c5bca92133a8160214b98e9bfa901683d5eb28a9a2bcf1ed1036ff5b3f6e16fd4654d6dd36bc622f9ecfc0de1913cc909f5b6a75209fb750c1a5cb2e8a461b334cfd47a964fc9864eaf8111cd7cff5a0701a9c98c79898547032c6273027d953b23bdeb9ed67e519fb7084f5e5b6d034627ed505b89d322ffb7edb6cb8cbbe188b3b54056b17990fcc777af379fba4a7a40e86db97a9396b7e376c25193165981e8b18b035e7aa579c3e7bf95dc4cc59ceb9b67b61098e1ce7402e7ebd811eae0e4702b8acdd6161769e1a4125adbf98133a0afadc2bd05056a8f14246b401208656073624c6328fc26dc9bc8602cdf611bec074dd5e7b2dcee20fe05f8f86c8df20ac427be7255a681f3160196537174b50ddd670a87ca7e8c9e7efc1d88987d0f6d457fc93e361b262498a2d876391c0b29f13edcb89df9a0104655275e0b38d7225af756ea6247dc17cc54202e67c452419b1f5a7e6dc7a7cef1a8771eb98060646530ed7c2560530f04f17d83efc2d70341720ce4a1c0be396a8d80285e4af558a00a320ee81ff1551b69e26e726f812c4537abf28c003c4643ab2fd0ca3de2685efb0387925e0767e2468db9c56243c0d8bf6acc82597625003adaa8ec46e0dcca0fcb2ea972d9d3440eda59c460edff6cb5274c432a366044244fb3ecab98e53deb6d4b41eb5c99eda5e8dd712fc08f289b6fc8f6fc12fafbaada5d7643708248f6bd14cf2be3a37486b27d5b209b0da674d2c7425d860895fae308d40c682a50778799e920f2657a5bae65295f97ad054c81c8bfdcf6e9dd93fe3080ab451b9f8e0242994c5baf2ad3487bdcd8e5ec311cc8518e0be5651752a7de66d50db41665d25269b1490a6dcd277baa47af0ea0032dfc1ff0097f345c24aa2abd02673b659eaceb7c15f8e3a18a5625ae0f42d8b884555efd2a2af801dd0dfa8ac03dc28fc70fbda51bf069df0c2580dd87b7ab527ecb771f11fe41827f87eec14a6f714dfae0d0340cf6531";
  String KyberSharedSecret = "8c89940a7ff0ed1a63734746c08021f2061edc89b00a0559500f8b7cd48cf9b8";

  @Test
  void checkKyberKEMResult() throws NoSuchAlgorithmException, InvalidKeySpecException {

    KeyPair kyberKeyPair = getKyberFixedKeypair();

    byte[] computedSharedSecret = KyberEncoding.pqcGenerateDecryptionKey(kyberKeyPair.getPrivate(),
            Hex.decode(KyberKEMEncapsulation));

    System.out.println(Hex.toHexString(computedSharedSecret));

    assertThat(computedSharedSecret).isEqualTo(Hex.decode(KyberSharedSecret));
  }

  KeyPair getKyberFixedKeypair() throws NoSuchAlgorithmException, InvalidKeySpecException {
    String keyType = "KYBER";
    KeyFactory keyFactory = KeyFactory.getInstance(keyType, new BouncyCastlePQCProvider());

    X509EncodedKeySpec kyberPubKey = new X509EncodedKeySpec(Hex.decode(KyberPublicKeyEncodingHeader + KyberPublicKey), keyType);
    PKCS8EncodedKeySpec kyberPrivKey = new PKCS8EncodedKeySpec(Hex.decode(KyberPrivateKeyEncodingHeader + KyberPrivateKey), keyType);

    return new KeyPair(
            keyFactory.generatePublic(kyberPubKey),
            keyFactory.generatePrivate(kyberPrivKey)
    );
  }

  @SneakyThrows
  private static boolean containsKyberEncodedOfLength(byte[] encoded) {
    final ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(encoded));
    final ASN1Primitive object = asn1InputStream.readObject();
    final ASN1Primitive secondParameterASN1Primitive = ((DLSequence) object).getObjectAt(1).toASN1Primitive();
    final byte[] secondParameter = ((DERBitString) secondParameterASN1Primitive).getOctets();
    return secondParameter.length == KYBER_768_BYTE_LENGTH;
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
