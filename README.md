# VAU Library (lib-vau)

Dieses Repository dient als Beispielimplementierung in JAVA und implementiert den kryptografischen Teil der Spezifikation des VAU-Protokolls für ePA für alle ([gemSpec_Krypt Kaptiel 7](https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/latest/#7)). 

## Einschränkungen & Hinweise

- Es werden keine Zertifikate geprüft. 
- Es beinhaltet außerdem nur ECC, kein RSA. 
- Die kryptografischen Abhängigkeiten sind neben java.security auch 
Bouncy Castle. 
- Der Transport der Daten der Public Keys geschieht über die binäre Codierung CBOR.

## VAU Handshake
In der Datei [VauHandshakeTest.java](src/test/java/de/gematik/vau/VauHandshakeTest.java) befindet sich eine Beispielimplementierung des gesamten Handshakes wie er in der Spezifikation im [Kapitel 7.1](https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/latest/#7.1) beschrieben ist:

### VauMessage 1:
Der Client erzeugt die ECDH und Kyber KeyPairs. Diese werden in Message 1 gepackt und zum Server geschickt.

### VauMessage 2:
Der Server nimmt die VauMessage 1 entgegen. Die PublicKeys des Clients und seinen eigenen PrivateKeys nutzt er,
um die ECDH und Kyber Shared Secrets mitsamt Ciphertexts (KdfMessage) zu erstellen. Daraus erstellt er den ersten Schlüssel KdfKey1.
Diesen nutzt er, um seine signierten PublicKeys zu verschlüsseln. In VauMessage 2 werden die Ciphertexts der Shared
Secrets sowie die verschlüsselten signierten PublicKeys gespeichert und diese Nachricht wird zurück zum Client geschickt.

### VauMessage 3:
Der Client erhält VauMessage 2. Mithilfe der Ciphertexts des Servers und den eigenen PrivateKey erstellt er seine
eigenen Shared Secrets, mit welchen er den gleichen KdfKey1 wie der Server herleitet. Damit entschlüsselt er die signierten
PublicKeys des Servers. Mit diesen PublicKeys und den eigenen PrivateKeys erstellt der Client weitere Shared Secrets
mit zugehörigen Ciphertexts. Mit den Shared Secrets aus beiden Vorgängen wird nun ein KdfKey2 generiert, welcher für das
Ver-/Entschlüsseln zwischen Client und Server nach dem Handshake genutzt wird. Die Ciphertexts für den KdfKey2 werden mit
dem KdfKey1 verschlüsselt. Ein Transcript, was aus den bisherigen codierten Nachrichten besteht, wird in SHA-256 (=Hash) und dann mit
dem KdfKey2 verschlüsselt (=Ciphertext-KeyConfirmation). Die VauMessage 3 besteht aus den Ciphertexts und der Ciphertext-KeyConfirmation. Diese wird
zum Server zurückgeschickt.

### VauMessage 4:
Der Server öffnet VauMessage 4 und erhält mit seinem KdfKey1 die Ciphertexts. Mit diesen kann er nun seinen eigenen Shared Secrets
erstellen. Mit allen Shared Secrets leitet er, wie der Client zuvor, den KdfKey2 her. Um den Vorgang zu validieren, überprüft der
Server die Hash des Clients: Er entschlüsselt die Ciphertext-KeyConfirmation mit dem KdfKey2 und erhält den Client-Hash. 
Diese vergleicht er mit dem SHA-256 verschlüsselten eigenen Transcript. Den eigenen Hash verschlüsselt er mit dem KdfKey2 (=Ciphertext-KeyConfirmation).
Diese wird in VauMessage 4 gespeichert und zurück zum Client geschickt.

Der Client öffnet die Nachricht, entschlüsselt die Ciphertext-KeyConfirmation und vergleicht wieder den erhalten Hash mit selbst berechneten.
Erst dann ist der Handshake abgeschlossen.
