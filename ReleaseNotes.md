<!--suppress CheckImageSize -->
<img width="200" height="37" src="Gematik_Logo_Flag_With_Background.png" alt="Gematik Logo"/> <br/>

# Release notes lib-vau for ePA 3.x and above

# Release 1.0.17

### update

- updated Bouncy Castle to 1.86 and migrated internal cryptographic operations to ML-KEM-768 while preserving Kyber v3.0.2 protocol compatibility.
- updated to the latest versions: Bouncy Castle 1.86, Commons Lang 3.21.0, Jackson CBOR 2.22.3, SLF4J 2.0.20, Lombok 1.18.48, JUnit 6.1.3 and JaCoCo 0.8.15.
- updated dependencies and build tooling: Commons Codec 1.22.1, Logback 1.6.3, Maven Surefire Plugin 3.5.6 and Maven Compiler Plugin 3.14.1

### fixed 

- fix Lombok annotation processing on JDK 23+

# Release 1.0.16

### update

- several dependencies updated to their latest versions (BouncyCastle, Apache commons-lang3, JUnit, Mockito, Jackson, etc.)
- Gematik Copyright Header updated to 2025–2026
- Formating of code and comments improved

### fixed

- it now also applies the PU flag configuration to message encryption

# Release 1.0.15

### update

- updated to Apache commons-lang3 3.18.0

# Release 1.0.14

### update

- Updated to BouncyCastle 1.80

## Release 1.0.13

### fixed

- corrected encoding of "signature-ES256" to no longer be DER-encoded

### added

- made PU VAU-header configurable for client/server statemachine instances

## Release 1.0.12

### added

- Extended trace logging for received encrypted VAU messages (user data)
- Error message with more details in case of an exception during the VAU decryption process
- Added an imported hint for the VAU key derivation in Readme using a workaround for the
  BouncyCastle FIPS 203 draft implementation

## Release 1.0.11

### fixed

- Deleted unnecessary (and erroneous) second request counter

## Release 1.0.10

### fixed

- Corrected eight byte request counter using type long (eight bytes) instead of type int (four
  bytes)

## Release 1.0.9

### fixed

- Correct the order of S2C and C2S keys in the KeyDerivation in the first key derivation.

## Release 1.0.8

### fixed

- Added workaround in to Kyber key generation be compliant with Kyber Release v3.0.2
  this due to FIPS 203 draft implementation in BouncyCastle which is incompatible with the current
  release

## Release 1.0.7

### added

- tests for Shared Secrets Length/Signing in EllipticCurve.getSharedSecret()

### fixed

- Fixed Kyber key encoding (remove ASN.1 Prelude) in VauBasicPublicKey.toKyberPublicKey()

## Release 1.0.6

### added

- pullFromGitHubToGitLab.jenkinsfile

### changed

- integrated test better into tiger

### fixed

- Shared Secrets Length/Signing in EllipticCurve.getSharedSecret()

## Release 1.0.5

### fixed

- Updated .gitignore
- Updated teams notification url

## Release 1.0.4

### fixed

- Added jenkinsfiles to .githubignore

## Release 1.0.3

### added

- .githubignore

### added

- Added Files LICENSE.md, ReleaseNotes.md, SECURITY.md and LICENSE headers for external release

## Release 1.0.2

### fixed

- Internal release only

## Release 1.0.1

### added

- Additional checks and error handling

## Release 1.0.0

- Initial version (internal only)
- Available functions:
    - VAU handshake for client & server
    - encryption and decryption of data streams
    - statemachine for VAU client
    - statemachine for VAU server
      x
