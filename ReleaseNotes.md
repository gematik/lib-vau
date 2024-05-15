<img align="right" width="200" height="37" src="Gematik_Logo_Flag_With_Background.png" alt="Gematik Logo"/> <br/>

# Release notes lib-vau for ePA 3.x and above

## Release 1.0.9
### fixed
- Corrected the order of S2C and C2S keys in the KeyDerivation in the first key derivation.

## Release 1.0.8
### fixed
- Added workaround in to Kyber key generation be compliant with Kyber Release v3.0.2
  this due to FIPS 203 draft implementation in BouncyCastle which is incompatible with the current release

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
- Additional checks & error handling

## Release 1.0.0
- Initial version (internal only)
- Available functions:
  - VAU handshake for client & server
  - encryption & decryption of data streams
  - statemachine for VAU client
  - statemachine for VAU server
x
