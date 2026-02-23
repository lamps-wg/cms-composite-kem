---
title: Composite ML-KEM for use in Cryptographic Message Syntax (CMS)
abbrev: Composite ML-KEM CMS
docname: draft-ietf-lamps-cms-composite-kem-latest

stand_alone: true # This lets us do fancy auto-generation of references
ipr: trust200902
area: Security
stream: IETF
wg: LAMPS
keyword:
 - X.509
 - CMS
 - Post-Quantum
 - KEM
 - Composite ML-KEM
cat: std

venue:
  group: LAMPS
  type: Working Group
  mail: spams@ietf.org
  arch: https://datatracker.ietf.org/wg/lamps/about/
  github: lamps-wg/draft-composite-kem
  latest: https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html

coding: utf-8
pi:    # can use array (if all yes) or hash here
  toc: yes
  sortrefs:   # defaults to yes
  symrefs: yes

author:
  -
    ins: D. Van Geest
    name: Daniel Van Geest
    org: CryptoNext Security
    email: daniel.vangeest@cryptonext-security.com
    street: ‍16, Boulevard Saint-Germain
    code: 75007
    city: Paris
    country: France
  -
    ins: M. Ounsworth
    name: Mike Ounsworth
    org: Entrust Limited
    abbrev: Entrust
    street: 2500 Solandt Road – Suite 100
    city: Ottawa, Ontario
    country: Canada
    code: K2K 3G5
    email: mike.ounsworth@entrust.com
  -
    ins: J. Gray
    name: John Gray
    org: Entrust Limited
    abbrev: Entrust
    street: 2500 Solandt Road – Suite 100
    city: Ottawa, Ontario
    country: Canada
    code: K2K 3G5
    email: john.gray@entrust.com
  -
    ins: J. Klaussner
    name: Jan Klaussner
    org: Bundesdruckerei GmbH
    email: jan.klaussner@bdr.de
    street: Kommandantenstr. 18
    code: 10969
    city: Berlin
    country: Germany

normative:
  SP.800-57pt1r5:
    title: "Recommendation for Key Management: Part 1 – General"
    date: May 2020
    author:
      org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
  FIPS180: DOI.10.6028/NIST.FIPS.180-4
  X680:
    target: https://www.itu.int/rec/T-REC-X.680
    title: >
      Information technology - Abstract Syntax Notation One (ASN.1):
      Specification of basic notation
    date: 2021-02
    author:
    -  org: ITU-T
    seriesinfo:
      ITU-T Recommendation: X.680
      ISO/IEC: 8824-1:2021
  X690:
    target: https://www.itu.int/rec/T-REC-X.690
    title: >
      Information technology - Abstract Syntax Notation One (ASN.1):
      ASN.1 encoding rules: Specification of Basic Encoding Rules (BER),
      Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)
    date: 2021-02
    author:
    -  org: ITU-T
    seriesinfo:
      ITU-T Recommendation: X.690
      ISO/IEC: 8825-1:2021
  RFC5911:
  RFC8551:

informative:
  FIPS203: DOI.10.6028/NIST.FIPS.203


--- abstract

Composite ML-KEM defines combinations of ML-KEM with RSA-OAEP, ECDH, X25519, and X448.
This document specifies the conventions for using Composite ML-KEM algorithms with the Cryptographic Message Syntax (CMS) using the KEMRecipientInfo structure defined in “Using Key Encapsulation
Mechanism (KEM) Algorithms in the Cryptographic Message Syntax (CMS)” (RFC 9629).


--- middle



# Introduction {#sec-intro}

{{!I-D.ietf-lamps-pq-composite-kem}} defines a collection of Key Encapsulation Mechanism (KEM) algorithms, referred to as Composite ML-KEM, which combine ML-KEM {{FIPS203}} with traditional algorithms RSA-OAEP, ECDH, X25519, and X448.
{{!RFC9629}} defines the KEMRecipientInfo structure for the use of KEM algorithms for the Cryptographic Message Syntax (CMS) {{!RFC5652}} enveloped-data content type, the CMS authenticated-data content type, and the CMS authenticated-enveloped-data content type.
This document acts as a companion to {{I-D.ietf-lamps-pq-composite-kem}} by providing conventions for using Composite ML-KEM algorithms with the KEMRecipientInfo structure within the CMS.


## ASN.1

CMS values are generated using ASN.1 {{X680}}, using the Basic Encoding Rules (BER) and the Distinguished Encoding Rules (DER) {{X690}}.


## Conventions and Terminology {#sec-terminology}

{::boilerplate bcp14+}


## Composite ML-KEM

ML-KEM is a lattice-based KEM using Module Learning with Errors as its underlying primitive.
It was standardized with three parameter sets: ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
Composite ML-KEM pairs ML-KEM-768 or ML-KEM-1024 with RSA-OAEP, ECDH, X25519, or X448 at similar security levels such that the shared secret key from each component algorithm is combined into a single shared secret key.

All KEM algorithms provide three functions: KeyGen(), Encapsulate(), and Decapsulate().

The following summarizes these three functions for Composite ML-KEM:

KeyGen() -> (ek, dk):
: Generate the public encapsulation key (ek) and a private decapsulation key (dk).
{{Section 3.1 of I-D.ietf-lamps-pq-composite-kem}} specifies the key generation algorithm for Composite ML-KEM.

Encapsulate(ek) -> (c, ss):
: Given the recipient's public key (ek), produce both a ciphertext (c) to be passed to the recipient and a shared secret (ss) for use by the originator.
{{Section 3.2 of I-D.ietf-lamps-pq-composite-kem}} specifies the encapsulation algorithm for Composite ML-KEM.

Decapsulate(dk, c) -> ss:
: Given the private key (dk) and the ciphertext (c), produce the shared secret (ss) for the recipient.
{{Section 3.3 of I-D.ietf-lamps-pq-composite-kem}} specifies the decapsulation algorithm for Composite ML-KEM.


# Use of Composite ML-KEM in the CMS

Composite ML-KEM algorithms MAY be employed for one or more recipients in the CMS enveloped-data content type {{!RFC5652}}, the CMS authenticated-data content type {{!RFC5652}}, or the CMS authenticated-enveloped-data content type {{!RFC5083}}. In each case, the KEMRecipientInfo {{!RFC9629}} type is used with the Composite ML-KEM algorithm to securely transfer the content-encryption key from the originator to the recipient.

Processing a Composite ML-KEM algorithm with KEMRecipientInfo follows the same steps as {{Section 2 of RFC9629}}. To support the Composite ML-KEM algorithm, a CMS originator MUST implement the Encapsulate() function and a CMS recipient MUST implement the Decapsulate() function.


## RecipientInfo Conventions {#sec-using-recipientInfo}

When a Composite ML-KEM algorithm is employed for a recipient, the RecipientInfo alternative for that recipient MUST be OtherRecipientInfo using the KEMRecipientInfo structure as defined in {{!RFC9629}}.

The fields of the KEMRecipientInfo have the following meanings:

{: newline="true"}
version
: The syntax version number; it MUST be 0.

rid
: Identifies the recipient's certificate or public key.

kem
: Identifies the KEM algorithm; it MUST contain one of the Composite ML-KEM OIDs in {{sec-identifiers}}.

kemct
: The ciphertext produced for this recipient.

kdf
: Identifies the key derivation algorithm. Note that the Key Derivation Function (KDF) used for CMS RecipientInfo process MAY be different than the KDF used within the Composite ML-KEM algorithm.
Implementations MUST support the HMAC-based Key Derivation Function (HKDF) {{!RFC5869}} with SHA-256 {{!FIPS180}}, using the id-alg-hkdf-with-sha256 KDF object identifier (OID) {{!RFC8619}}.
As specified in {{!RFC8619}}, the parameter field MUST be absent when this OID appears within the ASN.1 type AlgorithmIdentifier.
Implementations MAY support other KDFs as well.

kekLength
: The size of the key-encryption key in octets.

ukm
: Optional input to the KDF.
The secure use of Composite ML-KEM in CMS does not depend on the use of a ukm value, so this document does not place any requirements on this value.
See {{Section 3 of RFC9629}} for more information about the ukm parameter.

wrap:
: Identifies a key-encryption algorithm used to encrypt the content-encryption key.
Implementations MUST support the AES-Wrap-256 {{!RFC3394}} key-encryption algorithm using the id-aes256-wrap key-encryption algorithm OID {{!RFC3565}}.
Implementations MAY support other key-encryption algorithms as well.

{{example}} contains an example of establishing a content-encryption key using Composite ML-KEM in the KEMRecipientInfo type.


## Underlying Components

When Composite ML-KEM is employed in the CMS, the underlying components used within the KEMRecipientInfo structure SHOULD be consistent with a minimum desired security level.
Several security levels have been identified {{?SP.800-57pt1r5}}.

If underlying components other than those specified in {{sec-using-recipientInfo}} are used, then the following table gives the minimum requirements on the components used with Composite ML-KEM in the KEMRecipientInfo type in order to satisfy the KDF and key wrapping algorithm requirements from {{Section 7 of RFC9629}}.
The components are chosen based on the ML-KEM variant used within the Composite ML-KEM algorithm.

| Security Strength | ML-KEM Variant | KDF Preimage Strength | Symmetric Key-Encryption Strength |
|---                |---             |---                    |---                                |
| 192-bit           | ML-KEM-768     | 192-bit               | 192-bit (*)                       |
| 256-bit           | ML-KEM-1024    | 256-bit               | 256-bit                           |
{: #tab-strong title="Composite ML-KEM KEMRecipientInfo Component Security Levels"}

(*) In the case of AES Key Wrap, a 256-bit key is typically used because AES-192 is not as commonly deployed.

### Use of the HKDF-Based Key Derivation Function

The HKDF function is a composition of the HKDF-Extract and HKDF-Expand functions.

~~~ pseudocode
HKDF(salt, IKM, info, L)
  = HKDF-Expand(HKDF-Extract(salt, IKM), info, L)
~~~

When used with KEMRecipientInfo, the salt parameter is unused; that is, it is the zero-length string "".
The IKM, info, and L parameters correspond to the same KDF inputs from {{Section 5 of RFC9629}}.
The info parameter is independently generated by the originator and recipient.
Implementations MUST confirm that L is consistent with the key size of the key-encryption algorithm.


## Certificate Conventions {#sec-using-certs}

{{!RFC5280}} specifies the profile for using X.509 certificates in Internet applications.
A recipient static public key is needed for Composite ML-KEM and the originator obtains that public key from the recipient's certificate.
The conventions for carrying Composite ML-KEM public keys are specified in {{I-D.ietf-lamps-pq-composite-kem}}.


## SMIME Capabilities Attribute Conventions {#sec-using-smime-caps}

{{Section 2.5.2 of RFC8551}} defines the SMIMECapabilities attribute to announce a partial list of algorithms that an S/MIME implementation can support.
When constructing a CMS enveloped-data content type, a CMS authenticated-data content type, or a CMS authenticated-enveloped-data content type, a compliant implementation MAY include the SMIMECapabilities attribute that announces support for one or more of the Composite ML-KEM algorithm identifiers.

The SMIMECapability SEQUENCE representing the Composite ML-KEM algorithm MUST include one of the Composite ML-KEM OIDs in the capabilityID field.
When one of the Composite ML-KEM OIDs appears in the capabilityID field, the parameters MUST NOT be present.


# Identifiers {#sec-identifiers}

All identifiers used to indicate Composite ML-KEM within the CMS are defined in {{I-D.ietf-lamps-pq-composite-kem}}, {{!RFC8619}}, and {{!RFC3565}}; they are reproduced here for convenience:

~~~ asn.1

  -- Composite ML-KEM OIDs

  id-MLKEM768-RSA2048-SHA3-256 OBJECT IDENTIFIER ::= {
    iso(1) org(3) dod(6) internet(1) security(5) mechanisms(5)
    pkix(7) alg(6) 55 }

  id-MLKEM768-RSA3072-SHA3-256 OBJECT IDENTIFIER ::= {
    iso(1) org(3) dod(6) internet(1) security(5) mechanisms(5)
    pkix(7) alg(6) 56 }

  id-MLKEM768-RSA4096-SHA3-256 OBJECT IDENTIFIER ::= {
    iso(1) org(3) dod(6) internet(1) security(5) mechanisms(5)
    pkix(7) alg(6) 57 }

  id-MLKEM768-X25519-SHA3-256 OBJECT IDENTIFIER ::= {
    iso(1) org(3) dod(6) internet(1) security(5) mechanisms(5)
    pkix(7) alg(6) 58 }

  id-MLKEM768-ECDH-P256-SHA3-256 OBJECT IDENTIFIER ::= {
    iso(1) org(3) dod(6) internet(1) security(5) mechanisms(5)
    pkix(7) alg(6) 59 }

  id-MLKEM768-ECDH-P384-SHA3-256 OBJECT IDENTIFIER ::= {
    iso(1) org(3) dod(6) internet(1) security(5) mechanisms(5)
    pkix(7) alg(6) 60 }

  id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256 OBJECT IDENTIFIER ::= {
    iso(1) org(3) dod(6) internet(1) security(5) mechanisms(5)
    pkix(7) alg(6) 61 }

  id-MLKEM1024-RSA3072-SHA3-256 OBJECT IDENTIFIER ::= {
    iso(1) org(3) dod(6) internet(1) security(5) mechanisms(5)
    pkix(7) alg(6) 62 }

  id-MLKEM1024-ECDH-P384-SHA3-256 OBJECT IDENTIFIER ::= {
    iso(1) org(3) dod(6) internet(1) security(5) mechanisms(5)
    pkix(7) alg(6) 63 }

  id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256 OBJECT IDENTIFIER ::= {
    iso(1) org(3) dod(6) internet(1) security(5) mechanisms(5)
    pkix(7) alg(6) 64 }

  id-MLKEM1024-X448-SHA3-256 OBJECT IDENTIFIER ::= {
    iso(1) org(3) dod(6) internet(1) security(5) mechanisms(5)
    pkix(7) alg(6) 65 }

  id-MLKEM1024-ECDH-P521-SHA3-256 OBJECT IDENTIFIER ::= {
    iso(1) org(3) dod(6) internet(1) security(5) mechanisms(5)
    pkix(7) alg(6) 66 }

  -- KEMRecipientInfo.kdf OIDs

  id-alg-hkdf-with-sha256 OBJECT IDENTIFIER ::= { iso(1)
      member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
      smime(16) alg(3) 28 }

  -- KEMRecipientInfo.wrap OIDs

  aes OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840)
      organization(1) gov(101) csor(3) nistAlgorithms(4) 1 }

  id-aes256-wrap OBJECT IDENTIFIER ::= { aes 45 }
~~~

# Security Considerations

The Security Considerations sections of {{I-D.ietf-lamps-pq-composite-kem}} and {{!RFC9629}} apply to this specification as well.

Implementations MUST protect the Composite ML-KEM private key, the key-encryption key, the content-encryption key, message-authentication key, and the content-authenticated-encryption key.
Of these keys, all but the private key are ephemeral and MUST be wiped after use.
Disclosure of the Composite ML-KEM private key could result in the compromise of all messages protected with that key.
Disclosure of the key-encryption key, the content-encryption key, or the content-authenticated-encryption key could result in the compromise of the associated encrypted content.
Disclosure of the key-encryption key, the message-authentication key, or the content-authenticated-encryption key could allow modification of the associated authenticated content.

Additional considerations related to key management may be found in {{?SP.800-57pt1r5}}.

The generation of private keys relies on random numbers, as does the encapsulation function of Composite ML-KEM.
The use of inadequate pseudorandom number generators (PRNGs) to generate these values can result in little or no security.
If the random value is weakly chosen, then an attacker may find it much easier to reproduce the PRNG environment that produced the keys or ciphertext, searching the resulting small set of possibilities for a matching public key or ciphertext value, rather than performing a more complex algorithmic attack against Composite ML-KEM.

Composite ML-KEM encapsulation and decapsulation only outputs a shared secret and ciphertext.
Implementations MUST NOT use intermediate values directly for any purpose.

Implementations SHOULD NOT reveal information about intermediate values or calculations, whether by timing or other "side channels"; otherwise an opponent may be able to determine information about the keying data and/or the recipient's private key.
Although not all intermediate information may be useful to an opponent, it is preferable to conceal as much information as is practical, unless analysis specifically indicates that the information would not be useful to an opponent.

Generally, good cryptographic practice employs a given Composite ML-KEM key pair in only one scheme. This practice avoids the risk that vulnerability in one scheme may compromise the security of the other and may be essential to maintain provable security.


# IANA Considerations {#sec-iana}

IANA is requested to allocate a value from the "SMI Security for PKIX Module Identifier" registry for the included ASN.1 module.

-  Decimal: IANA Assigned - **Replace TBDMOD**
-  Description: Composite-KEM-2026 - id-mod-composite-mlkem-cms-2026
-  References: This Document

<aside markdown="block">
  RFC EDITOR: Please replace TBDCompositeMOD in the ASN.1 module with with module number assigned to id-mod-composite-mlkem-2025 in {{I-D.ietf-lamps-pq-composite-kem}}.
</aside>


--- back

# ASN.1 Module {#sec-asn1-module}

This appendix includes the ASN.1 module {{X680}} for Composite ML-KEM. This module imports objects from {{RFC5911}}, {{RFC9629}}, {{RFC8619}}, {{I-D.ietf-lamps-pq-composite-kem}}.

~~~ asn.1
<CODE BEGINS>
{::include Composite-MLKEM-CMS-2026.asn}
<CODE ENDS>
~~~


# Composite ML-KEM CMS Authenticated-Enveloped-Data Example {#example}

This example shows the establishment of an AES-256 content-encryption
key using:

*  id-MLKEM768-ECDH-P256-SHA3-256;

*  KEMRecipientInfo key derivation using HKDF with SHA-256; and

*  KEMRecipientInfo key wrap using AES-256-KEYWRAP.

In real-world use, the originator would encrypt the content-
encryption key in a manner that would allow decryption with their own
private key as well as the recipient's private key.  This is omitted
in an attempt to simplify the example.

## Originator CMS Processing

Alice obtains Bob's id-MLKEM768-ECDH-P256-SHA3-256 public key:

~~~ test-vectors
{::include ./example/MLKEM768-ECDH-P256-SHA3-256.pub}
~~~

Bob's id-MLKEM768-ECDH-P256-SHA3-256 public key has the following key identifier:

~~~ test-vectors
{::include ./example/MLKEM768-ECDH-P256-SHA3-256.keyid}
~~~

Alice generates a shared secret and ciphertext using Bob's id-MLKEM768-ECDH-P256-SHA3-256 public key:

Shared secret:

~~~ test-vectors
{::include ./example/shared_secret.txt}
~~~

Ciphertext:

~~~ test-vectors
{::include ./example/ciphertext.txt}
~~~

Alice encodes the CMSORIforKEMOtherInfo:

~~~ test-vectors
{::include ./example/ori_info.txt}
~~~

Alice derives the key-encryption key from the shared secret and CMSORIforKEMOtherInfo using HKDF with SHA-256:

~~~ test-vectors
{::include ./example/kek.txt}
~~~

Alice randomly generates a 128-bit content-encryption key:

~~~ test-vectors
{::include ./example/cek.txt}
~~~

Alice uses AES-256-KEYWRAP to encrypt the content-encryption key with the key-encryption key:

~~~ test-vectors
{::include ./example/encrypted_cek.txt}
~~~

Alice encrypts the padded content using AES-256-GCM with the content-encryption key and encodes the AuthEnvelopedData (using KEMRecipientInfo) and ContentInfo, and then sends the result to Bob.

The Base64-encoded result is:

~~~ test-vectors
{::include ./example/MLKEM768-ECDH-P256-SHA3-256.cms}
~~~

This result decodes to:

~~~ test-vectors
{::include ./example/MLKEM768-ECDH-P256-SHA3-256.cms.txt}
~~~

## Recipient CMS Processing

Bob's id-MLKEM768-ECDH-P256-SHA3-256 private key:

~~~ test-vectors
{::include ./example/MLKEM768-ECDH-P256-SHA3-256.priv}
~~~

Bob decapsulates the ciphertext in the KEMRecipientInfo to get the MLKEM768-ECDH-P256-SHA3-256 shared secret, encodes the CMSORIforKEMOtherInfo, derives the key-encryption key from the shared secret and the DER-encoded CMSORIforKEMOtherInfo using HKDF with SHA-256, uses AES-256-KEYWRAP to decrypt the content-encryption key with the key-encryption key, and decrypts the encrypted contents with the content-encryption key, revealing the plaintext content:

~~~ test-vectors
{::include ./example/decrypted.txt}
~~~


# Acknowledgments

This document borrows heavily from {{?RFC9690}} and {{?RFC9936}}. Thanks go to the authors of those documents. "Copying always makes things easier and less error prone" - RFC8411.

