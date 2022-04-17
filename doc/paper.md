Introduction
============

SKI is a novel cryptographic library that has been developed with a focus on
hardware-constrained environments such as embedded systems, which are becoming
more prevalent with the proliferation of "smart" devices and the Internet of
Things. To date, security in such platforms has always been at odds with
performance and design constraints, and thus suffered in comparison to its
other features; such issues have precipitated widespread security breaches of
unprecedented scale, such as the Mirai botnet (ca. 2016). When hardware and
budgets are tight, economic incentives for security simply don't make the cut,
especially in high-volume production runs. The SKI project thus aims to create
a simple, interoperable, unified specification, using modern algorithms
selected for speed (without sacrificing security), to ease the burden on
embedded systems developers to introduce good security practices into their
products from the start.

SKI is not the first cryptographic library. It borrows heavily from concepts
introduced by Pretty Good Privacy (PGP, Zimmermann 1991), and is very similar
in interface to D.J. Bernstein's 2012 "Networking and Cryptography Library"
(NaCL), which has been revised ("forked") by other major projects, including
libsodium (Frank Denis, 2013). Our major technical contribution is a focus on
hardware constraints, such as processing performance, working memory, or the
presence of a reliable entropy source. Design choices made in concession to
such constraints will be mentioned throughout the presentation.



Overview
========

SKI provides three major cryptographic operations:

- Symmetric ("shared-key") encryption: A scheme to protect the confidentiality
  of data where all trusted parties hold the exact same key;

- Asymmetric ("public-key") key derivation: A scheme to derive a shared,
  trusted secret using two-part keys (a "keypair"): a public part that can be
  disclosed, and a private part kept secret;

- Digital signature: A scheme to provide authenticity of data using a keypair,
  where the private part is present for attestation, and the public part can be
  used for verification.

For simplicity, SKI can use the same keypair for both key derivation and
digital signature, but library users can separate this functionality amongst
multiple keys if they so choose. SKI imposes no inherent limitations on the use
of keys beyond that they are valid for the operation; such details, if they
must be implemented, are delegated to the developer.

It is worth note that SKI does not provide "authenticated encryption" directly,
while in most similar libraries, this is the only option. It is easy and, we
believe, secure for the authentication and encryption primitives to be composed
in any order to provide the same service. As an added benefit, the primitives
are separable if the use case has no need for, or cannot perform well with, a
particular one.



Data Encoding
=============

Perhaps the most innovative part of the design of this standard is the use of
Uniform Resource Name (URN) syntax as specified in RFC 2141 (but note that we
have not yet registered our namespace), along with RFC 3548 "URI-safe" Base64
encoding to ensure the binary data can be efficiently represented as text. This
decision was primarily because this form is very easy to convey
graphically--for example, in the ubiquitous "Quick Response" (QR) code. We
anticipate that devices can come with a card or attachment (for example, a
sticker), with such a graphical code conveying a SKI URN, and that this is a
practical, scaleable, and secure way to do key exchange on a per-unit basis.
(Such key exchanges may be used to bootstrap trust in the device and allow for
further key exchange, or be the sole key on the device--we will discuss this
more in the section on asymmetric keys and signatures).

All codable objects that SKI can use are compatible with this encoding,
including variable-length data, such as encrypted data packets. However, the
Base64 encoding, while compressible, is unwieldy in many circumstances, so SKI
also allows for a "binary" encoding when using "8-bit clean" (pure binary)
communication channels that will not be rendered as text. This is also a valid
encoding for all objects, but it is generally used only when the packet size is
linear in the input size (thus, encryption operations).

SKI data packets, in either URN or binary form, are not self-describing and
require transport metadata, such as a packet length over a stream protocol (or
a dedicated packet protocol) to communicate. We anticipate this is a reasonable
burden to offload to library users, but if this proves to be false, the current
coding standard is flexible enough to admit a self-describing packet.



Symmetric Encryption
====================

Arguably the easiest form of encryption, symmetric encryption depends on a
shared secret, referred to as a "symmetric key", or simply a key. A symmetric
cipher is two operations, encryption and decryption, which take some amount of
data and such a key, and for which encryption composed with decryption only
with the same key is an identity. The design of such ciphers is considered
secure when the key cannot efficiently be derived from the initial data (the
plaintext), the encrypted data (the ciphertext), or both.

SKI uses the "XChaCha" variant of the ChaCha20 stream cipher, the latter by
Bernstein (2008). As a stream cipher, the ciphertext and the plaintext have the
same length, but--to prevent key recovery--each encryption with the same key
must use a nonce (a number "used once"), which is safe to disclose but must be
unique per key use. It is catastrophic to the security of the cryptosystem to
use the same nonce with different plaintexts. The XChaCha variant we have
chosen has a 256-bit key and 192-bit nonce, which should allow, in theory, an
average of about 7.9e28 uniformly-randomly-chosen nonces to be used with the
same key before such a failure occurs. However, it is unsafe to assume that
embedded systems have a good source of entropy; we posit that it is safe to use
a simple incrementing counter in non-volatile memory for the nonce on such
constrained implementations, which allow for about 6.2e57 nonces before
wrap-around occurs. It is an astronomically remote possibility that any single
device will send this much data, even with a fixed key, over the course of its
usable lifetime.

Our reference implementation provides the "ski:symk" scheme for the 256-bit
key, and the "ski:syed" scheme for symmetrically-encrypted data, which is the
simple concatenation of the 192-bit nonce and the ciphertext. Under the "sym"
command:

- A new, random key on a host with sufficient entropy can be generated with
  "gen".

- A key derived from some input (such as a password) can be derived using
  "derive". We use the Argon2 key derivation function, which is specifically
  chosen to be hard against adversaries with access to FPGAs and difficult to
  implement on an ASIC with better performance than a modern computer. As it
  requires 8MB of random-access memory, we do not anticipate that such a
  command will be used on an embedded device; rather, only the key itself needs
  to be stored.

- Ciphertext can be produced from plaintext using the "encrypt" command, and
  the inverse done with the "decrypt" command, both of which expect a symmetric
  key. Both use the binary encoding of the "syed" scheme by default, but can be
  given an argument to generate a URN instead.



Asymmetric Encryption
=====================

Asymmetric encryption is so named for having two distinct keys for its
operation, one of which can be disclosed. In a secure asymmetric cryptosystem,
the disclosed "public" key cannot be used to efficiently derive the undisclosed
"private" key in the same pair. Otherwise, the guarantees from a symmetric
cipher hold analogously.

SKI uses Elliptic Curve Diffie-Hellman (ECDH) over Curve25519, an elliptic
curve over the prime 2 ^ 255 - 19, developed by Bernstein (2005), which he
conjectures to have the equivalent of 128-bit security (requires the equivalent
of 2^128 brute-force attempts to break some aspect of the cryptosystem). The
Diffie-Hellman protocol requires that both parties attempting to encrypt a
message have disclosed their public keys to each other, and generates a shared
secret key that is believed to be difficult to derive without access to at
least one of the private keys. To preserve forward secrecy, the shared key,
which is constant for the lifetime of the two keypairs, is used to encrypt a
random per-message key; in this way, disclosure of the message key does not
provide significant information about the shared key, or either private key.
The cipher used for encrypting both the message key and the message itself is
the selfsame symmetric cipher discussed previously.

In embedded implementations where randomness may be a concern, we posit that it
is acceptable to use a non-volatile counter, as with the nonce, to generate the
message keys. However, to avoid catastrophic loss of confidentiality, the
initial values of the message key and symmetric nonce counters should be
unrelated and never disclosed. We anticipate that it is acceptable to use some
entropy at manufacture or program time to initialize the values of these
counters independently, but for this reason, we encourage systems using
asymmetric encryption to use a cryptographically-secure entropy source for
these operations whenever resources allow (such as applications designed for
general-purpose computers).

Our reference implementation provides the "ski:prvk" and "ski:pubk" URN schemes
for private and public keys, respectively, both of which are 256-bit. It also
provides the "ski:shak" scheme for the ECDH-derived shared key. Finally, it
provides the "ski:encr" scheme for asymmetrically-encrypted data packets, which
consists of the data of two "syed" packets: the first, of fixed length, is an
encrypted message key, and the second, of variable length, is the message,
encrypted with the message key. Under the "key" command:

- A new, random private key on a host with sufficient entropy can be generated
  with "gen". Compared to many other contemporary cryptosystems, the generation
  of a private key for Curve25519 is relatively fast, and requires only 253
  bits of entropy.

- The public key for a given private key can be derived with "pub".

- The shared key for one public and one private key can be generated with
  "shared". We don't recommend this in practice, because disclosing this key
  can result in loss of confidentiality in all messages between these two keys;
  it is provided as a diagnostic aid, and for integration with other systems.

- Ciphertext can be produced from plaintext with "encrypt", and the inverse
  done with "decrypt". Both operations require a public key (usually the
  "recipient") and a private key (usually the "sender"). "decrypt" can recover
  using either the original private and public key, or (more typically) the
  private key of the recipient and the public key of the sender.

Future work includes extending the number of public keys to which a single
message can be addressed, as it requires only constant size (the size of one
encrypted message key) to add further recipients by public key.



Digital Signatures
==================

A signature is a token, produced over some data, using a secret, which can be
"verified" by other parties to ensure integrity of the data. For such a system
to be secure, an adversary cannot efficiently derive such a token without the
secret, nor derive the secret from the token, and any attempt to interfere with
the integrity of the message (change its data in any way) or of the token
should cause verification to fail.

Efficient cryptographic-hash-based schemes, known as Hash-based Message
Authetication Codes (HMACs) exist for shared secrets, but are unimplemented in
SKI. Instead, SKI uses the Elliptic Curve Digital Signature Algorithm, also
over Bernstein's Curve25519, and using the 512-bit variant of the NIST Secure
Hashing Algorithm 2, published 2001, as the message digest. Because
Curve25519's field is 256-bit, we use only the first 256 bits of the 512 bit
digest; nonetheless, SHA-512 has better preimage resistance than SHA-256 (the
256-bit variant), so we posit this design has better--or, at least, no
worse--security properties.

As with other primitives, ECDSA requires a 255-bit "nonce" per signature;
unlike the previous primitives, this "nonce" is a secret. Because of this
change of role, we refer to this datum as a "nonce preimage". Disclosing the
nonce preimage, or using the same nonce preimage for distinct messages, allows
an adversary to recover the private key, thus defeating the integrity
guarantees of this signature scheme and the confidentiality of any encrypted
messages for which this private key was used. For this reason, we recommend
using distinct signature and encryption keys whenever possible, to mitigate the
damage caused by an accidental disclosure. While yet another nonce counter
could be used for such nonces, SKI also provides for deterministic nonces,
where the 255 bits are derived from a SHA-512 digest over the private key and
the data. Thus, the security of this scheme relies on the resistance of the
underlying hash function to collision; to the best of our knowledge, SHA-512
remains secure in this regard. Nonetheless, on platforms where access to
entropy is readily available, we still recommend using randomized signatures,
which relaxes the security proof to not rely on SHA-512's collision resistance.

Our reference implementation provides digital signatures through the "ski:sign"
scheme, which consists of a "nonce postimage" (frequently labelled "r" in ECDSA
literature) and the signature token (usually "s") derived from the private key
and the given nonce preimage. Both of these are a constant 256 bits in length.
Since the private and public keys are compatible with the asymmetric encryption
keys, they can be used with two more "key" subcommands:

- "sign", which generates a SKI signature for a message, and

- "verify", which validates a SKI signature for a message.

Note that the SKI signature is of constant size and "detached"; it must be sent
independently of the message.



Authenticated Encryption
========================

Although not included as a primitive, we revisit that the two previous
primitives combined--asymmetric encryption and digital signatures--can create
"authenticated encryption". There are three ways, in general, to combine these
functions:

- Encrypt-then-MAC: Encrypt the data, then sign the ciphertext;

- MAC-then-encrypt: Compute a signature, concatenate it with the plaintext, and
  encrypt the concatenation;

- Encrypt-and-MAC: Sign the plaintext independently of encrypting it.

Various subtleties should be observed with each approach, but we believe that
the systems we have chosen have beneficial properties regardless of AE scheme:
primarily, the reliance on independent nonces makes it difficult to attack any
scheme even if the same private key is used for both primitives, and the use of
a stream cipher mitigates the effects of padding-oracle attacks. Note, however,
that other protocol-specific oracles may be possible due to the malleability of
the stream cipher, and thus we encourage authenticating encrypted data (using
any above scheme) unless a compelling reason justifies otherwise.



Pragmatics and Miscellany
=========================

One familiar with other cryptosystems occupying a similar niche in software
design, particularly PGP, will note that SKI has no concept of a "certificate".
This is a simplifying assumption--we make no attempt to implement any kind of
database, key storage, or key validation scheme, as we anticipate that these
will depend heavily on implementation details and the environment in which a
solution is deployed. Similarly, without certificates, SKI has no inbuilt
concept of "key expiry"; it is up to the designers of devices to determine
their rekeying policies, and requires support in the sense of a (trusted)
timekeeping device, such as a real-time clock or networked time server. These,
we believe, are ancillary to the design of a good foundation of a cryptosystem,
though we have made every effort to ensure that the primitives provided by this
library remain secure enough for practical use, as of the present, for the
forseeable lifetimes of these embedded devices.

There is presently no quantum-resistant cryptography in SKI as of yet; the
implementations of such cryptosystems we've reviewed so far have not met our
standards of performance on embedded devices. However, this is only a pragmatic
compromise for the time being; as hardware and cryptography improve, we plan on
devoting future work to including quantum-resistant suites.



Conclusion
==========

In summation, we present SKI, a simple, novel cryptographic library targeting
embedded and hardware-constrained systems, with a focus on performance,
portability, and ease of use. We discussed its cryptographic primitives, their
usage, and the concessions made pursuant these goals. We release an
implementation freely, in hopes that it can improve the status quo of security
for embedded platforms and devices as they continue to proliferate, and we hope
that this contribution will help abate the security concerns of such
technologies.

Thank you for listening.
