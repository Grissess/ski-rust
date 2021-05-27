SKI
===

_A modern library and standard for "good enough" encryption, designed with
embedded devices and hardware-constrained environments in mind._

Although the interface is rather different (I'd like to think: streamlined),
the standard and the reference implementation are designed to operate and
"feel" much like GnuPG, and can, in theory, be used for many of the same tasks.
One notable non-goal is keyring management, however; anyone is welcome to
implement their own key store on top of this suite, but the standard explicitly
does not address the details.

SKI is, at this point, _untested software_, and you probably should not depend
on it in production, because:

1. Though the algorithms are tested, this implementation of them is not
   audited; and
2. They are subject to change at any time as of right now.

Nonetheless, you are welcome to try this software, use it, and develop it as
you will.



Ki
--

As more of a proof of concept than anything, this release comes with the bash
script `ki`, which can be used for keyring management in a practical setting,
and which can create "certificates" (signed bindings of a public key and
identity) as well as "boxes" (cryptographic data, possibly signed, possibly
encrypted, sent from one ID to another).

There is no install method at the moment, but you can copy it into a directory
in your $PATH if you would like. Common choices are a personal `bin` dir or
`/usr/local/bin` (for systemwide access).

`ki` is by-and-large untested and has _absolutely_ no standardization in its
export formats--for example, it lacks revocation certificates or expiration.
Nonetheless, it is provided for responsible use and testing.



Cryptography
------------

The current best source of information on the exact specification is [a short
presentation][paper] I delivered at a college, which covers all of the
algorithms, the underlying standard, and the rationale for design decisions.

[paper]: doc/paper.md



License
-------

The source code here is available under the Creative Commons CC0
license--effectively, public domain. See `COPYING` for details.

Nonetheless, I remain receptive to issues, requests, and comments published
against the [official repository][repo].

[repo]: https://github.com/Grissess/ski-rust
