# Sparse Post Quantum Ratchet - ML-KEM Braid

This is an alternate "clean" implementation of Signal's SPQR.

It currently implements ML-KEM Braid and Reed-Solomon Erasure codes
with the intention of expanding to a complete Triple Ratchet 
(SPQR + Double Ratchet) implementation.

# WARNING: this is in-progress, incomplete, and not production ready!

Contributions are welcome and encourage. Contributions must be cleanly developed
or come from MIT or BSD licensed code.

# Deviations from the Specification
- The [The ML-KEM Braid Protocol](https://signal.org/docs/specifications/mlkembraid) calls 
for `Encaps2(encaps_secret, ek_header, ek_vector) -> ct2`; however, our
code implements `encaps2(encaps_secret, ek_vector) -> ct2` without `ek_header`.
  - This is because `libcrux_ml_kem::mlkem768::incremental`'s implementation signature is 
`encapsulate2(state, public_key_part)` where `state` is the `encaps_secret` and
`public_key_part` is `ek_vector`. Thus, `ek_header` is **not** a parameter
to the function.
  - Feedback or thoughts on this (or any of the code) are welcome.

# Next Steps
- Tests for ML-KEM Braid - many tests are needed!
- We need a `ratchet chain` implementation to fully support forward secrecy for `sending` and `receiving` respectively with the epoch concept. The chain must also be able to survive restarts. Consider the pattern used in [double-ratchet-crux](https://github.com/dpasirst/double-ratchet-crux)'s `MessageKeyCacheTrait` with a similar default memory only implementation.
- Abstraction: there are a few places in the code today where OsRng is used directly. This should be abstracted out and passed `function<R: Rng + CryptoRng>(rng: &mut R)` by the library caller.
- Abstraction: some portions should be more clearly defined in a trait and use generics rather than the current hardcoded implementation.
- Sparse Message Cache - The code currently assumes all is stored in memory, but a real implementation must be able to survive restarts. Consider the pattern used in [double-ratchet-crux](https://github.com/dpasirst/double-ratchet-crux)'s `MessageKeyCacheTrait` with a similar default memory only implementation.
- Triple Ratchet calls for its use in combination of SPQR and double-ratchet although some of those details are not 100% clear. We have prepared a 'libcrux` friendly implementation of [double-ratchet-crux](https://github.com/dpasirst/double-ratchet-crux)

# References
- [The ML-KEM Braid Protocol](https://signal.org/docs/specifications/mlkembraid)
- [Triple Ratchet: A Bandwidth Efficient Hybrid-Secure Signal Protocol](https://eprint.iacr.org/2025/078)
- [USENIX Paper](https://www.usenix.org/system/files/usenixsecurity25-auerbach.pdf)
- [Signal SPQR Blog Post](https://signal.org/blog/spqr/)
- [Cryspen: Helping Secure Signal's Post-Quantum Transition](https://cryspen.com/post/signal-spqr-verification/)
