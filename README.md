# Sparse Post Quantum Ratchet - ML Braid

This is an alternate "clean" implementation of Signal's SPQR.

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

# References
- [The ML-KEM Braid Protocol](https://signal.org/docs/specifications/mlkembraid)
- [Triple Ratchet: A Bandwidth Efficient Hybrid-Secure Signal Protocol](https://eprint.iacr.org/2025/078)
- [USENIX Paper](https://www.usenix.org/system/files/usenixsecurity25-auerbach.pdf)
- [Signal SPQR Blog Post](https://signal.org/blog/spqr/)
- [Cryspen: Helping Secure Signal's Post-Quantum Transition](https://cryspen.com/post/signal-spqr-verification/)
