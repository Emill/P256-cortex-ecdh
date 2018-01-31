# P256-cortex-ecdh
P256 ECDH for Cortex-M0, Cortex-M4 and other ARM processors

This implements highly optimimzed assembler versions of P-256 (secp256r1) ECDH for Cortex-M0 and Cortex-M4. While optimized for these processors, it works on other ARM processors as well, as long as the used instructions are supported (ARMv7 for Cortex-M4). For example, the Cortex-M3 processor can use the Cortex-M0 code and the Cortex-A53 processor can use the Cortex-M4 code.

## P256 ECDH
ECDH is an Elliptic curve version of the Diffie-Hellman protocol, using NIST's P-256 as the elliptic curve.

### API
```
bool P256_ecdh_keygen(uint8_t result_my_public_point[64], const uint8_t private_key[32]);
bool P256_ecdh_shared_secret(uint8_t result_point_x[32], const uint8_t others_public_point[64], const uint8_t private_key[32]);
```
For full documentation, see the header file.

### About endianness
All parameters (coordinates, scalars/private keys, shared secret) are represented in little endian byte order.
Other libraries might use big endian convention, so if this should be used against such a library, make sure all 32-byte values exchanged are reversed.

### How to use

Each part generates a key pair:
```
uint8_t my_public_point[64], my_private_key[32];
do {
  generate_random_bytes(my_private_key, 32);
} while (!P256_ecdh_keygen(my_public_point, my_private_key));
```
The function generate_random_bytes is a placeholder for calling the system's cryptographically secure random generator. Do NOT use rand() from the C stdlib.
With probability around 1/2^32, the loop will need more than one iteration.

The public points are then exchanged, and the shared secret is computed:
```
uint8_t shared_secret[32];
if (!P256_ecdh_shared_secret(shared_secret, others_public_point, my_private_key)) {
  // The other part sent an invalid public point, so abort
} else {
  // The shared_secret is now the same for both parts and may be used for cryptographic purposes
}
```

To use it in your project, include the header file `P256-cortex-ecdh.h`. Then add _only_ one of the `.s` files that suits you best as a compilation unit to your project. If you use Keil, just add it as a source file. If you use GCC, add it to your Makefile just like any other C source file.

### Example
An example can be seen in `linux_example.c` that uses `/dev/urandom` to get random data. It can be compiled on for example Raspberry Pi 3 with:
```
gcc linux-example.c P256-cortex-m4-ecdh-speedopt-gcc.s -march=armv7-a -o linux_example
```

### Performance
For Cortex-M4, depending on sizeopt or speedopt, the library uses only 3508 or 2588 bytes of code space in compiled form, uses 1.5 kb of stack and runs one scalar multiplication in 994k or 1108k cycles on Cortex-M4, which is speed record as far as I know. For a 64 MHz processor that means less than 16 or 18 ms per operation!

For Cortex-M0, the library uses between 2416 and 3708 bytes in code size and for run time between 4457k and 5764k in cycles, depending on optimization settings (see the beginning of the assembler file where you can choose settings). Stack size is at most 1356 bytes. For a 16 MHz processor that means as low as between 279 and 360 ms per operation!

The Raspberry Pi 3 (Cortex-A53) runs one operation in 0.94 ms when the Cortex-M4 version (speedopt) is used.

### Security
The implementation runs in constant time (unless input values are invalid) and uses a constant memory access pattern, regardless of the scalar/private key in order to protect against side channel attacks.

### Code
The code is written in Keil's assembler format but was converted to GCC's assembler syntax using the included script `convert-keil-to-gcc.sh` (reads from stdin and writes to stdout).

### Copying
The code is licensed under the BSD 2-clause license.

### Future work
1. Keygen can done even faster (around 2-3 times as fast) by using a pre-computed lookup table and a different algorithm.
2. Support ECDSA signature generation and verification.
