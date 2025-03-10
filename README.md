# Mina AES

A provable AES implementation using o1js

## Installation and Quick Start

### Installation

```shell
npm ci
```

### Build

```shell

npm run build
npm run start
```

Or if you want to use the dev build

```shell
npm run dev
```

### Formatting and Linting

```
npm run lint
npm run format
```

### Testing

Unit tests:

```
npm run test
```

If you want to test zk programs locally as well:

```
npm run test:zk
```

To run a summary of constraints in all library functions:

```
npm run build
 node ./build/test/circuitSummary.js

```

## Architecture & Design

- **Detailed Design/Architecture:** The proposers currently have a proof-of-concept AES codebase capable of verifying 128-bit ciphertext messages. However, this codebase is a prototype and requires significant modifications, including implementing the [S-Box](https://en.wikipedia.org/wiki/Rijndael_S-box), various block mode of operations (e.g., [CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)), and key expansion to support different key sizes. Additionally, a comprehensive test suite is crucial to ensure correctness during development.
- **Vision:** Provide a well-documented, robust library for the AES scheme, which can be easily utilized for future development.
- **Existing Work:** See the current proof-of-concept [here](https://github.com/scaraven/eth-oxford).

## Detailed Breakdown

### Core:

- Integrating previously completed **ShiftRows** and **MixColumns** stages into the new codebase.
- Implementing an algorithmic (rather than memory-heavy) **S-Box** or with a provable **Merkle Map**.
- Key expansion.
- Padding message text using **PKCS7** (off-circuit).
- Implementing block mode: **Counter Mode (CTR)**.
- Testing: Since AES is a security primitive, we propose testing with millions of randomly generated inputs and comparing results against an industrial implementation (**Differential Testing**).
- Creating documentation with libraries such as [documentation.js](https://documentation.js.org/).

### Optional:

- User authentication block mode: **Galois Counter Mode (GCM)**.
- Additional testing: Deploying on a testnet and running integration tests.
- Addressing trade-offs between recursion and off-chain computation for an optimized design.
- Benchmarking: Exploring optimizations to minimize circuit size.
