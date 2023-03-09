Ref: https://zokrates.github.io/examples/sha256example.html

# Problem Statement

- hash digeat = hash'ed message
- preimage = plain text
- Overview : proving knowledge of the preimage for a given hash digest.
- prover: Peggy
- verifier: Victor
- claim: that Peggy knows a hash preimage for a digest "chosen by Victor", without revealing what the preimage is.
  - d

---

# Solution

## Note: The size of `out` file is more than 100MB and due to github policy it will not uploaded. So generate it by compiling the .zok file and have a gitignore if you are also using git.

## 1. Victor compute a hash of 5 using ZoKrates.

- our goal is to compute the hash for the number 5

```
zokrates compile -i generatehash.zok
zokrates compute-witness -a 0 0 0 5
grep '~out' witness
```

The output looks like

```
~out_0 263561599766550617289250058199814760685
~out_1 65303172752238645975888084098459749904
```

Hence, by concatenating the outputs as 128 bit numbers, we arrive at the following value as the hash for our selected pre-image (5) is : `0xc6481e22c5ff4164af680b8cfaa5e8ed3120eeff89c4f307c4a6faaae059ce10`

Now we have a hash / hash digest. Lets say that Victor chose this hash digest `0xc6481e22c5ff4164af680b8cfaa5e8ed3120eeff89c4f307c4a6faaae059ce10`

## 2. Victor creates a new hashexample.zok file similar to generatehash.zok but now it also checks whether the hash generated matches with the one selected by Victor

```
import "hashes/sha256/512bitPacked" as sha256packed;  // is a SHA256 implementation that is optimized for the use in the ZoKrates DSL

// a field value can only hold 254 bits due to the size of the underlying prime field we are using
// As a consequence, we use four field elements, each one encoding 128 bits, to represent our input. The four elements are then concatenated in ZoKrates and passed to SHA256.

// note that -> is not included in this function.

def main(private field a, private field b, private field c, private field d) {
    // Given that the resulting hash is 256 bit long, we split it in two and return each value as a 128 bit number.
    field[2] h = sha256packed([a, b, c, d]);

    // extra checks to confirm that it is a hash(5)
    assert(h[0] == 263561599766550617289250058199814760685);
    assert(h[1] == 65303172752238645975888084098459749904);
    return;
}
```

## 3. Victor computes the proving key and verification key of the updated `hashexample.zok` so that this code cannot be modified, and then send the provikey to Peggy

- `zokrates setup`
- Victor then copies the `proving.key` to Peggy folder.

## 4. Victor then creates a solidity verifier for `hashexample.zok` such that Peggy can verify its claim ZKP on blockchain. Then deploys this solidity code to the blockchain.

- `zokrates export-verifier`
- Victor then deploys the `verifier.sol` file to blockchain.
- Now all done on victor's end.

## 5. Peggy prepares its environment

- Peggy copies `hashexample.zok` to its folder.
- Compiles this file
  - `zokrates compile -i hashexample.zok` which creates `out` file
- Now either Peggy can use the `provikey.key` or generate its own, but it is best to use Victor's sent proving key. This key will be used to execute the `out` program by sending it the "private witness", in our case is 5 ( in decimal)
  - `zokrates compute-witness -a 0 0 0 5`
- Now peggy can generate the proof so that the claim that peggy knows about the "private witness" can be verified by Victor.
  - `zokrates generate-proof`
  - As the inputs were declared as private in the program, they do not appear in the proof thanks to the zero-knowledge property of the protocol.
  - This will create a new file named `proof.json`
  - ZoKrates creates a file, proof.json, consisting of the three elliptic curve points that make up the zkSNARKs proof.

## 6. Peggy verifies its of claim ZKP, that she knows the required hash pre-image

- Assuming the Victor has deployed the blockchain.
- The verification contract requires 2 arguments

  - proof object (object of the 3 elliptic curve points)
  - Public argumements or inputs for the verification (this is optional, it depends on whether the ZKP verifier is designed to need it or not.)
    - In this case there is no public arguments. Just witness is required which is already represented by the 3 elliptic curve points such that others will not know the value of the "private witness"

- For verification, Peggy simply has to get the values of the 3 elliptic curve points and create an object similar to below:

```json
{
  "proof": {
    "a": [
      "0x1dc1fa289ae39a2de8c062fb7b26a337fa4e282a0994745919520c4f4f58fd57",
      "0x039da1f4abb6ba45970ebee1e29c21c3dad67f0953294b8a4fd5032c6cc74345"
    ],
    "b": [
      [
        "0x1df219efea4e94466fe0012862f607ab972922af50674e49aff628e776cc3414",
        "0x1bd8eac3975e449510a505f2617a9ebad0f5ae77943eda1a86385a296394cbf2"
      ],
      [
        "0x0f2baf186c51055c396000cd758a358968e2ca9e3f337a23ed488e46f5990817",
        "0x07f1454813641b2f4256cdc7be27e90a4394b9f99ac0fb0769d43840d3a472d4"
      ]
    ],
    "c": [
      "0x1396b83bf25c258fc00028b28dc6e06d7cf153f2b4efd7c42f37d3f74885244f",
      "0x1e6fae7ea8cbc847d7693de8103d29439ed3588b30e5d4798058647a622c67b3"
    ]
  }
}
```

## 7. Testing the claim using hardhat.

visit the "test" folder

---

# For more details visit

https://blog.decentriq.com/proving-hash-pre-image-zksnarks-zokrates/
