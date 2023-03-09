// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x21ab9dc8030180a2c02ae8286eadde56e1bbe20dac11ecf2987bd486f17e698a), uint256(0x0a2eff372b978ba651955d9ac7120acd227b656d09227738b2241a8e879dc85b));
        vk.beta = Pairing.G2Point([uint256(0x3031f885e8a61a5ef77e00551514978cd757abff93cf6a6d0e66fe8d9b79a5dc), uint256(0x00ec8b6f6e5ec87d760236c9e2a33544690361994187afb6a4cf311d4ad29b23)], [uint256(0x152c30641eeefe2b868cde4d07fd011a5a253178bbf16abd40bf755fadf148d2), uint256(0x0fbc142abba298463e99b568a5b6e759e13658c88b71db6b7f267412441d4511)]);
        vk.gamma = Pairing.G2Point([uint256(0x2f9b7b298d897a574293d40586682deda591c1b0cecefeb4f7ea9cf3f87cd7f7), uint256(0x131cda345134f0c04f3d8201a71c088b36429228eb827cd40d5a22fd43b45ada)], [uint256(0x0d703aaa875a5eabab0ef06a3bbc14846ec1981e9af93c984d2b20915736161c), uint256(0x133371c82b143721846db9b237c0eb8a0744a5b92eaec82114be3d5bf344fc0d)]);
        vk.delta = Pairing.G2Point([uint256(0x2971d1fdfa1cc5e3b83dbe92db73dd1495753d3c0677060e49c14d778c3cd8fd), uint256(0x3013b0c26db44ec269bb45b8c587fa93704b06d976c0e16ec555ec833ba05184)], [uint256(0x0afd6b88964f1552e9c1a985acc1f9660ab292025895e69614e84ee44a5126c2), uint256(0x18c94921c1508b09fe41981e47678b304c527fd2573a798db07738ee874f1305)]);
        vk.gamma_abc = new Pairing.G1Point[](11);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2129877c25b3fb7f1d18b22c0e11472b5611d428f05d21eae3c0647bebad70b1), uint256(0x162f3d76f6c839daf74215ae23391941239263d9661bc76b261d888985ec062c));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2077dceaea910db4f8c1122a63efd19452d282c66b3a89bbe1337a35ae09f4ce), uint256(0x2e2c450b7f2b6d720a1a2424aa2ddb25fa03d755945f6591c13d3bc680c32a4f));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x040001ca816f8d8bc8347338c43cc6f1f7e422aff948deafc0a6ba6b0cf35709), uint256(0x25ca43c096e6d316a9c0d32c9ac89642bc257ae9caff7cf9f296938008832a19));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0d8882ef9a3171832db8bd6d5aaa8b1562a98bb324710990681b742c4bf316d8), uint256(0x1ce2910bf1046a71f1b51b1953a51ae7ebff96ccec5011fc3bd15d99bd1f4a95));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2c4dfb081ee110b0881ec4abc04d75bf703f2686afbb84c5975e006c5335ee2d), uint256(0x0cbb904c52020d567c37e6cbd49f3f8b32030ec89dfc394c6c13d6d05e07d801));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2b2fa2181cd69e8f5988d805dca9789ae67a47c42a1b5690777702612935262f), uint256(0x29fd87353e93bdea0ee4400ee49457ba9656593397c09df2eb8c40ab6f764b34));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2fcebe89c04cfd3830b3a780c1a70680e1b9cb9f9df8e404d58dbced63d46aa6), uint256(0x1893945fa9106251779537e6de8cec9c1fecf40eef45ffd097b59637a6b4ad11));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2fd0302f47d15295b6928f5c15f12f886ecdcc0c6521469bf2595eb6bd5cf08d), uint256(0x2fed7024b8a577f0e381be6fe22dc37802436bbe9d6262f3f0d86569dc60ebc3));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x110276aa51e30cdb71fb5cc625366dcdefa17cf98fe508efabaf7da3624b89c6), uint256(0x002d482f615f429277806908f0e51287a46246d0e92c46d55dabf1e7ae4353d4));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x11f59d4c5127b5a1d8f942737169b511d1a9e22b79ff68e7a6af9b523b5c0934), uint256(0x0b9a8e99b3039dd7450a857c94ffd3bc911045099142235a8390ab667b0f6b3a));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0d5a32288e59d42dfda01655cd96017e3aa2c15e7d43e6631115f31de32f058a), uint256(0x1cdd49bb93faa8402d959e7c311222bb7417d07c0426da01ba9b962ff6fb4810));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[10] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](10);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
