import { time, loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { anyValue } from '@nomicfoundation/hardhat-chai-matchers/withArgs'
import { expect } from 'chai'
import { ethers } from 'hardhat'
const fs = require('fs')

describe('ZKP', function () {
  // We define a fixture to reuse the same setup in every test.
  // We use loadFixture to run this setup once, snapshot that state,
  // and reset Hardhat Network to that snapshot in every test.
  async function deployOneYearLockFixture() {
    // Contracts are deployed using the first signer/account by default
    const [owner, otherAccount] = await ethers.getSigners()

    let proof: any

    fs.readFile(
      '/home/le4kno3/Documents/Github/ZKP-Projects/ZoKrates-Tutorials/SNARK_RNG_Project/test/proof.json',
      (err: any, data: any) => {
        if (err) throw err
        proof = JSON.parse(data)
      }
    )

    console.log('The proof is: ', proof)

    const Verifier = await ethers.getContractFactory('Verifier')
    const verifier = await Verifier.deploy()

    return { verifier, proof, owner, otherAccount }
  }

  describe('Test Cases', function () {
    it('Valid proof is verified', async function () {
      const { verifier, proof, owner } = await loadFixture(
        deployOneYearLockFixture
      )
      expect(await verifier.verifyTx(proof.proof, proof.inputs)).to.equal(true)
    })

    it('Cheat proof is shown invalid verification', async function () {
      const { verifier, proof, owner } = await loadFixture(
        deployOneYearLockFixture
      )

      const cheat = [...proof.inputs]
      cheat[cheat.length - 1] = cheat[cheat.length - 1].replace(
        /[01]$/,
        cheat[cheat.length - 1][65] == '1' ? '0' : '1'
      )

      expect(await verifier.verifyTx(proof.proof, cheat)).to.equal(false)
    })
  })
})
