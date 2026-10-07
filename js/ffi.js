#!/usr/bin/env node
// Foundry FFI entrypoint. Every command prints a single ABI-encoded hex blob to stdout.
//
//   note   <seed>                                              -> (bytes32 commitment, bytes32 nullifierHash)
//   root   <leaf,leaf,...>                                     -> (bytes32 root)
//   prove  <seed> <recipient> <relayer> <fee> <refund> <leaves> -> (bytes proof, bytes32 root, bytes32 nullifierHash)
//   hasher                                                     -> MiMCSponge(220) EVM bytecode
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const t = require('./tornado')
const genContract = require('circomlib/src/mimcsponge_gencontract.js')

const CACHE_DIR = path.join(__dirname, '.cache')
const word = (n) => t.toHex(n).slice(2)
const parseLeaves = (s) => (s ? s.split(',').filter(Boolean) : [])

async function main() {
  const [cmd, ...args] = process.argv.slice(2)
  switch (cmd) {
    case 'note': {
      const note = t.createNote(args[0])
      return '0x' + word(note.commitment) + word(note.nullifierHash)
    }
    case 'root': {
      const leaves = parseLeaves(args[0])
      if (leaves.length === 0) leaves.push(t.ZERO_VALUE)
      return '0x' + word(t.merkleProof(leaves, 0).root)
    }
    case 'prove': {
      // Proving takes ~10s, so proofs are cached by their full input (any valid proof will do).
      const cacheFile = path.join(CACHE_DIR, crypto.createHash('sha256').update(args.join('|').toLowerCase()).digest('hex'))
      if (fs.existsSync(cacheFile)) return fs.readFileSync(cacheFile, 'utf8')
      const [seed, recipient, relayer, fee, refund, leaves] = args
      const res = await t.prove({ note: t.createNote(seed), leaves: parseLeaves(leaves), recipient, relayer, fee, refund })
      const proof = res.proof.slice(2)
      // abi.encode(bytes, bytes32, bytes32): head = offset, root, nullifierHash; tail = len, data
      const out = '0x' + word(0x60) + word(res.root) + word(res.nullifierHash) + word(proof.length / 2) + proof
      fs.mkdirSync(CACHE_DIR, { recursive: true })
      fs.writeFileSync(cacheFile, out)
      return out
    }
    case 'hasher':
      return genContract.createCode('mimcsponge', 220)
    default:
      throw new Error(`unknown command ${cmd}`)
  }
}

main()
  .then((out) => {
    process.stdout.write(out)
    t.terminate()
    process.exit(0)
  })
  .catch((e) => {
    console.error(e)
    process.exit(1)
  })
