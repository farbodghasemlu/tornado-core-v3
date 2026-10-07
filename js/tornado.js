// Note / Merkle tree / proof helpers that reproduce the original Tornado Cash
// client logic (tornado-cli) using the exact library versions it shipped with.
// Proofs are generated against the 2020 trusted-setup proving key, so they
// verify on the Verifier contract deployed on Ethereum mainnet.
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const snarkjs = require('snarkjs')
const circomlib = require('circomlib')
const buildGroth16 = require('websnark/src/groth16')
const websnarkUtils = require('websnark/src/utils')

const bigInt = snarkjs.bigInt
const FIELD_SIZE = bigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617')
// keccak256("tornado") % FIELD_SIZE
const ZERO_VALUE = bigInt('21663839004416932945382355908790599225266501822907911457504978515578255421292')
const LEVELS = 20
const ARTIFACTS = path.join(__dirname, 'artifacts')

const toHex = (n, bytes = 32) => '0x' + bigInt(n).toString(16).padStart(bytes * 2, '0')
const pedersenHash = (data) => circomlib.babyJub.unpackPoint(circomlib.pedersenHash.hash(data))[0]
const mimc = (left, right) => circomlib.mimcsponge.multiHash([bigInt(left), bigInt(right)])

/** Build a note. `seed` makes it deterministic (tests); omit it for a random note. */
function createNote(seed) {
  const bytes = seed
    ? crypto.createHash('sha512').update(String(seed)).digest()
    : crypto.randomBytes(62)
  const nullifier = bigInt.leBuff2int(bytes.subarray(0, 31))
  const secret = bigInt.leBuff2int(bytes.subarray(31, 62))
  const preimage = Buffer.concat([nullifier.leInt2Buff(31), secret.leInt2Buff(31)])
  return {
    nullifier,
    secret,
    preimage,
    commitment: pedersenHash(preimage),
    nullifierHash: pedersenHash(nullifier.leInt2Buff(31)),
  }
}

/** Parse / format notes in the original `tornado-<currency>-<amount>-<chainId>-0x<preimage>` format. */
function parseNote(noteString) {
  const m = /tornado-(?<currency>\w+)-(?<amount>[\d.]+)-(?<chainId>\d+)-0x(?<hex>[0-9a-fA-F]{124})/g.exec(noteString)
  if (!m) throw new Error('invalid note format')
  const buf = Buffer.from(m.groups.hex, 'hex')
  const nullifier = bigInt.leBuff2int(buf.subarray(0, 31))
  const secret = bigInt.leBuff2int(buf.subarray(31, 62))
  return {
    ...m.groups,
    nullifier,
    secret,
    preimage: buf,
    commitment: pedersenHash(buf),
    nullifierHash: pedersenHash(nullifier.leInt2Buff(31)),
  }
}

const formatNote = (note, currency, amount, chainId) =>
  `tornado-${currency}-${amount}-${chainId}-0x${note.preimage.toString('hex')}`

/** Merkle path for `leaves[index]` in a depth-20 MiMC tree, matching MerkleTreeWithHistory. */
function merkleProof(leaves, index) {
  let layer = leaves.map(bigInt)
  let zero = ZERO_VALUE
  const pathElements = []
  const pathIndices = []
  for (let level = 0; level < LEVELS; level++) {
    pathIndices.push(index % 2)
    const sibling = index ^ 1
    pathElements.push(sibling < layer.length ? layer[sibling] : zero)
    const next = []
    for (let i = 0; i < layer.length; i += 2) {
      next.push(mimc(layer[i], i + 1 < layer.length ? layer[i + 1] : zero))
    }
    layer = next
    zero = mimc(zero, zero)
    index >>= 1
  }
  return { root: layer[0], pathElements, pathIndices }
}

let groth16
async function prove({ note, leaves, recipient, relayer = 0, fee = 0, refund = 0 }) {
  const index = leaves.findIndex((l) => bigInt(l).equals(note.commitment))
  if (index < 0) throw new Error('note commitment not found in leaves')
  const { root, pathElements, pathIndices } = merkleProof(leaves, index)

  groth16 = groth16 || (await buildGroth16())
  const circuit = require(path.join(ARTIFACTS, 'withdraw.json'))
  const provingKey = fs.readFileSync(path.join(ARTIFACTS, 'withdraw_proving_key.bin')).buffer
  const input = {
    root,
    nullifierHash: note.nullifierHash,
    recipient: bigInt(recipient),
    relayer: bigInt(relayer),
    fee: bigInt(fee),
    refund: bigInt(refund),
    nullifier: note.nullifier,
    secret: note.secret,
    pathElements,
    pathIndices,
  }
  const proofData = await websnarkUtils.genWitnessAndProve(groth16, input, circuit, provingKey)
  const { proof } = websnarkUtils.toSolidityInput(proofData)
  return { proof, root, nullifierHash: note.nullifierHash }
}

module.exports = {
  bigInt,
  FIELD_SIZE,
  ZERO_VALUE,
  LEVELS,
  toHex,
  mimc,
  createNote,
  parseNote,
  formatNote,
  merkleProof,
  prove,
  terminate: () => groth16 && groth16.terminate(),
}
