// Downloads the original Tornado Cash trusted-setup artifacts (tornado-core release v2.1, 2020 ceremony)
// and checks them against pinned SHA-256 hashes.
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const https = require('https')

const RELEASE = 'https://github.com/tornadocash/tornado-core/releases/download/v2.1'
const FILES = {
  'withdraw.json': '3ddd61dbff09caeec82d8edde95c674a3c34f9e66b1fe9f2c8783e72fe536f98',
  'withdraw_proving_key.bin': '8e2d2f22beafb5a9666daebca57b13f8029c3656c65fcfbcc86e2418fa16a3af',
  'withdraw_verification_key.json': '3eedcf6ec6b5c24219ed19c7a33966fbfa6a03ae7c84124270589091e87cf8d3',
  'Verifier.sol': '9f15bfde22a607012d6aae29533da3d22c7f73f4401bc34a619867f9e289504c',
}
const DIR = path.join(__dirname, 'artifacts')

const sha256 = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')

function get(url, dest, redirects = 5) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { 'User-Agent': 'tornado-core-v3' } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirects > 0) {
          res.resume()
          return resolve(get(res.headers.location, dest, redirects - 1))
        }
        if (res.statusCode !== 200) return reject(new Error(`${url}: HTTP ${res.statusCode}`))
        const out = fs.createWriteStream(dest)
        res.pipe(out)
        out.on('finish', () => out.close(resolve))
        out.on('error', reject)
      })
      .on('error', reject)
  })
}

async function main() {
  fs.mkdirSync(DIR, { recursive: true })
  for (const [name, hash] of Object.entries(FILES)) {
    const dest = path.join(DIR, name)
    if (fs.existsSync(dest) && sha256(dest) === hash) {
      console.log(`ok       ${name}`)
      continue
    }
    console.log(`fetching ${name}`)
    await get(`${RELEASE}/${name}`, dest)
    const actual = sha256(dest)
    if (actual !== hash) throw new Error(`${name}: sha256 ${actual} != ${hash}`)
  }
}

main().catch((e) => {
  console.error(e.message)
  process.exit(1)
})
