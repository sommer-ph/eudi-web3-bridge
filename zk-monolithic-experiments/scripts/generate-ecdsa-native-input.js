const fs = require('fs');
const {randomBytes} = require('crypto');
const {buildBabyjub} = require('circomlibjs');

// Convert bigint to array of k limbs of n bits each
function bigintToArray(n, k, x) {
  const mod = 1n << BigInt(n);
  const res = [];
  let tmp = BigInt(x);
  for (let i = 0; i < k; i++) {
    res.push(tmp % mod);
    tmp = tmp / mod;
  }
  return res;
}

function mod(a, m) {
  const res = a % m;
  return res >= 0n ? res : res + m;
}

function modInv(a, m) {
  let t = 0n, newT = 1n;
  let r = m, newR = mod(a, m);
  while (newR !== 0n) {
    const q = r / newR;
    [t, newT] = [newT, t - q * newT];
    [r, newR] = [newR, r - q * newR];
  }
  if (r > 1n) throw new Error('Inverse does not exist');
  if (t < 0n) t += m;
  return t;
}

(async () => {
  const babyjub = await buildBabyjub();
  const F = babyjub.F;
  const ORDER = babyjub.subOrder;
  const G = babyjub.Base8;

  function randFr() {
    let x;
    do { x = BigInt('0x' + randomBytes(32).toString('hex')); } while (x === 0n || x >= ORDER);
    return x;
  }

  // Generate private key and public key
  const priv = randFr();
  const pub = babyjub.mulPointEscalar(G, priv);
  const pubX = F.toObject(pub[0]);
  const pubY = F.toObject(pub[1]);

  // Generate message to sign
  const message = randFr();
  
  // Generate ECDSA signature
  const k = randFr();
  const R = babyjub.mulPointEscalar(G, k);
  const Rx = F.toObject(R[0]);
  const r = mod(Rx, ORDER);
  const kinv = modInv(k, ORDER);
  const s = mod(kinv * (message + r * priv), ORDER);

  const rArr = bigintToArray(64, 4, r).map(x => x.toString());
  const sArr = bigintToArray(64, 4, s).map(x => x.toString());
  const msgArr = bigintToArray(64, 4, message).map(x => x.toString());
  const pubXArr = bigintToArray(64, 4, pubX).map(x => x.toString());
  const pubYArr = bigintToArray(64, 4, pubY).map(x => x.toString());

  // Create input for circuit using limb representation
  const input = {
    r: rArr,
    s: sArr,
    msghash: msgArr,
    pubkey: [pubXArr, pubYArr]
  };

  console.log('Generated ECDSA signature data:');
  console.log('Public Key X:', pubX.toString());
  console.log('Public Key Y:', pubY.toString());
  console.log('Message:', message.toString());
  console.log('Signature R:', r.toString());
  console.log('Signature S:', s.toString());

  const outPath = __dirname + '/../input/prepared/ecdsa-native-verification.json';
  fs.writeFileSync(outPath, JSON.stringify(input, null, 2));
  console.log('Data saved to ' + outPath);
})().catch(console.error);