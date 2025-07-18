const fs = require('fs');
const {randomBytes} = require('crypto');
const {buildBabyjub} = require('circomlibjs');

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

  const priv = randFr();
  const pub = babyjub.mulPointEscalar(G, priv);
  const pubX = F.toObject(pub[0]);
  const pubY = F.toObject(pub[1]);

  const message = randFr();
  const k = randFr();
  const R = babyjub.mulPointEscalar(G, k);
  const Rx = F.toObject(R[0]);
  const r = mod(Rx, ORDER);
  const kinv = modInv(k, ORDER);
  const s = mod(kinv * (message + r * priv), ORDER);

  const input = {
    message: message.toString(),
    pubKeyX: pubX.toString(),
    pubKeyY: pubY.toString(),
    sigR: r.toString(),
    sigS: s.toString()
  };

  fs.writeFileSync(__dirname + '/ecdsa-native-verification.json', JSON.stringify(input, null, 2));
})();
