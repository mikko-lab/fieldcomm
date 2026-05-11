/**
 * dilithium.js — ML-DSA-65 digitaaliset allekirjoitukset
 * NIST FIPS 204 (aiemmin CRYSTALS-Dilithium)
 *
 * Vastaa kysymykseen: "Kuka tämän lähetti?"
 * GCM-tagi todistaa eheyden — Dilithium todistaa identiteetin.
 *
 * ALLEKIRJOITUSPAKETTI (erillinen 50t kehyksen rinnalla):
 * ┌──────────────────────────────────────────────┐
 * │ [0-3]    Viittaus-kehyksen sekvenssimero (4t) │
 * │ [4-7]    Allekirjoittajan ID            (4t)  │
 * │ [8-11]   Aikaleima                      (4t)  │
 * │ [12-15]  Allekirjoituksen pituus        (4t)  │
 * │ [16-N]   ML-DSA-65 allekirjoitus    (3309t)   │
 * └──────────────────────────────────────────────┘
 * Yhteensä: 16 + 3309 = 3325 tavua
 * Lähetetään Iris²:n kautta (ei LoRa — liian iso)
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from 'node:crypto';

/**
 * Generoi ML-DSA-65 allekirjoitusavainpari
 * Julkinen avain rekisteröidään DID-rekisteriin
 * Yksityisavain pysyy HSM-sirussa
 */
export function generateSigningKeyPair() {
  const seed = randomBytes(32);
  const { publicKey, secretKey } = ml_dsa65.keygen(seed);
  return {
    publicKey,  // 1952 tavua — julkinen, rekisteröitävissä
    secretKey   // 4032 tavua — HSM-sirussa, ei koskaan lähetetä
  };
}

/**
 * Allekirjoita 50-tavun kenttäkomento
 * Allekirjoitetaan koko kehys (sisältää aikaleiman + MAC)
 *
 * @param {Buffer} frame       - 50t kenttäkomento
 * @param {Uint8Array} secretKey - lähettäjän yksityinen allekirjoitusavain
 * @param {number} senderId    - lähettäjä-ID lisätietona
 * @returns {Buffer} allekirjoituspaketti (3325t)
 */
export function signFrame(frame, secretKey, senderId) {
  const frameBytes = new Uint8Array(frame);
  const signature = ml_dsa65.sign(frameBytes, secretKey);

  const packet = Buffer.alloc(16 + signature.length);
  const view = new DataView(packet.buffer);

  // Sekvenssimero kehyksestä (tavut 12-13, laajennetaan 32-bittiseksi)
  view.setUint32(0, frame.readUInt16BE(12), false);
  // Allekirjoittajan ID
  view.setUint32(4, senderId, false);
  // Aikaleima
  view.setUint32(8, Math.floor(Date.now() / 1000), false);
  // Allekirjoituksen pituus
  view.setUint32(12, signature.length, false);
  // Allekirjoitus
  Buffer.from(signature).copy(packet, 16);

  return packet;
}

/**
 * Vahvista allekirjoituspaketti
 * Palauttaa vahvistustiedot tai heittää virheen
 *
 * @param {Buffer} frame          - alkuperäinen 50t kehys
 * @param {Buffer} signaturePacket - allekirjoituspaketti
 * @param {Uint8Array} publicKey  - lähettäjän julkinen avain (DID-rekisteristä)
 */
export function verifyFrame(frame, signaturePacket, publicKey) {
  const view = new DataView(signaturePacket.buffer);

  const refSequence  = view.getUint32(0, false);
  const signerIdent  = view.getUint32(4, false);
  const timestamp    = view.getUint32(8, false);
  const sigLen       = view.getUint32(12, false);

  // Tarkista että sigLen on järkevä ennen kuin luodaan TypedArray
  if (sigLen < 100 || sigLen > 10000 || 16 + sigLen > signaturePacket.length) {
    throw new Error(`ALLEKIRJOITUSPAKETTI VIOITTUNUT — epäkelpo pituus (${sigLen}t)`);
  }

  const signature    = new Uint8Array(signaturePacket.buffer, 16, sigLen);
  const frameBytes   = new Uint8Array(frame);

  // Aikaleima — allekirjoitus ei saa olla yli 5min vanha
  const now = Math.floor(Date.now() / 1000);
  const age = now - timestamp;
  if (age > 300 || age < -5) {
    throw new Error(`ALLEKIRJOITUS VANHENTUNUT — ${age}s vanha (max 300s)`);
  }

  // Varmista että sekvenssi täsmää kehyksen sekvenssiin
  const frameSequence = frame.readUInt16BE(12);
  if (refSequence !== frameSequence) {
    throw new Error(`SEKVENSSI EI TÄSMÄÄ — paketti: ${refSequence}, kehys: ${frameSequence}`);
  }

  // Kryptografinen vahvistus
  const valid = ml_dsa65.verify(signature, frameBytes, publicKey);
  if (!valid) {
    throw new Error('ALLEKIRJOITUS EPÄKELPO — identiteetti ei vahvistunut');
  }

  return {
    valid: true,
    signerId: signerIdent,
    timestamp: new Date(timestamp * 1000).toISOString(),
    signatureSize: sigLen,
    algorithm: 'ML-DSA-65 (NIST FIPS 204)'
  };
}
