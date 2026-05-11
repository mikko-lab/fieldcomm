/**
 * shamir.js — Shamirin salaisuuksien jako
 *
 * Ratkaisee: "Kenraalin avain ei saa olla yhden ihmisen hallussa"
 *
 * Malli: 3/5 — avain jaetaan viidelle luotetulle henkilölle.
 * Tarvitaan vähintään kolme rekonstruointiin.
 * Yksi tai kaksi osaa eivät paljasta mitään.
 *
 * Käyttötapaukset:
 *  - Kriittisen avaimen varmuuskopiointi ilman keskitettyä riskiä
 *  - Pakottamissuoja: yksittäinen henkilö ei voi paljastaa avainta
 *  - Toipuminen: avain saadaan takaisin vaikka 2 osanhaltijaa katoaisi
 */

import { split, join } from 'shamir';
import { randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Jaa avain n osaan, joista tarvitaan k rekonstruointiin
 *
 * @param {Uint8Array} secret   - jaettava avain (esim. ML-KEM yksityisavain)
 * @param {number}     n        - osien kokonaismäärä (esim. 5)
 * @param {number}     k        - tarvittava vähimmäismäärä (esim. 3)
 * @returns {Object}  shares    - { '1': Uint8Array, '2': ..., ... }
 */
export function splitSecret(secret, n = 5, k = 3) {
  if (k < 2)  throw new Error('Kynnys (k) täytyy olla vähintään 2');
  if (n < k)  throw new Error('Osien määrä (n) täytyy olla >= kynnys (k)');
  if (n > 255) throw new Error('Osien maksimimäärä on 255');

  const secretBytes = secret instanceof Uint8Array
    ? secret
    : new Uint8Array(secret);

  return split(randomBytes, n, k, secretBytes);
}

/**
 * Rekonstruoi avain osakentältä
 *
 * @param {Object} shares   - { '1': Uint8Array, '3': Uint8Array, ... }
 * @param {number} k        - vaadittu kynnys (validointia varten)
 * @returns {Uint8Array}    rekonstruoitu avain
 */
export function reconstructSecret(shares, k = 3) {
  const provided = Object.keys(shares).length;
  if (provided < k) {
    throw new Error(
      `Liian vähän osia: ${provided} toimitettu, vaaditaan ${k}`
    );
  }
  return join(shares);
}

/**
 * Tarkista täsmääkö rekonstruoitu avain alkuperäiseen
 * (käytetään testauksessa — tuotannossa ei ole alkuperäistä vertailtavaksi)
 */
export function verifyReconstruction(original, reconstructed) {
  if (original.length !== reconstructed.length) return false;
  return timingSafeEqual(Buffer.from(original), Buffer.from(reconstructed));
}

/**
 * Generoi ihmisluettava kuvaus osanhaltijalle
 * Oikeassa järjestelmässä tämä tulostettaisiin QR-koodina
 * ja tallennettaisiin fyysiseen turvavarastoon
 */
export function describeShare(shareIndex, shareBytes, metadata = {}) {
  const hex = Buffer.from(shareBytes).toString('hex');
  const checksum = Buffer.from(shareBytes)
    .reduce((acc, b) => (acc + b) & 0xFF, 0)
    .toString(16).padStart(2, '0').toUpperCase();

  return {
    shareId: shareIndex,
    holder: metadata.holder || `Osanhaltija ${shareIndex}`,
    role: metadata.role || 'Ei määritelty',
    hexEncoded: hex,
    checksum: `0x${checksum}`,
    byteLength: shareBytes.length,
    created: new Date().toISOString(),
    instructions: [
      'Säilytä tämä osa turvallisessa fyysisessä paikassa',
      'Älä koskaan jaa tai lähetä digitaalisesti',
      'Tuhoa turvallisesti jos tehtäväsi päättyy',
      `Tarvitaan ${metadata.k || 3}/${metadata.n || 5} osaa rekonstruointiin`
    ]
  };
}
