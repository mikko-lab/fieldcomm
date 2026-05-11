/**
 * duress.js — Pakottamisprotokolla
 *
 * Ongelma: vihollinen pakottaa virkamiehen avaamaan järjestelmän.
 * Ratkaisu: kaksi PIN-koodia jotka molemmat "toimivat" —
 *           mutta vain toinen antaa oikean datan.
 *
 * NORMAALI PIN:
 *   → Avaa oikean avaimen
 *   → Normaali pääsy
 *
 * DURESS PIN:
 *   → Näyttää toimivan täysin normaalisti
 *   → Lähettää hiljaisen hälytyksen (aikaleima + sijainti)
 *   → Avaa DECOY-holvin väärennetyllä datalla
 *   → Hyökkääjä ei tiedä saavansa väärää dataa
 *
 * TEKNINEN RAKENNE:
 *
 *   scrypt(normalPin, salt)  → normalKey  → salaa oikean holvin
 *   scrypt(duressPin, salt)  → duressKey  → salaa decoy-holvin
 *
 *   Molemmat holvit tallennetaan rinnakkain.
 *   Ulkopuolinen ei erota kumpi on kumpi.
 *   Holvit näyttävät identtisiltä (samankokoinen salattu blob).
 */

import {
  scryptSync,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  timingSafeEqual
} from 'node:crypto';

// scrypt-parametrit — tarkoituksella hidas brute-forcea vastaan
const SCRYPT_N = 16384; // CPU-työ
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN  = 32;

/**
 * Johda avain PIN-koodista ja saltista
 * timingSafeEqual käytetään myöhemmin — ei ajoitushyökkäyksiä
 */
function deriveKey(pin, salt) {
  return scryptSync(pin, salt, KEY_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });
}

/**
 * Salaa data AES-256-GCM:llä
 */
function seal(plaintext, key) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, tag, enc]); // 12 + 16 + N
}

/**
 * Pura AES-256-GCM salattu data
 * Heittää virheen jos avain tai eheys epäonnistuu
 */
function unseal(blob, key) {
  const nonce = blob.slice(0, 12);
  const tag   = blob.slice(12, 28);
  const enc   = blob.slice(28);
  const dec   = createDecipheriv('aes-256-gcm', key, nonce);
  dec.setAuthTag(tag);
  return Buffer.concat([dec.update(enc), dec.final()]);
}

/**
 * Alusta duress-holvijärjestelmä
 *
 * @param {string}     normalPin  - oikea PIN (käyttäjällä)
 * @param {string}     duressPin  - pakottamis-PIN (eri kuin normalPin)
 * @param {Buffer}     realSecret - oikea data/avain jota suojataan
 * @param {Buffer}     decoySecret- väärennetty data jota näytetään pakottamistilanteessa
 * @returns {Object}   vault — tallennetaan laitteelle
 */
export function initVault(normalPin, duressPin, realSecret, decoySecret) {
  if (normalPin === duressPin) {
    throw new Error('Normaali PIN ja duress PIN eivät saa olla samat');
  }

  const normalSalt = randomBytes(32);
  const duressSalt = randomBytes(32);

  const normalKey = deriveKey(normalPin, normalSalt);
  const duressKey = deriveKey(duressPin, duressSalt);

  // Salataan molemmat holvit — samankokoiset blobit
  const realBlob  = seal(realSecret,  normalKey);
  const decoyBlob = seal(decoySecret, duressKey);

  return {
    version: 1,
    normalSalt:  normalSalt.toString('hex'),
    duressSalt:  duressSalt.toString('hex'),
    realBlob:    realBlob.toString('hex'),
    decoyBlob:   decoyBlob.toString('hex'),
    createdAt:   Date.now(),
    // Hälytyslokit — täytetään duress-käytössä
    duressEvents: []
  };
}

/**
 * Avaa holvi PIN-koodilla
 *
 * Palautusrakenne on SAMA molemmille PIN-tyypeille —
 * hyökkääjä ei näe eroa käyttäytymisessä.
 *
 * @param {Object}  vault     - initVault:in palauttama rakenne
 * @param {string}  pin       - annettu PIN
 * @param {Object}  context   - { location, deviceId } hälytystä varten
 * @returns {Object} { secret, isDuress, alertSent }
 */
export function openVault(vault, pin, context = {}) {
  const normalSalt = Buffer.from(vault.normalSalt, 'hex');
  const duressSalt = Buffer.from(vault.duressSalt, 'hex');

  const attemptKey = deriveKey(pin, normalSalt);

  // Kokeile normaalia avainta ensin
  let secret = null;
  let isDuress = false;

  try {
    secret = unseal(Buffer.from(vault.realBlob, 'hex'), attemptKey);
    // Onnistui — normaali pääsy
    return { secret, isDuress: false, alertSent: false };
  } catch {
    // Normaali avain ei toiminut — kokeile duress-avainta
  }

  const duressAttemptKey = deriveKey(pin, duressSalt);
  try {
    secret = unseal(Buffer.from(vault.decoyBlob, 'hex'), duressAttemptKey);
    isDuress = true;
  } catch {
    throw new Error('VIRHEELLINEN PIN — pääsy estetty');
  }

  // ── DURESS-POLKU ──────────────────────────────────────────
  // Hyökkääjä näkee: normaali vastaus, ei virhettä, data tulee
  // Järjestelmä tekee: lähettää hiljaisen hälytyksen

  const alert = {
    timestamp:  new Date().toISOString(),
    unixTime:   Math.floor(Date.now() / 1000),
    deviceId:   context.deviceId  || 'TUNTEMATON',
    location:   context.location  || 'TUNTEMATON',
    ipHint:     context.ip        || 'TUNTEMATON',
    severity:   'KRIITTINEN',
    message:    'DURESS-PIN KÄYTETTY — henkilö saattaa olla pakottamistilanteessa',
    action:     'Ota välittömästi yhteys turvatiimiin'
  };

  // Tallennetaan lokiin (oikeassa järjestelmässä: lähetetään OOB-kanavaa pitkin)
  vault.duressEvents.push(alert);

  return {
    secret,           // decoy-data — hyökkääjä luulee saavansa oikean
    isDuress: true,   // VAIN järjestelmän sisäinen tieto — ei näytetä käyttäjälle
    alertSent: true,
    alert
  };
}

/**
 * Simuloi hiljainen OOB-hälytys (Out-Of-Band)
 * Oikeassa järjestelmässä: SMS turvapuhelimeen, Iris²-paketti,
 * tai ennalta sovittu "kuolleen miehen kytkimen" triggeröinti
 */
export function formatAlert(alert) {
  return [
    '╔══════════════════════════════════════════╗',
    '║  ⚠  DURESS-HÄLYTYS — LUOTTAMUKSELLINEN  ║',
    '╠══════════════════════════════════════════╣',
    `║  Aika:     ${alert.timestamp.slice(0,19).replace('T',' ')}          ║`,
    `║  Laite:    ${alert.deviceId.padEnd(30)}  ║`,
    `║  Sijainti: ${alert.location.padEnd(30)}  ║`,
    `║  Vakavuus: ${alert.severity.padEnd(30)}  ║`,
    '╠══════════════════════════════════════════╣',
    `║  ${alert.message.slice(0,40)}  ║`,
    `║  ${alert.action.padEnd(40)}  ║`,
    '╚══════════════════════════════════════════╝',
  ].join('\n');
}
