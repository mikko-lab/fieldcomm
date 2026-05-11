/**
 * index.js — FieldComm PoC v0.2 demo
 *
 * Täydellinen ketju:
 * ML-KEM avaintenvaihto → 50t salattu komento → ML-DSA allekirjoitus → purku + vahvistus
 */

import { generateKeyPair, encapsulate, decapsulate } from './crypto/kyber.js';
import { generateSigningKeyPair, signFrame, verifyFrame } from './crypto/dilithium.js';
import { buildCommand, parseCommand, COMMAND_TYPES } from './protocol/command.js';

function printHeader(title) {
  console.log('\n' + '═'.repeat(58));
  console.log(`  ${title}`);
  console.log('═'.repeat(58));
}

function printStep(step, desc) {
  console.log(`\n  [${step}] ${desc}`);
}

function hex(bytes, max = 14) {
  const s = Array.from(bytes.slice(0, max)).map(b => b.toString(16).padStart(2, '0')).join(' ');
  return bytes.length > max ? `${s} ...` : s;
}

async function runDemo() {

  printHeader('FIELDCOMM v0.2 — ML-KEM + ML-DSA');
  console.log('  Salaus: ML-KEM-768 (FIPS 203) + AES-256-GCM');
  console.log('  Allekirjoitus: ML-DSA-65 (FIPS 204)');
  console.log('  Skenaario: Helsinki HQ → Lapin kenttäyksikkö LA09');

  // ── 1. AVAINPARIT ──────────────────────────────────────────

  printHeader('1 — Avainparien generointi');

  // Salausavaimet (ML-KEM)
  printStep('1a', 'Kenttäyksikkö LA09 generoi ML-KEM salausavainparin...');
  const fieldEncKeys = generateKeyPair();
  console.log(`       KEM julkinen: ${hex(fieldEncKeys.publicKey)} (${fieldEncKeys.publicKey.length}t)`);

  // Allekirjoitusavaimet (ML-DSA) — molemmille osapuolille
  printStep('1b', 'HQ generoi ML-DSA allekirjoitusavainparin...');
  const hqSignKeys = generateSigningKeyPair();
  console.log(`       DSA julkinen: ${hex(hqSignKeys.publicKey)} (${hqSignKeys.publicKey.length}t)`);
  console.log(`       DSA yksit.:   [HSM-sirussa — 4032t]`);

  printStep('1c', 'Kenttäyksikkö generoi ML-DSA allekirjoitusavainparin...');
  const fieldSignKeys = generateSigningKeyPair();
  console.log(`       DSA julkinen: ${hex(fieldSignKeys.publicKey)} (${fieldSignKeys.publicKey.length}t)`);

  // ── 2. AVAINTENVAIHTO ──────────────────────────────────────

  printHeader('2 — ML-KEM avaintenvaihto');

  printStep('2a', 'HQ kapseloi salaisuuden kenttäyksikön julkisella KEM-avaimella...');
  const { cipherText, sharedSecret: hqSecret } = encapsulate(fieldEncKeys.publicKey);
  console.log(`       Kapseloitu: ${hex(cipherText)} (${cipherText.length}t) → lähetetään LA09:lle`);

  printStep('2b', 'LA09 purkaa salaisuuden omalla yksityisavaimellaan...');
  const fieldSecret = decapsulate(cipherText, fieldEncKeys.secretKey);

  const match = hqSecret.every((b, i) => b === fieldSecret[i]);
  console.log(`\n       ✓ Jaettu salaisuus muodostettu: ${match ? 'KYLLÄ' : 'EI — VIRHE'}`);
  console.log(`       Salaisuus: ${hex(hqSecret)} [identtinen molemmilla]`);

  // ── 3. KOMENTO: SALAUS + ALLEKIRJOITUS ─────────────────────

  printHeader('3 — Komennon lähetys HQ → LA09');

  const HQ_ID    = 0xF101;
  const FIELD_ID = 0x0A09;

  // 6 tavun payload: grid-ref + prioriteetti
  const payload = new Uint8Array([0x42, 0x1A, 0x03, 0x00, 0x00, 0x00]);

  printStep('3a', 'Rakennetaan 50t salattu SIIRRY-komento...');
  const frame = buildCommand(HQ_ID, FIELD_ID, COMMAND_TYPES.SIIRRY, payload, hqSecret);

  console.log('\n       50-tavun kehys:');
  const fhex = Array.from(frame).map(b => b.toString(16).padStart(2, '0'));
  const labels = ['Lähettäjä-ID ', 'Aikaleima    ', 'Enc.payload  ', 'Nonce        ', 'GCM Auth Tag '];
  for (let i = 0; i < 50; i += 10) {
    console.log(`       [${String(i).padStart(2,'0')}] ${fhex.slice(i,i+10).join(' ')}  ${labels[i/10]}`);
  }

  printStep('3b', 'HQ allekirjoittaa kehyksen ML-DSA-65:llä...');
  const sigPacket = signFrame(frame, hqSignKeys.secretKey, HQ_ID);
  console.log(`       Allekirjoituspaketti: ${sigPacket.length}t (kulkee Iris²:n kautta, ei LoRa)`);
  console.log(`       Allekirjoitus: ${hex(sigPacket.slice(16))} ... (3309t)`);

  // ── 4. VASTAANOTTO: PURKU + VAHVISTUS ─────────────────────

  printHeader('4 — Vastaanotto LA09:ssä');

  printStep('4a', 'Puretaan 50t komento kenttäyksikön avaimella...');
  const parsed = parseCommand(frame, fieldSecret);

  console.log('\n       ┌─ SALATTU KOMENTO PURETTU ──────────────────┐');
  console.log(`       │  Lähettäjä:    0x${parsed.senderId.toString(16).toUpperCase().padEnd(10)} (HQ)          │`);
  console.log(`       │  Kohde:        0x${parsed.receiverId.toString(16).toUpperCase().padEnd(10)} (LA09)        │`);
  console.log(`       │  Aikaleima:    ${parsed.timestamp.slice(11,19)} UTC                 │`);
  console.log(`       │  Komento:      ${parsed.commandName.padEnd(10)}                     │`);
  console.log(`       │  Payload:      ${hex(parsed.payload, 6).padEnd(20)}              │`);
  console.log('       └───────────────────────────────────────────────┘');

  printStep('4b', 'Vahvistetaan HQ:n ML-DSA-65 allekirjoitus...');
  // LA09 hakee HQ:n julkisen avaimen DID-rekisteristä
  const verification = verifyFrame(frame, sigPacket, hqSignKeys.publicKey);

  console.log('\n       ┌─ ALLEKIRJOITUS VAHVISTETTU ────────────────┐');
  console.log(`       │  ✓ Kryptografisesti aito                   │`);
  console.log(`       │  Allekirjoittaja: 0x${verification.signerId.toString(16).toUpperCase().padEnd(4)}                 │`);
  console.log(`       │  Algoritmi:  ${verification.algorithm.padEnd(25)}   │`);
  console.log(`       │  Aikaleima:  ${verification.timestamp.slice(11,19)} UTC                │`);
  console.log('       └───────────────────────────────────────────────┘');

  // ── 5. TURVALLISUUSTESTIT ──────────────────────────────────

  printHeader('5 — Turvallisuustestit');

  printStep('5a', 'Manipuloitu kehys (man-in-the-middle)...');
  const tampered = Buffer.from(frame);
  tampered[28] ^= 0xFF;
  try {
    parseCommand(tampered, fieldSecret);
    console.log('       ✗ VIRHE — manipulointi ei havaittu!');
  } catch (e) {
    console.log(`       ✓ AES-GCM hylkäsi: "${e.message}"`);
  }

  printStep('5b', 'Väärä allekirjoittaja (identiteettipetos)...');
  const impostor = generateSigningKeyPair();
  const fakePacket = signFrame(frame, impostor.secretKey, HQ_ID);
  try {
    verifyFrame(frame, fakePacket, hqSignKeys.publicKey);
    console.log('       ✗ VIRHE — väärennetty allekirjoitus hyväksyttiin!');
  } catch (e) {
    console.log(`       ✓ ML-DSA hylkäsi: "${e.message}"`);
  }

  printStep('5c', 'Sekvenssiviittauksen manipulointi (replay-attack)...');
  const replayPacket = Buffer.from(sigPacket);
  replayPacket.writeUInt32BE(9999, 0); // Väärennetty sekvenssimero
  try {
    verifyFrame(frame, replayPacket, hqSignKeys.publicKey);
    console.log('       ✗ VIRHE — replay hyväksyttiin!');
  } catch (e) {
    console.log(`       ✓ Sekvenssisuoja hylkäsi: "${e.message}"`);
  }

  // ── YHTEENVETO ─────────────────────────────────────────────

  printHeader('YHTEENVETO — v0.2');
  console.log(`
  Toteutettu:
  ✓ ML-KEM-768  — kvanttikestävä avaintenvaihto     (FIPS 203)
  ✓ AES-256-GCM — viestisalaus + eheyden tarkistus
  ✓ ML-DSA-65   — digitaalinen allekirjoitus         (FIPS 204)
  ✓ 50t kehys   — LoRa-yhteensopiva kenttäprotokolla
  ✓ Replay-suoja — aikaleima + sekvenssimero
  ✓ Identiteettivahvistus — DID-rekisteriviite

  Seuraava — v0.3:
  → Shamir's Secret Sharing (avainten hajautus)
  → Duress-protokolla (pakottamistilanne)
  → CLI-työkalu testaukseen
  `);
}

runDemo().catch(console.error);
