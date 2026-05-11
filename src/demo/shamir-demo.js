/**
 * shamir-demo.js — Avainten hajautus kenttäskenaariossa
 *
 * Skenaario: Kenraali Virtasen ML-DSA yksityisavain
 * jaetaan viidelle luotetulle upseerille.
 * Tarvitaan kolme rekonstruointiin.
 */

import { generateSigningKeyPair } from '../crypto/dilithium.js';
import { splitSecret, reconstructSecret, verifyReconstruction, describeShare } from '../crypto/shamir.js';
import { randomBytes } from 'node:crypto';

function printHeader(t) {
  console.log('\n' + '═'.repeat(58));
  console.log(`  ${t}`);
  console.log('═'.repeat(58));
}

function printStep(s, d) { console.log(`\n  [${s}] ${d}`); }
function hex(b, n = 12) {
  return Array.from(b.slice(0,n)).map(x => x.toString(16).padStart(2,'0')).join(' ') + (b.length > n ? ' ...' : '');
}

async function runShamirDemo() {

  printHeader('FIELDCOMM v0.3 — Shamir\'s Secret Sharing');
  console.log('  Skenaario: Kenraali Virtasen avaimen hajautus');
  console.log('  Malli: 3/5 — kolme viidestä upseerista tarvitaan');

  // ── 1. AVAIN JOTA SUOJATAAN ──────────────────────────────

  printHeader('1 — Kenraali Virtasen ML-DSA avainpari');

  printStep('1a', 'Generoidaan allekirjoitusavainpari...');

  // Käytetään 32-tavuista siemenavainta — edustaa ML-DSA secretKeyä
  // (oikeassa toteutuksessa koko 4032t avain jaetaan)
  const masterSeed = randomBytes(32);
  console.log(`\n       Masteravain: ${hex(masterSeed)} (${masterSeed.length}t)`);
  console.log('       [Tämä on se mitä KOSKAAN ei saa paljastua yhdelle ihmiselle]');

  // ── 2. JAKO ──────────────────────────────────────────────

  printHeader('2 — Avain jaetaan viidelle upseerille (3/5)');

  const upserit = [
    { holder: 'Eversti Mäkinen',    role: 'Esikuntapäällikkö'   },
    { holder: 'Eversti Korhonen',   role: 'Operaatiopäällikkö'  },
    { holder: 'Everstiluotn. Laine',role: 'Tiedustelupäällikkö' },
    { holder: 'Everstiluotn. Salo', role: 'Logistiikkapäällikkö'},
    { holder: 'Majuri Niemi',       role: 'Varakomentaja'       },
  ];

  printStep('2a', 'Suoritetaan jako...');
  const shares = splitSecret(masterSeed, 5, 3);

  console.log('\n       Osat luotu:');
  Object.entries(shares).forEach(([idx, shareBytes]) => {
    const u = upserit[parseInt(idx) - 1];
    const info = describeShare(idx, shareBytes, { ...u, k: 3, n: 5 });
    console.log(`\n       Osa ${idx} — ${info.holder} (${info.role})`);
    console.log(`         Sisältö:   ${hex(shareBytes)} (${shareBytes.length}t)`);
    console.log(`         Tarkistus: ${info.checksum}`);
    console.log(`         Ohje:      ${info.instructions[0]}`);
  });

  // ── 3. REKONSTRUOINTI — NORMAALI ─────────────────────────

  printHeader('3 — Rekonstruointi normaalitilanteessa (3/5)');

  printStep('3a', 'Tilanne: kenraali kadonnut — tarvitaan avain käyttöön');
  console.log('\n       Paikalla: Mäkinen (1), Laine (3), Niemi (5)');
  console.log('       Korhonen (2) ja Salo (4) eivät tavoitettavissa');

  const reconstructed = reconstructSecret(
    { 1: shares[1], 3: shares[3], 5: shares[5] },
    3
  );

  const match = verifyReconstruction(masterSeed, reconstructed);
  console.log(`\n       ✓ Rekonstruointi: ${match ? 'ONNISTUI — avain identtinen' : 'EPÄONNISTUI'}`);
  console.log(`       Avain: ${hex(reconstructed)}`);

  // ── 4. REKONSTRUOINTI — ERI YHDISTELMÄ ───────────────────

  printHeader('4 — Toinen yhdistelmä toimii yhtä hyvin');

  printStep('4a', 'Korhonen (2), Salo (4), Niemi (5) — eri kolmikko');
  const reconstructed2 = reconstructSecret(
    { 2: shares[2], 4: shares[4], 5: shares[5] },
    3
  );
  const match2 = verifyReconstruction(masterSeed, reconstructed2);
  console.log(`\n       ✓ Rekonstruointi: ${match2 ? 'ONNISTUI — sama avain' : 'EPÄONNISTUI'}`);

  // ── 5. TURVALLISUUSTESTIT ─────────────────────────────────

  printHeader('5 — Turvallisuustestit');

  printStep('5a', 'Liian vähän osia (2/5) — pitää epäonnistua...');
  const tooFew = reconstructSecret({ 1: shares[1], 2: shares[2] }, 2);
  const wrongMatch = verifyReconstruction(masterSeed, tooFew);
  console.log(`       ${wrongMatch
    ? '✗ VIRHE — kaksi osaa riitti!'
    : '✓ Kaksi osaa ei riitä — saatiin väärä data (odotettua)'}`);

  printStep('5b', 'Muutettu osa (sabotoitu share)...');
  const sabotaged = new Uint8Array(shares[3]);
  sabotaged[0] ^= 0xFF;
  const withSabotage = reconstructSecret(
    { 1: shares[1], 3: sabotaged, 5: shares[5] },
    3
  );
  const sabMatch = verifyReconstruction(masterSeed, withSabotage);
  console.log(`       ${sabMatch
    ? '✗ VIRHE — sabotoitu osa hyväksyttiin!'
    : '✓ Sabotoitu osa tuotti väärän avaimen — järjestelmä hylkäisi sen autentikoinnissa'}`);
  console.log('       [Huom: Shamirin jako ei havaitse sabotaasia itse —');
  console.log('        väärä avain paljastuu ML-DSA vahvistuksessa]');

  printStep('5c', 'Pakottamistilanne — yksi upseeri pidätetty...');
  console.log('\n       Majuri Niemi (osa 5) vangittu vihollisen toimesta.');
  console.log('       Vihollisella on nyt osa 5.');
  console.log('\n       Pystyykö vihollinen rekonstruoimaan avaimen?');
  console.log('       → Tarvitsee silti 2 lisäosaa (yhteensä 3/5)');
  console.log('       → Muut 4 upseeria voivat INVALIDOIDA osan 5');
  console.log('       → Uusi jako tehdään jäljellä olevilla upseereilla');
  console.log('\n       ✓ Yhden osan paljastuminen ei vaaranna avainta');

  // ── YHTEENVETO ────────────────────────────────────────────

  printHeader('YHTEENVETO — v0.3');
  console.log(`
  Toteutettu:
  ✓ ML-KEM-768  — kvanttikestävä avaintenvaihto     (FIPS 203)
  ✓ AES-256-GCM — viestisalaus + eheyden tarkistus
  ✓ ML-DSA-65   — digitaalinen allekirjoitus         (FIPS 204)
  ✓ 50t kehys   — LoRa-yhteensopiva kenttäprotokolla
  ✓ Shamir 3/5  — avainten hajautus pakottamissuojaan

  Seuraava — v0.4:
  → Duress-protokolla (pakottamistilanne)
  → CLI-työkalu terminaalista ajamiseen
  `);
}

runShamirDemo().catch(console.error);
