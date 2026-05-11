/**
 * duress-demo.js — Pakottamisprotokolla kenttäskenaariossa
 *
 * Skenaario: Majuri Nieminen pidätetään tarkistuspisteellä.
 * Vihollinen vaatii pääsyä viestijärjestelmään.
 */

import { initVault, openVault, formatAlert } from '../crypto/duress.js';
import { randomBytes } from 'node:crypto';

function printHeader(t) {
  console.log('\n' + '═'.repeat(60));
  console.log(`  ${t}`);
  console.log('═'.repeat(60));
}
function printStep(s, d) { console.log(`\n  [${s}] ${d}`); }

async function runDuressDemo() {

  printHeader('FIELDCOMM v0.4 — Duress-protokolla');
  console.log('  Skenaario: Pakottamistilanne tarkistuspisteellä');
  console.log('  Tekniikka: Dual-vault + OOB-hälytys');

  // ── 1. HOLVIN ALUSTUS ─────────────────────────────────────

  printHeader('1 — Majuri Niemisen holvin alustus (tehdään etukäteen)');

  const normalPin = '7749';   // Oikea PIN — vain Niemisellä
  const duressPin = '1234';   // Pakottamis-PIN — Nieminen antaa tässä

  // Oikea data: viittaus oikeaan avainmateriaaliin
  const realSecret = Buffer.from(
    'OIKEA_AVAIN:ALPHA-GRID-7749:KOMENTO-KANAVA-3:PV-TURVA-1'
  );

  // Decoy-data: uskottava mutta turha
  const decoySecret = Buffer.from(
    'AVAIN:BETA-GRID-0000:HUOLTO-KANAVA-9:EI-KRIITTINEN'
  );

  printStep('1a', 'Alustetaan dual-vault...');
  const vault = initVault(normalPin, duressPin, realSecret, decoySecret);

  console.log('\n       Holvi luotu:');
  console.log(`         Normaali salt:  ${vault.normalSalt.slice(0, 20)}...`);
  console.log(`         Duress salt:    ${vault.duressSalt.slice(0, 20)}...`);
  console.log(`         Holvi A (oikea): ${vault.realBlob.length / 2}t salattu`);
  console.log(`         Holvi B (decoy): ${vault.decoyBlob.length / 2}t salattu`);
  console.log('\n       [Ulkopuolinen ei erota kumpi holvi on kumpi]');

  // ── 2. NORMAALI KÄYTTÖ ────────────────────────────────────

  printHeader('2 — Normaali tilanne: Nieminen avaa omalla PINillään');

  printStep('2a', `Nieminen syöttää oikean PINin: ${normalPin}`);
  const normalResult = openVault(vault, normalPin, {
    deviceId: 'FIELD-UNIT-LA09',
    location: 'Rovaniemi HQ'
  });

  console.log('\n       ┌─ HOLVI AVATTU ─────────────────────────────────┐');
  console.log(`       │  Status:   NORMAALI PÄÄSY                      │`);
  console.log(`       │  Hälytys:  ${normalResult.alertSent ? 'LÄHETETTY' : 'EI LÄHETETTY — normaalia'.padEnd(35)}│`);
  console.log(`       │  Data:     ${normalResult.secret.toString().padEnd(35)}│`);
  console.log('       └───────────────────────────────────────────────────┘');

  // ── 3. PAKOTTAMISTILANNE ──────────────────────────────────

  printHeader('3 — Pakottamistilanne: vihollinen vaatii pääsyä');

  console.log('\n  Tilanne:');
  console.log('  Majuri Nieminen on pidätetty tarkistuspisteellä.');
  console.log('  Vihollinen: "Anna PIN tai seuraukset ovat vakavat."');
  console.log('  Nieminen antaa duress-PINin: ' + duressPin);
  console.log('\n  [Nieminen tietää: järjestelmä lähettää hälytyksen');
  console.log('   ja antaa viholliselle väärää dataa]');

  printStep('3a', `Vihollinen syöttää PINin: ${duressPin}`);

  const duressResult = openVault(vault, duressPin, {
    deviceId: 'FIELD-UNIT-LA09',
    location: 'TUNTEMATON — GPS häiritty',
    ip: '10.44.x.x'
  });

  // ── MITÄ VIHOLLINEN NÄKEE ─────────────────────────────────

  console.log('\n  ┌─ MITÄ VIHOLLINEN NÄKEE ───────────────────────────┐');
  console.log(`  │  Status:  "Pääsy myönnetty"                        │`);
  console.log(`  │  Data:    ${duressResult.secret.toString().padEnd(43)}│`);
  console.log('  │  Virheet: EI YHTÄÄN — kaikki näyttää normaalilta   │');
  console.log('  └───────────────────────────────────────────────────────┘');

  // ── MITÄ JÄRJESTELMÄ TEKEE ────────────────────────────────

  console.log('\n  ┌─ MITÄ JÄRJESTELMÄ TEKEE (vihollinen ei tiedä) ────┐');
  console.log(`  │  isDuress:  ${String(duressResult.isDuress).toUpperCase().padEnd(41)}│`);
  console.log(`  │  Hälytys:   LÄHETETTY OOB-kanavaa pitkin           │`);
  console.log(`  │  Aika:      ${duressResult.alert.unixTime}                          │`);
  console.log('  └───────────────────────────────────────────────────────┘');

  // ── HÄLYTYS ───────────────────────────────────────────────

  printHeader('4 — Hiljainen hälytys turvatiimille');

  console.log('\n  [Lähetetty samanaikaisesti Iris²:n kautta — 50t hälytysviesti]');
  console.log('\n' + formatAlert(duressResult.alert).split('\n').map(l => '  ' + l).join('\n'));

  // ── VERTAILU ──────────────────────────────────────────────

  printHeader('5 — Data-vertailu: mitä kukin sai');

  console.log('\n  Nieminen (normaali PIN):');
  console.log(`    "${normalResult.secret.toString()}"`);

  console.log('\n  Vihollinen (duress PIN):');
  console.log(`    "${duressResult.secret.toString()}"`);

  console.log('\n  Datarakenteet ovat uskottavan samannäköisiä —');
  console.log('  vihollinen ei heti tiedä saavansa väärää dataa.');

  // ── VÄÄRÄ PIN ─────────────────────────────────────────────

  printHeader('6 — Väärä PIN (ei normaali eikä duress)');

  printStep('6a', 'Kolmas osapuoli kokeilee arvata: 0000');
  try {
    openVault(vault, '0000', {});
    console.log('       ✗ VIRHE — satunnainen PIN hyväksyttiin!');
  } catch (e) {
    console.log(`       ✓ Hylätty: "${e.message}"`);
  }

  // ── YHTEENVETO ────────────────────────────────────────────

  printHeader('YHTEENVETO — v0.4');
  console.log(`
  Toteutettu:
  ✓ ML-KEM-768   — kvanttikestävä avaintenvaihto    (FIPS 203)
  ✓ AES-256-GCM  — viestisalaus + eheyden tarkistus
  ✓ ML-DSA-65    — digitaalinen allekirjoitus        (FIPS 204)
  ✓ 50t kehys    — LoRa-yhteensopiva kenttäprotokolla
  ✓ Shamir 3/5   — avainten hajautus pakottamissuojaan
  ✓ Duress vault — dual-vault + hiljainen OOB-hälytys

  Seuraava — v0.5:
  → CLI-työkalu: fieldcomm send / receive / keygen
  `);
}

runDuressDemo().catch(console.error);
