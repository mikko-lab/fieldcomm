#!/usr/bin/env node
/**
 * fieldcomm — Post-quantum field command CLI
 *
 * Komennot:
 *   fieldcomm keygen              — generoi avainpari
 *   fieldcomm send                — lähetä salattu komento
 *   fieldcomm receive             — vastaanota ja pura komento
 *   fieldcomm shamir split        — jaa avain osiin
 *   fieldcomm shamir join         — rekonstruoi avain osista
 *   fieldcomm vault init          — alusta duress-holvi
 *   fieldcomm vault open          — avaa holvi PINillä
 */

import { program } from 'commander';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { generateKeyPair, encapsulate, decapsulate } from '../crypto/kyber.js';
import { generateSigningKeyPair, signFrame, verifyFrame } from '../crypto/dilithium.js';
import { buildCommand, parseCommand, COMMAND_TYPES } from '../protocol/command.js';
import { splitSecret, reconstructSecret } from '../crypto/shamir.js';
import { initVault, openVault, formatAlert } from '../crypto/duress.js';

// ─── APUFUNKTIOT ───────────────────────────────────────────────

function loadJSON(path) {
  if (!existsSync(path)) throw new Error(`Tiedostoa ei löydy: ${path}`);
  return JSON.parse(readFileSync(path, 'utf8'));
}

function saveJSON(path, data) {
  writeFileSync(path, JSON.stringify(data, null, 2));
  console.log(`  → Tallennettu: ${path}`);
}

function hex(buf, max = 16) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  const h = b.slice(0, max).toString('hex').match(/.{2}/g).join(' ');
  return b.length > max ? `${h} ...` : h;
}

function uint8ToHex(arr) { return Buffer.from(arr).toString('hex'); }
function hexToUint8(str) { return new Uint8Array(Buffer.from(str, 'hex')); }

// ─── KEYGEN ────────────────────────────────────────────────────

program
  .command('keygen')
  .description('Generoi ML-KEM + ML-DSA avainpari')
  .option('-o, --out <prefix>', 'Tallennusprefiksi', 'keys')
  .option('--id <id>', 'Yksikön tunnus (hex, esim. F101)', 'F101')
  .action((opts) => {
    console.log('\n  FieldComm — Avainten generointi');
    console.log('  ─────────────────────────────────');

    console.log('\n  [1/2] ML-KEM-768 salausavainpari...');
    const kemKeys = generateKeyPair();

    console.log('  [2/2] ML-DSA-65 allekirjoitusavainpari...');
    const dsaKeys = generateSigningKeyPair();

    const unitId = parseInt(opts.id, 16);

    const pub = {
      unitId:       opts.id,
      unitIdInt:    unitId,
      kemPublicKey: uint8ToHex(kemKeys.publicKey),
      dsaPublicKey: uint8ToHex(dsaKeys.publicKey),
      createdAt:    new Date().toISOString(),
      algorithm:    'ML-KEM-768 + ML-DSA-65 (NIST FIPS 203/204)'
    };

    const priv = {
      unitId:       opts.id,
      unitIdInt:    unitId,
      kemSecretKey: uint8ToHex(kemKeys.secretKey),
      dsaSecretKey: uint8ToHex(dsaKeys.secretKey),
      createdAt:    new Date().toISOString(),
      warning:      'SÄILYTÄ TURVALLISESTI — EI KOSKAAN LÄHETÄ VERKON YLI'
    };

    saveJSON(`${opts.out}.pub.json`, pub);
    saveJSON(`${opts.out}.priv.json`, priv);

    console.log('\n  Avaimet luotu:');
    console.log(`    KEM julkinen:  ${hex(kemKeys.publicKey)} (${kemKeys.publicKey.length}t)`);
    console.log(`    DSA julkinen:  ${hex(dsaKeys.publicKey)} (${dsaKeys.publicKey.length}t)`);
    console.log(`    Yksityiset:    [${opts.out}.priv.json — pidä turvassa]\n`);
  });

// ─── SEND ──────────────────────────────────────────────────────

program
  .command('send')
  .description('Rakenna ja allekirjoita salattu kenttäkomento')
  .requiredOption('--from-priv <file>', 'Lähettäjän yksityisavaintiedosto')
  .requiredOption('--to-pub <file>',    'Vastaanottajan julkinen avaintiedosto')
  .requiredOption('--cmd <komento>',    `Komento: ${Object.keys(COMMAND_TYPES).join(', ')}`)
  .option('--payload <hex>',            'Payload hex-muodossa (max 6t)', '000000000000')
  .option('-o, --out <file>',           'Tallenna paketti tiedostoon', 'packet.json')
  .action((opts) => {
    console.log('\n  FieldComm — Komennon lähetys');
    console.log('  ─────────────────────────────────');

    const fromPriv = loadJSON(opts.fromPriv);
    const toPub    = loadJSON(opts.toPub);

    const cmdType = COMMAND_TYPES[opts.cmd.toUpperCase()];
    if (!cmdType) {
      console.error(`\n  VIRHE: Tuntematon komento "${opts.cmd}"`);
      console.error(`  Saatavilla: ${Object.keys(COMMAND_TYPES).join(', ')}`);
      process.exit(1);
    }

    const payloadHex = opts.payload.replace(/\s/g, '').padEnd(12, '0').slice(0, 12);
    const payload    = new Uint8Array(Buffer.from(payloadHex, 'hex'));

    console.log(`\n  Lähettäjä: 0x${fromPriv.unitId}  →  Kohde: 0x${toPub.unitId}`);
    console.log(`  Komento:   ${opts.cmd.toUpperCase()}`);
    console.log(`  Payload:   ${payloadHex}`);

    console.log('\n  [1/3] ML-KEM avaintenvaihto...');
    const kemPub = hexToUint8(toPub.kemPublicKey);
    const { cipherText, sharedSecret } = encapsulate(kemPub);

    console.log('  [2/3] Rakennetaan 50t salattu kehys...');
    const frame = buildCommand(fromPriv.unitIdInt, toPub.unitIdInt, cmdType, payload, sharedSecret);

    console.log('  [3/3] ML-DSA-65 allekirjoitus...');
    const dsaPriv   = hexToUint8(fromPriv.dsaSecretKey);
    const sigPacket = signFrame(frame, dsaPriv, fromPriv.unitIdInt);

    const packet = {
      version:       2,
      senderId:      fromPriv.unitId,
      receiverId:    toPub.unitId,
      command:       opts.cmd.toUpperCase(),
      kemCipherText: uint8ToHex(cipherText),
      frame:         frame.toString('hex'),
      signature:     sigPacket.toString('hex'),
      timestamp:     new Date().toISOString(),
      frameBytes:    frame.length,
      sigBytes:      sigPacket.length
    };

    saveJSON(opts.out, packet);

    console.log('\n  Paketti valmis:');
    console.log(`    Kehys:          ${frame.length}t  (50t LoRa-kehys)`);
    console.log(`    KEM ciphertext: ${cipherText.length}t`);
    console.log(`    Allekirjoitus:  ${sigPacket.length}t (Iris²:n kautta)\n`);
  });

// ─── RECEIVE ───────────────────────────────────────────────────

program
  .command('receive')
  .description('Vastaanota, pura ja vahvista komento')
  .requiredOption('--packet <file>',     'Pakettitiedosto (send:in tuloste)')
  .requiredOption('--my-priv <file>',    'Vastaanottajan yksityisavaintiedosto')
  .requiredOption('--sender-pub <file>', 'Lähettäjän julkinen avaintiedosto')
  .action((opts) => {
    console.log('\n  FieldComm — Komennon vastaanotto');
    console.log('  ─────────────────────────────────');

    const packet    = loadJSON(opts.packet);
    const myPriv    = loadJSON(opts.myPriv);
    const senderPub = loadJSON(opts.senderPub);

    console.log(`\n  Paketti:   ${packet.senderId} → ${packet.receiverId}`);
    console.log(`  Aikaleima: ${packet.timestamp}`);

    console.log('\n  [1/3] ML-KEM: puretaan jaettu salaisuus...');
    const cipherText   = hexToUint8(packet.kemCipherText);
    const myKemPriv    = hexToUint8(myPriv.kemSecretKey);
    const sharedSecret = decapsulate(cipherText, myKemPriv);

    console.log('  [2/3] AES-256-GCM: puretaan 50t kehys...');
    const frame  = Buffer.from(packet.frame, 'hex');
    const parsed = parseCommand(frame, sharedSecret);

    console.log('  [3/3] ML-DSA-65: vahvistetaan allekirjoitus...');
    const sigPacket = Buffer.from(packet.signature, 'hex');
    const dsaPub    = hexToUint8(senderPub.dsaPublicKey);
    const verified  = verifyFrame(frame, sigPacket, dsaPub);

    console.log('\n  ┌─ KOMENTO VAHVISTETTU ───────────────────────────┐');
    console.log(`  │  Lähettäjä:  0x${parsed.senderId.toString(16).toUpperCase().padEnd(37)}│`);
    console.log(`  │  Komento:    ${parsed.commandName.padEnd(39)}│`);
    console.log(`  │  Sekvenssi:  #${String(parsed.sequence).padEnd(38)}│`);
    console.log(`  │  Aikaleima:  ${parsed.timestamp.slice(11,19)} UTC${' '.repeat(31)}│`);
    console.log(`  │  Payload:    ${Buffer.from(parsed.payload).toString('hex').padEnd(39)}│`);
    console.log('  ├─────────────────────────────────────────────────────┤');
    console.log(`  │  ✓ AES-GCM:  eheys vahvistettu${' '.repeat(21)}│`);
    console.log(`  │  ✓ ML-DSA:   ${verified.algorithm.padEnd(39)}│`);
    console.log('  └─────────────────────────────────────────────────────┘\n');
  });

// ─── SHAMIR ────────────────────────────────────────────────────

const shamirCmd = program.command('shamir').description('Shamirin salaisuuksien jako');

shamirCmd
  .command('split')
  .description('Jaa avain osiin')
  .requiredOption('--secret <hex>', 'Jaettava salaisuus (hex)')
  .option('-n <n>',                 'Osien kokonaismäärä', '5')
  .option('-k <k>',                 'Rekonstruointikynnys', '3')
  .option('-o, --out <prefix>',     'Tallennusprefiksi', 'share')
  .action((opts) => {
    console.log('\n  FieldComm — Shamir: avainten jako');
    console.log('  ─────────────────────────────────');

    const secret = hexToUint8(opts.secret);
    const n = parseInt(opts.n);
    const k = parseInt(opts.k);

    console.log(`\n  Jaetaan ${secret.length}t salaisuus ${n} osaan (kynnys: ${k}/${n})\n`);

    const shares = splitSecret(secret, n, k);

    Object.entries(shares).forEach(([idx, shareBytes]) => {
      saveJSON(`${opts.out}-${idx}.json`, {
        shareId:    idx,
        n, k,
        data:       uint8ToHex(shareBytes),
        byteLength: shareBytes.length,
        createdAt:  new Date().toISOString(),
        warning:    'Säilytä fyysisesti turvallisessa paikassa'
      });
    });

    console.log(`\n  ✓ ${n} osaa luotu. Tarvitaan ${k} rekonstruointiin.\n`);
  });

shamirCmd
  .command('join')
  .description('Rekonstruoi avain osista')
  .requiredOption('--shares <files>', 'Osa-tiedostot pilkulla erotettuna')
  .option('-o, --out <file>',         'Tallenna rekonstruoitu avain', 'reconstructed.hex')
  .action((opts) => {
    console.log('\n  FieldComm — Shamir: rekonstruointi');
    console.log('  ─────────────────────────────────\n');

    const files  = opts.shares.split(',').map(f => f.trim());
    const loaded = {};
    let k = 3;

    files.forEach(file => {
      const s = loadJSON(file);
      loaded[s.shareId] = hexToUint8(s.data);
      k = s.k;
      console.log(`  Ladattu osa ${s.shareId}: ${file}`);
    });

    console.log(`\n  Rekonstruoidaan (${files.length}/${k} osia)...`);
    const reconstructed = reconstructSecret(loaded, k);

    writeFileSync(opts.out, Buffer.from(reconstructed).toString('hex'));
    console.log(`\n  ✓ Rekonstruointi onnistui — ${reconstructed.length}t`);
    console.log(`    Avain: ${hex(Buffer.from(reconstructed))}`);
    console.log(`    Tallennettu: ${opts.out}\n`);
  });

// ─── VAULT ─────────────────────────────────────────────────────

const vaultCmd = program.command('vault').description('Duress-holvin hallinta');

vaultCmd
  .command('init')
  .description('Alusta uusi duress-holvi')
  .requiredOption('--normal-pin <pin>', 'Normaali PIN')
  .requiredOption('--duress-pin <pin>', 'Duress-PIN (anna pakottamistilanteessa)')
  .requiredOption('--real <text>',      'Oikea suojattava data')
  .requiredOption('--decoy <text>',     'Väärennetty data pakottajalle')
  .option('-o, --out <file>',           'Holvin tallennustiedosto', 'vault.json')
  .action((opts) => {
    console.log('\n  FieldComm — Vault: alustus');
    console.log('  ─────────────────────────────────');

    const vault = initVault(opts.normalPin, opts.duressPin, Buffer.from(opts.real), Buffer.from(opts.decoy));
    saveJSON(opts.out, vault);

    console.log('\n  ✓ Dual-vault luotu:');
    console.log('    Molemmat holvit saman kokoisia — ei erota ulkoa.\n');
  });

vaultCmd
  .command('open')
  .description('Avaa holvi PINillä')
  .requiredOption('--vault <file>', 'Holvin tiedosto')
  .requiredOption('--pin <pin>',    'PIN-koodi')
  .option('--device-id <id>',       'Laitteen tunnus', 'TUNTEMATON')
  .option('--location <loc>',       'Sijainti', 'TUNTEMATON')
  .action((opts) => {
    console.log('\n  FieldComm — Vault: avaus');
    console.log('  ─────────────────────────────────');

    const vault = loadJSON(opts.vault);

    let result;
    try {
      result = openVault(vault, opts.pin, { deviceId: opts.deviceId, location: opts.location });
    } catch (e) {
      console.error(`\n  ✗ ${e.message}\n`);
      process.exit(1);
    }

    // Molemmissa tapauksissa: näytä sama vastaus käyttäjälle
    console.log('\n  ✓ Pääsy myönnetty');
    console.log(`  Data: ${result.secret.toString()}\n`);

    if (result.isDuress) {
      const alertFile = `duress-alert-${Date.now()}.txt`;
      writeFileSync(alertFile, formatAlert(result.alert));
      // Oikeassa järjestelmässä: lähetä Iris²:n kautta OOB
    }
  });

// ─── OHJE JA PARSE ─────────────────────────────────────────────

program
  .name('fieldcomm')
  .description('Post-quantum kenttäkomentoprotokolla — FieldComm v0.5')
  .version('0.5.0');

program.parse();
