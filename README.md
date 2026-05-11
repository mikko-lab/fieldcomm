# FieldComm

**Post-quantum field command protocol — proof of concept**

Kvanttikestävä valtiotason viestintäprotokolla. Rakennettu NIST:n standardoimilla algoritmeilla, suunniteltu Suomen geopoliittiseen todellisuuteen.

---

## Miksi tämä on olemassa

Nykyiset valtiotason viestintäjärjestelmät käyttävät RSA/ECC-kryptografiaa. Kvanttitietokoneet murtavat nämä algoritmit Shor'in algoritmilla — arviolta 2030-luvulla. Siirtymäaika on nyt.

Tämä projekti demonstroi käytännössä miten siirtymä tehdään. Ei teoria. Ajettava koodi.

### Suomen konteksti

- **1340 km** raja Venäjän kanssa — pisin NATO-maan maaraja
- Itämeren kaapelit sabotoitu 2023–2024 (Nordstream, BCS East-1, Estlink)
- TUVE-verkko (turvallisuusviranomaisten viestintä) on vanhentunut arkkitehtuuri
- **Iris²** — EU:n oma satelliittikonstellaatio (290 satelliittia, operatiivinen ~2030) tarjoaa EU-kontrolloidun siirtotien

FieldComm on suunniteltu Iris²:n päälle rakennettavaksi sovellustasoksi.

---

## Kryptografinen rakenne

```
┌─────────────────────────────────────────────────────┐
│  SOVELLUSTASO                                        │
│  fieldcomm send / receive / keygen                  │
├─────────────────────────────────────────────────────┤
│  IDENTITEETTI                                        │
│  ML-DSA-65 allekirjoitukset (NIST FIPS 204)         │
├─────────────────────────────────────────────────────┤
│  SALAUS                                              │
│  ML-KEM-768 avaintenvaihto (NIST FIPS 203)          │
│  AES-256-GCM viestisalaus                           │
├─────────────────────────────────────────────────────┤
│  INHIMILLISET UHAT                                   │
│  Shamir 3/5 — avainten hajautus                     │
│  Duress vault — pakottamissuoja                     │
├─────────────────────────────────────────────────────┤
│  SIIRTOTIE                                           │
│  Iris² (EU-satelliitti) / LoRa-mesh (vara, ~50km)   │
└─────────────────────────────────────────────────────┘
```

### Miksi ML-KEM kestää kvanttihyökkäyksen

RSA ja ECC perustuvat tekijähajotelmaan — Shor'in algoritmi ratkaisee tämän kvanttitietokoneella polynomisessa ajassa.

ML-KEM perustuu **Learning With Errors (LWE)** -ongelmaan. Ei tunneta kvanttialgoritmia joka ratkaisisi tämän merkittävästi klassista nopeammin. NIST standardoi ML-KEM:n elokuussa 2024 (FIPS 203).

---

## 50-tavun kenttäkomentoprotokolla

Suunniteltu toimimaan myös LoRa-verkon kautta häirinnässä (~50km kantama avoimessa maastossa).

```
┌─────────────────────────────────────────────────────┐
│ [0-3]   Lähettäjä-ID        (4t)                    │
│ [4-7]   Vastaanottaja-ID    (4t)                    │
│ [8-11]  Aikaleima Unix      (4t)                    │
│ [12-13] Sekvenssimero       (2t)  replay-suoja      │
│ [14-15] Komento-tyyppi      (2t)                    │
│ [16-27] AES-GCM Nonce       (12t)                   │
│ [28-33] Salattu payload     (6t)                    │
│ [34-49] AES-GCM Auth Tag    (16t)                   │
└─────────────────────────────────────────────────────┘
= 50 tavua
```

---

## Asennus

```bash
git clone https://github.com/mikko-lab/fieldcomm
cd fieldcomm
npm install
```

**Vaatimukset:** Node.js 22+

---

## CLI-käyttö

### Avainten generointi

```bash
node src/cli/fieldcomm.js keygen --id F101 --out hq
node src/cli/fieldcomm.js keygen --id 0A09 --out field
```

### Komennon lähetys

```bash
node src/cli/fieldcomm.js send \
  --from-priv hq.priv.json    \
  --to-pub field.pub.json     \
  --cmd SIIRRY                \
  --payload 421a030000
```

### Komennon vastaanotto

```bash
node src/cli/fieldcomm.js receive \
  --packet packet.json            \
  --my-priv field.priv.json       \
  --sender-pub hq.pub.json
```

### Shamirin avainten jako

```bash
# Jaa 5 osaan, tarvitaan 3
node src/cli/fieldcomm.js shamir split --secret <hex> -n 5 -k 3

# Rekonstruoi
node src/cli/fieldcomm.js shamir join \
  --shares share-1.json,share-3.json,share-5.json
```

### Duress-holvi

```bash
node src/cli/fieldcomm.js vault init \
  --normal-pin 7749 --duress-pin 1234 \
  --real "OIKEA_AVAIN:..." --decoy "VALEAVAIN:..."

node src/cli/fieldcomm.js vault open --vault vault.json --pin 1234
```

---

## Tiedostorakenne

```
src/
  crypto/
    kyber.js       ML-KEM-768 avaintenvaihto      (FIPS 203)
    dilithium.js   ML-DSA-65 allekirjoitukset     (FIPS 204)
    shamir.js      Shamirin salaisuuksien jako
    duress.js      Dual-vault + OOB-hälytys
  protocol/
    command.js     50t kenttäkomentoprotokolla
  cli/
    fieldcomm.js   CLI-työkalu
  demo/
    shamir-demo.js Upseeriskenaario (3/5)
    duress-demo.js Pakottamisskenaario
```

---

## Tunnetut rajoitukset (PoC)

- ML-DSA-allekirjoitus (3325t) ei mahdu 50t LoRa-kehykseen — kulkee Iris²:n kautta erillisenä
- Shamirin jako ei havaitse sabotoitua osaa — väärä avain paljastuu ML-DSA-vahvistuksessa
- Ei HSM-integraatiota — yksityisavaimet JSON-tiedostoissa

---

## Viitteet

- [NIST FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum)
- [Iris² — EU Space Programme](https://www.euspa.europa.eu/iris2)
- [NCSC-FI — Kyberturvallisuuskeskus](https://www.kyberturvallisuuskeskus.fi)

---

## Lisenssi

MIT — vapaa käyttää, muokata ja jakaa.

---

*Rakennettu Suomessa. Suomalaisen kyberturvallisuuden kehittämiseksi.*
