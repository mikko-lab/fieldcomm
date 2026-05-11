/**
 * command.js — 50-tavun kenttäkomentoprotokolla
 *
 * RAKENNE (50 tavua):
 * ┌────────────────────────────────────────┐
 * │ [0-3]   Lähettäjä-ID        (4t)       │
 * │ [4-7]   Vastaanottaja-ID    (4t)       │
 * │ [8-11]  Aikaleima Unix      (4t)       │
 * │ [12-13] Sekvenssimero       (2t)       │
 * │ [14-15] Komento-tyyppi      (2t)       │
 * │ [16-27] AES-GCM Nonce       (12t)      │
 * │ [28-33] Salattu payload     (6t)       │
 * │ [34-49] AES-GCM Auth Tag    (16t)      │
 * └────────────────────────────────────────┘
 * = 4+4+4+2+2+12+6+16 = 50 tavua
 */

import { encryptPayload, decryptPayload } from '../crypto/kyber.js';

export const COMMAND_TYPES = {
  SIIRRY:        0x01,
  PYSÄHDY:       0x02,
  RAPORTOI:      0x03,
  HÄLYTYS:       0x04,
  VAHVISTUS:     0x05,
  EVAKUOI:       0x06,
  YLLÄPIDÄ:      0x07,
  VAIHDA_KANAVA: 0x08,
};

let sequenceCounter = 0;

export function buildCommand(senderId, receiverId, commandType, payload, sharedSecret) {
  if (payload.length > 6) {
    throw new Error(`Payload liian suuri: ${payload.length}t (max 6t)`);
  }

  const paddedPayload = Buffer.alloc(6);
  Buffer.from(payload).copy(paddedPayload);

  const { encrypted, nonce, tag } = encryptPayload(paddedPayload, sharedSecret);

  const frame = Buffer.alloc(50);
  frame.writeUInt32BE(senderId, 0);
  frame.writeUInt32BE(receiverId, 4);
  frame.writeUInt32BE(Math.floor(Date.now() / 1000), 8);
  frame.writeUInt16BE(sequenceCounter++ & 0xFFFF, 12);
  frame.writeUInt16BE(commandType, 14);
  nonce.copy(frame, 16);      // [16-27] 12t nonce
  encrypted.copy(frame, 28);  // [28-33] 6t ciphertext
  tag.copy(frame, 34);        // [34-49] 16t GCM auth tag

  return frame;
}

export function parseCommand(frame, sharedSecret) {
  if (frame.length !== 50) {
    throw new Error(`Virheellinen kehyskoko: ${frame.length} (pitäisi olla 50)`);
  }

  const senderId    = frame.readUInt32BE(0);
  const receiverId  = frame.readUInt32BE(4);
  const timestamp   = frame.readUInt32BE(8);
  const sequence    = frame.readUInt16BE(12);
  const commandType = frame.readUInt16BE(14);
  const nonce       = frame.slice(16, 28);
  const encrypted   = frame.slice(28, 34);
  const tag         = frame.slice(34, 50);

  let payload;
  try {
    payload = decryptPayload(encrypted, nonce, tag, sharedSecret);
  } catch {
    throw new Error('AUTENTIKOINTI EPÄONNISTUI — viesti manipuloitu tai väärä avain');
  }

  const now = Math.floor(Date.now() / 1000);
  const age = now - timestamp;
  if (age > 60 || age < -5) {
    throw new Error(`AIKALEIMA EPÄKELPO — viesti ${age}s vanha (max 60s)`);
  }

  return {
    senderId,
    receiverId,
    timestamp: new Date(timestamp * 1000).toISOString(),
    sequence,
    commandType,
    commandName: Object.keys(COMMAND_TYPES).find(k => COMMAND_TYPES[k] === commandType) || 'TUNTEMATON',
    payload
  };
}
