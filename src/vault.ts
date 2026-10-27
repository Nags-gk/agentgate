import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { config } from "./config.js";

/**
 * Envelope encryption. Each secret gets its own random 256-bit data key (DEK). The secret is
 * sealed with AES-256-GCM under the DEK; the DEK is sealed under a versioned key-encryption
 * key (KEK). Only ciphertexts reach the database, so a database dump alone reveals nothing,
 * and rotating the KEK re-wraps 32-byte DEKs instead of re-encrypting every secret.
 *
 * Sealed layout: [12-byte IV][16-byte GCM tag][ciphertext]. Associated data binds a
 * ciphertext to its row (e.g. tenant + connector), so swapping ciphertexts between rows fails.
 */

export interface Sealed {
  ciphertext: Buffer;
  wrappedKey: Buffer;
  kekVersion: number;
}

function parseKeks(spec: string): Map<number, Buffer> {
  const out = new Map<number, Buffer>();
  for (const part of spec.split(",").map((s) => s.trim()).filter(Boolean)) {
    const [v, b64] = part.split(":");
    const key = Buffer.from(b64 ?? "", "base64");
    if (!v || key.length !== 32) throw new Error("VAULT_KEKS entries must be version:base64(32 bytes)");
    out.set(Number(v), key);
  }
  if (!out.size) throw new Error("no key-encryption keys configured");
  return out;
}

export class Vault {
  private readonly keks: Map<number, Buffer>;
  readonly activeVersion: number;

  constructor(spec = config.keks) {
    this.keks = parseKeks(spec);
    this.activeVersion = Math.max(...this.keks.keys());
  }

  private static seal(key: Buffer, plain: Buffer, aad: string): Buffer {
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", key, iv);
    c.setAAD(Buffer.from(aad));
    const body = Buffer.concat([c.update(plain), c.final()]);
    return Buffer.concat([iv, c.getAuthTag(), body]);
  }

  private static open(key: Buffer, sealed: Buffer, aad: string): Buffer {
    const d = createDecipheriv("aes-256-gcm", key, sealed.subarray(0, 12));
    d.setAAD(Buffer.from(aad));
    d.setAuthTag(sealed.subarray(12, 28));
    return Buffer.concat([d.update(sealed.subarray(28)), d.final()]);
  }

  encrypt(plaintext: string, aad: string): Sealed {
    const dek = randomBytes(32);
    const kek = this.keks.get(this.activeVersion)!;
    const out = {
      ciphertext: Vault.seal(dek, Buffer.from(plaintext, "utf8"), aad),
      wrappedKey: Vault.seal(kek, dek, `dek:${aad}`),
      kekVersion: this.activeVersion,
    };
    dek.fill(0);
    return out;
  }

  decrypt(s: Sealed, aad: string): string {
    const kek = this.keks.get(Number(s.kekVersion));
    if (!kek) throw new Error(`key-encryption key version ${s.kekVersion} is not available`);
    const dek = Vault.open(kek, s.wrappedKey, `dek:${aad}`);
    try {
      return Vault.open(dek, s.ciphertext, aad).toString("utf8");
    } finally {
      dek.fill(0);
    }
  }

  /** Re-wrap a data key under the active KEK without touching the secret itself. */
  rewrap(s: Sealed, aad: string): Sealed {
    if (Number(s.kekVersion) === this.activeVersion) return s;
    const oldKek = this.keks.get(Number(s.kekVersion));
    if (!oldKek) throw new Error(`key-encryption key version ${s.kekVersion} is not available`);
    const dek = Vault.open(oldKek, s.wrappedKey, `dek:${aad}`);
    const wrappedKey = Vault.seal(this.keks.get(this.activeVersion)!, dek, `dek:${aad}`);
    dek.fill(0);
    return { ciphertext: s.ciphertext, wrappedKey, kekVersion: this.activeVersion };
  }
}

let vault: Vault | undefined;
export const getVault = () => (vault ??= new Vault());
