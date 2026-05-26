// scripts/generate-cloud-mldsa-key.mjs
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { randomBytes } from "@noble/post-quantum/utils.js";
import fs from "fs";

const seed = randomBytes(32);
const keys = ml_dsa65.keygen(seed);

const output = {
  alg: "ML-DSA-65",
  keyId: "cloud-mldsa-key-v1",
  seedBase64: Buffer.from(seed).toString("base64"),
  publicKeyBase64: Buffer.from(keys.publicKey).toString("base64"),
  secretKeyBase64: Buffer.from(keys.secretKey).toString("base64"),
};

fs.writeFileSync(
  "cloud-mldsa-key.json",
  JSON.stringify(output, null, 2)
);

console.log("Generated cloud-mldsa-key.json");
console.log("Public key:", output.publicKeyBase64);