// services/pqcSignature.service.js

let mlDsa65Module = null;

async function getMLDSA65() {
    if (!mlDsa65Module) {
        const module = await import("@noble/post-quantum/ml-dsa.js");
        mlDsa65Module = module.ml_dsa65;
    }

    return mlDsa65Module;
}

function getCloudSecretKey() {
    const secretKeyBase64 = process.env.CLOUD_MLDSA_SECRET_KEY_BASE64;

    if (!secretKeyBase64) {
        throw new Error("CLOUD_MLDSA_SECRET_KEY_BASE64 is missing");
    }

    return Buffer.from(secretKeyBase64, "base64");
}

function getCloudPublicKey() {
    const publicKeyBase64 = process.env.CLOUD_MLDSA_PUBLIC_KEY_BASE64;

    if (!publicKeyBase64) {
        throw new Error("CLOUD_MLDSA_PUBLIC_KEY_BASE64 is missing");
    }

    return Buffer.from(publicKeyBase64, "base64");
}

function getCloudKeyId() {
    return process.env.CLOUD_MLDSA_KEY_ID || "cloud-mldsa-key-v1";
}

async function signRevokeCommand(canonicalPayloadString) {
    const ml_dsa65 = await getMLDSA65();

    const message = new TextEncoder().encode(canonicalPayloadString);
    const secretKey = getCloudSecretKey();

    const signature = ml_dsa65.sign(message, secretKey);

    return Buffer.from(signature).toString("base64");
}

async function verifyRevokeCommand(canonicalPayloadString, signatureBase64, publicKeyBuffer) {
    const ml_dsa65 = await getMLDSA65();

    const message = new TextEncoder().encode(canonicalPayloadString);
    const signature = Buffer.from(signatureBase64, "base64");
    const publicKey = publicKeyBuffer || getCloudPublicKey();

    return ml_dsa65.verify(signature, message, publicKey);
}

module.exports = {
    signRevokeCommand,
    verifyRevokeCommand,
    getCloudKeyId,
    getCloudPublicKey
};