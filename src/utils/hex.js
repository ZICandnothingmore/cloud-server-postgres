function normalizeHex(value, fieldName) {
    if (value === undefined || value === null || String(value).trim() === "") {
        throw new Error(`${fieldName} là bắt buộc`);
    }

    const normalized = String(value).trim().toLowerCase();

    if (!/^[0-9a-f]+$/.test(normalized)) {
        throw new Error(`${fieldName} phải là chuỗi hex`);
    }

    if (normalized.length % 2 !== 0) {
        throw new Error(`${fieldName} phải có độ dài chẵn`);
    }

    return normalized;
}

function normalizeHexOptional(value) {
    if (value === undefined || value === null || String(value).trim() === "") {
        return null;
    }

    const normalized = String(value).trim().toLowerCase();

    if (!/^[0-9a-f]+$/.test(normalized)) {
        return null;
    }

    if (normalized.length % 2 !== 0) {
        return null;
    }

    return normalized;
}

module.exports = {
    normalizeHex,
    normalizeHexOptional
};