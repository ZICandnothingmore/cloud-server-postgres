function byteNumberToHex(n) {
    const value = Number(n);

    if (!Number.isInteger(value)) {
        throw new Error("ByteArray chứa giá trị không phải số nguyên");
    }

    const unsigned = value < 0 ? value + 256 : value;

    if (unsigned < 0 || unsigned > 255) {
        throw new Error("ByteArray chứa giá trị ngoài khoảng byte");
    }

    return unsigned.toString(16).padStart(2, "0");
}

function byteArrayToHex(arr) {
    if (!Array.isArray(arr)) {
        throw new Error("Giá trị không phải ByteArray");
    }

    return arr.map(byteNumberToHex).join("").toLowerCase();
}

function normalizeBinaryToHex(value, fieldName = "field") {
    if (value === undefined || value === null) {
        throw new Error(`${fieldName} là bắt buộc`);
    }

    if (Array.isArray(value)) {
        return byteArrayToHex(value);
    }

    if (typeof value === "string") {
        const normalized = value.trim().replace(/^0x/i, "").toLowerCase();

        if (!/^[0-9a-f]+$/.test(normalized) || normalized.length % 2 !== 0) {
            throw new Error(`${fieldName} phải là hex string hợp lệ`);
        }

        return normalized;
    }

    throw new Error(`${fieldName} phải là hex string hoặc ByteArray`);
}

module.exports = {
    normalizeBinaryToHex,
    byteArrayToHex
};