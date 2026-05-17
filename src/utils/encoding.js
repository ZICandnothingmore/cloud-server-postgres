function isHexString(value) {
    return typeof value === "string" && /^[0-9a-fA-F]+$/.test(value) && value.length % 2 === 0;
}

function normalizeHex(value, fieldName = "byte_field") {
    if (!value) {
        throw new Error(`${fieldName} là bắt buộc`);
    }

    if (typeof value !== "string") {
        throw new Error(`${fieldName} phải là Hex String`);
    }

    const trimmed = value.trim();

    if (!isHexString(trimmed)) {
        throw new Error(`${fieldName} phải là chuỗi hex hợp lệ`);
    }

    return trimmed.toLowerCase();
}

module.exports = {
    isHexString,
    normalizeHex
};