// utils/canonicalize.js

function sortObject(value) {
    if (Array.isArray(value)) {
        return value.map(sortObject);
    }

    if (value && typeof value === "object") {
        return Object.keys(value)
            .sort()
            .reduce((result, key) => {
                result[key] = sortObject(value[key]);
                return result;
            }, {});
    }

    return value;
}

function canonicalize(value) {
    return JSON.stringify(sortObject(value));
}

module.exports = {
    canonicalize
};