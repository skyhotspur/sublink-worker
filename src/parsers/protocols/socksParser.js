import { parseServerInfo, parseUrlParams, decodeBase64 } from '../../utils.js';

function safeDecode(value) {
    try {
        return decodeURIComponent(value);
    } catch {
        return value;
    }
}

// v2rayN/Shadowrocket encode "user:pass" as base64; plain URIs carry it verbatim.
function parseCredentials(userInfo) {
    if (!userInfo) return {};
    const raw = safeDecode(userInfo);
    if (!raw.includes(':')) {
        try {
            const decoded = decodeBase64(raw);
            if (decoded && decoded.includes(':') && !/[\u0000-\u001f]/.test(decoded)) {
                return splitUserPass(decoded);
            }
        } catch {
            // not base64, treat as bare username
        }
        return { username: raw };
    }
    return splitUserPass(raw);
}

function splitUserPass(value) {
    const idx = value.indexOf(':');
    return { username: value.slice(0, idx), password: value.slice(idx + 1) };
}

export function parseSocks(url) {
    const { addressPart, params, name } = parseUrlParams(url);
    const atIndex = addressPart.lastIndexOf('@');
    const userInfo = atIndex === -1 ? '' : addressPart.slice(0, atIndex);
    const serverInfo = atIndex === -1 ? addressPart : addressPart.slice(atIndex + 1);
    const { host, port } = parseServerInfo(serverInfo);
    if (!host || !port) return null;

    const { username, password } = parseCredentials(userInfo);
    return {
        type: 'socks',
        tag: name || `${host}:${port}`,
        server: host,
        server_port: port,
        version: '5',
        ...(username ? { username } : {}),
        ...(password ? { password } : {}),
        ...(params.udp === 'false' || params.udp === '0' ? { udp: false } : {})
    };
}
