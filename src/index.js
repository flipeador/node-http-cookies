/*
    Simplifies the handling of HTTP cookies.
    https://github.com/flipeador/node-http-cookies
*/

import crypto from 'node:crypto';

function tryDecodeURIComponent(value) {
    if (value === undefined || value === null) return '';
    value = `${value}`.trim();
    try { return decodeURIComponent(value); }
    catch { return value; }
}

function hashCookie(data, secret) {
    return crypto
    .createHmac('sha256', secret)
    .update(data)
    .digest('base64')
    .replace(/[=]+$/u, '');
}

/**
 * Sign a cookie value.
 */
export function signCookie(value, secret) {
    return `${value}.${hashCookie(value, secret)}`;
}

/**
 * Parse a cookie value as a signed cookie.
 */
export function signedCookie(data, secret) {
    const index = data.lastIndexOf('.');
    const value = data.slice(0, index);
    const signature = data.slice(index + 1);

    if (signature === hashCookie(value, secret))
        return value;
}

/**
 * Try to parse a cookie value as a signed cookie.
 */
export function parseSignedCookie(value, secret) {
    if (typeof(value) === 'string' && value.startsWith('s:'))
        try { return signedCookie(value.slice(2), secret); }
        catch { /* EMPTY */ }
}

/**
 * Try to parse a cookie value as JSON.
 */
export function parseJsonCookie(value) {
    if (typeof(value) === 'string' && value.startsWith('j:'))
        try { return JSON.parse(value.slice(2)); }
        catch { /* EMPTY */ }
}

/**
 * Parse a Cookie header.
 * @reference https://developer.mozilla.org/docs/Web/HTTP/Headers/Cookie
 */
export function parseCookieHeader(cookieHeader) {
    if (!cookieHeader || typeof(cookieHeader) !== 'string')
        return {};

    return cookieHeader.split(';').map(
        cookie => cookie.split('=')
    ).reduce((cookies, cookie) => {
        cookies[tryDecodeURIComponent(cookie[0])]
            = tryDecodeURIComponent(cookie[1]);
        return cookies;
    }, {});
}

/**
 * Create a cookie.
 * @reference https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie
 */
export function createCookie(name, value, options) {
    if (!name || !value) throw new Error('Invalid cookie');
    if (typeof(value) !== 'string') value = `j:${JSON.stringify(value)}`;
    if (options?.secret) value = `s:${signCookie(value, options.secret)}`;
    let cookie = `${encodeURIComponent(name)}=${encodeURIComponent(value)}`;
    for (const [key, value] of Object.entries(options ?? {}))
        if (!['secret'].includes(key))
            cookie += `;${key}` + (value === true ? '' : `=${value}`);
    return cookie;
}

/**
 * Add a cookie given a response.
 */
export function addCookie(res, name, value, options) {
    const cookie = createCookie(name, value, options);
    let cookies = res.getHeader('Set-Cookie') ?? [];
    if (!(cookies instanceof Array)) cookies = [cookies];
    cookies.push(cookie);
    res.setHeader('Set-Cookie', cookies);
    return cookies;
}

/**
 * Create a middleware to parse Cookie headers.
 */
export function cookieParser() {
    return (req, res, next) => {
        if (req.cookies !== undefined)
            throw new Error('Cookies already set');

        req.cookies = parseCookieHeader(req.headers.cookie);
        res.addCookie = addCookie.bind(undefined, res);

        next();
    };
}

export default cookieParser;
