/*
    Simplifies the handling of HTTP cookies.
    https://github.com/flipeador/node-http-cookies
*/

import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';

/**
 * Add a property to an object with a custom getter that runs only once.
 * On first access, the property is redefined with the return value of the getter.
 */
function defineProperty(obj, name, getter) {
    Object.defineProperty(obj, name, {
        get() {
            delete this[name];
            return this[name] = getter.call(this);
        },
        configurable: true
    });
}

/**
 * Add a header, preserving other headers with the same name.
 */
function addHeader(res, name, value) {
    let array = res.getHeader(name);
    if (array instanceof Array) array.push(value);
    else res.setHeader(name, array = [array??value]);
    return array;
}

function tryDecodeURIComponent(value) {
    if (value === undefined || value === null)
        return '';
    value = `${value}`.trim();
    try { return decodeURIComponent(value); }
    catch { return value; }
}

function hash(data, secret, encoding) {
    return crypto
    .createHmac('sha256', secret)
    .update(data)
    .digest(encoding);
}

/**
 * Sign a cookie value given a secret key.
 */
export function signCookie(value, secret) {
    const signature = hash(value, secret, 'base64');
    return `${value}.${signature}`;
}

/**
 * Verify the integrity of a signed cookie value.
 */
export function signedCookie(data, secret) {
    const index = data.lastIndexOf('.');
    const value = data.slice(0, index);
    const signature = data.slice(index + 1);
    const result = crypto.timingSafeEqual(
        Buffer.from(signature, 'base64'),
        hash(value, secret)
    );
    if (result) return value;
}

/**
 * Try to parse a signed cookie value.
 */
export function parseSignedCookie(value, secret) {
    if (typeof(value) === 'string' && value.startsWith('s:'))
        try { return signedCookie(value.slice(2), secret); }
        catch { /* EMPTY */ }
}

/**
 * Try to parse a JSON cookie value.
 */
export function parseJsonCookie(value) {
    if (typeof(value) === 'string' && value.startsWith('j:'))
        try { return JSON.parse(value.slice(2)); }
        catch { /* EMPTY */ }
}

/**
 * Parse the Cookie header.
 * @reference https://developer.mozilla.org/docs/Web/HTTP/Headers/Cookie
 */
export function parseCookieHeader(cookieHeader) {
    if (!cookieHeader || typeof(cookieHeader) !== 'string')
        return { };

    return cookieHeader.split(';').map(
        cookie => cookie.split('=')
    ).reduce((cookies, cookie) => {
        cookies[tryDecodeURIComponent(cookie[0])]
            = tryDecodeURIComponent(cookie[1]);
        return cookies;
    }, { });
}

/**
 * Create a cookie.
 * @reference https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie
 */
export function createCookie(name, value, options) {
    if (!name || !value)
        throw new TypeError('Invalid cookie');
    if (typeof(value) !== 'string')
        value = `j:${JSON.stringify(value)}`;
    if (options?.secret)
        value = `s:${signCookie(value, options.secret)}`;
    let cookie = `${encodeURIComponent(name)}=${encodeURIComponent(value)}`;
    [
        ['Domain', options?.domain],
        ['Path', options?.path ?? '/'],
        ['Secure', !!options?.secure],
        ['HttpOnly', !!options?.httpOnly],
        ['SameSite', options?.sameSite ?? 'lax'],
        ['Partitioned', !!options?.partitioned],
        ['Expires', options?.expires],
        ['Max-Age', options?.maxAge]
    ].forEach(([key, value]) => {
        if (![null, undefined, false, NaN, ''].includes(value))
            cookie += `;${key}${value === true ? '' : `=${value}`}`;
    });
    return cookie;
}

/**
 * Set a cookie given a response.
 */
export function setCookie(res, name, value, options) {
    return addHeader(res, 'Set-Cookie', (
        value === undefined && options === undefined
        ? name : createCookie(name, value, options)
    ));
}

/**
 * Create a middleware to parse Cookie headers.
 */
export function cookieParser() {
    return (req, res, next) => {
        if (req.cookies)
            throw Error('req.cookies already set');
        defineProperty(req, 'cookies', function() {
            return parseCookieHeader(this.headers.cookie);
        });
        res.cookie = setCookie.bind(undefined, res);
        next();
    };
}

export default cookieParser;
