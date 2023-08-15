import test from 'node:test';
import assert from 'node:assert/strict';

import {
    createCookie,
    parseSignedCookie,
    parseJsonCookie,
    parseCookieHeader
} from '@flipeador/node-http-cookies';

const secret = 'SIGNED_COOKIE_SECRET';

await test('cookie parser test', () => {
    const jsonCookie = createCookie('json', ['json cookie']);
    assert.equal(jsonCookie, 'json=j%3A%5B%22json%20cookie%22%5D');

    const strCookie = createCookie('str', 'str cookie');
    assert.equal(strCookie, 'str=str%20cookie');

    const cookies = parseCookieHeader(`${jsonCookie};${strCookie}`);

    assert.deepEqual(parseJsonCookie(cookies.json), ['json cookie']);

    assert.deepEqual(cookies, {
        json: 'j:["json cookie"]',
        str: 'str cookie'
    });

    const sigCookie = parseCookieHeader(createCookie('sig', 'sig cookie', { secret }));
    assert.equal(parseSignedCookie(sigCookie.sig, secret), 'sig cookie');
});
