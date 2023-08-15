# Cookie HTTP Request Header

Simplifies the handling of [HTTP cookies][httpcookie].

### Features

- Create string or JSON cookies with an optional signature.
- Parse the [Cookie][cookie] header and create a key-value pair object.
- Use the cookie parser as a middleware in [Express][express].

> [!NOTE]
> This is a lightweight alternative library to [cookie-parser][cookie-parser] with no dependencies.

### Information

Cookies are mainly used for storing credentials, user preferences, site settings, and tracking data.

- The cookie name can contain any US-ASCII characters except for control characters, space, tab, and separators (`( ) < > @ , ; : \ " / [ ] ? = { }`).
- The cookie value can optionally be wrapped in double quotes and include any US-ASCII character excluding control characters, whitespace, double quotes, commas, semicolons, and backslashes.
- The cookie name or value can be [URI encoded][uriencode] to satisfy the allowed character requirement.
- The cookie value can be a number, or a [JSON-stringified][stringify] object prefixed with `j:`.
- The cookie value can be [signed][createhmac] to ensure that it has not been tampered with, and prefixed with `s:`.

The server sends cookies to the browser by setting the [Set-Cookie header][setcookie].

```js
[
    '<cookie-name>=<cookie-value>; attribute1; attribute2; ...',
    ...
]
```

The browser sends cookies back to the server by setting the [Cookie header][cookie].

```js
'<cookie-name>=<cookie-value>; ...'
```

If the server does not provide information about the expiration of the cookie by specifying the exact date or after a specific length of time, it becomes a **session cookie** and is deleted when the user closes the browser.
You can specify one of the following attributes to create a **persistent cookie**.

| Attribute | Description | Note |
| :---: | --- | --- |
| [`Expires`][setcookie] | The exact expiration [date][date] in the [RFC 7231][rfc7231] format. | [`new Date().toUTCString()`][toutcstr] |
| [`Max-Age`][setcookie] | Number of seconds until the cookie expires. | Invalidates [`Expires`][setcookie]. |

The [SameSite][samesite] attribute allows to declare if the cookie should be restricted to a **same-site** or **cross-site** context, providing some protection against [Cross-site Request Forgery][csrf] (CSRF) attacks.
If the server stores a session token with full access to the user's account in the cookies, you don't want the browser to send it in a malicious request from an unauthorized site.
The included cookie is **first-party** when the request is made in a **same-site** context, and **third-party** when the request is made in a **cross-site** context.

| SameSite | Description |
| :---: | --- |
| [`Strict`][setcookie] | Cookies will only be sent in a **same-site** context. |
| [`Lax`][setcookie] | Like [`Strict`][setcookie], except the browser also sends the cookie when the user navigates to the cookie's origin site (e.g. by following a link from an external/different site). |
| [`None`][setcookie] | Cookies will be sent in both **cross-site** and **same-site** contexts. The [`Secure`][setcookie] attribute must also be set. |

[Top-level domains][tld] (TLD) are listed in the [Root Zone Database][rzd].
The [Public Suffix List][psl] (PSL) is a catalog of certain Internet domain names, whose [entries in the list][psld] are also referred to as **effective Top-Level Domains** (eTLD). The [PSL][psl] is used for some domains where the [TLD][tld] is not granular enough to identify the site.

[User agents][ua] group [URI][uri]s together into protection domains called origins. Two [URI][uri]s are part of the same origin if they have the same scheme, host, and port ([RFC 6454][rfc6454]).
All **cross-site** requests are necessarily **cross-origin**, but not all **cross-origin** requests are **cross-site**.

<p align="center">
  <img src="https://raw.githubusercontent.com/flipeador/node-http-cookies/assets/url.png"/>
</p>

The **same-site** context treats all subdomains of the `eTLD+1` to be equivalent to the root domain.

| Origin | eTLD+1 | Same-Site | Cross-Site |
| --- | --- | --- | --- |
| `http://www.example.com` | `.example.com` | `http://example.com` `http://x.example.com` `http://x.y.example.com` | `https://www.example.com` `example.net` `username.github.io` |
| `username.github.io` | `username.github.io` | `x.username.github.io` `x.y.username.github.io` | `otheruser.github.io` |

> [!WARNING]
> The definition of **site** extends beyond the host and [require scheme matches as well][sitesch], although some browsers may not yet be URL scheme-aware, see [Browser Compatibility][setcookbc].

> [!NOTE]
> The [Sec-Fetch-Site][secfetchsite] header can be used to determine if the request is **same-origin**, **same-site**, **cross-site**, or it is a user-originated operation (e.g. entering a URL into the address bar, opening a bookmark, or a drag-and-drop operation).

Further reading:

- <https://github.com/flipeador/node-http-cors>
- <https://jub0bs.com/posts/2021-01-29-great-samesite-confusion>
- <https://jub0bs.com/posts/2022-08-04-scraping-the-bottom-of-the-cors-barrel-part1>

## Installation

```
npm install flipeador/node-http-cookies
```

## Example

<details>
<summary><h4>Express</h4></summary>

```js
import express from 'express';
import {
    addCookie,
    cookieParser,
    parseJsonCookie,
    parseSignedCookie
} from '@flipeador/node-http-cookies';

const app = express();

app.use(express.json());
app.use(cookieParser());

app.get('/set-cookies', (req, res) => {
    // string cookie
    addCookie(res, 'string', 'value');
    // json cookie
    addCookie(res, 'json', ['value']);
    // signed string cookie
    addCookie(res, 'signed', 'value', {
        // attributes
        'Max-Age': 60000, // expires in 1 minute
        'HttpOnly': true, // true means no value
        // options
        secret: 'SIGNED_COOKIE_SECRET'
    });
    res.status(200).json(req.cookies);
});

app.get('/get-cookies', (req, res) => {
    res.status(200).json({
        string: req.cookies.string,
        json: parseJsonCookie(req.cookies.json),
        signed: parseSignedCookie(req.cookies.signed, 'SIGNED_COOKIE_SECRET')
    });
});

app.listen(8080, () => {
    console.log('Server is running!');
    console.log('http://localhost:8080/set-cookies');
    console.log('http://localhost:8080/get-cookies');
});
```

</details>

## License

This project is licensed under the **Apache License 2.0**. See the [license file](LICENSE) for details.

<!-- REFERENCE LINKS -->
[express]: https://github.com/expressjs/express
[cookie-parser]: https://github.com/expressjs/cookie-parser

[ua]: https://developer.mozilla.org/docs/Glossary/User_agent
[csrf]: https://en.wikipedia.org/wiki/Cross-site_request_forgery "Cross-Site Request Forgery"
[uri]: https://en.wikipedia.org/wiki/Uniform_Resource_Identifier "Uniform Resource Identifier"
[url]: https://en.wikipedia.org/wiki/URL "Uniform Resource Locator"

[httpcookie]: https://en.wikipedia.org/wiki/HTTP_cookie "HTTP Cookie"
[cookie]: https://developer.mozilla.org/docs/Web/HTTP/Headers/Cookie "Cookie HTTP request header"
[setcookie]: https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie "Set-Cookie HTTP response header"
[setcookbc]: https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie#browser_compatibility
[samesite]: https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie/SameSite "SameSite HTTP response header"
[secfetchsite]: https://developer.mozilla.org/docs/Web/HTTP/Headers/Sec-Fetch-Site
[date]: https://developer.mozilla.org/docs/Web/HTTP/Headers/Date

[stringify]: https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/JSON/stringify "JSON-stringify"
[uriencode]: https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent "encodeURIComponent()"
[toutcstr]: https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Date/toUTCString
[createhmac]: https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options "Node.js crypto#createHmac"

[tld]: https://developer.mozilla.org/docs/Glossary/TLD "Top-Level Domain"
[etld]: https://publicsuffix.org "Effective Top-Level Domain"
[rzd]: https://www.iana.org/domains/root/db "Root Zone Database"
[psl]: https://publicsuffix.org "Public Suffix List"
[psld]: https://github.com/publicsuffix/list/blob/master/public_suffix_list.dat "Public Suffix List (file)"

[rfc6454]: https://www.rfc-editor.org/rfc/rfc6454#section-3.2 "RFC 6454 Section 3.2"
[rfc7231]: https://datatracker.ietf.org/doc/html/rfc7231#section-7.1.1.1 "RFC 7231 Section 7.1.1.1"
[sitesch]: https://github.com/whatwg/url/issues/448
