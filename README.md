# HTTP Cookies

Simplifies the handling of [HTTP cookies][httpcookie].

### Features

- Create string or JSON cookies with an optional signature.
- Parse the [Cookie][cookie] header into a key-value Object.
- Use the cookie parser as a middleware in [Express][express].

> [!NOTE]
> This is a lightweight alternative library to [cookie-parser][cookie-parser] with no dependencies.

## Installation

```
npm i flipeador/node-http-cookies#semver:^2.0.0
```

## Cookie Attributes

Cookies are mainly used for storing credentials, user preferences, site settings, and tracking data.

- The cookie name can contain any US-ASCII characters except for control characters, space, tab, and separators (`( ) < > @ , ; : \ " / [ ] ? = { }`).
- The cookie value can optionally be wrapped in double quotes and include any US-ASCII character excluding control characters, whitespace, double quotes, commas, semicolons, and backslashes.
- The cookie name or value can be [URI encoded][uriencode] to satisfy the allowed character requirement.
- The cookie value can be a number, or a [JSON-stringified][stringify] object prefixed with `j:`.
- The cookie value can be [signed][createhmac] to ensure that it has not been tampered with, and prefixed with `s:`.

The server sends cookies to the browser by setting the [Set-Cookie header][setcookie]:

```js
[
    '<cookie-name>=<cookie-value>; attribute1; attribute2; ...',
    ...
]
```

The browser sends cookies back to the server by setting the [Cookie header][cookie]:

```js
'<cookie-name>=<cookie-value>; ...'
```

Cookie names can have specific semantics via the following prefixes:

| Prefix | Description |
| :---: | --- |
| `__Secure-` | Require the cookie to be set from a secure page (HTTPS). |
| `__Host-` | Make the cookie bound to the hostname (and not the registrable domain). |

The following are the cookie attributes recognized by the library:

| Attribute | Default | Description | Note |
| :---: | ---: | --- | --- |
| [`Domain`][setcookie] | — | Defines the host to which the cookie will be sent. | — |
| [`Path`][setcookie] | `/` | Restrict the cookie to a specific path, including subpaths. | — |
| [`Secure`][setcookie] | `false` | Set the cookie over HTTPS only, except on localhost. | — |
| [`HttpOnly`][setcookie] | `false` | Make the cookie inaccessible to the JavaScript [`Document.cookie`][doccookie] API. | — |
| [`SameSite`][setcookie] | `lax` | Origin relationship between request and resource. | Values: `strict` `lax` `none`. |
| [`Partitioned`][setcookie] | `false` | The cookie should be stored using partitioned storage. | Requires the `Secure` attribute. |
| [`Expires`][setcookie] | — | The exact expiration [date][date] in the [RFC 7231][rfc7231] format. | [`new Date().toUTCString()`][toutcstr] |
| [`Max-Age`][setcookie] | — | Number of seconds until the cookie expires. | Invalidates [`Expires`][setcookie]. |

> [!NOTE]
> - The value `true` will cause the attribute to be added to the cookie with no value assigned.
> - The values `false` `NaN` `''` will cause the attribute not to be added to the cookie.
> - The values `null` `undefined` will cause the attribute to keep the default value, if any.

The following are special attributes used as options:

| Option | Description |
| :---: | --- |
| `secret` | Secret to use to sign the cookie value. |

### Cookie Lifetime

By specifying the `Expires` or `Max-Age` attribute, you can create a **persistent cookie**.
If the server does not provide information about the expiration of the cookie by specifying the exact date or after a specific length of time, it becomes a **session cookie** and is removed when the browser shuts down.

A cookie can be removed by specifying a zero or negative number in the `Max-Age` attribute, wich will expire the cookie immediately.

### Partitioned Attribute

Cookies Having Independent Partitioned State (CHIPS) allows developers to opt a cookie into partitioned storage, with separate cookie jars per top-level site, which restricts the contexts in which a cookie is available to only those whose top-level document is same-site with the top-level document that initiated the request that created the cookie. Partitioned cookies allows to embedded sites which are cross-site with the top-level frame to have access to HTTP state which cannot be used for tracking across multiple top-level sites.

#### Google Chrome (≥118):
- Visit <chrome://flags/#test-third-party-cookie-phaseout> and enable partitioned cookies.
- The Application tab shows both partition and unparitioned stored cookies, even if they are not accessible in the current page.
- Unpartitioned third-party cookies will not be available to embedded sites on different top-level sites.
- You can better visualize unpartitioned cookies that are being blocked by checking `Only show cookies with an issue` in the DevTools.

#### Further reading:
- https://developer.mozilla.org/docs/Web/Privacy/Partitioned_cookies
- https://developers.google.com/privacy-sandbox/3pcd/chips
- https://www.ietf.org/archive/id/draft-cutler-httpbis-partitioned-cookies-01.html
- https://github.com/privacycg/CHIPS

### SameSite Attribute

The `SameSite` attribute allows to declare if the cookie should be restricted to a **same-site** or **cross-site** context, providing some protection against [Cross-site Request Forgery][csrf] (CSRF) attacks.
If the server stores a session token with full access to the user's account in the cookies, you don't want the browser to send it in a malicious request from an unauthorized site.
The included cookie is **first-party** when the request is made in a **same-site** context, and **third-party** when the request is made in a **cross-site** context.

| SameSite | Description |
| :---: | --- |
| [`Strict`][setcookie] | Cookies will only be sent in a **same-site** context. |
| [`Lax`][setcookie] | Like [`Strict`][setcookie], except the browser also sends the cookie when the user navigates to the cookie's origin site (e.g. by following a link from an external/different site). |
| [`None`][setcookie] | Cookies will be sent in both **cross-site** and **same-site** contexts. Requires the `Secure` attribute. |

> [!IMPORTANT]
> If the `SameSite` attribute is set to `None`, browsers that have enabled the **third-party cookie phaseout** will require the [`Partitioned`](#partitioned-attribute) attribute to be present, otherwise unparitioned cookies will be blocked in third-party contexts.

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

> [!IMPORTANT]
> - If you are dealing with **third-party** cookies (e.g. for tracking purposes), make sure to specify the [Partitioned](#partitioned-attribute) attribute.
> - The definition of **site** extends beyond the host and [require scheme matches as well][sitesch], although some browsers may not yet be URL scheme-aware, see [Browser Compatibility][setcookbc].

> [!NOTE]
> The [Sec-Fetch-Site][secfetchsite] header can be used to determine if the request is **same-origin**, **same-site**, **cross-site**, or it is a user-originated operation (e.g. entering a URL into the address bar, opening a bookmark, or a drag-and-drop operation).

#### Further reading:
- <https://github.com/flipeador/node-http-cors>
- <https://jub0bs.com/posts/2021-01-29-great-samesite-confusion>
- <https://jub0bs.com/posts/2022-08-04-scraping-the-bottom-of-the-cors-barrel-part1>

## Example

<details>
<summary><h4>Express</h4></summary>

```js
import express from 'express';
import {
    cookieParser,
    parseJsonCookie,
    parseSignedCookie
} from '@flipeador/node-http-cookies';

const app = express();

// Add the middleware here and not individually to the routes.
// This does not have a significant impact on performance,
// as the cookies are not parsed immediately for every request.
// Cookies are parsed only once on first access to the 'req.cookies' property.
// The middleware also sets a function 'res.cookie()' that allows cookies to be added.
app.use(cookieParser());

app.get('/set-cookie', (req, res) => {
    res.cookie('string', 'value', {
        secure: true,
        sameSite: 'none',
        partitioned: true,
        // Restrict the cookie to the current path and subpaths.
        path: `${req.baseUrl}${req.path}`
    });
    res.cookie('json', ['value']);
    res.cookie('signed', 'value', { secret: 'XXX' });
    res.json(req.cookies);
});

app.get('/get-cookie', (req, res) => {
    res.json({
        string: req.cookies.string ??
        'not accessible due to different path',
        json: parseJsonCookie(req.cookies.json),
        signed: parseSignedCookie(req.cookies.signed, 'XXX')
    });
});

app.listen(3000, () => {
    console.log('Server is running!');
    console.log('http://localhost:3000/set-cookie');
    console.log('http://localhost:3000/get-cookie');
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
[cookie]: https://developer.mozilla.org/docs/Web/HTTP/Headers/Cookie "Cookie Request Header"
[setcookie]: https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie "Set-Cookie Response Header"
[setcookbc]: https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie#browser_compatibility
[samesite]: https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie/SameSite
[secfetchsite]: https://developer.mozilla.org/docs/Web/HTTP/Headers/Sec-Fetch-Site "Sec-Fetch-Site Request Header"
[date]: https://developer.mozilla.org/docs/Web/HTTP/Headers/Date "Date Header"

[doccookie]: https://developer.mozilla.org/docs/Web/API/Document/cookie
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
