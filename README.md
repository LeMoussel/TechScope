# <img style="margin-right: 1rem;" align="left" height="72" src="icon_192.png" alt="TechScope" />TechScope

<br>

[![License](https://img.shields.io/badge/license-MIT-blue)](https://opensource.org/licenses/BSD-2-Clause)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)

**TechScope** is a Python library built to detect and identify various technologies used on websites, including content management systems (CMS), web frameworks, e-commerce platforms, JavaScript libraries, analytics tools, and more.

We're currently using `technologies` files maintained by the [Pentest-Tools.com](https://pentest-tools.com/) team on [their fork of Wappalyzer](https://github.com/pentesttoolscom/wappalyzer).

## Prerequisites

- [Python](https://www.python.org/) version 3.10 or higher
- [Playwright for Python](https://playwright.dev/python/)

## Installation

TechScope is a breeze to get started.We only require at least Python 3.10 to work and the rest of the requirements are installed automatically with the package.

```bash
# Using pip
pip install techscope

# Or the latest from GitHub
pip install git+https://github.com/LeMoussel/TechScope@master

# TechScope uses PlayWright
# It is necessary to install the browsers required by Playwright
playwright install
```

## Usage

Let's look at a basic example that illustrates TechScope's functionality:

```python
import os
import json

# https://github.com/LeMoussel/TechScope
from techscope import TechScope, PlaywrightError as PWError


if __name__ == "__main__":
    os.system("cls || clear")

    SITE_URL = "https://stackoverflow.com/"

    try:
        with TechScope({
            "debug": True,
        }) as ts:
            ts.log.info(
                f"TechScope detect and identify various technologies used on website: {SITE_URL}"
            )
            ts.log.info('Browser options')
            for item in ts.options.items():
                ts.log.info(f"\t{item[0]}: {item[1]}")

            site = ts.open(SITE_URL)
            results = site.analyze()
            with open(
                file="example-techscope.json", mode="w", encoding="utf-8"
            ) as fjson:
                json.dump(results, fjson, ensure_ascii=False, indent=4)
    except ValueError as verror:
        TechScope.log.error(f"TechScope Error: {verror}")
    except PWError as pwerror:
        TechScope.log.error(f"Playwright Error: {pwerror}")
```

## Specification

A long list of [regular expressions](https://docs.python.org/3.10/library/re.html) is used to identify technologies on web pages. TechScope inspects HTML code, as well as JavaScript variables, response headers and more.

Patterns (regular expressions) are kept in [`data/technologies/`](https://github.com/LeMoussel/TechScope/tree/master/techscope/data/technologies). The following is an example of an application fingerprint.

### Example

```json
"Example": {
  "description": "A short description of the technology.",
  "cats": [
    "1"
  ],
  "cookies": {
    "cookie_name": "Example"
  },
  "dom": {
    "#example-id": {
      "exists": "",
      "attributes": {
        "class": "example-class"
      },
      "properties": {
        "example-property": ""
      },
      "text": "Example text content"
    }
  },
  "dns": {
    "MX": [
      "example\\.com"
    ]
  },
  "js": {
    "Example.method": ""
  },
  "excludes": "Example",
  "headers": {
    "X-Powered-By": "Example"
  },
  "html": "<link[^>]example\\.css",
  "text": "\bexample\b",
  "css": "\\.example-class",
  "robots": "Disallow: /unique-path/",
  "implies": "PHP\\;confidence:50",
  "requires": "WordPress",
  "requiresCategory": "Ecommerce",
  "meta": {
    "generator": "(?:Example|Another Example)"
  },
  "scriptSrc": "example-([0-9.]+)\\.js\\;confidence:50\\;version:\\1",
  "scripts": "function webpackJsonpCallback\\(data\\) {",
  "url": "example\\.com",
  "xhr": "example\\.com",
  "oss": true,
  "saas": true,
  "pricing": ["mid", "freemium", "recurring"],
  "website": "https://example.com",
}
```

## JSON fields

Find the JSON schema at [`schema.json`](https://github.com/LeMoussel/TechScope/tree/master/techscope/data/schema.json).

### Required properties

<table>
  <thead>
    <tr>
      <th>Field</th>
      <th>Type</th>
      <th>Description</th>
      <th>Example</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>cats</code></td>
      <td>Array</td>
      <td>
        One or more category IDs.
      </td>
      <td><code>[1, 6]</code></td>
    </tr>
    <tr>
      <td><code>website</code></td>
      <td>String</td>
      <td>URL of the application's website.</td>
      <td>
        <code>"https://example.com"</code>
      </td>
    </tr>
  </tbody>
</table>

### Optional properties

<table>
  <thead>
    <tr>
      <th>Field</th>
      <th>Type</th>
      <th>Description</th>
      <th>Example</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>description</code></td>
      <td>String</td>
      <td>
        A short description of the technology in British English (max.
        250 characters). Write in a neutral, factual tone; not like an
        ad.
      </td>
      <td><code>"A short description."</code></td>
    </tr>
    <tr>
      <td><code>icon</code></td>
      <td>String</td>
      <td>Application icon filename.</td>
      <td><code>"WordPress.svg"</code></td>
    </tr>
    <tr>
      <td><code>cpe</code></td>
      <td>String</td>
      <td>
        Search Common Platform Enumerations (<a href="https://nvd.nist.gov/products/cpe" target="_blank">CPE</a>) is a structured naming scheme for technologies. To check if a CPE is valid and exists (using v2.3), use the <a href="https://nvd.nist.gov/products/cpe/search" target="_blank">search</a>).
      </td>
      <td><code>"cpe:2.3:a:apache:http_server</code><br /><code>:*:*:*:*:*:*:*:*"</code></td>
    </tr>
    <tr>
      <td><code>saas</code></td>
      <td>Boolean</td>
      <td>
        The technology is offered as a Software-as-a-Service (SaaS), i.e. hosted or cloud-based.
      </td>
      <td><code>true</code></td>
    </tr>
    <tr>
      <td><code>oss</code></td>
      <td>Boolean</td>
      <td>
        The technology has an open-source license.
      </td>
      <td><code>true</code></td>
    </tr>
    <tr>
      <td><code>pricing</code></td>
      <td>Array</td>
      <td>
Cost indicator (based on a typical plan or average monthly price) and available pricing models. For paid products only.

One of:
<ul>
  <li><code>low</code>Less than US $100 / mo</li>
  <li><code>mid</code>Between US $100 - $1,000 / mo</li>
  <li><code>high</code>More than US $1,000 / mo</li>
</ul>

Plus any of:
<ul>
  <li><code>freemium</code> Free plan available</li>
  <li><code>onetime</code> One-time payments accepted</li>
  <li><code>recurring</code> Subscriptions available</li>
  <li><code>poa</code> Price on asking</li>
  <li><code>payg</code> Pay as you go (e.g. commissions or usage-based fees)</li>
</ul>
      </td>
      <td><code>["low", "freemium"]</code></td>
    </tr>
  </tbody>
</table>

### Implies, requires and excludes (optional)

<table>
  <thead>
    <tr>
      <th>Field</th>
      <th>Type</th>
      <th>Description</th>
      <th>Example</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>implies</code></td>
      <td>String | Array</td>
      <td>
        The presence of one application can imply the presence of
        another, e.g. WordPress means PHP is also in use.
      </td>
      <td><code>"PHP"</code></td>
    </tr>
    <tr>
      <td><code>requires</code></td>
      <td>String | Array</td>
      <td>
        Similar to implies but detection only runs if the required technology has been identified. Useful for themes for a specific CMS.
      </td>
      <td><code>"WordPress"</code></td>
    </tr>
    <tr>
      <td><code>requiresCategory</code></td>
      <td>String | Array</td>
      <td>
        Similar to requires; detection only runs if a technology in the required category has been identified.
      </td>
      <td><code>"Ecommerce"</code></td>
    </tr>
    <tr>
      <td><code>excludes</code></td>
      <td>String | Array</td>
      <td>
        Opposite of implies. The presence of one application can exclude
        the presence of another.
      </td>
      <td><code>"Apache"</code></td>
    </tr>
  </tbody>
</table>

### Patterns (optional)

<table>
  <thead>
    <tr>
      <th>Field</th>
      <th>Type</th>
      <th>Description</th>
      <th>Example</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>cookies</code></td>
      <td>Object</td>
      <td>Cookies.</td>
      <td><code>{ "cookie_name": "Cookie value" }</code></td>
    </tr>
    <tr>
      <td><code>dom</code></td>
      <td>String | Array | Object</td>
      <td>
        Uses a
        <a
          href="https://developer.mozilla.org/en-US/docs/Web/API/Document/querySelectorAll"
          target="_blank"
          noopener
          >query selector</a
        >
        to inspect element properties, attributes and text content.
      </td>
      <td>
        <code
          >{ "#example-id": { "property": { "example-prop": "" } }
          }</code
        >
      </td>
    </tr>
    <tr>
      <td><code>dns</code></td>
      <td>Object</td>
      <td>
        DNS records: supports MX, TXT, SOA and NS (NPM driver only).
      </td>
      <td>
        <code>{ "MX": "example\\.com" }</code>
      </td>
    </tr>
    <tr>
      <td><code>js</code></td>
      <td>Object</td>
      <td>
        JavaScript properties (case sensitive). Avoid short property
        names to prevent matching minified code.
      </td>
      <td><code>{ "jQuery.fn.jquery": "" }</code></td>
    </tr>
    <tr>
      <td><code>headers</code></td>
      <td>Object</td>
      <td>HTTP response headers.</td>
      <td><code>{ "X-Powered-By": "^WordPress$" }</code></td>
    </tr>
    <tr>
      <td><code>html</code></td>
      <td>String | Array</td>
      <td>
        HTML source code. Patterns must include an HTML opening tag to
        avoid matching plain text. For performance reasons, avoid
        <code>html</code> where possible and use
        <code>dom</code> instead.
      </td>
      <td><code>"&lt;a [^&gt;]*href=\"index.html"</code></td>
    </tr>
    <tr>
      <td><code>text</code></td>
      <td>String | Array</td>
      <td>
        Matches plain text. Should only be used in very specific cases where other methods can't be used.
      </td>
      <td><code>\bexample\b</code></td>
    </tr>
    <tr>
      <td><code>css</code></td>
      <td>String | Array</td>
      <td>
        CSS rules. Unavailable when a website enforces a same-origin
        policy. For performance reasons, only a portion of the available
        CSS rules are used to find matches.
      </td>
      <td><code>"\\.example-class"</code></td>
    </tr>
    <tr>
      <td><code>robots</code></td>
      <td>String | Array</td>
      <td>
        Robots.txt contents.
      </td>
      <td><code>"Disallow: /unique-path/"</code></td>
    </tr>
    <tr>
      <td><code>url</code></td>
      <td>String | Array</td>
      <td>Full URL of the page.</td>
      <td><code>"^https?//.+\\.wordpress\\.com"</code></td>
    </tr>
    <tr>
      <td><code>xhr</code></td>
      <td>String | Array</td>
      <td>Hostnames of XHR requests.</td>
      <td><code>"cdn\\.netlify\\.com"</code></td>
    </tr>
    <tr>
      <td><code>meta</code></td>
      <td>Object</td>
      <td>HTML meta tags, e.g. generator.</td>
      <td><code>{ "generator": "^WordPress$" }</code></td>
    </tr>
    <tr>
      <td><code>scriptSrc</code></td>
      <td>String | Array</td>
      <td>
        URLs of JavaScript files included on the page.
      </td>
      <td><code>"jquery\\.js"</code></td>
    </tr>
    <tr>
      <td><code>scripts</code></td>
      <td>String | Array</td>
      <td>
        JavaScript source code. Inspects inline and external scripts. For performance reasons, avoid
        <code>scripts</code> where possible and use
        <code>js</code> instead.
      </td>
      <td><code>"function webpackJsonpCallback\\(data\\) {"</code></td>
    </tr>
  </tbody>
</table>

## Patterns

Patterns are essentially JavaScript regular expressions written as strings, but with some additions.

### Quirks and pitfalls

- Because of the string format, the escape character itself must be escaped when using special characters such as the dot (`\\.`). Double quotes must be escaped only once (`\"`). Slashes do not need to be escaped (`/`).
- Flags are not supported. Regular expressions are treated as case-insensitive.
- Capture groups (`()`) are used for version detection. In other cases, use non-capturing groups (`(?:)`).
- Use start and end of string anchors (`^` and `$`) where possible for optimal performance.
- Short or generic patterns can cause applications to be identified incorrectly. Try to find unique strings to match.

### Tags

Tags (a non-standard syntax) can be appended to patterns (and implies and excludes, separated by `\\;`) to store additional information.

<table>
  <thead>
    <tr>
      <th>Tag</th>
      <th>Description</th>
      <th>Example</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>confidence</code></td>
      <td>
        Indicates a less reliable pattern that may cause false
        positives. The aim is to achieve a combined confidence of 100%.
        Defaults to 100% if not specified.
      </td>
      <td>
        <code>"js": { "Mage": "\\;confidence:50" }</code>
      </td>
    </tr>
    <tr>
      <td><code>version</code></td>
      <td>
        Gets the version number from a pattern match using a special
        syntax.
      </td>
      <td>
        <code>"scriptSrc": "jquery-([0-9.]+)\.js\\;version:\\1"</code>
      </td>
    </tr>
  </tbody>
</table>

### Version syntax

Application version information can be obtained from a pattern using a capture group. A condition can be evaluated using the ternary operator (`?:`).

<table>
  <thead>
    <tr>
      <th>Example</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>\\1</code></td>
      <td>Returns the first match.</td>
    </tr>
    <tr>
      <td><code>\\1?a:</code></td>
      <td>
        Returns a if the first match contains a value, nothing
        otherwise.
      </td>
    </tr>
    <tr>
      <td><code>\\1?a:b</code></td>
      <td>
        Returns a if the first match contains a value, b otherwise.
      </td>
    </tr>
    <tr>
      <td><code>\\1?:b</code></td>
      <td>
        Returns nothing if the first match contains a value, b
        otherwise.
      </td>
    </tr>
    <tr>
      <td><code>foo\\1</code></td>
      <td>
        Returns foo with the first match appended.
      </td>
    </tr>
  </tbody>
</table>

## Contributing

Contributions are welcome! If you'd like to contribute to this project, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE.md) file for details.
