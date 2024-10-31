import re
from typing import Dict, List
from urllib.parse import urlparse, urljoin

from playwright.sync_api import Route, Error as PlaywrightError


class Site:
    def __init__(self, url, driver, headers=None):
        try:
            self.original_url = urlparse(url)
        except ValueError as error:
            raise ValueError(str(error)) from error

        self.driver = driver
        self.options = {}
        self.options["headers"] = {
            **(driver.options.get("headers", {}) if driver.options else {}),
            **(headers if headers else {}),
        }

        self.raw_html = None
        self.response_received = False
        self.analyzed_urls = {}
        self.analyzed_xhr = {}
        self.detections = []

    def analyze(self, parsed_url=None):
        if parsed_url is None:
            parsed_url = self.original_url

        self._goto(parsed_url)

        def map_technology(detection):
            slug = detection.get("slug", "")
            name = detection.get("name", "")
            description = detection.get("description", "")
            confidence = detection.get("confidence", 0)
            version = detection.get("version", "")
            icon = detection.get("icon", "")
            website = detection.get("website", "")
            cpe = detection.get("cpe", "")
            categories = detection.get("categories", [])
            mapped_categories = [
                {
                    "id": category.get("id"),
                    "slug": category.get("slug"),
                    "name": category.get("name"),
                }
                for category in categories
            ]

            return {
                "slug": slug,
                "name": name,
                "description": description,
                "confidence": confidence,
                "version": version,
                "icon": icon,
                "website": website,
                "cpe": cpe,
                "categories": mapped_categories,
            }

        results = {
            "url": self.analyzed_urls,
            "technologies": [
                map_technology(detection) for detection in self.detections
            ],
        }

        return results

    def _goto(self, parsed_url):
        self.analyzed_urls[parsed_url.geturl()] = {
            "status": 0,
        }

        self.driver.log.info(
            f"Page analysis: {parsed_url.geturl()} with noScripts={self.driver.options.get('noScripts')} and timeout={self.driver.options.get('maxWait')}"
        )

        try:
            page = self.driver.context.new_page()

            page.on("dialog", lambda dialog: dialog.dismiss())
            page.on(
                "pageerror",
                lambda page, error: self.driver.log.error(
                    f"Error on page: {error.message} ({page.url})"
                ),
            )
            page.on("response", self._handle_response)

            page.route("**", self._handle_route)

            page.goto(parsed_url.geturl())

            page.wait_for_load_state("networkidle")

            # Cookies
            cookies = self._process_cookies(self.driver.context.cookies())

            # HTML
            if self.raw_html:
                # Text
                text = page.evaluate(
                    "() => document.body ? document.body.innerText : ''"
                )
                # CSS
                css = page.evaluate(
                    """
                    (maxRows) => {{
                        const css = [];

                        try {{
                            if (!document.styleSheets.length) {{
                                return '';
                            }}

                            for (const sheet of Array.from(document.styleSheets)) {{
                                for (const rules of Array.from(sheet.cssRules)) {{
                                    css.push(rules.cssText);

                                    if (css.length >= maxRows) {{
                                        break;
                                    }}
                                }}
                            }}
                        }} catch (error) {{
                            return '';
                        }}

                        return css.join('\\n');
                    }}
                """,
                    1000,
                )
                # Script tags
                script_src, scripts = page.evaluate("""
                    () => {
                        const nodes = Array.from(document.getElementsByTagName('script'));

                        const scriptSrc = nodes
                            .filter(({ src }) => src && !src.startsWith('data:text/javascript;'))
                            .map(({ src }) => src);

                        const scripts = nodes
                            .map((node) => node.textContent)
                            .filter((script) => script);

                        return [scriptSrc, scripts];
                    }
                """)
                # Meta tags
                meta = page.evaluate("""
                    () => Array.from(document.querySelectorAll('meta')).reduce((metas, meta) => {
                        const key = meta.getAttribute('name') || meta.getAttribute('property');
                        if (key) {
                            const lowerKey = key.toLowerCase();
                            metas[lowerKey] = metas[lowerKey] || [];
                            metas[lowerKey].push(meta.getAttribute('content'));
                        }
                        return metas;
                    }, {})
                """)
                # JavaScript
                js = self._get_js(page, self.driver.technologies)
                # DOM
                dom = self._get_dom(page, self.driver.technologies)

                all_analyse = (
                    self.driver.analyze_dom(dom)
                    + self.driver.analyze_js(js)
                    + self.driver.analyze(
                        {
                            "url": self.original_url.geturl(),
                            "cookies": cookies,
                            "html": self.raw_html,
                            "text": text,
                            "css": css,
                            "scripts": scripts,
                            "scriptSrc": script_src,
                            "meta": meta,
                        }
                    )
                )

                self.on_detect(all_analyse)

                requires = (
                    [req for req in self.driver.requires
                    if any(r['technology']['name'] == req['name'] for r in self.detections)]
                    +
                    [req for req in  self.driver.category_requires
                    if any(any(cat == req['categoryId'] for cat in r['technology']['categories']) for r in self.detections)]
                )

                for require in requires:
                    require_analyse = (
                        self.driver.analyze_dom(dom, require['technologies'])
                        + self.driver.analyze_js(js, require['technologies'])
                        + self.driver.analyze(
                            {
                                "url": self.original_url.geturl(),
                                "cookies": cookies,
                                "html": self.raw_html,
                                "text": text,
                                "css": css,
                                "scripts": scripts,
                                "scriptSrc": script_src,
                                "meta": meta,
                            },
                            require['technologies']
                        )
                    )
                    if len(require_analyse) > 0:
                        self.on_detect(require_analyse)

                resolved = self._resolve_detections()
                resolved = self._resolve_excludes(resolved)
                resolved = self._resolve_implies(resolved)

                self.detections = [
                    {
                        **item['technology'],
                        'categories': [self.driver.get_category(id) for id in item['technology']['categories']],
                        'confidence': item['confidence'],
                        'version': item['version'],
                    }
                    for item in sorted(resolved, key=self.driver.get_max_category_priority)
                ]

                self.driver.log.info(f"# Technologies detected: {len(self.detections)}")

                page.close()
        except PlaywrightError as error:
            raise PlaywrightError(str(error)) from error

    def _handle_route(self, route: Route) -> None:
        if route.request.resource_type == "xhr":
            parsed_uri = urlparse(route.request.url)
            hostname = parsed_uri.hostname

            if self.original_url.hostname not in self.analyzed_xhr:
                self.analyzed_xhr[self.original_url.hostname] = []

            if hostname not in self.analyzed_xhr[self.original_url.hostname]:
                self.analyzed_xhr[self.original_url.hostname].append(hostname)
                self.on_detect(self.driver.analyze({"xhr": hostname}))

        route.continue_()

    def _handle_response(self, response):
        if (
            response.status < 300
            and response.frame.url == response.frame.page.url
            and response.request.resource_type == "script"
        ):
            scripts = [response.text()]
            self.on_detect(self.driver.analyze({"scripts": scripts}))

        if response.url == self.original_url.geturl():
            self.analyzed_urls[response.request.url] = {
                "status": response.status,
            }

            headers = {}
            for key, value in response.headers.items():
                headers[key] = headers.get(key, [])
                headers[key].extend(value if isinstance(value, list) else [value])

            # Handle cross-domain redirects
            if 300 <= response.status < 400 and "location" in headers:
                _url = urljoin(response.request.url, headers["location"][-1])
                parsed_url = urlparse(_url)
                original_host = self.original_url.hostname.replace("www.", "")
                new_host = parsed_url.hostname.replace("www.", "")

                if new_host == original_host or (
                    len(self.analyzed_urls) == 1
                    and not self.driver.options.get("noRedirect")
                ):
                    self.original_url = parsed_url
                    return

            self.raw_html = response.text()
            self.response_received = True

            # https://playwright.dev/python/docs/next/api/class-response#response-security-details
            cert_issuer = (
                response.security_details()["issuer"]
                if response.security_details()
                else ""
            )
            self.on_detect(self.driver.analyze({"headers": headers, "certIssuer": cert_issuer}))

    def _resolve_detections(self):
        resolved = []
        for detection in self.detections:
            if not any(
                det["technology"]["name"] == detection["technology"]["name"]
                for det in resolved
            ):
                version = ""
                confidence = 0

                filtered_detections = [
                    det
                    for det in self.detections
                    if det.get("technology", {}).get("name")
                    == detection["technology"]["name"]
                ]
                for det in filtered_detections:
                    confidence = min(100, confidence + det["pattern"]["confidence"])
                    _version = det.get("version", "")
                    if (
                        len(_version) > len(version)
                        and len(_version) <= 15
                        and (int(_version, 10) if _version.isdigit() else 0) < 10000
                    ):
                        version = _version

                resolved.append(
                    {
                        "technology": detection["technology"],
                        "confidence": confidence,
                        "version": version,
                    }
                )

        return resolved

    def _resolve_excludes(self, resolved):
        for tech in resolved:
            for excluded_name in tech["technology"]["excludes"]:
                excluded = self.driver.get_technology(excluded_name)
                if excluded is None:
                    raise ValueError(
                        f"Excluded technology does not exist: {excluded_name}"
                    )

                resolved = [
                    t for t in resolved if t["technology"]["name"] != excluded.name
                ]
        return resolved

    def _resolve_implies(self, resolved):
        while resolved:
            done = True
            for tech in resolved:
                for implication in tech["technology"]["implies"]:
                    implied = self.driver.get_technology(implication["name"])
                    if implied is None:
                        raise ValueError(
                            f"Implied technology does not exist: {implication['name']}"
                        )

                    if implied["name"] not in [
                        t["technology"]["name"] for t in resolved
                    ]:
                        resolved.append(
                            {
                                "technology": implied,
                                "confidence": min(
                                    tech["confidence"], implication["confidence"]
                                ),
                                "version": implication.get("version", ""),
                            }
                        )

                        done = False

            if done:
                return resolved

    def on_detect(self, detections=None):
        if detections is None:
            detections = []

        self.detections = [
            detection
            for index, detection in enumerate(self.detections + detections)
            if not any(
                detection["technology"]["name"] == _detection["technology"]["name"]
                and detection["version"] == _detection["version"]
                and (
                    not detection["pattern"]["regex"]
                    or detection["pattern"]["regex"].pattern
                    == _detection["pattern"]["regex"].pattern
                )
                for _index, _detection in enumerate(self.detections + detections)
                if _index < index
            )
        ]

    def _process_cookies(self, page_cookies) -> Dict[str, List[str]]:
        """
        Process cookies from a page, converting them to a dictionary format
        and handling special cases like GA4 cookies.

        Args:
            page: The page object (assuming it has a cookies() method)

        Returns:
            Dict with cookie names as keys and lists of values
        """

        # Convert cookies to dictionary with lowercase names
        cookies = {cookie["name"].lower(): [cookie["value"]] for cookie in page_cookies}

        # Handle Google Analytics 4 cookies
        ga4_pattern = re.compile(r"_ga_[A-Z0-9]+")

        # Find and process GA4 cookies
        ga4_cookies = [name for name in cookies.keys() if ga4_pattern.match(name)]

        # Replace GA4 cookies with wildcard version
        for name in ga4_cookies:
            cookies["_ga_*"] = cookies[name]
            del cookies[name]

        return cookies

    def _get_js(self, page, technologies):
        return page.evaluate(
            """(technologies) => {
                return technologies
                    .filter(({ js }) => Object.keys(js).length)
                    .map(({ name, js }) => ({ name, chains: Object.keys(js) }))
                    .reduce((technologies, { name, chains }) => {
                        chains.forEach((chain) => {
                            chain = chain.replace(/\\[([^\\]]+)\\]/g, '.$1');
                            const value = chain
                                .split('.')
                                .reduce(
                                    (value, method) =>
                                        value &&
                                        value instanceof Object &&
                                        Object.prototype.hasOwnProperty.call(value, method)
                                            ? value[method]
                                            : '__UNDEFINED__',
                                    window
                                );
                            if (value !== '__UNDEFINED__') {
                                technologies.push({
                                    name,
                                    chain,
                                    value: typeof value === 'string' || typeof value === 'number'
                                        ? value
                                        : !!value,
                                });
                            }
                        });
                        return technologies;
                    }, []);
            }""",
            technologies,
        )

    def _get_dom(self, page, technologies):
        return page.evaluate(
            """(technologies) => {
                return technologies
                    .filter(({ dom }) => dom && dom.constructor === Object)
                    .reduce((technologies, { name, dom }) => {
                        const toScalar = (value) => typeof value === 'string' || typeof value === 'number' ? value : !!value;
                        Object.keys(dom).forEach((selector) => {
                            let nodes = [];
                            try {
                                nodes = document.querySelectorAll(selector);
                            } catch (error) {
                                // Continue
                            }
                            if (!nodes.length) return;
                            dom[selector].forEach(({ exists, text, properties, attributes }) => {
                                nodes.forEach((node) => {
                                    if (technologies.filter(({ name: _name }) => _name === name).length >= 50) return;
                                    if (exists && !technologies.find(({ name: _name, selector: _selector, exists }) => name === _name && selector === _selector && exists === '')) {
                                        technologies.push({ name, selector, exists: '' });
                                    }
                                    if (text) {
                                        const value = (node.textContent ? node.textContent.trim() : '').slice(0, 1000000);
                                        if (value && !technologies.find(({ name: _name, selector: _selector, text }) => name === _name && selector === _selector && text === value)) {
                                            technologies.push({ name, selector, text: value });
                                        }
                                    }
                                    if (properties) {
                                        Object.keys(properties).forEach((property) => {
                                            if (Object.prototype.hasOwnProperty.call(node, property) && !technologies.find(({ name: _name, selector: _selector, property: _property, value }) => name === _name && selector === _selector && property === _property && value === toScalar(value))) {
                                                const value = node[property];
                                                if (typeof value !== 'undefined') {
                                                    technologies.push({ name, selector, property, value: toScalar(value) });
                                                }
                                            }
                                        });
                                    }
                                    if (attributes) {
                                        Object.keys(attributes).forEach((attribute) => {
                                            if (node.hasAttribute(attribute) && !technologies.find(({ name: _name, selector: _selector, attribute: _attribute, value }) => name === _name && selector === _selector && attribute === _attribute && value === toScalar(value))) {
                                                const value = node.getAttribute(attribute);
                                                technologies.push({ name, selector, attribute, value: toScalar(value) });
                                            }
                                        });
                                    }
                                });
                            });
                        });
                        return technologies;
                    }, []);
            }""",
            technologies,
        )
