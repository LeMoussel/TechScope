import pathlib
import json
import os
import sys
import re
from itertools import chain

# https://playwright.dev/python/
# playwright install
from playwright.sync_api import sync_playwright, Error as PlaywrightError

# https://loguru.readthedocs.io/en/stable/index.html
from loguru import logger


from techscope import utils
from techscope.site import Site

logger.remove()
logger.add(
    sys.stdout,
    colorize=True,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> <level>{level: <8} {message}</level>",
)


class TechScope:
    def __init__(self, options=None):
        if options is None:
            options = {}

        self.options = {
            "debug": False,
            "delay": 500,
            "maxWait": 30000,
            "proxy": False,
            "noScripts": False,
            "noRedirect": False,
            "userAgent": None,
            **options,
        }

        self.chromium_bin = os.environ.get("CHROMIUM_BIN")
        self.chromium_data_dir = os.environ.get("CHROMIUM_DATA_DIR")
        self.chromium_websocket = os.environ.get("CHROMIUM_WEBSOCKET")
        self.chromium_args = os.environ.get("CHROMIUM_ARGS")

        self.chromium_args = (
            self.chromium_args.split(" ")
            if self.chromium_args
            else [
                "--single-process",
                "--no-sandbox",
                "--no-zygote",
                "--disable-gpu",
                "--ignore-certificate-errors",
                "--allow-running-insecure-content",
                "--disable-web-security",
            ]
        )
        self._playwright = None
        self.browser = None
        self.destroyed = False

        with open(
            file=str(
                pathlib.Path(__file__).parent.resolve().joinpath("data/categories.json")
            ),
            mode="r",
            encoding="utf-8",
        ) as f:
            self.categories = json.load(f)

        with open(
            file=str(
                pathlib.Path(__file__)
                .parent.resolve()
                .joinpath("data/technologies/custom.json")
            ),
            mode="r",
            encoding="utf-8",
        ) as f:
            technologies = json.load(f)

        for index in range(27):
            character = chr(index + 96) if index else "_"
            technologies = {
                **technologies,
                **json.load(
                    open(
                        file=os.path.join(
                            os.path.dirname(__file__),
                            f"data/technologies/{character}.json",
                        ),
                        mode="r",
                        encoding="utf-8",
                    )
                ),
            }

        self.requires = []
        self.category_requires = []

        self.technologies = [
            {
                "name": name,
                "description": info.get("description", None),
                "categories": info.get("cats", []),
                "slug": utils.slugify(name),
                "url": utils.transform_patterns(info.get("url")),
                "xhr": utils.transform_patterns(info.get("xhr")),
                "headers": utils.transform_patterns(info.get("headers")),
                "dns": utils.transform_patterns(info.get("dns")),
                "cookies": utils.transform_patterns(info.get("cookies")),
                "dom": utils.transform_patterns(
                    {
                        selector: {"exists": ""}
                        for selector in utils.to_array(info["dom"])
                    }
                    if isinstance(info.get("dom"), str)
                    or isinstance(info.get("dom"), list)
                    else info.get("dom", {}),
                    True,
                    False,
                ),
                "html": utils.transform_patterns(info.get("html")),
                "text": utils.transform_patterns(info.get("text")),
                "scripts": utils.transform_patterns(info.get("scripts")),
                "css": utils.transform_patterns(info.get("css")),
                "certIssuer": utils.transform_patterns(info.get("certIssuer")),
                "robots": utils.transform_patterns(info.get("robots")),
                "meta": utils.transform_patterns(info.get("meta")),
                "scriptSrc": utils.transform_patterns(info.get("scriptSrc")),
                "js": utils.transform_patterns(info.get("js"), True),
                "implies": [
                    {
                        "name": implied.get("value"),
                        "confidence": implied.get("confidence"),
                        "version": implied.get("version"),
                    }
                    for implied in utils.transform_patterns(info.get("implies", []))
                ],
                "excludes": [
                    {"name": excluded.get("value")}
                    for excluded in utils.transform_patterns(info.get("excludes", []))
                ],
                "requires": [
                    {"name": required.get("value")}
                    for required in utils.transform_patterns(info.get("requires", []))
                ],
                "requiresCategory": []
                if info.get("requiresCategory") is None
                else [{"id": info.get("requiresCategory")}],
                "icon": info.get("icon", "default.svg"),
                "website": info.get("website", None),
                "pricing": info.get("pricing", []),
                "cpe": info.get("cpe", None),
            }
            for name, info in technologies.items()
        ]

        self._set_technologies()
        self._set_categories()

    def __enter__(self):
        self._init_browser()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.destroyed = True
        self.browser.close()
        self._playwright.stop()
        return False

    def _set_technologies(self):
        for technology in [tech for tech in self.technologies if tech['requires']]:
            for req in technology['requires']:
                if not self.get_technology(req['name']):
                    raise ValueError(f"Required technology does not exist: {req['name']}")

                req_entry = next((entry for entry in self.requires if entry['name'] == req['name']), None)
                if req_entry:
                    # If it exists, append the current technology to the list of technologies
                    req_entry['technologies'].append(technology)
                else:
                    # If it doesn't exist, add a new entry with the required technology and the current one
                    self.requires.append({'name': req['name'], 'technologies': [technology]})

        remove_requires_values = [req_tech for req in self.requires for req_tech in req['technologies']]
        self.technologies = [tech for tech in self.technologies if not any(req_tech['name'] == tech["name"] for req_tech in remove_requires_values)]

        for technology in [tech for tech in self.technologies if tech['requiresCategory']]:
            for category in technology['requiresCategory']:
                req_cat_entry = next((entry for entry in self.category_requires if entry['categoryId']== category['id']), None)
                if req_cat_entry:
                    req_cat_entry['technologies'].append(technology)
                else:
                    self.category_requires.append({'categoryId': category['id'], 'technologies': [technology]})

        remove_category_requires_values = [cat_req_tech for req in self.category_requires for cat_req_tech in req['technologies']]
        self.technologies = [tech for tech in self.technologies if not any(req_tech['name'] == tech["name"] for req_tech in remove_category_requires_values)]

    def _set_categories(self):
        self.categories = sorted(
            [
                {
                    "id": int(id),
                    "slug": utils.slugify(category["name"]),
                    **category,
                }
                for id, category in self.categories.items()
            ],
            key=lambda x: x.get("priority", 0),
            reverse=True,
        )

    def _init_browser(self):
        try:
            self._playwright = sync_playwright().start()
            if self.chromium_websocket:
                self.browser = self._playwright.chromium.connect_over_cdp(
                    endpoint_url=self.chromium_websocket,
                )
            else:
                self.browser = self._playwright.chromium.launch(
                    args=self.chromium_args,
                    executable_path=self.chromium_bin,
                    headless=False,
                )

            def handle_disconnected():
                logger.info("Browser disconnected")
                if not self.destroyed:
                    try:
                        self.__init__(self.options)
                    except PlaywrightError as error:
                        raise PlaywrightError(str(error)) from error

            # https://playwright.dev/python/docs/api/class-browser#browser-event-disconnected
            self.browser.on("disconnected", handle_disconnected)
        except PlaywrightError as error:
            raise PlaywrightError(str(error)) from error

    def open(self, url, headers=None):
        return Site(url.split("#")[0], self, headers)

    def analyze(self, items, technologies=None):
        if technologies is None:
            technologies = self.technologies

        relations = {
            "url": self._analyze_one_to_one,
            "xhr": self._analyze_one_to_one,
            "html": self._analyze_one_to_one,
            "text": self._analyze_one_to_one,
            "scripts": self._analyze_one_to_many,
            "css": self._analyze_one_to_one,
            "robots": self._analyze_one_to_one,
            "certIssuer": self._analyze_one_to_one,
            "scriptSrc": self._analyze_one_to_many,
            "cookies": self._analyze_many_to_many,
            "meta": self._analyze_many_to_many,
            "headers": self._analyze_many_to_many,
            "dns": self._analyze_many_to_many,
        }

        detections = [
            detection
            for technology in technologies
            for type_name in relations
            if items.get(type_name)
            for detection in relations[type_name](
                technology, type_name, items[type_name]
            )
        ]

        return detections

    def analyze_js(self, js, technologies=None):
        if technologies is None:
            technologies = self.technologies
        results = []

        for item in js:
            name, chain, value = item["name"], item["chain"], item["value"]
            technology = next(
                (tech for tech in technologies if tech["name"] == name), None
            )
            if technology:
                result = self._analyze_many_to_many(technology, "js", {chain: [value]})
                results.extend(result)
        return results

    def analyze_dom(self, dom, technologies=None):
        if technologies is None:
            technologies = self.technologies
        results = []

        for item in dom:
            name = item["name"]
            selector = item.get("selector")
            exists = item.get("exists")
            text = item.get("text")
            prop_name = item.get("property")
            attribute = item.get("attribute")
            value = item.get("value")

            technology = next(
                (tech for tech in technologies if tech["name"] == name), None
            )
            if technology:
                if exists is not None:
                    results.extend(
                        self._analyze_many_to_many(
                            technology, "dom.exists", {selector: [""]}
                        )
                    )
                elif text is not None:
                    results.extend(
                        self._analyze_many_to_many(
                            technology, "dom.text", {selector: [text]}
                        )
                    )
                elif prop_name is not None:
                    results.extend(
                        self._analyze_many_to_many(
                            technology,
                            f"dom.properties.{prop_name}",
                            {selector: [value]},
                        )
                    )
                elif attribute is not None:
                    results.extend(
                        self._analyze_many_to_many(
                            technology,
                            f"dom.attributes.{attribute}",
                            {selector: [value]},
                        )
                    )
        return results

    def _resolve_version(self, version_info, match):
        version = version_info.get('version', '')
        regex = version_info.get('regex')
        resolved = version

        if version:
            matches = regex.search(match)
            if matches:
                # Convert matches object to list including the full match
                matches_list = [matches.group(i) for i in range(matches.lastindex + 1)] if matches.lastindex else [matches.group(0)]

                for index, match_value in enumerate(matches_list):
                    # Skip if match is too long
                    if match_value and len(str(match_value)) > 10:
                        continue

                    # Parse ternary operator
                    ternary = re.search(fr'\\{index}\?([^:]+):(.*)$', version)
                    if ternary and len(ternary.groups()) == 2:
                        resolved = version.replace(
                            ternary.group(0),
                            ternary.group(1) if match_value else ternary.group(2)
                        )

                    # Replace back references
                    resolved = resolved.strip().replace(f'\\{index}', match_value or '')

        return resolved

    def _analyze_one_to_one(self, technology, type_name, value):
        technologies = []
        for pattern in technology[type_name]:
            matches = re.search(pattern["regex"], value)
            if matches:
                technologies.append(
                    {
                        "technology": technology,
                        "pattern": {
                            **pattern,
                            "type": type_name,
                            "value": value,
                            "match": matches.group(0),
                        },
                        "version": self._resolve_version(pattern, value),
                    }
                )

        return technologies

    def _analyze_one_to_many(self, technology, type_name, items=None):
        if items is None:
            items = []
        technologies = []
        patterns = technology.get(type_name, [])

        for value in items:
            for pattern in patterns:
                matches = re.search(pattern["regex"], value)
                if matches:
                    technologies.append(
                        {
                            "technology": technology,
                            "pattern": {
                                **pattern,
                                "type": type_name,
                                "value": value,
                                "match": matches.group(0),
                            },
                            "version": self._resolve_version(pattern, value),
                        }
                    )

        return technologies

    def _analyze_many_to_many(self, technology, types, items=None):
        if items is None:
            items = []
        type_name, *subtypes = types.split(".")
        technologies = []

        if not technology[type_name]:
            return technologies

        for key, patterns in technology.get(type_name, {}).items():
            values = items.get(key, [])

            for _pattern in patterns:
                pattern = _pattern
                for subtype in subtypes:
                    pattern = pattern.get(subtype, {})

                for value in values:
                    matches = re.search(pattern["regex"], str(value))
                    if matches:
                        technologies.append(
                            {
                                "technology": technology,
                                "pattern": {
                                    **pattern,
                                    "type": type_name,
                                    "value": value,
                                    "match": matches.group(0),
                                },
                                "version": self._resolve_version(pattern, value),
                            }
                        )

        return technologies

    def get_technologyOLD(self, name):
        # Flatten and combine the lists of technologies
        combined_technologies = chain(
            self.technologies,
            *[tech.get('technologies', []) for req_list in self.requires.values() for tech in req_list],
            *[tech.get('technologies', []) for req_list in self.category_requires.values() for tech in req_list],
        )

        # Find the technology by name
        return next((tech for tech in combined_technologies if tech['name'] == name), None)

    def get_technology(self, name):
        # Flatten and combine the lists of technologies
        combined_technologies = chain(
            self.technologies,
            *[tech.get('technologies', []) for tech in self.requires],
            *[tech.get('technologies', []) for tech in self.category_requires],
        )

        # Find the technology by name
        return next((tech for tech in combined_technologies if tech['name'] == name), None)

    def get_category(self, category_id):
        return next((category for category in self.categories if category['id'] == category_id), None)

    def get_max_category_priority(self, item):
        return max(
            (self.get_category(category_id)['priority'] for category_id in item['technology']['categories']),
            default=0
        )
