import re
from typing import Any, Dict, List, Union


def slugify(string):
    return re.sub(
        r"(^-)|(-$)",
        "",
        re.sub(r"--+", "-", re.sub(r"[^a-z0-9-]", "-", string.lower())),
    )


def to_array(value: Any) -> List[Any]:
    """Converts a value to an array if it's not already."""
    return value if isinstance(value, list) else [value]


def parse_pattern(
    pattern: Union[str, Dict[str, Any]], is_regex: bool = True
) -> Dict[str, Any]:
    """Extract information from regex pattern."""
    if isinstance(pattern, dict):
        return {key: parse_pattern(value) for key, value in pattern.items()}
    else:
        attrs = {}
        parts = pattern.split("\\;")

        for i, attr in enumerate(parts):
            if i > 0:
                key_value = attr.split(":")
                if len(key_value) > 1:
                    attrs[key_value[0]] = ":".join(key_value[1:])
            else:
                attrs["value"] = pattern if isinstance(pattern, (int, float)) else attr

                if is_regex:
                    if not attr:
                        regex_str = "(?:)"
                    else:
                        regex_str = (
                            attr.replace("/", r"\/")
                            .replace(r"\+", "__escapedPlus__")
                            .replace("+", "{1,250}")
                            .replace("*", "{0,250}")
                            .replace("__escapedPlus__", r"\+")
                        )
                else:
                    regex_str = ""

                attrs["regex"] = re.compile(regex_str, re.IGNORECASE)

        attrs["confidence"] = int(attrs.get("confidence", 100))
        attrs["version"] = attrs.get("version", "")
        return attrs


def transform_patterns(
    patterns: Any, case_sensitive: bool = False, is_regex: bool = True
) -> Union[Dict[str, List[Dict[str, Any]]], List[Dict[str, Any]]]:
    """Transform patterns into a standard format."""
    if not patterns:
        return []

    if isinstance(patterns, (str, int, float)) or isinstance(patterns, list):
        patterns = {"main": patterns}

    parsed = {}
    for key, value in patterns.items():
        parsed[key if case_sensitive else key.lower()] = [
            parse_pattern(pattern, is_regex) for pattern in to_array(value)
        ]

    return parsed.get("main", parsed)
