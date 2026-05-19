from __future__ import annotations

from html import escape
from html.parser import HTMLParser
from urllib.parse import urlparse

_ALLOWED_TAGS = {
    "a",
    "b",
    "blockquote",
    "br",
    "code",
    "div",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "i",
    "li",
    "ol",
    "p",
    "pre",
    "span",
    "strong",
    "table",
    "tbody",
    "td",
    "th",
    "thead",
    "tr",
    "u",
    "ul",
}
_ALLOWED_LINK_SCHEMES = {"http", "https", "mailto"}
_VOID_TAGS = {"br"}


def _sanitize_link(href: str) -> str | None:
    href = href.strip()
    if not href:
        return None
    if href.startswith(("/", "#")):
        if ":" in href:
            return None
        return href

    parsed = urlparse(href)
    scheme = parsed.scheme.lower()
    if scheme in _ALLOWED_LINK_SCHEMES:
        return href
    return None


class _ResultHTMLSanitizer(HTMLParser):
    """Sanitize command result HTML using an allowlist parser approach.

    Only a small set of formatting tags is preserved; unsupported tags are
    dropped while their text content is kept. Script-like tags are dropped
    entirely together with their content. For links, dangerous URI schemes are
    removed and `_blank` targets are forced to use `rel="noopener noreferrer"`.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self._parts: list[str] = []
        self._open_allowed_tags: list[str] = []
        self._drop_content_until: list[str] = []

    def _in_drop_mode(self) -> bool:
        return bool(self._drop_content_until)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in {"script", "style", "iframe", "object", "embed"}:
            self._drop_content_until.append(tag)
            return
        if self._in_drop_mode():
            return
        if tag not in _ALLOWED_TAGS:
            return

        rendered_attrs: list[str] = []
        if tag == "a":
            attrs_map = {k.lower(): (v or "") for k, v in attrs}
            href = _sanitize_link(attrs_map.get("href", ""))
            if href:
                rendered_attrs.append(f'href="{escape(href, quote=True)}"')

            title = attrs_map.get("title", "").strip()
            if title:
                rendered_attrs.append(f'title="{escape(title, quote=True)}"')

            target = attrs_map.get("target", "").strip().lower()
            if target in {"_blank", "_self", "_parent", "_top"}:
                rendered_attrs.append(f'target="{target}"')
                if target == "_blank":
                    rendered_attrs.append('rel="noopener noreferrer"')

        attrs_str = (" " + " ".join(rendered_attrs)) if rendered_attrs else ""
        self._parts.append(f"<{tag}{attrs_str}>")
        if tag not in _VOID_TAGS:
            self._open_allowed_tags.append(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self._drop_content_until:
            if tag == self._drop_content_until[-1]:
                self._drop_content_until.pop()
            return
        if tag in _VOID_TAGS:
            return
        if self._open_allowed_tags and self._open_allowed_tags[-1] == tag:
            self._open_allowed_tags.pop()
            self._parts.append(f"</{tag}>")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.lower() in _VOID_TAGS:
            return
        self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if not self._in_drop_mode():
            self._parts.append(escape(data))

    def handle_entityref(self, name: str) -> None:
        if not self._in_drop_mode():
            self._parts.append(f"&{name};")

    def handle_charref(self, name: str) -> None:
        if not self._in_drop_mode():
            self._parts.append(f"&#{name};")

    def get_html(self) -> str:
        while self._open_allowed_tags:
            self._parts.append(f"</{self._open_allowed_tags.pop()}>")
        return "".join(self._parts)


def sanitize_result_html(value: str) -> str:
    """Return a safe HTML subset for rendering command results in admin UI.

    This is designed as primary sanitization for untrusted command output:
    unsupported tags/attributes are stripped, and dangerous URL schemes are
    blocked while preserving common formatting tags.
    """
    parser = _ResultHTMLSanitizer()
    parser.feed(value)
    parser.close()
    return parser.get_html()
