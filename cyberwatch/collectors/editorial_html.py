"""Extract editorial HTML without interpreting comments as markup."""
from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
import re

EXTRACTOR_VERSION = "editorial-html-2026-09-06.1"
_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
_SKIP = {"script", "style", "noscript", "nav", "footer", "header", "aside", "form", "button", "svg", "head"}
_BLOCK = {"p", "div", "section", "article", "main", "li", "ul", "ol", "br", "h1", "h2", "h3", "h4", "blockquote", "table", "tr"}


@dataclass
class _Node:
    tag: str
    attrs: dict = field(default_factory=dict)
    children: list = field(default_factory=list)

    def walk(self):
        yield self
        for child in self.children:
            if isinstance(child, _Node):
                yield from child.walk()


class _Document(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = _Node("document")
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = _Node(tag, dict(attrs))
        self.stack[-1].children.append(node)
        if tag not in _VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in _VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index].tag == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        self.stack[-1].children.append(data)


def _excluded(node: _Node) -> bool:
    classes = str(node.attrs.get("class") or "").lower()
    return node.tag in _SKIP or any(marker in classes for marker in (
        "related-", "article-related", "share-buttons", "inarticle-ad", "newsletter",
    ))


def _text(node: _Node) -> str:
    if _excluded(node):
        return ""
    text = "".join(child if isinstance(child, str) else _text(child) for child in node.children)
    return f"\n{text}\n" if node.tag in _BLOCK else text


def editorial_text(html: str) -> str:
    parser = _Document()
    parser.feed(html or "")
    nodes = list(parser.root.walk())
    body = next((n for n in nodes if n.tag == "article" and
                 "article-content" in str(n.attrs.get("class") or "").split()), None)
    if body is None:
        body = next((n for n in nodes if n.tag == "article" and not _excluded(n)), None)
    if body is None:
        body = next((n for n in nodes if n.tag == "main"), parser.root)
    lines = [" ".join(line.split()) for line in _text(body).splitlines()]
    return "\n".join(line for line in lines if line)


def usable_detail(text: str, title: str) -> bool:
    """Reject title-only/challenge/error responses, even after HTTP 200."""
    body = text.replace(title, "").strip()
    prose = len(body) >= 80 and len(re.findall(r"\w+", body)) >= 12 and bool(
        re.search(r"[.!?:]", body)
    )
    structured = len(body) >= 40 and bool(re.search(r"donn[ée]es compromises", body, re.I)) and bool(
        re.search(r"\d[\d\s]* victimes", body, re.I)
    )
    return (prose or structured) and not re.search(
        r"^(?:just a moment|access denied|verify you are human)", body, re.I
    )
