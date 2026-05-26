

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List



C_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "inline", "int", "long", "register", "restrict", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while",
}



class TokenType:
    KEYWORD      = "KEYWORD"
    IDENTIFIER   = "IDENTIFIER"
    INTEGER      = "INTEGER"
    FLOAT        = "FLOAT"
    STRING       = "STRING"
    CHAR_LIT     = "CHAR"
    OPERATOR     = "OPERATOR"
    PUNCTUATION  = "PUNCTUATION"
    PREPROCESSOR = "PREPROCESSOR"
    COMMENT      = "COMMENT"
    EOF          = "EOF"


@dataclass
class Token:

    type: str
    value: str
    line: int

    def __repr__(self) -> str:
        return f"Token({self.type}, {self.value!r}, line={self.line})"



_PATTERNS: list[tuple[str, str | None]] = [

    (r"/\*[\s\S]*?\*/",                                       TokenType.COMMENT),

    (r"//[^\n]*",                                             TokenType.COMMENT),

    (r"#\s*(?:include|define|undef|ifdef|ifndef|if|else|elif|"
     r"endif|pragma|error|warning)[^\n]*",                    TokenType.PREPROCESSOR),

    (r'"(?:[^"\\]|\\.)*"',                                    TokenType.STRING),

    (r"'(?:[^'\\]|\\.)*'",                                    TokenType.CHAR_LIT),

    (r"\b\d+\.\d*(?:[eE][+-]?\d+)?[fFlL]?\b",                TokenType.FLOAT),
    (r"\b\d*\.\d+(?:[eE][+-]?\d+)?[fFlL]?\b",                TokenType.FLOAT),

    (r"\b0[xX][0-9a-fA-F]+[uUlL]*\b",                        TokenType.INTEGER),

    (r"\b0[0-7]+[uUlL]*\b",                                  TokenType.INTEGER),

    (r"\b\d+[uUlL]*\b",                                      TokenType.INTEGER),

    (r"<<=|>>=|->|<<|>>|<=|>=|==|!=|&&|\|\|"
     r"|\+=|-=|\*=|/=|%=|&=|\|=|\^=|\+\+|--",                TokenType.OPERATOR),

    (r"[+\-*/%=<>!&|^~?:]",                                  TokenType.OPERATOR),

    (r"[{}\[\]();,.]",                                        TokenType.PUNCTUATION),

    (r"\b[A-Za-z_]\w*\b",                                    "_WORD"),

    (r"\s+",                                                  None),
]


_COMPILED = [(re.compile(p), t) for p, t in _PATTERNS]


def tokenize(source: str) -> List[Token]:

    tokens: List[Token] = []
    pos = 0
    line = 1
    length = len(source)

    while pos < length:
        matched = False
        for regex, token_type in _COMPILED:
            m = regex.match(source, pos)
            if not m:
                continue

            value = m.group(0)
            newlines = value.count("\n")

            if token_type == "_WORD":

                if value in C_KEYWORDS:
                    tokens.append(Token(TokenType.KEYWORD, value, line))
                else:
                    tokens.append(Token(TokenType.IDENTIFIER, value, line))
            elif token_type is not None:
                tokens.append(Token(token_type, value, line))


            line += newlines
            pos = m.end()
            matched = True
            break

        if not matched:

            if source[pos] == "\n":
                line += 1
            pos += 1

    tokens.append(Token(TokenType.EOF, "", line))
    return tokens
