

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .lexer import Token, TokenType




@dataclass
class ASTNode:

    kind: str
    line: int = 0
    children: List["ASTNode"] = field(default_factory=list)


@dataclass
class ProgramNode(ASTNode):
    kind: str = "Program"


@dataclass
class PreprocessorNode(ASTNode):
    kind: str = "Preprocessor"
    directive: str = ""


@dataclass
class FunctionDeclNode(ASTNode):
    kind: str = "FunctionDecl"
    return_type: str = ""
    name: str = ""
    params: List[str] = field(default_factory=list)
    body: List[ASTNode] = field(default_factory=list)


@dataclass
class VarDeclNode(ASTNode):
    kind: str = "VarDecl"
    var_type: str = ""
    name: str = ""
    is_pointer: bool = False
    is_array: bool = False
    array_size: str = ""
    initializer: Optional[ASTNode] = None


@dataclass
class FunctionCallNode(ASTNode):
    kind: str = "FunctionCall"
    name: str = ""
    arguments: List[ASTNode] = field(default_factory=list)


@dataclass
class AssignmentNode(ASTNode):
    kind: str = "Assignment"
    target: str = ""
    operator: str = "="
    value: Optional[ASTNode] = None


@dataclass
class IfNode(ASTNode):
    kind: str = "If"
    condition: List[Token] = field(default_factory=list)
    then_body: List[ASTNode] = field(default_factory=list)
    else_body: List[ASTNode] = field(default_factory=list)


@dataclass
class WhileNode(ASTNode):
    kind: str = "While"
    condition: List[Token] = field(default_factory=list)
    body: List[ASTNode] = field(default_factory=list)


@dataclass
class ForNode(ASTNode):
    kind: str = "For"
    init_tokens: List[Token] = field(default_factory=list)
    condition_tokens: List[Token] = field(default_factory=list)
    update_tokens: List[Token] = field(default_factory=list)
    body: List[ASTNode] = field(default_factory=list)


@dataclass
class ReturnNode(ASTNode):
    kind: str = "Return"
    value_tokens: List[Token] = field(default_factory=list)


@dataclass
class ExpressionNode(ASTNode):
    kind: str = "Expression"
    tokens: List[Token] = field(default_factory=list)




_TYPE_KEYWORDS = {
    "void", "int", "char", "float", "double", "short", "long",
    "unsigned", "signed", "struct", "union", "enum", "const",
    "static", "extern", "volatile", "register", "typedef", "auto",
}


class Parser:


    def __init__(self, tokens: List[Token]):
        self.all_tokens = tokens
        self.tokens = [t for t in tokens if t.type != TokenType.COMMENT]
        self.pos = 0
        self.errors: List[str] = []



    def _cur(self) -> Token:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return Token(TokenType.EOF, "", -1)

    def _peek(self, offset: int = 1) -> Token:
        idx = self.pos + offset
        if idx < len(self.tokens):
            return self.tokens[idx]
        return Token(TokenType.EOF, "", -1)

    def _advance(self) -> Token:
        tok = self._cur()
        self.pos += 1
        return tok

    def _expect(self, value: str) -> Token:
        tok = self._cur()
        if tok.value == value:
            return self._advance()
        self.errors.append(f"Line {tok.line}: expected '{value}', got '{tok.value}'")
        return tok

    def _match(self, value: str) -> bool:
        if self._cur().value == value:
            self._advance()
            return True
        return False

    def _at_end(self) -> bool:
        return self._cur().type == TokenType.EOF

    @staticmethod
    def _is_type(token: Token) -> bool:
        return token.type == TokenType.KEYWORD and token.value in _TYPE_KEYWORDS



    def parse(self) -> ProgramNode:
        root = ProgramNode(line=1)
        while not self._at_end():
            try:
                node = self._top_level()
                if node:
                    root.children.append(node)
            except Exception:
                self._advance()
        return root

    def _top_level(self) -> Optional[ASTNode]:
        tok = self._cur()
        if tok.type == TokenType.PREPROCESSOR:
            return PreprocessorNode(line=self._advance().line, directive=tok.value)
        if self._is_type(tok) or tok.type == TokenType.IDENTIFIER:
            return self._declaration()
        self._advance()
        return None



    def _declaration(self) -> Optional[ASTNode]:
        save = self.pos
        line = self._cur().line


        type_parts: list[str] = []
        while self._is_type(self._cur()) or (
            self._cur().type == TokenType.IDENTIFIER and not type_parts
        ):
            type_parts.append(self._advance().value)
            if self._at_end():
                break


        is_ptr = False
        while self._cur().value == "*":
            is_ptr = True
            type_parts.append("*")
            self._advance()

        if self._at_end() or not type_parts:
            return None

        if self._cur().type != TokenType.IDENTIFIER:
            self.pos = save
            return self._statement()

        name = self._advance().value
        vtype = " ".join(type_parts)

        if self._cur().value == "(":
            return self._func_decl(vtype, name, line)
        if self._cur().value == "[":
            return self._array_decl(vtype, name, is_ptr, line)
        return self._var_decl(vtype, name, is_ptr, line)

    def _func_decl(self, rtype: str, name: str, line: int) -> FunctionDeclNode:
        node = FunctionDeclNode(line=line, return_type=rtype, name=name)
        self._expect("(")
        params: list[str] = []
        depth = 1
        while depth > 0 and not self._at_end():
            if self._cur().value == "(":
                depth += 1
            elif self._cur().value == ")":
                depth -= 1
                if depth == 0:
                    break
            params.append(self._advance().value)
        self._expect(")")
        node.params = params

        if self._cur().value == "{":
            node.body = self._block()
        elif self._cur().value == ";":
            self._advance()
        return node

    def _array_decl(self, vtype: str, name: str, is_ptr: bool, line: int) -> VarDeclNode:
        self._expect("[")
        size = ""
        while self._cur().value != "]" and not self._at_end():
            size += self._advance().value
        self._expect("]")
        node = VarDeclNode(
            line=line, var_type=vtype, name=name,
            is_pointer=is_ptr, is_array=True, array_size=size,
        )
        self._skip_to(";")
        return node

    def _var_decl(self, vtype: str, name: str, is_ptr: bool, line: int) -> VarDeclNode:
        node = VarDeclNode(line=line, var_type=vtype, name=name, is_pointer=is_ptr)
        if self._cur().value == "=":
            self._advance()
            toks = self._collect_until(";", ",")
            node.initializer = ExpressionNode(line=line, tokens=toks)
        if self._cur().value == ",":
            self._advance()
        if self._cur().value == ";":
            self._advance()
        return node



    def _block(self) -> List[ASTNode]:
        stmts: list[ASTNode] = []
        self._expect("{")
        while self._cur().value != "}" and not self._at_end():
            s = self._statement()
            if s:
                stmts.append(s)
        self._expect("}")
        return stmts

    def _statement(self) -> Optional[ASTNode]:
        tok = self._cur()
        if tok.type == TokenType.EOF:
            return None
        if tok.value == "{":
            body = self._block()
            n = ASTNode(kind="Block", line=tok.line)
            n.children = body
            return n
        if tok.value == "if":
            return self._if_stmt()
        if tok.value == "while":
            return self._while_stmt()
        if tok.value == "for":
            return self._for_stmt()
        if tok.value == "return":
            return self._return_stmt()
        if self._is_type(tok):
            return self._declaration()
        if tok.type == TokenType.IDENTIFIER:
            return self._expr_stmt()
        if tok.value == "*" and self._peek().type == TokenType.IDENTIFIER:
            return self._expr_stmt()
        self._advance()
        return None

    def _if_stmt(self) -> IfNode:
        line = self._advance().line
        node = IfNode(line=line)
        if self._cur().value == "(":
            node.condition = self._paren_tokens()
        if self._cur().value == "{":
            node.then_body = self._block()
        else:
            s = self._statement()
            if s:
                node.then_body = [s]
        if self._cur().value == "else":
            self._advance()
            if self._cur().value == "{":
                node.else_body = self._block()
            else:
                s = self._statement()
                if s:
                    node.else_body = [s]
        return node

    def _while_stmt(self) -> WhileNode:
        line = self._advance().line
        node = WhileNode(line=line)
        if self._cur().value == "(":
            node.condition = self._paren_tokens()
        if self._cur().value == "{":
            node.body = self._block()
        else:
            s = self._statement()
            if s:
                node.body = [s]
        return node

    def _for_stmt(self) -> ForNode:
        line = self._advance().line
        node = ForNode(line=line)
        self._expect("(")
        while self._cur().value != ";" and not self._at_end():
            node.init_tokens.append(self._advance())
        self._expect(";")
        while self._cur().value != ";" and not self._at_end():
            node.condition_tokens.append(self._advance())
        self._expect(";")
        depth = 0
        while not self._at_end():
            if self._cur().value == "(":
                depth += 1
            elif self._cur().value == ")":
                if depth == 0:
                    break
                depth -= 1
            node.update_tokens.append(self._advance())
        self._expect(")")
        if self._cur().value == "{":
            node.body = self._block()
        else:
            s = self._statement()
            if s:
                node.body = [s]
        return node

    def _return_stmt(self) -> ReturnNode:
        line = self._advance().line
        node = ReturnNode(line=line)
        while self._cur().value != ";" and not self._at_end():
            node.value_tokens.append(self._advance())
        if self._cur().value == ";":
            self._advance()
        return node



    def _expr_stmt(self) -> Optional[ASTNode]:
        tok = self._cur()
        line = tok.line


        if tok.type == TokenType.IDENTIFIER and self._peek().value == "(":
            return self._func_call_stmt()


        if tok.type == TokenType.IDENTIFIER and self._peek().value in (
            "=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=",
        ):
            return self._assignment()


        if tok.value == "*" and self._peek().type == TokenType.IDENTIFIER:
            self._advance()
            name = self._advance().value
            if self._cur().value in ("=", "+=", "-="):
                op = self._advance().value
                vtoks = self._collect_until(";")
                if self._cur().value == ";":
                    self._advance()
                return AssignmentNode(
                    line=line, target=f"*{name}", operator=op,
                    value=ExpressionNode(line=line, tokens=vtoks),
                )
            return ExpressionNode(line=line, tokens=[Token(TokenType.OPERATOR, "*", line),
                                                      Token(TokenType.IDENTIFIER, name, line)])


        toks = self._collect_until(";", "}")
        if self._cur().value == ";":
            self._advance()
        if toks:
            return ExpressionNode(line=line, tokens=toks)
        return None

    def _func_call_stmt(self) -> FunctionCallNode:
        name_tok = self._advance()
        line = name_tok.line
        self._expect("(")
        args = self._arg_list()
        self._expect(")")
        if self._cur().value == ";":
            self._advance()
        return FunctionCallNode(line=line, name=name_tok.value, arguments=args)

    def _arg_list(self) -> List[ASTNode]:
        args: list[ASTNode] = []
        if self._cur().value == ")":
            return args
        while not self._at_end():
            arg_toks: list[Token] = []
            depth = 0
            while not self._at_end():
                if self._cur().value in ("(", "{", "["):
                    depth += 1
                elif self._cur().value in (")", "}", "]"):
                    if depth == 0:
                        break
                    depth -= 1
                elif self._cur().value == "," and depth == 0:
                    break
                arg_toks.append(self._advance())
            if arg_toks:
                args.append(ExpressionNode(line=arg_toks[0].line, tokens=arg_toks))
            if self._cur().value == ",":
                self._advance()
            else:
                break
        return args

    def _assignment(self) -> AssignmentNode:
        name = self._advance().value
        line = self._cur().line
        op = self._advance().value
        vtoks = self._collect_until(";")
        if self._cur().value == ";":
            self._advance()
        return AssignmentNode(
            line=line, target=name, operator=op,
            value=ExpressionNode(line=line, tokens=vtoks),
        )



    def _paren_tokens(self) -> List[Token]:
        toks: list[Token] = []
        self._expect("(")
        depth = 1
        while depth > 0 and not self._at_end():
            if self._cur().value == "(":
                depth += 1
            elif self._cur().value == ")":
                depth -= 1
                if depth == 0:
                    break
            toks.append(self._advance())
        self._expect(")")
        return toks

    def _collect_until(self, *stops: str) -> List[Token]:
        toks: list[Token] = []
        depth = 0
        while not self._at_end():
            if self._cur().value in ("(", "{", "["):
                depth += 1
            elif self._cur().value in (")", "}", "]"):
                if depth == 0:
                    break
                depth -= 1
            elif self._cur().value in stops and depth == 0:
                break
            toks.append(self._advance())
        return toks

    def _skip_to(self, stop: str) -> None:
        while self._cur().value != stop and not self._at_end():
            self._advance()
        if self._cur().value == stop:
            self._advance()




def parse(tokens: List[Token]) -> ProgramNode:
    p = Parser(tokens)
    return p.parse()
