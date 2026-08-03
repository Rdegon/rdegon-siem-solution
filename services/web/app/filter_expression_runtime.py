from __future__ import annotations

import re
from typing import Any


Token = tuple[str, str]
Expression = tuple[Any, ...]
COMPARISON_WORDS = {"contains", "icontains", "startswith", "endswith"}


def _tokenize(expression: str) -> list[Token]:
    tokens: list[Token] = []
    position = 0
    while position < len(expression):
        character = expression[position]
        if character.isspace():
            position += 1
            continue
        if expression.startswith("==", position) or expression.startswith("!=", position):
            tokens.append(("OP", expression[position : position + 2]))
            position += 2
            continue
        if character == "'":
            end = position + 1
            value: list[str] = []
            while end < len(expression) and expression[end] != "'":
                value.append(expression[end])
                end += 1
            if end >= len(expression):
                raise ValueError("Unterminated string literal in filter expression")
            tokens.append(("STRING", "".join(value)))
            position = end + 1
            continue
        if character == "(":
            tokens.append(("LPAREN", character))
            position += 1
            continue
        if character == ")":
            tokens.append(("RPAREN", character))
            position += 1
            continue
        if re.match(r"[A-Za-z0-9_]", character):
            end = position + 1
            while end < len(expression) and re.match(r"[A-Za-z0-9_.]", expression[end]):
                end += 1
            value = expression[position:end]
            token_type = {
                "and": "AND",
                "or": "OR",
                "not": "NOT",
            }.get(value, "OP" if value in COMPARISON_WORDS else "NAME")
            tokens.append((token_type, value))
            position = end
            continue
        raise ValueError(f"Unexpected character in filter expression: {character!r} at position {position}")
    return tokens


def parse_expr(expression: str) -> Expression:
    tokens = _tokenize(expression)
    if not tokens:
        raise ValueError("Empty expression")
    position = 0

    def comparison() -> Expression:
        nonlocal position
        if position + 3 > len(tokens):
            raise ValueError("Invalid comparison in expression")
        field_type, field = tokens[position]
        operator_type, operator = tokens[position + 1]
        value_type, value = tokens[position + 2]
        if field_type != "NAME":
            raise ValueError("Expected field name in comparison")
        if operator_type != "OP" or operator not in {"==", "!=", *COMPARISON_WORDS}:
            raise ValueError("Expected comparison operator in expression")
        if value_type != "STRING":
            raise ValueError("Expected string literal in comparison")
        position += 3
        return ("cmp", field, operator, value)

    def factor() -> Expression:
        nonlocal position
        if position >= len(tokens):
            raise ValueError("Unexpected end of expression")
        token_type = tokens[position][0]
        if token_type == "LPAREN":
            position += 1
            node = expression_node()
            if position >= len(tokens) or tokens[position][0] != "RPAREN":
                raise ValueError("Expected closing parenthesis")
            position += 1
            return node
        if token_type == "NOT":
            position += 1
            return ("not", factor())
        return comparison()

    def conjunction() -> Expression:
        nonlocal position
        node = factor()
        while position < len(tokens) and tokens[position][0] == "AND":
            position += 1
            node = ("and", node, factor())
        return node

    def expression_node() -> Expression:
        nonlocal position
        node = conjunction()
        while position < len(tokens) and tokens[position][0] == "OR":
            position += 1
            node = ("or", node, conjunction())
        return node

    parsed = expression_node()
    if position != len(tokens):
        raise ValueError("Unexpected tokens at end of expression")
    return parsed


def eval_expr(expression: Expression | None, event: dict[str, Any]) -> bool:
    if expression is None:
        return False
    node_type = expression[0]
    if node_type == "cmp":
        _, field, operator, expected = expression
        actual = str(event.get(field) if event.get(field) is not None else "")
        if operator == "==":
            return actual == expected
        if operator == "!=":
            return actual != expected
        if operator == "contains":
            return expected in actual
        if operator == "icontains":
            return expected.lower() in actual.lower()
        if operator == "startswith":
            return actual.startswith(expected)
        if operator == "endswith":
            return actual.endswith(expected)
        return False
    if node_type == "and":
        return eval_expr(expression[1], event) and eval_expr(expression[2], event)
    if node_type == "or":
        return eval_expr(expression[1], event) or eval_expr(expression[2], event)
    if node_type == "not":
        return not eval_expr(expression[1], event)
    raise ValueError(f"Unknown expression node type: {node_type}")
