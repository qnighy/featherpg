// https://github.com/postgres/postgres/blob/REL_18_1/src/backend/parser/gram.y

use crate::{
    ast::{ExprKind, ExprNode, StmtKind, StmtMultiNode, StmtNode},
    diag::{CodeDiagnostic, CodeDiagnostics, CodeError},
    lexer::Lexer,
    token::{Token, TokenKind},
};

pub fn parse_stmtmulti(src: &str) -> Result<StmtMultiNode, CodeError> {
    let mut diags = CodeDiagnostics::new();
    let stmt = parse_stmtmulti_with_diags(src, &mut diags);
    diags.check_errors()?;
    Ok(stmt)
}

pub fn parse_stmtmulti_with_diags(src: &str, diags: &mut CodeDiagnostics) -> StmtMultiNode {
    let mut parser = Parser::new(src);
    parser.parse_stmtmulti_toplevel(diags)
}

pub fn parse_stmt(src: &str) -> Result<StmtNode, CodeError> {
    let mut diags = CodeDiagnostics::new();
    let stmt = parse_stmt_with_diags(src, &mut diags);
    diags.check_errors()?;
    Ok(stmt)
}

pub fn parse_stmt_with_diags(src: &str, diags: &mut CodeDiagnostics) -> StmtNode {
    let mut parser = Parser::new(src);
    parser.parse_stmt_toplevel(diags)
}

#[derive(Debug)]
struct Parser<'a> {
    lexer: Lexer<'a>,
}

impl<'a> Parser<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            lexer: Lexer::new(src),
        }
    }

    fn parse_stmtmulti_toplevel(&mut self, diags: &mut CodeDiagnostics) -> StmtMultiNode {
        let tok0 = self.lexer.next_token(diags);
        let (stmtmulti, tok1) = self.parse_stmtmulti(tok0, diags);
        if tok1.kind != TokenKind::Eof {
            // TODO: handle errors gracefully
            panic!("unexpected token after statement list: {:?}", tok1);
        }
        stmtmulti
    }

    fn parse_stmtmulti(
        &mut self,
        mut tok0: Token,
        diags: &mut CodeDiagnostics,
    ) -> (StmtMultiNode, Token) {
        let mut stmts = Vec::new();
        loop {
            let (stmt, tok1) = self.parse_stmt(tok0, diags);
            if tok1.kind == TokenKind::Semicolon {
                // TODO: record semicolon in stmt
                stmts.push(stmt);
                tok0 = self.lexer.next_token(diags);
                continue;
            } else if tok1.kind == TokenKind::Eof {
                stmts.push(stmt);
                tok0 = tok1;
                break;
            } else {
                // TODO: handle errors gracefully
                panic!("unexpected token after statement: {:?}", tok1);
            }
        }
        let stmtmulti = StmtMultiNode { stmts };
        (stmtmulti, tok0)
    }

    fn parse_stmt_toplevel(&mut self, diags: &mut CodeDiagnostics) -> StmtNode {
        let tok0 = self.lexer.next_token(diags);
        let (stmt, tok1) = self.parse_stmt(tok0, diags);
        if tok1.kind != TokenKind::Eof {
            diags.add(CodeDiagnostic::UnexpectedEof { range: tok1.range });
        }
        stmt
    }

    fn parse_stmt(&mut self, tok0: Token, diags: &mut CodeDiagnostics) -> (StmtNode, Token) {
        // TODO: incomplete list of statement syntaxes
        match tok0.kind {
            TokenKind::KeywordSelect => {
                let tok1 = self.lexer.next_token(diags);
                let (expr, tok2) = self.parse_expr(tok1, diags);
                let stmt = StmtNode {
                    kind: StmtKind::Select {
                        select_list: vec![expr],
                    },
                    range: tok0.range,
                };
                (stmt, tok2)
            }
            // TODO: handle errors gracefully
            _ => unimplemented!(),
        }
    }

    fn parse_expr(&mut self, tok0: Token, diags: &mut CodeDiagnostics) -> (ExprNode, Token) {
        // TODO: incomplete list of expression syntaxes
        match tok0.kind {
            TokenKind::Integer(value) => {
                let expr = ExprNode {
                    kind: ExprKind::IntegerLiteral {
                        value: value.try_into().unwrap(),
                    },
                    range: tok0.range,
                };
                let tok1 = self.lexer.next_token(diags);
                (expr, tok1)
            }
            // TODO: handle errors gracefully
            _ => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::pos::pos;

    use super::*;

    #[test]
    fn test_parse_stmtmulti_single() {
        let src = "select 1";
        let stmtmulti = parse_stmtmulti(src).unwrap();
        assert_eq!(
            stmtmulti,
            StmtMultiNode {
                stmts: vec![StmtNode {
                    kind: StmtKind::Select {
                        select_list: vec![ExprNode {
                            kind: ExprKind::IntegerLiteral { value: 1 },
                            range: pos(src, "1", 0),
                        }],
                    },
                    range: pos(src, "select", 0),
                }],
            }
        );
    }

    #[test]
    fn test_parse_stmtmulti_multiple() {
        let src = "select 1; select 2";
        let stmtmulti = parse_stmtmulti(src).unwrap();
        assert_eq!(
            stmtmulti,
            StmtMultiNode {
                stmts: vec![
                    StmtNode {
                        kind: StmtKind::Select {
                            select_list: vec![ExprNode {
                                kind: ExprKind::IntegerLiteral { value: 1 },
                                range: pos(src, "1", 0),
                            }],
                        },
                        range: pos(src, "select", 0),
                    },
                    StmtNode {
                        kind: StmtKind::Select {
                            select_list: vec![ExprNode {
                                kind: ExprKind::IntegerLiteral { value: 2 },
                                range: pos(src, "2", 0),
                            }],
                        },
                        range: pos(src, "select", 1),
                    },
                ],
            }
        );
    }

    #[test]
    fn test_parse_select_integer() {
        let src = "select 42";
        let stmt = parse_stmt(src).unwrap();
        assert_eq!(
            stmt,
            StmtNode {
                kind: StmtKind::Select {
                    select_list: vec![ExprNode {
                        kind: ExprKind::IntegerLiteral { value: 42 },
                        range: pos(src, "42", 0),
                    }],
                },
                range: pos(src, "select", 0),
            }
        );
    }
}
