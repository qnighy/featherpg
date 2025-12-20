use crate::{
    ast::{ExprKind, ExprNode, StmtKind, StmtNode},
    diag::{CodeDiagnostic, CodeDiagnostics, CodeError},
    lexer::Lexer,
    token::{Token, TokenKind},
};

pub fn parse(src: &str) -> Result<StmtNode, CodeError> {
    let mut diags = CodeDiagnostics::new();
    let stmt = parse_with_diags(src, &mut diags);
    diags.check_errors()?;
    Ok(stmt)
}

// TODO: error handling
// TODO: return statement list
pub fn parse_with_diags(src: &str, diags: &mut CodeDiagnostics) -> StmtNode {
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

    fn parse_stmt_toplevel(&mut self, diags: &mut CodeDiagnostics) -> StmtNode {
        let tok0 = self.lexer.next_token(diags);
        let (stmt, tok1) = self.parse_stmt(tok0, diags);
        if tok1.kind != TokenKind::Eof {
            diags.add(CodeDiagnostic::UnexpectedEof { range: tok1.range });
        }
        stmt
    }

    fn parse_stmt(&mut self, tok0: Token, diags: &mut CodeDiagnostics) -> (StmtNode, Token) {
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
    fn test_parse_select_integer() {
        let src = "select 42";
        let stmt = parse(src).unwrap();
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
