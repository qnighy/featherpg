use crate::{
    ast::{ExprKind, ExprNode, StmtKind, StmtNode},
    diag::{CodeDiagnostics, CodeError},
    lexer::Lexer,
    token::TokenKind,
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
    let stmt = parser.parse_stmt(diags);
    parser.parse_eof(diags);
    stmt
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

    fn parse_eof(&mut self, diags: &mut CodeDiagnostics) {
        if let Some(tok) = self.lexer.next_token(diags) {
            panic!("expected EOF, found token: {:?}", tok);
        }
    }

    fn parse_stmt(&mut self, diags: &mut CodeDiagnostics) -> StmtNode {
        let tok0 = self.lexer.next_token(diags).unwrap();

        match tok0.kind {
            TokenKind::KeywordSelect => {
                let expr = self.parse_expr(diags);
                StmtNode {
                    kind: StmtKind::Select {
                        select_list: vec![expr],
                    },
                    range: tok0.range,
                }
            }
            _ => unimplemented!(),
        }
    }

    fn parse_expr(&mut self, diags: &mut CodeDiagnostics) -> ExprNode {
        let tok0 = self.lexer.next_token(diags).unwrap();

        match tok0.kind {
            TokenKind::Integer(value) => ExprNode {
                kind: ExprKind::IntegerLiteral {
                    value: value.try_into().unwrap(),
                },
                range: tok0.range,
            },
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
