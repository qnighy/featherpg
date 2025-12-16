use crate::pos::CodeRange;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StmtNode {
    pub kind: StmtKind,
    pub range: CodeRange,
}

// TODO: incomplete list of statement kinds
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StmtKind {
    // TODO: incomplete select structure
    Select { select_list: Vec<ExprNode> },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExprNode {
    pub kind: ExprKind,
    pub range: CodeRange,
}

// TODO: incomplete list of expression kinds
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExprKind {
    IntegerLiteral { value: i64 },
}
