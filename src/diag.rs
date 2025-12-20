use std::{error::Error, fmt};

use thiserror::Error;

use crate::pos::CodeRange;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CodeError {
    diagnostics: Vec<CodeDiagnostic>,
}

impl From<CodeDiagnostics> for CodeError {
    fn from(diags: CodeDiagnostics) -> Self {
        Self {
            diagnostics: diags.diagnostics,
        }
    }
}

impl fmt::Display for CodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.diagnostics.is_empty() {
            writeln!(f, "No errors")?;
            return Ok(());
        } else if self.diagnostics.len() == 1 {
            writeln!(f, "{}", self.diagnostics[0])?;
            return Ok(());
        }
        writeln!(f, "{} errors found:", self.diagnostics.len())?;
        for diag in &self.diagnostics {
            writeln!(f, "{}", diag)?;
        }
        Ok(())
    }
}

impl Error for CodeError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CodeDiagnostics {
    pub diagnostics: Vec<CodeDiagnostic>,
}

impl CodeDiagnostics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, diagnostic: CodeDiagnostic) {
        self.diagnostics.push(diagnostic);
    }

    pub fn has_errors(&self) -> bool {
        // TODO: distinguish warnings from errors
        !self.diagnostics.is_empty()
    }

    pub fn check_errors(self) -> Result<Self, CodeError> {
        if self.has_errors() {
            Err(CodeError::from(self))
        } else {
            Ok(self)
        }
    }
}

impl Default for CodeDiagnostics {
    fn default() -> Self {
        Self {
            diagnostics: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
pub enum CodeDiagnostic {
    #[error("unknown token")]
    UnknownToken { range: CodeRange },
    #[error("unexpected end of input")]
    UnexpectedEof { range: CodeRange },
}

impl CodeDiagnostic {
    pub fn range(&self) -> &CodeRange {
        match self {
            CodeDiagnostic::UnknownToken { range } => range,
            CodeDiagnostic::UnexpectedEof { range } => range,
        }
    }
}
