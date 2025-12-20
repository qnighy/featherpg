#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CodeRange {
    pub start: usize,
    pub end: usize,
}

#[cfg(test)]
pub(crate) fn pos(source: &str, needle: &str, occurrence: usize) -> CodeRange {
    let mut current = 0;
    for _ in 0..occurrence {
        let Some(pos) = source[current..].find(needle) else {
            return CodeRange { start: 0, end: 0 };
        };
        current += pos + 1;
    }
    let Some(pos) = source[current..].find(needle) else {
        return CodeRange { start: 0, end: 0 };
    };
    let start = current + pos;
    CodeRange {
        start,
        end: start + needle.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pos_simple() {
        assert_eq!(pos("foo bar", "bar", 0), CodeRange { start: 4, end: 7 })
    }
}
