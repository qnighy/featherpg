use std::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    ops::Deref,
};

use phf::phf_map;

// TODO: represent Vec<u8> (BString) rather than String for custom encodings.
#[derive(Clone, PartialEq, Eq)]
pub struct Symbol {
    inner: SymbolCase,
}

impl Symbol {
    fn trivially_equal(&self, other: &Self) -> bool {
        match (&self.inner, &other.inner) {
            (SymbolCase::Keyword(id1), SymbolCase::Keyword(id2)) => id1 == id2,
            _ => false,
        }
    }

    fn try_from_keyword(s: &str) -> Option<Self> {
        KEYWORD_MAP.get(s).map(|&id| Symbol {
            inner: SymbolCase::Keyword(id),
        })
    }

    const fn from_keyword_id(id: usize) -> Self {
        Symbol {
            inner: SymbolCase::Keyword(id),
        }
    }
}

impl Deref for Symbol {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        match &self.inner {
            SymbolCase::Keyword(id) => KEYWORDS[*id].unwrap(),
            SymbolCase::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Debug for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <str as fmt::Debug>::fmt(&**self, f)
    }
}

impl PartialOrd for Symbol {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self.trivially_equal(other) {
            return Some(Ordering::Equal);
        }
        Some(<str as Ord>::cmp(&**self, &**other))
    }

    fn lt(&self, other: &Self) -> bool {
        if self.trivially_equal(other) {
            return false;
        }
        <str as PartialOrd>::lt(&**self, &**other)
    }

    fn le(&self, other: &Self) -> bool {
        if self.trivially_equal(other) {
            return true;
        }
        <str as PartialOrd>::le(&**self, &**other)
    }

    fn gt(&self, other: &Self) -> bool {
        if self.trivially_equal(other) {
            return false;
        }
        <str as PartialOrd>::gt(&**self, &**other)
    }

    fn ge(&self, other: &Self) -> bool {
        if self.trivially_equal(other) {
            return true;
        }
        <str as PartialOrd>::ge(&**self, &**other)
    }
}

impl Ord for Symbol {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.trivially_equal(other) {
            return Ordering::Equal;
        }
        <str as Ord>::cmp(&**self, &**other)
    }
}

impl Hash for Symbol {
    fn hash<H: Hasher>(&self, state: &mut H) {
        <str as Hash>::hash(&**self, state);
    }
}

impl Default for Symbol {
    fn default() -> Self {
        Symbol {
            inner: SymbolCase::Keyword(ID__empty_string),
        }
    }
}

impl<'a> From<&'a str> for Symbol {
    fn from(s: &str) -> Self {
        if let Some(sym) = Symbol::try_from_keyword(s) {
            sym
        } else {
            Symbol {
                inner: SymbolCase::Custom(s.to_string()),
            }
        }
    }
}

impl From<String> for Symbol {
    fn from(s: String) -> Self {
        if let Some(sym) = Symbol::try_from_keyword(&s) {
            sym
        } else {
            Symbol {
                inner: SymbolCase::Custom(s),
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
enum SymbolCase {
    Keyword(usize),
    Custom(String),
}

macro_rules! build_keyword_list {
    ($($key:expr => $value:expr,)*) => {
        static KEYWORDS: [Option<&'static str>; ID__max] = {
            let mut keywords: [Option<&'static str>; ID__max] = [None; ID__max];
            $(
                keywords[$value] = Some($key);
            )*
            keywords
        };
    };
}

macro_rules! build_keywords {
    ($($args:tt)*) => {
        build_keyword_list! {
            $($args)*
        }

        static KEYWORD_MAP: phf::Map<&'static str, usize> = phf_map! {
            $($args)*
        };
    };
}

build_keywords!(
    "" => ID__empty_string,
    "select" => ID_select,
    "from" => ID_from,
);

#[allow(non_upper_case_globals)]
const ID__empty_string: usize = 0;
#[allow(non_upper_case_globals)]
const ID_select: usize = 1;
#[allow(non_upper_case_globals)]
const ID_from: usize = 2;
#[allow(non_upper_case_globals)]
const ID__max: usize = 3;

impl Symbol {
    #[allow(non_upper_case_globals)]
    pub const KEYWORD__empty_string: Symbol = Symbol::from_keyword_id(ID__empty_string);
    #[allow(non_upper_case_globals)]
    pub const KEYWORD_select: Symbol = Symbol::from_keyword_id(ID_select);
    #[allow(non_upper_case_globals)]
    pub const KEYWORD_from: Symbol = Symbol::from_keyword_id(ID_from);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_keyword_from_str() {
        let sym = Symbol::from("select");
        assert_eq!(sym, Symbol::KEYWORD_select);
    }

    #[test]
    fn test_symbol_deref_keyword() {
        let sym = Symbol::from("select");
        assert_eq!(&*sym, "select");
    }

    #[test]
    fn test_symbol_deref_custom() {
        let sym = Symbol::from("my_custom_symbol");
        assert_eq!(&*sym, "my_custom_symbol");
    }

    #[test]
    fn test_symbol_debug_keyword() {
        let sym = Symbol::from("from");
        assert_eq!(format!("{:?}", sym), format!("{:?}", "from"));
    }

    #[test]
    fn test_symbol_debug_custom() {
        let sym = Symbol::from("custom_sym");
        assert_eq!(format!("{:?}", sym), format!("{:?}", "custom_sym"));
    }

    #[test]
    fn test_symbol_eq_eq_keyword_keyword() {
        let sym1 = Symbol::from("select");
        let sym2 = Symbol::from("select");
        assert_eq!(sym1, sym2);
    }

    #[test]
    fn test_symbol_eq_neq_keyword_keyword() {
        let sym1 = Symbol::from("select");
        let sym2 = Symbol::from("from");
        assert_ne!(sym1, sym2);
    }

    #[test]
    fn test_symbol_eq_neq_keyword_custom() {
        let sym1 = Symbol::from("select");
        let sym2 = Symbol::from("my_select");
        assert_ne!(sym1, sym2);
    }

    #[test]
    fn test_symbol_eq_eq_custom_custom() {
        let sym1 = Symbol::from("my_symbol");
        let sym2 = Symbol::from("my_symbol");
        assert_eq!(sym1, sym2);
    }

    #[test]
    fn test_symbol_eq_neq_custom_custom() {
        let sym1 = Symbol::from("my_symbol1");
        let sym2 = Symbol::from("my_symbol2");
        assert_ne!(sym1, sym2);
    }

    #[test]
    fn test_symbol_ord_eq_keyword_keyword() {
        let sym1 = Symbol::from("from");
        let sym2 = Symbol::from("from");
        assert_eq!(sym1.cmp(&sym2), Ordering::Equal);
    }

    #[test]
    fn test_symbol_ord_lt_keyword_keyword() {
        let sym1 = Symbol::from("from");
        let sym2 = Symbol::from("select");
        assert_eq!(sym1.cmp(&sym2), Ordering::Less);
    }

    #[test]
    fn test_symbol_ord_lt_keyword_custom() {
        let sym1 = Symbol::from("from");
        let sym2 = Symbol::from("my_from");
        assert_eq!(sym1.cmp(&sym2), Ordering::Less);
    }

    #[test]
    fn test_symbol_ord_gt_keyword_custom() {
        let sym1 = Symbol::from("select");
        let sym2 = Symbol::from("my_select");
        assert_eq!(sym1.cmp(&sym2), Ordering::Greater);
    }

    #[test]
    fn test_symbol_ord_eq_custom_custom() {
        let sym1 = Symbol::from("my_symbol");
        let sym2 = Symbol::from("my_symbol");
        assert_eq!(sym1.cmp(&sym2), Ordering::Equal);
    }

    #[test]
    fn test_symbol_ord_lt_custom_custom() {
        let sym1 = Symbol::from("my_symbol1");
        let sym2 = Symbol::from("my_symbol2");
        assert_eq!(sym1.cmp(&sym2), Ordering::Less);
    }

    #[test]
    fn test_symbol_hash_keyword() {
        use std::collections::hash_map::DefaultHasher;

        let sym = Symbol::from("select");
        let mut hasher = DefaultHasher::new();
        sym.hash(&mut hasher);
        let hash1 = hasher.finish();

        let mut hasher2 = DefaultHasher::new();
        "select".hash(&mut hasher2);
        let hash2 = hasher2.finish();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_symbol_hash_custom() {
        use std::collections::hash_map::DefaultHasher;

        let sym = Symbol::from("custom_sym");
        let mut hasher = DefaultHasher::new();
        sym.hash(&mut hasher);
        let hash1 = hasher.finish();

        let mut hasher2 = DefaultHasher::new();
        "custom_sym".hash(&mut hasher2);
        let hash2 = hasher2.finish();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_symbol_default() {
        let sym = Symbol::default();
        assert_eq!(&*sym, "");
    }
}
