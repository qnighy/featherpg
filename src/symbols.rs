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
        Symbol::KEYWORD__EMPTY_STRING
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

macro_rules! build_keywords {
    ($($key:expr => ($value:expr, $kwd_const:ident),)*) => {
        static KEYWORDS: [Option<&'static str>; ID_MAX] = {
            let mut keywords: [Option<&'static str>; ID_MAX] = [None; ID_MAX];
            $(
                keywords[$value] = Some($key);
            )*
            keywords
        };

        static KEYWORD_MAP: phf::Map<&'static str, usize> = phf_map! {
            $($key => $value,)*
        };

        impl Symbol {
            $(
                #[allow(non_upper_case_globals)]
                pub const $kwd_const: Symbol = Symbol::from_keyword_id($value);
            )*
        }
    };
}

build_keywords!(
    "" => (0, KEYWORD__EMPTY_STRING),
    "abort" => (1, KEYWORD_abort),
    "absent" => (2, KEYWORD_absent),
    "absolute" => (3, KEYWORD_absolute),
    "access" => (4, KEYWORD_access),
    "action" => (5, KEYWORD_action),
    "add" => (6, KEYWORD_add),
    "admin" => (7, KEYWORD_admin),
    "after" => (8, KEYWORD_after),
    "aggregate" => (9, KEYWORD_aggregate),
    "all" => (10, KEYWORD_all),
    "also" => (11, KEYWORD_also),
    "alter" => (12, KEYWORD_alter),
    "always" => (13, KEYWORD_always),
    "analyse" => (14, KEYWORD_analyse),
    "analyze" => (15, KEYWORD_analyze),
    "and" => (16, KEYWORD_and),
    "any" => (17, KEYWORD_any),
    "array" => (18, KEYWORD_array),
    "as" => (19, KEYWORD_as),
    "asc" => (20, KEYWORD_asc),
    "asensitive" => (21, KEYWORD_asensitive),
    "assertion" => (22, KEYWORD_assertion),
    "assignment" => (23, KEYWORD_assignment),
    "asymmetric" => (24, KEYWORD_asymmetric),
    "at" => (25, KEYWORD_at),
    "atomic" => (26, KEYWORD_atomic),
    "attach" => (27, KEYWORD_attach),
    "attribute" => (28, KEYWORD_attribute),
    "authorization" => (29, KEYWORD_authorization),
    "backward" => (30, KEYWORD_backward),
    "before" => (31, KEYWORD_before),
    "begin" => (32, KEYWORD_begin),
    "between" => (33, KEYWORD_between),
    "bigint" => (34, KEYWORD_bigint),
    "binary" => (35, KEYWORD_binary),
    "bit" => (36, KEYWORD_bit),
    "boolean" => (37, KEYWORD_boolean),
    "both" => (38, KEYWORD_both),
    "breadth" => (39, KEYWORD_breadth),
    "by" => (40, KEYWORD_by),
    "cache" => (41, KEYWORD_cache),
    "call" => (42, KEYWORD_call),
    "called" => (43, KEYWORD_called),
    "cascade" => (44, KEYWORD_cascade),
    "cascaded" => (45, KEYWORD_cascaded),
    "case" => (46, KEYWORD_case),
    "cast" => (47, KEYWORD_cast),
    "catalog" => (48, KEYWORD_catalog),
    "chain" => (49, KEYWORD_chain),
    "char" => (50, KEYWORD_char),
    "character" => (51, KEYWORD_character),
    "characteristics" => (52, KEYWORD_characteristics),
    "check" => (53, KEYWORD_check),
    "checkpoint" => (54, KEYWORD_checkpoint),
    "class" => (55, KEYWORD_class),
    "close" => (56, KEYWORD_close),
    "cluster" => (57, KEYWORD_cluster),
    "coalesce" => (58, KEYWORD_coalesce),
    "collate" => (59, KEYWORD_collate),
    "collation" => (60, KEYWORD_collation),
    "column" => (61, KEYWORD_column),
    "columns" => (62, KEYWORD_columns),
    "comment" => (63, KEYWORD_comment),
    "comments" => (64, KEYWORD_comments),
    "commit" => (65, KEYWORD_commit),
    "committed" => (66, KEYWORD_committed),
    "compression" => (67, KEYWORD_compression),
    "concurrently" => (68, KEYWORD_concurrently),
    "conditional" => (69, KEYWORD_conditional),
    "configuration" => (70, KEYWORD_configuration),
    "conflict" => (71, KEYWORD_conflict),
    "connection" => (72, KEYWORD_connection),
    "constraint" => (73, KEYWORD_constraint),
    "constraints" => (74, KEYWORD_constraints),
    "content" => (75, KEYWORD_content),
    "continue" => (76, KEYWORD_continue),
    "conversion" => (77, KEYWORD_conversion),
    "copy" => (78, KEYWORD_copy),
    "cost" => (79, KEYWORD_cost),
    "create" => (80, KEYWORD_create),
    "cross" => (81, KEYWORD_cross),
    "csv" => (82, KEYWORD_csv),
    "cube" => (83, KEYWORD_cube),
    "current" => (84, KEYWORD_current),
    "current_catalog" => (85, KEYWORD_current_catalog),
    "current_date" => (86, KEYWORD_current_date),
    "current_role" => (87, KEYWORD_current_role),
    "current_schema" => (88, KEYWORD_current_schema),
    "current_time" => (89, KEYWORD_current_time),
    "current_timestamp" => (90, KEYWORD_current_timestamp),
    "current_user" => (91, KEYWORD_current_user),
    "cursor" => (92, KEYWORD_cursor),
    "cycle" => (93, KEYWORD_cycle),
    "data" => (94, KEYWORD_data),
    "database" => (95, KEYWORD_database),
    "day" => (96, KEYWORD_day),
    "deallocate" => (97, KEYWORD_deallocate),
    "dec" => (98, KEYWORD_dec),
    "decimal" => (99, KEYWORD_decimal),
    "declare" => (100, KEYWORD_declare),
    "default" => (101, KEYWORD_default),
    "defaults" => (102, KEYWORD_defaults),
    "deferrable" => (103, KEYWORD_deferrable),
    "deferred" => (104, KEYWORD_deferred),
    "definer" => (105, KEYWORD_definer),
    "delete" => (106, KEYWORD_delete),
    "delimiter" => (107, KEYWORD_delimiter),
    "delimiters" => (108, KEYWORD_delimiters),
    "depends" => (109, KEYWORD_depends),
    "depth" => (110, KEYWORD_depth),
    "desc" => (111, KEYWORD_desc),
    "detach" => (112, KEYWORD_detach),
    "dictionary" => (113, KEYWORD_dictionary),
    "disable" => (114, KEYWORD_disable),
    "discard" => (115, KEYWORD_discard),
    "distinct" => (116, KEYWORD_distinct),
    "do" => (117, KEYWORD_do),
    "document" => (118, KEYWORD_document),
    "domain" => (119, KEYWORD_domain),
    "double" => (120, KEYWORD_double),
    "drop" => (121, KEYWORD_drop),
    "each" => (122, KEYWORD_each),
    "else" => (123, KEYWORD_else),
    "empty" => (124, KEYWORD_empty),
    "enable" => (125, KEYWORD_enable),
    "encoding" => (126, KEYWORD_encoding),
    "encrypted" => (127, KEYWORD_encrypted),
    "end" => (128, KEYWORD_end),
    "enforced" => (129, KEYWORD_enforced),
    "enum" => (130, KEYWORD_enum),
    "error" => (131, KEYWORD_error),
    "escape" => (132, KEYWORD_escape),
    "event" => (133, KEYWORD_event),
    "except" => (134, KEYWORD_except),
    "exclude" => (135, KEYWORD_exclude),
    "excluding" => (136, KEYWORD_excluding),
    "exclusive" => (137, KEYWORD_exclusive),
    "execute" => (138, KEYWORD_execute),
    "exists" => (139, KEYWORD_exists),
    "explain" => (140, KEYWORD_explain),
    "expression" => (141, KEYWORD_expression),
    "extension" => (142, KEYWORD_extension),
    "external" => (143, KEYWORD_external),
    "extract" => (144, KEYWORD_extract),
    "false" => (145, KEYWORD_false),
    "family" => (146, KEYWORD_family),
    "fetch" => (147, KEYWORD_fetch),
    "filter" => (148, KEYWORD_filter),
    "finalize" => (149, KEYWORD_finalize),
    "first" => (150, KEYWORD_first),
    "float" => (151, KEYWORD_float),
    "following" => (152, KEYWORD_following),
    "for" => (153, KEYWORD_for),
    "force" => (154, KEYWORD_force),
    "foreign" => (155, KEYWORD_foreign),
    "format" => (156, KEYWORD_format),
    "forward" => (157, KEYWORD_forward),
    "freeze" => (158, KEYWORD_freeze),
    "from" => (159, KEYWORD_from),
    "full" => (160, KEYWORD_full),
    "function" => (161, KEYWORD_function),
    "functions" => (162, KEYWORD_functions),
    "generated" => (163, KEYWORD_generated),
    "global" => (164, KEYWORD_global),
    "grant" => (165, KEYWORD_grant),
    "granted" => (166, KEYWORD_granted),
    "greatest" => (167, KEYWORD_greatest),
    "group" => (168, KEYWORD_group),
    "grouping" => (169, KEYWORD_grouping),
    "groups" => (170, KEYWORD_groups),
    "handler" => (171, KEYWORD_handler),
    "having" => (172, KEYWORD_having),
    "header" => (173, KEYWORD_header),
    "hold" => (174, KEYWORD_hold),
    "hour" => (175, KEYWORD_hour),
    "identity" => (176, KEYWORD_identity),
    "if" => (177, KEYWORD_if),
    "ignore" => (178, KEYWORD_ignore),
    "ilike" => (179, KEYWORD_ilike),
    "immediate" => (180, KEYWORD_immediate),
    "immutable" => (181, KEYWORD_immutable),
    "implicit" => (182, KEYWORD_implicit),
    "import" => (183, KEYWORD_import),
    "in" => (184, KEYWORD_in),
    "include" => (185, KEYWORD_include),
    "including" => (186, KEYWORD_including),
    "increment" => (187, KEYWORD_increment),
    "indent" => (188, KEYWORD_indent),
    "index" => (189, KEYWORD_index),
    "indexes" => (190, KEYWORD_indexes),
    "inherit" => (191, KEYWORD_inherit),
    "inherits" => (192, KEYWORD_inherits),
    "initially" => (193, KEYWORD_initially),
    "inline" => (194, KEYWORD_inline),
    "inner" => (195, KEYWORD_inner),
    "inout" => (196, KEYWORD_inout),
    "input" => (197, KEYWORD_input),
    "insensitive" => (198, KEYWORD_insensitive),
    "insert" => (199, KEYWORD_insert),
    "instead" => (200, KEYWORD_instead),
    "int" => (201, KEYWORD_int),
    "integer" => (202, KEYWORD_integer),
    "intersect" => (203, KEYWORD_intersect),
    "interval" => (204, KEYWORD_interval),
    "into" => (205, KEYWORD_into),
    "invoker" => (206, KEYWORD_invoker),
    "is" => (207, KEYWORD_is),
    "isnull" => (208, KEYWORD_isnull),
    "isolation" => (209, KEYWORD_isolation),
    "join" => (210, KEYWORD_join),
    "json" => (211, KEYWORD_json),
    "json_array" => (212, KEYWORD_json_array),
    "json_arrayagg" => (213, KEYWORD_json_arrayagg),
    "json_exists" => (214, KEYWORD_json_exists),
    "json_object" => (215, KEYWORD_json_object),
    "json_objectagg" => (216, KEYWORD_json_objectagg),
    "json_query" => (217, KEYWORD_json_query),
    "json_scalar" => (218, KEYWORD_json_scalar),
    "json_serialize" => (219, KEYWORD_json_serialize),
    "json_table" => (220, KEYWORD_json_table),
    "json_value" => (221, KEYWORD_json_value),
    "keep" => (222, KEYWORD_keep),
    "key" => (223, KEYWORD_key),
    "keys" => (224, KEYWORD_keys),
    "label" => (225, KEYWORD_label),
    "language" => (226, KEYWORD_language),
    "large" => (227, KEYWORD_large),
    "last" => (228, KEYWORD_last),
    "lateral" => (229, KEYWORD_lateral),
    "leading" => (230, KEYWORD_leading),
    "leakproof" => (231, KEYWORD_leakproof),
    "least" => (232, KEYWORD_least),
    "left" => (233, KEYWORD_left),
    "level" => (234, KEYWORD_level),
    "like" => (235, KEYWORD_like),
    "limit" => (236, KEYWORD_limit),
    "listen" => (237, KEYWORD_listen),
    "load" => (238, KEYWORD_load),
    "local" => (239, KEYWORD_local),
    "localtime" => (240, KEYWORD_localtime),
    "localtimestamp" => (241, KEYWORD_localtimestamp),
    "location" => (242, KEYWORD_location),
    "lock" => (243, KEYWORD_lock),
    "locked" => (244, KEYWORD_locked),
    "logged" => (245, KEYWORD_logged),
    "lsn" => (246, KEYWORD_lsn),
    "mapping" => (247, KEYWORD_mapping),
    "match" => (248, KEYWORD_match),
    "matched" => (249, KEYWORD_matched),
    "materialized" => (250, KEYWORD_materialized),
    "maxvalue" => (251, KEYWORD_maxvalue),
    "merge" => (252, KEYWORD_merge),
    "merge_action" => (253, KEYWORD_merge_action),
    "method" => (254, KEYWORD_method),
    "minute" => (255, KEYWORD_minute),
    "minvalue" => (256, KEYWORD_minvalue),
    "mode" => (257, KEYWORD_mode),
    "month" => (258, KEYWORD_month),
    "move" => (259, KEYWORD_move),
    "name" => (260, KEYWORD_name),
    "names" => (261, KEYWORD_names),
    "national" => (262, KEYWORD_national),
    "natural" => (263, KEYWORD_natural),
    "nchar" => (264, KEYWORD_nchar),
    "nested" => (265, KEYWORD_nested),
    "new" => (266, KEYWORD_new),
    "next" => (267, KEYWORD_next),
    "nfc" => (268, KEYWORD_nfc),
    "nfd" => (269, KEYWORD_nfd),
    "nfkc" => (270, KEYWORD_nfkc),
    "nfkd" => (271, KEYWORD_nfkd),
    "no" => (272, KEYWORD_no),
    "none" => (273, KEYWORD_none),
    "normalize" => (274, KEYWORD_normalize),
    "normalized" => (275, KEYWORD_normalized),
    "not" => (276, KEYWORD_not),
    "nothing" => (277, KEYWORD_nothing),
    "notify" => (278, KEYWORD_notify),
    "notnull" => (279, KEYWORD_notnull),
    "nowait" => (280, KEYWORD_nowait),
    "null" => (281, KEYWORD_null),
    "nullif" => (282, KEYWORD_nullif),
    "nulls" => (283, KEYWORD_nulls),
    "numeric" => (284, KEYWORD_numeric),
    "object" => (285, KEYWORD_object),
    "objects" => (286, KEYWORD_objects),
    "of" => (287, KEYWORD_of),
    "off" => (288, KEYWORD_off),
    "offset" => (289, KEYWORD_offset),
    "oids" => (290, KEYWORD_oids),
    "old" => (291, KEYWORD_old),
    "omit" => (292, KEYWORD_omit),
    "on" => (293, KEYWORD_on),
    "only" => (294, KEYWORD_only),
    "operator" => (295, KEYWORD_operator),
    "option" => (296, KEYWORD_option),
    "options" => (297, KEYWORD_options),
    "or" => (298, KEYWORD_or),
    "order" => (299, KEYWORD_order),
    "ordinality" => (300, KEYWORD_ordinality),
    "others" => (301, KEYWORD_others),
    "out" => (302, KEYWORD_out),
    "outer" => (303, KEYWORD_outer),
    "over" => (304, KEYWORD_over),
    "overlaps" => (305, KEYWORD_overlaps),
    "overlay" => (306, KEYWORD_overlay),
    "overriding" => (307, KEYWORD_overriding),
    "owned" => (308, KEYWORD_owned),
    "owner" => (309, KEYWORD_owner),
    "parallel" => (310, KEYWORD_parallel),
    "parameter" => (311, KEYWORD_parameter),
    "parser" => (312, KEYWORD_parser),
    "partial" => (313, KEYWORD_partial),
    "partition" => (314, KEYWORD_partition),
    "partitions" => (315, KEYWORD_partitions),
    "passing" => (316, KEYWORD_passing),
    "password" => (317, KEYWORD_password),
    "path" => (318, KEYWORD_path),
    "period" => (319, KEYWORD_period),
    "placing" => (320, KEYWORD_placing),
    "plan" => (321, KEYWORD_plan),
    "plans" => (322, KEYWORD_plans),
    "policy" => (323, KEYWORD_policy),
    "position" => (324, KEYWORD_position),
    "preceding" => (325, KEYWORD_preceding),
    "precision" => (326, KEYWORD_precision),
    "prepare" => (327, KEYWORD_prepare),
    "prepared" => (328, KEYWORD_prepared),
    "preserve" => (329, KEYWORD_preserve),
    "primary" => (330, KEYWORD_primary),
    "prior" => (331, KEYWORD_prior),
    "privileges" => (332, KEYWORD_privileges),
    "procedural" => (333, KEYWORD_procedural),
    "procedure" => (334, KEYWORD_procedure),
    "procedures" => (335, KEYWORD_procedures),
    "program" => (336, KEYWORD_program),
    "publication" => (337, KEYWORD_publication),
    "quote" => (338, KEYWORD_quote),
    "quotes" => (339, KEYWORD_quotes),
    "range" => (340, KEYWORD_range),
    "read" => (341, KEYWORD_read),
    "real" => (342, KEYWORD_real),
    "reassign" => (343, KEYWORD_reassign),
    "recursive" => (344, KEYWORD_recursive),
    "ref" => (345, KEYWORD_ref),
    "references" => (346, KEYWORD_references),
    "referencing" => (347, KEYWORD_referencing),
    "refresh" => (348, KEYWORD_refresh),
    "reindex" => (349, KEYWORD_reindex),
    "relative" => (350, KEYWORD_relative),
    "release" => (351, KEYWORD_release),
    "rename" => (352, KEYWORD_rename),
    "repeatable" => (353, KEYWORD_repeatable),
    "replace" => (354, KEYWORD_replace),
    "replica" => (355, KEYWORD_replica),
    "reset" => (356, KEYWORD_reset),
    "respect" => (357, KEYWORD_respect),
    "restart" => (358, KEYWORD_restart),
    "restrict" => (359, KEYWORD_restrict),
    "return" => (360, KEYWORD_return),
    "returning" => (361, KEYWORD_returning),
    "returns" => (362, KEYWORD_returns),
    "revoke" => (363, KEYWORD_revoke),
    "right" => (364, KEYWORD_right),
    "role" => (365, KEYWORD_role),
    "rollback" => (366, KEYWORD_rollback),
    "rollup" => (367, KEYWORD_rollup),
    "routine" => (368, KEYWORD_routine),
    "routines" => (369, KEYWORD_routines),
    "row" => (370, KEYWORD_row),
    "rows" => (371, KEYWORD_rows),
    "rule" => (372, KEYWORD_rule),
    "savepoint" => (373, KEYWORD_savepoint),
    "scalar" => (374, KEYWORD_scalar),
    "schema" => (375, KEYWORD_schema),
    "schemas" => (376, KEYWORD_schemas),
    "scroll" => (377, KEYWORD_scroll),
    "search" => (378, KEYWORD_search),
    "second" => (379, KEYWORD_second),
    "security" => (380, KEYWORD_security),
    "select" => (381, KEYWORD_select),
    "sequence" => (382, KEYWORD_sequence),
    "sequences" => (383, KEYWORD_sequences),
    "serializable" => (384, KEYWORD_serializable),
    "server" => (385, KEYWORD_server),
    "session" => (386, KEYWORD_session),
    "session_user" => (387, KEYWORD_session_user),
    "set" => (388, KEYWORD_set),
    "setof" => (389, KEYWORD_setof),
    "sets" => (390, KEYWORD_sets),
    "share" => (391, KEYWORD_share),
    "show" => (392, KEYWORD_show),
    "similar" => (393, KEYWORD_similar),
    "simple" => (394, KEYWORD_simple),
    "skip" => (395, KEYWORD_skip),
    "smallint" => (396, KEYWORD_smallint),
    "snapshot" => (397, KEYWORD_snapshot),
    "some" => (398, KEYWORD_some),
    "source" => (399, KEYWORD_source),
    "split" => (400, KEYWORD_split),
    "sql" => (401, KEYWORD_sql),
    "stable" => (402, KEYWORD_stable),
    "standalone" => (403, KEYWORD_standalone),
    "start" => (404, KEYWORD_start),
    "statement" => (405, KEYWORD_statement),
    "statistics" => (406, KEYWORD_statistics),
    "stdin" => (407, KEYWORD_stdin),
    "stdout" => (408, KEYWORD_stdout),
    "storage" => (409, KEYWORD_storage),
    "stored" => (410, KEYWORD_stored),
    "strict" => (411, KEYWORD_strict),
    "string" => (412, KEYWORD_string),
    "strip" => (413, KEYWORD_strip),
    "subscription" => (414, KEYWORD_subscription),
    "substring" => (415, KEYWORD_substring),
    "support" => (416, KEYWORD_support),
    "symmetric" => (417, KEYWORD_symmetric),
    "sysid" => (418, KEYWORD_sysid),
    "system" => (419, KEYWORD_system),
    "system_user" => (420, KEYWORD_system_user),
    "table" => (421, KEYWORD_table),
    "tables" => (422, KEYWORD_tables),
    "tablesample" => (423, KEYWORD_tablesample),
    "tablespace" => (424, KEYWORD_tablespace),
    "target" => (425, KEYWORD_target),
    "temp" => (426, KEYWORD_temp),
    "template" => (427, KEYWORD_template),
    "temporary" => (428, KEYWORD_temporary),
    "text" => (429, KEYWORD_text),
    "then" => (430, KEYWORD_then),
    "ties" => (431, KEYWORD_ties),
    "time" => (432, KEYWORD_time),
    "timestamp" => (433, KEYWORD_timestamp),
    "to" => (434, KEYWORD_to),
    "trailing" => (435, KEYWORD_trailing),
    "transaction" => (436, KEYWORD_transaction),
    "transform" => (437, KEYWORD_transform),
    "treat" => (438, KEYWORD_treat),
    "trigger" => (439, KEYWORD_trigger),
    "trim" => (440, KEYWORD_trim),
    "true" => (441, KEYWORD_true),
    "truncate" => (442, KEYWORD_truncate),
    "trusted" => (443, KEYWORD_trusted),
    "type" => (444, KEYWORD_type),
    "types" => (445, KEYWORD_types),
    "uescape" => (446, KEYWORD_uescape),
    "unbounded" => (447, KEYWORD_unbounded),
    "uncommitted" => (448, KEYWORD_uncommitted),
    "unconditional" => (449, KEYWORD_unconditional),
    "unencrypted" => (450, KEYWORD_unencrypted),
    "union" => (451, KEYWORD_union),
    "unique" => (452, KEYWORD_unique),
    "unknown" => (453, KEYWORD_unknown),
    "unlisten" => (454, KEYWORD_unlisten),
    "unlogged" => (455, KEYWORD_unlogged),
    "until" => (456, KEYWORD_until),
    "update" => (457, KEYWORD_update),
    "user" => (458, KEYWORD_user),
    "using" => (459, KEYWORD_using),
    "vacuum" => (460, KEYWORD_vacuum),
    "valid" => (461, KEYWORD_valid),
    "validate" => (462, KEYWORD_validate),
    "validator" => (463, KEYWORD_validator),
    "value" => (464, KEYWORD_value),
    "values" => (465, KEYWORD_values),
    "varchar" => (466, KEYWORD_varchar),
    "variadic" => (467, KEYWORD_variadic),
    "varying" => (468, KEYWORD_varying),
    "verbose" => (469, KEYWORD_verbose),
    "version" => (470, KEYWORD_version),
    "view" => (471, KEYWORD_view),
    "views" => (472, KEYWORD_views),
    "virtual" => (473, KEYWORD_virtual),
    "volatile" => (474, KEYWORD_volatile),
    "wait" => (475, KEYWORD_wait),
    "when" => (476, KEYWORD_when),
    "where" => (477, KEYWORD_where),
    "whitespace" => (478, KEYWORD_whitespace),
    "window" => (479, KEYWORD_window),
    "with" => (480, KEYWORD_with),
    "within" => (481, KEYWORD_within),
    "without" => (482, KEYWORD_without),
    "work" => (483, KEYWORD_work),
    "wrapper" => (484, KEYWORD_wrapper),
    "write" => (485, KEYWORD_write),
    "xml" => (486, KEYWORD_xml),
    "xmlattributes" => (487, KEYWORD_xmlattributes),
    "xmlconcat" => (488, KEYWORD_xmlconcat),
    "xmlelement" => (489, KEYWORD_xmlelement),
    "xmlexists" => (490, KEYWORD_xmlexists),
    "xmlforest" => (491, KEYWORD_xmlforest),
    "xmlnamespaces" => (492, KEYWORD_xmlnamespaces),
    "xmlparse" => (493, KEYWORD_xmlparse),
    "xmlpi" => (494, KEYWORD_xmlpi),
    "xmlroot" => (495, KEYWORD_xmlroot),
    "xmlserialize" => (496, KEYWORD_xmlserialize),
    "xmltable" => (497, KEYWORD_xmltable),
    "year" => (498, KEYWORD_year),
    "yes" => (499, KEYWORD_yes),
    "zone" => (500, KEYWORD_zone),
);

#[allow(non_upper_case_globals)]
const ID_MAX: usize = 501;

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
