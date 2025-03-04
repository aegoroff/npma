use regex::Regex;

/// Filtering criteria
#[derive(Default, Debug)]
pub struct Criteria {
    include_regex: Option<Regex>,
    exclude_regex: Option<Regex>,
}

impl Criteria {
    #[must_use]
    pub fn new(include_pattern: Option<&String>, exclude_pattern: Option<&String>) -> Self {
        let include_regex = Self::create_regexp(include_pattern);
        let exclude_regex = Self::create_regexp(exclude_pattern);
        Self {
            include_regex,
            exclude_regex,
        }
    }

    #[must_use]
    pub fn allow(&self, value: &str) -> bool {
        Self::match_none_or(self.include_regex.as_ref(), |r| r.is_match(value))
            && Self::match_none_or(self.exclude_regex.as_ref(), |r| !r.is_match(value))
    }

    fn match_none_or<F: Fn(&Regex) -> bool>(regex: Option<&Regex>, some_match: F) -> bool {
        match regex {
            Some(r) => some_match(r),
            None => true,
        }
    }

    fn create_regexp(pattern: Option<&String>) -> Option<Regex> {
        if let Some(s) = pattern {
            if let Ok(r) = Regex::new(s) {
                Some(r)
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::{fixture, rstest};

    use super::*;

    #[test]
    fn empty_filter_allow_test() {
        // arrange
        let entry = "";
        let filter = Criteria::new(None, None);

        // act
        let r = filter.allow(entry);

        // assert
        assert!(r)
    }

    #[rstest]
    fn allow_entry_include_match_test(value: &str) {
        // arrange
        let filter = Criteria::new(Some(&"a".to_string()), None);

        // act
        let r = filter.allow(value);

        // assert
        assert!(r)
    }

    #[rstest]
    fn allow_entry_invalid_pattern_test(value: &str) {
        // arrange
        let filter = Criteria::new(Some(&"a[".to_string()), None);

        // act
        let r = filter.allow(value);

        // assert
        assert!(r)
    }

    #[rstest]
    fn allow_entry_include_not_match_test(value: &str) {
        // arrange
        let filter = Criteria::new(Some(&"b".to_string()), None);

        // act
        let r = filter.allow(value);

        // assert
        assert!(!r)
    }

    #[rstest]
    fn allow_entry_exclude_match_test(value: &str) {
        // arrange
        let filter = Criteria::new(None, Some(&"a".to_string()));

        // act
        let r = filter.allow(value);

        // assert
        assert!(!r)
    }

    #[rstest]
    fn allow_entry_exclude_not_match_test(value: &str) {
        // arrange
        let filter = Criteria::new(None, Some(&"b".to_string()));

        // act
        let r = filter.allow(value);

        // assert
        assert!(r)
    }

    #[rstest]
    fn allow_entry_same_pattern_for_both_that_match_request_test(value: &str) {
        // arrange
        let filter = Criteria::new(Some(&"a".to_string()), Some(&"a".to_string()));

        // act
        let r = filter.allow(value);

        // assert
        assert!(!r)
    }

    #[rstest]
    fn allow_entry_same_pattern_for_both_that_not_match_request_test(value: &str) {
        // arrange
        let filter = Criteria::new(Some(&"b".to_string()), Some(&"b".to_string()));

        // act
        let r = filter.allow(value);

        // assert
        assert!(!r)
    }

    #[rstest]
    fn allow_entry_different_patterns_for_both_that_match_only_include_test(value: &str) {
        // arrange
        let filter = Criteria::new(Some(&"a".to_string()), Some(&"b".to_string()));

        // act
        let r = filter.allow(value);

        // assert
        assert!(r)
    }

    #[rstest]
    fn allow_entry_different_patterns_for_both_that_match_only_exclude_test(value: &str) {
        // arrange
        let filter = Criteria::new(Some(&"b".to_string()), Some(&"a".to_string()));

        // act
        let r = filter.allow(value);

        // assert
        assert!(!r)
    }

    #[rstest]
    fn allow_entry_different_patterns_for_both_that_not_match_any_pattern_test(value: &str) {
        // arrange
        let filter = Criteria::new(Some(&"b".to_string()), Some(&"c".to_string()));

        // act
        let r = filter.allow(value);

        // assert
        assert!(!r)
    }

    #[fixture]
    fn value() -> &'static str {
        "a"
    }
}
