use std::borrow::Cow;

/// Equivalent to [`std::str::to_ascii_lowercase`] but does not allocate if the string is already lowercase and
/// reuses the allocation if given a [`Cow::Owned`].
pub fn into_ascii_lowercase(s: Cow<'_, str>) -> Cow<'_, str> {
    match s {
        Cow::Owned(mut s) => {
            s.make_ascii_lowercase();
            Cow::Owned(s)
        }
        Cow::Borrowed(s) => to_ascii_lowercase(s),
    }
}

/// Equivalent to [`std::str::to_ascii_lowercase`] but does not allocate if the string is already lowercase.
pub fn to_ascii_lowercase(s: &'_ str) -> Cow<'_, str> {
    if let Some(first_uppercase) = s
        .bytes()
        .position(|b| b.is_ascii_alphabetic() && !b.is_ascii_lowercase())
    {
        let mut string = String::with_capacity(s.len());
        string.push_str(&s[..first_uppercase]);
        for c in s[first_uppercase..].chars() {
            string.push(c.to_ascii_lowercase())
        }
        Cow::Owned(string)
    } else {
        Cow::Borrowed(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn basic() {
        let test = "Some strIng WITH RaNdOm casing. unicode: ఈ⌛龜∰ēƉʞ‱";
        let expected = test.to_ascii_lowercase();
        let actual = to_ascii_lowercase(test);
        assert_eq!(expected.as_str(), actual.as_ref());
    }

    #[test]
    fn no_alloc_on_lowercase() {
        let test = "some lowercase string. unicode: ఈ⌛龜∰ēƉʞ‱";
        let expected = test.to_ascii_lowercase();
        let actual = to_ascii_lowercase(test);
        assert!(matches!(actual, Cow::Borrowed(_)));
        assert_eq!(expected.as_str(), actual.as_ref());
    }
}
