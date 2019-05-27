//! Misc utils

/// Compute the length of a C string.
pub fn len_cstr(s: &[u8]) -> usize {
    s.iter().take_while(|x| **x != 0).count()
}

/// Compare two C strings.
pub fn compare_cstr(s1: &[u8], s2: &[u8]) -> isize {
    let mut s1_index = 0;
    let mut s2_index = 0;

    while s1[s1_index] != 0 && s2[s2_index] != 0 && s1[s1_index] == s2[s2_index] {
        s1_index += 1;
        s2_index += 1;
    }

    isize::from(s2[s2_index].wrapping_sub(s1[s1_index]))
}
