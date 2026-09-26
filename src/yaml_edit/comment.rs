pub fn remove_exact_comments(original: &str, text: &str) -> Result<(String, usize), String> {
    if text.contains(['\n', '\r']) {
        return Err("comment text cannot contain a newline".to_string());
    }
    let lines: Vec<&str> = original.lines().collect();
    let mut kept: Vec<(usize, &str)> = Vec::new();
    let mut removed = 0;
    for (index, line) in lines.iter().enumerate() {
        let candidate = line
            .trim_start_matches(' ')
            .strip_prefix('#')
            .map(|value| value.trim_start_matches(' '));
        if candidate == Some(text) {
            removed += 1;
        } else {
            kept.push((index, line));
        }
    }
    if removed == 0 {
        return Err("no exact comment matched".to_string());
    }
    let mut out = Vec::new();
    let mut previous_kept = None;
    for (index, line) in kept {
        let created_blank_pair = line.trim().is_empty()
            && out.last().is_some_and(|last: &&str| last.trim().is_empty())
            && previous_kept.is_some_and(|previous| index > previous + 1);
        if !created_blank_pair {
            out.push(line);
        }
        previous_kept = Some(index);
    }
    Ok((out.join("\n"), removed))
}

#[cfg(test)]
mod tests {
    use super::remove_exact_comments;

    #[test]
    fn exact_comments_match_at_any_indent_only() {
        let raw = "# Retired term\nvalue: 'Retired term'\n  # Retired term\n# Retired terms\nkey: 1 # Retired term\n";
        let (out, count) = remove_exact_comments(raw, "Retired term").expect("remove");
        assert_eq!(count, 2);
        assert!(out.contains("value: 'Retired term'"));
        assert!(out.contains("# Retired terms"));
        assert!(out.contains("key: 1 # Retired term"));
    }

    #[test]
    fn alignment_spaces_after_hash_are_comment_indentation() {
        let raw = "#   safety: retired\nvalue: 1\n";
        let (out, count) = remove_exact_comments(raw, "safety: retired").expect("remove");
        assert_eq!(count, 1);
        assert_eq!(out, "value: 1");
    }

    #[test]
    fn missing_comment_fails() {
        assert!(remove_exact_comments("# similar\n", "missing").is_err());
    }

    #[test]
    fn removal_normalizes_only_newly_adjacent_blanks() {
        let raw = "a: 1\n\n# remove\n\nb: 2\n\n\nc: 3\n";
        let (out, _) = remove_exact_comments(raw, "remove").expect("remove");
        assert!(out.contains("a: 1\n\nb: 2"));
        assert!(out.contains("b: 2\n\n\nc: 3"));
    }
}
