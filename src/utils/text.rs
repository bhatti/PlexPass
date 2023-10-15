use std::collections::HashSet;

fn term_frequency(s: &str) -> Vec<f64> {
    let mut tf = vec![0f64; 256]; // assuming ASCII; adjust if considering extended character sets
    for c in s.chars() {
        let idx = c as usize;
        tf[idx] += 1.0;
    }
    tf
}

// Edit Distance (Levenshtein Distance): Measures the minimum number of single-character edits
// (i.e., insertions, deletions, or substitutions) to change one word into the other.
fn levenshtein_distance(pass1: &str, pass2: &str) -> usize {
    strsim::levenshtein(pass1, pass2)
}

// Jaccard similarity measures the similarity between two sets.
// The Jaccard similarity between two sets is the size of the intersection divided by the size
// of the union.
fn jaccard_similarity(s1: &str, s2: &str) -> f64 {
    let set1: HashSet<_> = s1.chars().collect();
    let set2: HashSet<_> = s2.chars().collect();

    let intersection = set1.intersection(&set2).count() as f64;
    let union = set1.union(&set2).count() as f64;

    intersection / union
}

// Cosine Similarity: Represent passwords as vectors (e.g., using TF-IDF), then compute the
// cosine of the angle between them. For Cosine similarity, let's assume we're treating each
// string as a "document" and each character in the string as a "term" in that document.
fn cosine_similarity(s1: &str, s2: &str) -> f64 {
    let tf1 = term_frequency(s1);
    let tf2 = term_frequency(s2);

    let dot_product = tf1
        .iter()
        .zip(tf2.iter())
        .map(|(&a, &b)| a * b)
        .sum::<f64>();
    let magnitude1 = (tf1.iter().map(|&n| n * n).sum::<f64>()).sqrt();
    let magnitude2 = (tf2.iter().map(|&n| n * n).sum::<f64>()).sqrt();

    dot_product / (magnitude1 * magnitude2)
}

fn find_similar_strings<'a>(
    target: &'a str,
    candidates: &'a [&'a str],
    threshold: f64,
) -> Vec<&'a str> {
    candidates
        .iter()
        .filter(|&&candidate| {
            let similarity = strsim::jaro_winkler(target, candidate);
            similarity > threshold
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::utils::text::{
        cosine_similarity, find_similar_strings, jaccard_similarity, levenshtein_distance,
    };

    #[test]
    fn test_should_compute_levenshtein_distance() {
        let password1 = "password123";
        let password2 = "password154"; // Only two character different
        let distance = levenshtein_distance(password1, password2);
        assert_eq!(2, distance);
    }

    #[test]
    fn test_should_compute_jaccard_similarity() {
        let password1 = "password123";
        let password2 = "password154"; // Only two character different

        let distance = jaccard_similarity(password1, password2);
        assert!(distance > 0.6);
    }

    #[test]
    fn test_should_compute_cosine_similarity() {
        let password1 = "password123";
        let password2 = "password154"; // Only two character different

        let distance = cosine_similarity(password1, password2);
        assert!(distance > 0.8);
    }

    #[test]
    fn test_should_find_similar_strings() {
        let target = "apple";
        let candidates = ["apl", "aple", "applepie", "banana", "apple"];
        let similar_strings = find_similar_strings(target, &candidates, 0.9);
        assert_eq!(3, similar_strings.len()); //  ["aple", "applepie", "apple"]
    }
}
