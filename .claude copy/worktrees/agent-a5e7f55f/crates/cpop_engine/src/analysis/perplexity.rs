

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerplexityModel {
    /
    pub n: usize,
    /
    pub counts: HashMap<String, HashMap<char, usize>>,
    /
    pub totals: HashMap<String, usize>,
    /
    pub sample_count: usize,
}

impl PerplexityModel {
    /
    pub fn new(n: usize) -> Self {
        Self {
            n,
            ..Default::default()
        }
    }

    /
    pub fn train(&mut self, text: &str) {
        let chars: Vec<char> = text.chars().collect();
        if chars.len() <= self.n {
            return;
        }

        let mut buf = String::with_capacity(self.n * 4);
        for i in 0..(chars.len() - self.n) {
            buf.clear();
            buf.extend(&chars[i..(i + self.n)]);
            let next_char = chars[i + self.n];

            
            if let Some(total) = self.totals.get_mut(buf.as_str()) {
                *total += 1;
                *self
                    .counts
                    .get_mut(buf.as_str())
                    .expect("counts key exists when totals key exists")
                    .entry(next_char)
                    .or_default() += 1;
            } else {
                let key = buf.clone();
                self.totals.insert(key.clone(), 1);
                let mut char_map = HashMap::new();
                char_map.insert(next_char, 1);
                self.counts.insert(key, char_map);
            }
        }
        self.sample_count += text.len();
    }

    /
    /
    pub fn compute_perplexity(&self, text: &str) -> f64 {
        if self.sample_count < 1000 {
            return 1.0;
        }

        let chars: Vec<char> = text.chars().collect();
        if chars.len() <= self.n {
            return 1.0;
        }

        let mut log_prob_sum = 0.0;
        let mut count = 0;
        let mut buf = String::with_capacity(self.n * 4);

        for i in 0..(chars.len() - self.n) {
            buf.clear();
            buf.extend(&chars[i..(i + self.n)]);
            let next_char = chars[i + self.n];

            let prob = if let Some(context_counts) = self.counts.get(buf.as_str()) {
                let char_count = *context_counts.get(&next_char).unwrap_or(&0);
                let total = *self.totals.get(buf.as_str()).unwrap_or(&1);

                
                (char_count as f64 + 0.1) / (total as f64 + 0.1 * 256.0)
            } else {
                
                0.1 / (self.sample_count as f64 + 256.0)
            };

            log_prob_sum += prob.ln();
            count += 1;
        }

        if count == 0 {
            return 1.0;
        }

        (-log_prob_sum / count as f64).exp()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_model_defaults() {
        let model = PerplexityModel::new(3);
        assert_eq!(model.n, 3);
        assert_eq!(model.sample_count, 0);
        assert!(model.counts.is_empty());
        assert!(model.totals.is_empty());
    }

    #[test]
    fn test_train_populates_ngrams() {
        let mut model = PerplexityModel::new(2);
        model.train("hello world");

        assert!(model.sample_count > 0);
        assert!(!model.counts.is_empty());
        assert!(model.counts.contains_key("he"));
        assert!(model.counts.contains_key("ll"));
    }

    #[test]
    fn test_train_short_text_noop() {
        let mut model = PerplexityModel::new(5);
        model.train("hi"); 

        assert!(model.counts.is_empty());
    }

    #[test]
    fn test_perplexity_undertrained_returns_one() {
        let mut model = PerplexityModel::new(2);
        model.train("short");

        let ppl = model.compute_perplexity("test text");
        assert!((ppl - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_perplexity_familiar_text_lower_than_random() {
        let mut model = PerplexityModel::new(2);
        let training = "the quick brown fox jumps over the lazy dog ".repeat(50);
        model.train(&training);

        let ppl_same = model.compute_perplexity("the quick brown fox jumps over the lazy dog");
        let ppl_random = model.compute_perplexity("xzqw jklm npqr stvw yzab cdef ghij");

        assert!(
            ppl_same < ppl_random,
            "Perplexity of familiar text ({ppl_same}) should be lower than random ({ppl_random})"
        );
    }

    #[test]
    fn test_perplexity_short_input_returns_one() {
        let mut model = PerplexityModel::new(3);
        let training = "the quick brown fox jumps over the lazy dog ".repeat(50);
        model.train(&training);

        let ppl = model.compute_perplexity("ab");
        assert!((ppl - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_incremental_training() {
        let mut model = PerplexityModel::new(2);
        model.train("hello ");
        let count_after_first = model.sample_count;

        model.train("world ");
        assert!(model.sample_count > count_after_first);
        assert!(model.counts.contains_key("wo"));
    }

    #[test]
    fn test_perplexity_is_positive_and_finite() {
        let mut model = PerplexityModel::new(2);
        let training = "abcdefghijklmnopqrstuvwxyz ".repeat(50);
        model.train(&training);

        let ppl = model.compute_perplexity("abcdefghij");
        assert!(ppl > 0.0, "Perplexity must be positive, got {ppl}");
        assert!(ppl.is_finite(), "Perplexity must be finite, got {ppl}");
    }
}
