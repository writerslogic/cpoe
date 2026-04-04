

//! Dictation plausibility scoring: detect forged or implausible speech-to-text events.

use crate::evidence::DictationEvent;

/
const WPM_FAST_THRESHOLD: f64 = 200.0;

/
const WPM_SUSPICIOUS_THRESHOLD: f64 = 250.0;

/
const WPM_SLOW_THRESHOLD: f64 = 40.0;

/
const SLOW_SPEECH_MIN_WORDS: u32 = 10;

/
const MIN_DURATION_SEC: f64 = 2.0;

/
const SHORT_DURATION_WORD_LIMIT: u32 = 20;

/
const LONG_DURATION_SEC: f64 = 3600.0;

/
const PENALTY_SUSPICIOUS_WPM: f64 = 0.1;

/
const PENALTY_FAST_WPM: f64 = 0.5;

/
const PENALTY_SLOW_WPM: f64 = 0.6;

/
const PENALTY_SHORT_BURST: f64 = 0.2;

/
const PENALTY_LONG_SESSION: f64 = 0.7;

/
const PENALTY_NO_MIC: f64 = 0.3;

/
/
/
/
pub fn score_dictation_plausibility(event: &DictationEvent) -> f64 {
    let mut score = 1.0;

    
    
    
    if event.words_per_minute > WPM_SUSPICIOUS_THRESHOLD {
        score *= PENALTY_SUSPICIOUS_WPM;
    } else if event.words_per_minute > WPM_FAST_THRESHOLD {
        score *= PENALTY_FAST_WPM;
    } else if event.words_per_minute < WPM_SLOW_THRESHOLD
        && event.word_count > SLOW_SPEECH_MIN_WORDS
    {
        score *= PENALTY_SLOW_WPM;
    }

    
    let duration_sec = (event.end_ns - event.start_ns) as f64 / 1e9;
    if duration_sec < MIN_DURATION_SEC && event.word_count > SHORT_DURATION_WORD_LIMIT {
        score *= PENALTY_SHORT_BURST;
    }
    if duration_sec > LONG_DURATION_SEC {
        score *= PENALTY_LONG_SESSION;
    }

    
    if !event.mic_active {
        score *= PENALTY_NO_MIC;
    }

    score.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(word_count: u32, duration_sec: f64, mic_active: bool) -> DictationEvent {
        let wpm = if duration_sec > 0.0 {
            word_count as f64 / (duration_sec / 60.0)
        } else {
            0.0
        };
        DictationEvent {
            start_ns: 0,
            end_ns: (duration_sec * 1e9) as i64,
            word_count,
            char_count: word_count * 5,
            input_method: "com.apple.inputmethod.DictationIME".to_string(),
            mic_active,
            words_per_minute: wpm,
            plausibility_score: 0.0,
        }
    }

    #[test]
    fn normal_dictation_scores_high() {
        
        let event = make_event(60, 30.0, true);
        let score = score_dictation_plausibility(&event);
        assert!(
            score > 0.9,
            "normal dictation should score >0.9, got {score}"
        );
    }

    #[test]
    fn fast_dictation_penalized() {
        
        let event = make_event(110, 30.0, true);
        let score = score_dictation_plausibility(&event);
        assert!(
            (0.4..=0.6).contains(&score),
            "fast dictation should be penalized, got {score}"
        );
    }

    #[test]
    fn suspicious_speed_heavily_penalized() {
        
        let event = make_event(150, 30.0, true);
        let score = score_dictation_plausibility(&event);
        assert!(
            score < 0.2,
            "suspicious speed should score <0.2, got {score}"
        );
    }

    #[test]
    fn no_mic_penalized() {
        
        let event = make_event(60, 30.0, false);
        let score = score_dictation_plausibility(&event);
        assert!(score < 0.5, "no-mic should be penalized, got {score}");
    }

    #[test]
    fn short_burst_many_words_penalized() {
        
        let event = make_event(25, 1.0, true);
        let score = score_dictation_plausibility(&event);
        assert!(score < 0.3, "short burst should be penalized, got {score}");
    }

    #[test]
    fn long_session_mild_penalty() {
        
        let event = make_event(14400, 7200.0, true);
        let score = score_dictation_plausibility(&event);
        assert!(
            (0.5..=0.8).contains(&score),
            "long session should get mild penalty, got {score}"
        );
    }

    #[test]
    fn slow_speech_penalized_when_sustained() {
        
        let event = make_event(30, 60.0, true);
        let score = score_dictation_plausibility(&event);
        assert!(
            (0.5..=0.7).contains(&score),
            "slow sustained speech should be penalized, got {score}"
        );
    }

    #[test]
    fn slow_speech_not_penalized_when_few_words() {
        
        let event = make_event(5, 10.0, true);
        let score = score_dictation_plausibility(&event);
        assert!(
            score > 0.9,
            "short slow dictation should not be penalized, got {score}"
        );
    }

    #[test]
    fn combined_penalties_stack() {
        
        let event = make_event(110, 30.0, false);
        let score = score_dictation_plausibility(&event);
        assert!(score < 0.2, "combined penalties should stack, got {score}");
    }

    #[test]
    fn score_clamped_to_unit_range() {
        let event = make_event(60, 30.0, true);
        let score = score_dictation_plausibility(&event);
        assert!((0.0..=1.0).contains(&score));

        
        let event = make_event(150, 0.5, false);
        let score = score_dictation_plausibility(&event);
        assert!((0.0..=1.0).contains(&score));
    }
}
