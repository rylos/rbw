// How often and how recently each entry was used, to put the entries people
// actually use first. Only entry ids are stored, never names or values.
//
// Each use adds 1 to a score that halves every HALF_LIFE, so an entry used
// every day for a week beats one used fifty times last year.

const HALF_LIFE: f64 = 14.0 * 24.0 * 3600.0;

#[derive(serde::Serialize, serde::Deserialize, Default)]
pub struct Usage {
    entries: std::collections::HashMap<String, (f64, u64)>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[allow(clippy::cast_precision_loss, clippy::as_conversions)]
fn decay(score: f64, from: u64, to: u64) -> f64 {
    let age = to.saturating_sub(from) as f64;
    score * (-age * std::f64::consts::LN_2 / HALF_LIFE).exp()
}

impl Usage {
    // a missing or unreadable file only means no history yet
    pub fn load() -> Self {
        std::fs::read(crate::dirs::usage_file())
            .ok()
            .and_then(|data| serde_json::from_slice(&data).ok())
            .unwrap_or_default()
    }

    pub fn score(&self, id: &str) -> f64 {
        self.score_at(id, now())
    }

    fn score_at(&self, id: &str, at: u64) -> f64 {
        self.entries
            .get(id)
            .map_or(0.0, |&(score, last)| decay(score, last, at))
    }

    fn add_at(&mut self, id: &str, at: u64) {
        let score = self.score_at(id, at) + 1.0;
        self.entries.insert(id.to_string(), (score, at));
    }

    // best effort: losing a use to a concurrent write doesn't matter, so
    // there is no locking, but the file is replaced atomically so that
    // readers never see half of it
    pub fn record(id: &str) {
        let mut usage = Self::load();
        usage.add_at(id, now());
        // forget entries whose score has faded away
        let at = now();
        usage
            .entries
            .retain(|_, &mut (score, last)| decay(score, last, at) > 0.01);
        let file = crate::dirs::usage_file();
        let tmp = file.with_extension("tmp");
        let Ok(data) = serde_json::to_vec(&usage) else {
            return;
        };
        if std::fs::write(&tmp, data).is_ok() {
            let _ = std::fs::rename(&tmp, &file);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn recent_beats_old() {
        let mut usage = Usage::default();
        let day = 24 * 3600;
        for i in 0..50 {
            usage.add_at("old", i * 60);
        }
        for i in 0..7 {
            usage.add_at("recent", 365 * day + i * day);
        }
        let at = 365 * day + 7 * day;
        assert!(usage.score_at("recent", at) > usage.score_at("old", at));
        assert!(usage.score_at("missing", at).abs() < f64::EPSILON);
    }

    #[test]
    fn halves_after_half_life() {
        let mut usage = Usage::default();
        usage.add_at("a", 0);
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::as_conversions
        )]
        let later = HALF_LIFE as u64;
        assert!((usage.score_at("a", later) - 0.5).abs() < 1e-9);
    }
}
