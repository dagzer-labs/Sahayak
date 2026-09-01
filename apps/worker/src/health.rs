const MAX_CONSECUTIVE_FAILURES: u8 = 3;

/// Tracks consecutive dependency failures without masking later recovery.
#[derive(Debug, Default)]
pub struct HealthFailureBudget {
    consecutive_failures: u8,
}

impl HealthFailureBudget {
    /// Records a successful probe and clears previous transient failures.
    pub const fn record_success(&mut self) {
        self.consecutive_failures = 0;
    }

    /// Records a failed probe and returns whether the process should terminate.
    pub const fn record_failure(&mut self) -> bool {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.consecutive_failures >= MAX_CONSECUTIVE_FAILURES
    }

    /// Returns the current number of consecutive failures.
    #[must_use]
    pub const fn consecutive_failures(&self) -> u8 {
        self.consecutive_failures
    }
}

#[cfg(test)]
mod tests {
    use super::HealthFailureBudget;

    #[test]
    fn terminates_after_three_consecutive_failures() {
        let mut budget = HealthFailureBudget::default();

        assert!(!budget.record_failure());
        assert!(!budget.record_failure());
        assert!(budget.record_failure());
    }

    #[test]
    fn success_resets_transient_failures() {
        let mut budget = HealthFailureBudget::default();
        assert!(!budget.record_failure());
        budget.record_success();

        assert_eq!(budget.consecutive_failures(), 0);
        assert!(!budget.record_failure());
    }
}
