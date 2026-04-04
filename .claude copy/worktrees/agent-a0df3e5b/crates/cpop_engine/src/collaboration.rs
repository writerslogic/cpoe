

//! Collaborative authorship with per-contributor independent attestations.
//!
//! Each collaborator signs their own attestation (public key + role + checkpoint ranges),
//! so verifiers can confirm participation without shared signing keys.
//!
//! # Privacy Considerations
//!
//! - Public keys may be linkable across documents
//! - Active periods reveal contributor work schedules
//! - Contribution percentages may be contentious

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollaborationMode {
    /
    Sequential,
    /
    Parallel,
    /
    Delegated,
    /
    PeerReview,
}

/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollaboratorRole {
    /
    PrimaryAuthor,
    /
    CoAuthor,
    /
    ContributingAuthor,
    /
    Editor,
    /
    Reviewer,
    /
    TechnicalContributor,
    /
    Translator,
}

/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContributionType {
    /
    OriginalContent,
    /
    Editing,
    /
    Research,
    /
    DataAnalysis,
    /
    FiguresTables,
    /
    Code,
    /
    ReviewFeedback,
    /
    Structural,
}

/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeStrategy {
    /
    SequentialAppend,
    /
    Interleaved,
    /
    ConflictResolved,
    /
    Automated,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeInterval {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionSummary {
    pub checkpoints_authored: u32,
    pub chars_added: u64,
    pub chars_deleted: u64,
    pub active_time_seconds: f64,

    /
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_contribution_pct: Option<f32>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collaborator {
    /
    pub public_key: String,
    pub role: CollaboratorRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    pub active_periods: Vec<TimeInterval>,
    /
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_ranges: Option<Vec<(u32, u32)>>,
    /
    pub attestation_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contribution_summary: Option<ContributionSummary>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionClaim {
    pub contribution_type: ContributionType,
    /
    pub contributor_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_indices: Option<Vec<u32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extent: Option<f32>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeEvent {
    pub merge_time: DateTime<Utc>,
    pub resulting_checkpoint: u32,
    pub merged_contributor_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<MergeStrategy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_note: Option<String>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeRecord {
    pub merges: Vec<MergeEvent>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_approvers_for_merge: Option<u32>,
    #[serde(default)]
    pub requires_all_signatures: bool,
    /
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationSection {
    pub mode: CollaborationMode,
    pub participants: Vec<Collaborator>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributions: Vec<ContributionClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_record: Option<MergeRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<CollaborationPolicy>,
}

impl CollaborationSection {
    /
    pub fn new(mode: CollaborationMode) -> Self {
        Self {
            mode,
            participants: Vec::new(),
            contributions: Vec::new(),
            merge_record: None,
            policy: None,
        }
    }

    /
    pub fn add_participant(mut self, collaborator: Collaborator) -> Self {
        self.participants.push(collaborator);
        self
    }

    /
    pub fn add_contribution(mut self, claim: ContributionClaim) -> Self {
        self.contributions.push(claim);
        self
    }

    /
    pub fn with_merge_record(mut self, record: MergeRecord) -> Self {
        self.merge_record = Some(record);
        self
    }

    /
    pub fn with_policy(mut self, policy: CollaborationPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /
    pub fn validate_coverage(&self, total_checkpoints: u32) -> Result<(), String> {
        let mut covered = vec![false; total_checkpoints as usize];

        for participant in &self.participants {
            if let Some(ref ranges) = participant.checkpoint_ranges {
                for (start, end) in ranges {
                    for i in *start..=*end {
                        if (i as usize) < covered.len() {
                            covered[i as usize] = true;
                        }
                    }
                }
            }
        }

        let uncovered: Vec<usize> = covered
            .iter()
            .enumerate()
            .filter(|(_, &c)| !c)
            .map(|(i, _)| i)
            .collect();

        if uncovered.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "Checkpoints not covered by any participant: {:?}",
                uncovered
            ))
        }
    }

    /
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /
    pub fn participants_by_role(&self, role: CollaboratorRole) -> Vec<&Collaborator> {
        self.participants
            .iter()
            .filter(|p| p.role == role)
            .collect()
    }
}

impl Collaborator {
    /
    pub fn new(public_key: String, role: CollaboratorRole, signature: String) -> Self {
        Self {
            public_key,
            role,
            display_name: None,
            identifier: None,
            active_periods: Vec::new(),
            checkpoint_ranges: None,
            attestation_signature: signature,
            contribution_summary: None,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /
    pub fn with_identifier(mut self, id: impl Into<String>) -> Self {
        self.identifier = Some(id.into());
        self
    }

    /
    pub fn add_active_period(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.active_periods.push(TimeInterval { start, end });
        self
    }

    /
    pub fn with_checkpoint_ranges(mut self, ranges: Vec<(u32, u32)>) -> Self {
        self.checkpoint_ranges = Some(ranges);
        self
    }

    /
    pub fn with_summary(mut self, summary: ContributionSummary) -> Self {
        self.contribution_summary = Some(summary);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collaboration_section_builder() {
        let section = CollaborationSection::new(CollaborationMode::Parallel)
            .add_participant(
                Collaborator::new(
                    "pubkey1".to_string(),
                    CollaboratorRole::PrimaryAuthor,
                    "sig1".to_string(),
                )
                .with_name("Alice")
                .with_checkpoint_ranges(vec![(0, 10)]),
            )
            .add_participant(
                Collaborator::new(
                    "pubkey2".to_string(),
                    CollaboratorRole::CoAuthor,
                    "sig2".to_string(),
                )
                .with_name("Bob")
                .with_checkpoint_ranges(vec![(11, 20)]),
            );

        assert_eq!(section.participant_count(), 2);
        assert_eq!(section.mode, CollaborationMode::Parallel);
    }

    #[test]
    fn test_coverage_validation() {
        let section = CollaborationSection::new(CollaborationMode::Sequential)
            .add_participant(
                Collaborator::new(
                    "pk1".to_string(),
                    CollaboratorRole::CoAuthor,
                    "s1".to_string(),
                )
                .with_checkpoint_ranges(vec![(0, 4)]),
            )
            .add_participant(
                Collaborator::new(
                    "pk2".to_string(),
                    CollaboratorRole::CoAuthor,
                    "s2".to_string(),
                )
                .with_checkpoint_ranges(vec![(5, 9)]),
            );

        
        assert!(section.validate_coverage(10).is_ok());

        
        assert!(section.validate_coverage(11).is_err());
    }

    #[test]
    fn test_participants_by_role() {
        let section = CollaborationSection::new(CollaborationMode::Delegated)
            .add_participant(Collaborator::new(
                "pk1".to_string(),
                CollaboratorRole::PrimaryAuthor,
                "s1".to_string(),
            ))
            .add_participant(Collaborator::new(
                "pk2".to_string(),
                CollaboratorRole::Editor,
                "s2".to_string(),
            ))
            .add_participant(Collaborator::new(
                "pk3".to_string(),
                CollaboratorRole::Editor,
                "s3".to_string(),
            ));

        let editors = section.participants_by_role(CollaboratorRole::Editor);
        assert_eq!(editors.len(), 2);
    }

    #[test]
    fn test_serialization() {
        let section = CollaborationSection::new(CollaborationMode::PeerReview).add_participant(
            Collaborator::new(
                "test_key".to_string(),
                CollaboratorRole::Reviewer,
                "test_sig".to_string(),
            ),
        );

        let json = serde_json::to_string(&section).unwrap();
        let parsed: CollaborationSection = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.mode, CollaborationMode::PeerReview);
        assert_eq!(parsed.participants.len(), 1);
    }
}
