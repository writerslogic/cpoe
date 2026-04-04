

//! Cumulative per-document statistics that persist across tracking sessions.

use crate::store::SecureStore;
use rusqlite::params;

/
pub struct DocumentStats {
    pub file_path: String,
    pub total_keystrokes: i64,
    pub total_focus_ms: i64,
    pub session_count: i64,
    pub total_duration_secs: i64,
    pub first_tracked_at: i64,
    pub last_tracked_at: i64,
}

impl SecureStore {
    /
    pub fn load_document_stats(&self, file_path: &str) -> anyhow::Result<Option<DocumentStats>> {
        let mut stmt = self.conn.prepare(
            "SELECT file_path, total_keystrokes, total_focus_ms, session_count,
                    total_duration_secs, first_tracked_at, last_tracked_at
             FROM document_stats WHERE file_path = ?1",
        )?;

        let result = stmt.query_row(params![file_path], |row| {
            Ok(DocumentStats {
                file_path: row.get(0)?,
                total_keystrokes: row.get(1)?,
                total_focus_ms: row.get(2)?,
                session_count: row.get(3)?,
                total_duration_secs: row.get(4)?,
                first_tracked_at: row.get(5)?,
                last_tracked_at: row.get(6)?,
            })
        });

        match result {
            Ok(stats) => Ok(Some(stats)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /
    pub fn save_document_stats(&self, stats: &DocumentStats) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO document_stats
                (file_path, total_keystrokes, total_focus_ms, session_count,
                 total_duration_secs, first_tracked_at, last_tracked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(file_path) DO UPDATE SET
                total_keystrokes = ?2,
                total_focus_ms = ?3,
                session_count = ?4,
                total_duration_secs = ?5,
                first_tracked_at = ?6,
                last_tracked_at = ?7",
            params![
                stats.file_path,
                stats.total_keystrokes,
                stats.total_focus_ms,
                stats.session_count,
                stats.total_duration_secs,
                stats.first_tracked_at,
                stats.last_tracked_at,
            ],
        )?;
        Ok(())
    }
}
