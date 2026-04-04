# Project Workflow

## Core Mandates
1. **Test-Driven Development (TDD):** Every feature task must be broken down into a "Write Tests" sub-task followed by an "Implement Feature" sub-task.
2. **Coverage Requirement:** Maintain a minimum of **80%** test code coverage.
3. **Commit Frequency:** Commit changes after every completed **task**.
4. **Summary Storage:** Store implementation summaries in **Git notes** (`git notes add -m "[Summary Details]"`).
5. **Commit Format:** Use strictly one-line **Conventional Commits** (e.g., `feat(ui): add entropy map`).

## Development Loop
- **Compiler Feedback Loop:** The agent MUST use the `cargo-mcp` tool (or `cargo check`) to run a check after every task. If there are borrow-checker or lifetime errors, they must be resolved before proceeding.
- **Linting Standard:** Every task is only "Complete" if `cargo clippy --all-targets` passes with zero warnings.
- **Tokio Safety:** Strictly prohibit `std` blocking calls (e.g., `std::fs`, `std::thread::sleep`) in async contexts. Use `tokio` equivalents.
- **Documentation:** All new public functions and structs must include `///` doc comments.

## Phase Completion Verification and Checkpointing Protocol
At the end of each phase, the following steps must be completed:
1. **Verify All Tasks:** Ensure all tasks in the phase are marked as completed.
2. **Run Full Test Suite:** Execute `cargo test --workspace` and ensure all tests pass.
3. **Check Coverage:** Verify that the 80% coverage requirement is met.
4. **Final Lint Check:** Run `cargo clippy --workspace --all-targets` to ensure no warnings exist.
5. **Checkpoint:** Create a git checkpoint if requested.

- [ ] Task: Conductor - User Manual Verification '<Phase Name>' (Protocol in workflow.md)
