//! Memory & Context Security Scanner
//!
//! Priority: MEDIUM
//!
//! Checks:
//! - Sensitive data in session memory
//! - Memory backend exposure (QMD vs SQLite)
//! - Transcript retention
//! - Embedding model security

use crate::config::OpenClawConfig;
use crate::models::{Finding, Severity};
use crate::scanner::Scanner;

pub struct MemoryScanner;

impl Scanner for MemoryScanner {
    fn name(&self) -> &str {
        "memory"
    }

    fn description(&self) -> &str {
        "Memory and context handling security"
    }

    fn scan(&self, config: &OpenClawConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for memory configuration in raw config
        if let Some(memory) = config.raw.get("memory").and_then(|v| v.as_object()) {
            // Check backend type
            if let Some(backend) = memory.get("backend").and_then(|v| v.as_str()) {
                if backend == "qmd" {
                    findings.push(Finding::new(
                        "memory.qmd_backend",
                        self.name(),
                        Severity::Medium,
                        "QMD Memory Backend",
                        "Using QMD (Query-Metadata-Description) memory backend",
                        "May have different isolation characteristics than SQLite",
                        "Review QMD security properties",
                        "memory.backend",
                    ));
                }
            }

            // Check transcript retention
            if let Some(transcript) = memory.get("transcriptRetention").and_then(|v| v.as_str()) {
                if transcript == "forever" || transcript == "infinite" {
                    findings.push(Finding::new(
                        "memory.transcript_forever",
                        self.name(),
                        Severity::Medium,
                        "Unlimited Transcript Retention",
                        &format!("Transcript retention is '{}'", transcript),
                        "Conversation history stored indefinitely",
                        "Set to finite period (e.g., '30d')",
                        "memory.transcriptRetention",
                    ));
                }
            }

            // Check embedding model
            if let Some(embedding) = memory.get("embeddingModel").and_then(|v| v.as_str()) {
                // External embedding APIs could send data
                if !embedding.starts_with("local:") && !embedding.starts_with("ollama:") {
                    findings.push(Finding::new(
                        "memory.external_embedding",
                        self.name(),
                        Severity::Low,
                        "External Embedding Model",
                        &format!("Using external embedding: {}", embedding),
                        "Memory data sent to external API",
                        "Consider local embeddings for sensitive data",
                        "memory.embeddingModel",
                    ));
                }
            }

            // Check for search provider
            if let Some(search) = memory.get("searchProvider").and_then(|v| v.as_str()) {
                if search != "local" && search != "fuse" {
                    findings.push(Finding::new(
                        "memory.external_search",
                        self.name(),
                        Severity::Low,
                        "External Memory Search",
                        &format!("Using external search: {}", search),
                        "Memory queries sent to external service",
                        "Consider local search for privacy",
                        "memory.searchProvider",
                    ));
                }
            }
        }

        findings
    }
}
