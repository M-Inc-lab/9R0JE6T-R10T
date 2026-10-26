//! R3V3R53//F0RG3 — Wave 4 (Phases 136–137): Direct Rust Port of `libyara` Aho-Corasick
//! Multi-Pattern Automaton (`libyara/ahocorasick.c`) & Mandiant `CAPA` Rule Tree Evaluator
//! (`open_source_yara_ahocorasick_capa.rs`)
//!
//! Directly ports:
//!   1. `libyara` Aho-Corasick Trie + BFS Failure-Link Automaton (`yr_ac_automaton_create`,
//!      `yr_ac_add_string`, `yr_ac_create_failure_links`, `yr_ac_scan_bytes`):
//!      - Scans an entire binary in a single linear $O(N)$ pass regardless of how many
//!        hundreds or thousands of YARA patterns are loaded.
//!   2. Mandiant `CAPA` Hierarchical Boolean Statement Evaluator (`capa/engine.py`):
//!      - Evaluates nested `And`, `Or`, `Not`, `Some(min_count)` AST nodes over extracted
//!        binary features (`Api`, `Bytes`, `Number`, `StringFeature`, `Characteristic`, `Arch`).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone)]
pub struct AcNode {
    pub next: BTreeMap<u8, usize>,
    pub fail: usize,
    pub outputs: Vec<usize>, // Pattern IDs matching at this state
}

impl AcNode {
    pub fn new() -> Self {
        Self {
            next: BTreeMap::new(),
            fail: 0,
            outputs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct YaraPattern {
    pub id: usize,
    pub rule_name: String,
    pub ident: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct YaraMatchHit {
    pub pattern_id: usize,
    pub rule_name: String,
    pub ident: String,
    pub offset: usize,
}

#[derive(Debug, Clone)]
pub struct YaraAhoCorasickAutomaton {
    pub nodes: Vec<AcNode>,
    pub patterns: Vec<YaraPattern>,
    pub compiled: bool,
}

impl YaraAhoCorasickAutomaton {
    pub fn new() -> Self {
        Self {
            nodes: vec![AcNode::new()],
            patterns: Vec::new(),
            compiled: false,
        }
    }

    pub fn add_pattern(&mut self, rule_name: &str, ident: &str, bytes: &[u8]) -> usize {
        let pat_id = self.patterns.len();
        self.patterns.push(YaraPattern {
            id: pat_id,
            rule_name: rule_name.to_string(),
            ident: ident.to_string(),
            bytes: bytes.to_vec(),
        });

        let mut cur = 0usize;
        for &b in bytes {
            if let Some(&nxt) = self.nodes[cur].next.get(&b) {
                cur = nxt;
            } else {
                let new_idx = self.nodes.len();
                self.nodes.push(AcNode::new());
                self.nodes[cur].next.insert(b, new_idx);
                cur = new_idx;
            }
        }
        self.nodes[cur].outputs.push(pat_id);
        self.compiled = false;
        pat_id
    }

    /// Build BFS failure links (`libyara/ahocorasick.c:yr_ac_create_failure_links`)
    pub fn build_failure_links(&mut self) {
        let mut queue = VecDeque::new();
        let root_transitions: Vec<(u8, usize)> = self.nodes[0].next.iter().map(|(&b, &n)| (b, n)).collect();
        for (_, child) in root_transitions {
            self.nodes[child].fail = 0;
            queue.push_back(child);
        }

        while let Some(u) = queue.pop_front() {
            let transitions: Vec<(u8, usize)> = self.nodes[u].next.iter().map(|(&b, &v)| (b, v)).collect();
            for (b, v) in transitions {
                queue.push_back(v);
                let mut f = self.nodes[u].fail;
                while f != 0 && !self.nodes[f].next.contains_key(&b) {
                    f = self.nodes[f].fail;
                }
                let fail_target = *self.nodes[f].next.get(&b).unwrap_or(&0);
                let final_fail = if fail_target == v { 0 } else { fail_target };
                self.nodes[v].fail = final_fail;
                let inherited = self.nodes[final_fail].outputs.clone();
                for pat_id in inherited {
                    if !self.nodes[v].outputs.contains(&pat_id) {
                        self.nodes[v].outputs.push(pat_id);
                    }
                }
            }
        }
        self.compiled = true;
    }

    /// Single-pass $O(N)$ Aho-Corasick scan over `data`
    pub fn scan_bytes(&mut self, data: &[u8]) -> Vec<YaraMatchHit> {
        if !self.compiled {
            self.build_failure_links();
        }
        let mut hits = Vec::new();
        let mut state = 0usize;

        for (i, &b) in data.iter().enumerate() {
            while state != 0 && !self.nodes[state].next.contains_key(&b) {
                state = self.nodes[state].fail;
            }
            state = *self.nodes[state].next.get(&b).unwrap_or(&0);
            if !self.nodes[state].outputs.is_empty() {
                for &pat_id in &self.nodes[state].outputs {
                    let pat = &self.patterns[pat_id];
                    let start_off = (i + 1).saturating_sub(pat.bytes.len());
                    hits.push(YaraMatchHit {
                        pattern_id: pat_id,
                        rule_name: pat.rule_name.clone(),
                        ident: pat.ident.clone(),
                        offset: start_off,
                    });
                }
            }
        }
        hits
    }
}

/// Mandiant CAPA Feature & Statement AST Evaluator (`capa/engine.py`)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapaFeature {
    Api(String),
    StringLit(String),
    Number(u64),
    Characteristic(String),
    Arch(String),
}

#[derive(Debug, Clone)]
pub enum CapaStatement {
    Feature(CapaFeature),
    And(Vec<CapaStatement>),
    Or(Vec<CapaStatement>),
    Not(Box<CapaStatement>),
    Some { min_count: usize, children: Vec<CapaStatement> },
}

impl CapaStatement {
    pub fn evaluate(&self, features: &BTreeSet<CapaFeature>) -> bool {
        match self {
            CapaStatement::Feature(f) => features.contains(f),
            CapaStatement::And(list) => list.iter().all(|c| c.evaluate(features)),
            CapaStatement::Or(list) => list.iter().any(|c| c.evaluate(features)),
            CapaStatement::Not(inner) => !inner.evaluate(features),
            CapaStatement::Some { min_count, children } => {
                let matched = children.iter().filter(|c| c.evaluate(features)).count();
                matched >= *min_count
            }
        }
    }
}
