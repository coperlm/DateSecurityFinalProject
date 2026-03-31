use chrono::Utc;
use once_cell::sync::Lazy;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Clone, Serialize, Default)]
pub struct ProgressStep {
    pub name: String,
    pub status: String, // queued|in_progress|done|failed
    pub message: Option<String>,
}

#[derive(Clone, Serialize, Default)]
pub struct Progress {
    pub id: String,
    pub steps: Vec<ProgressStep>,
    pub done: bool,
    pub success: Option<bool>,
    pub result: Option<serde_json::Value>,
    pub last_update: String,
    pub created_at: i64,
}

static PROGRESS_STORE: Lazy<Mutex<HashMap<String, Progress>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub fn create_progress(op_id: String, step_names: &[&str]) {
    let now = Utc::now();
    let now_str = now.to_rfc3339();
    let steps = step_names
        .iter()
        .map(|name| ProgressStep {
            name: name.to_string(),
            status: "queued".to_string(),
            message: None,
        })
        .collect();
    let p = Progress {
        id: op_id.clone(),
        steps,
        done: false,
        success: None,
        result: None,
        last_update: now_str.clone(),
        created_at: now.timestamp(),
    };

    let mut store = PROGRESS_STORE.lock().unwrap();
    store.insert(op_id, p);
}

pub fn update_progress_step(op_id: &str, step_name: &str, status: &str, msg: Option<String>) {
    let mut store = PROGRESS_STORE.lock().unwrap();
    if let Some(p) = store.get_mut(op_id) {
        p.last_update = Utc::now().to_rfc3339();
        for step in p.steps.iter_mut() {
            if step.name == step_name {
                step.status = status.to_string();
                step.message = msg.clone();
            }
        }
    }
}

pub fn set_progress_done(op_id: &str, success: bool, result: Option<serde_json::Value>) {
    let mut store = PROGRESS_STORE.lock().unwrap();
    if let Some(p) = store.get_mut(op_id) {
        p.done = true;
        p.success = Some(success);
        p.result = result;
        p.last_update = Utc::now().to_rfc3339();
    }
}

pub fn cleanup_progress(ttl_seconds: i64) {
    let mut store = PROGRESS_STORE.lock().unwrap();
    let now = Utc::now().timestamp();
    store.retain(|_, p| now - p.created_at <= ttl_seconds);
}

pub fn get_progress(op_id: &str) -> Option<Progress> {
    cleanup_progress(600); // 10 minutes
    let store = PROGRESS_STORE.lock().unwrap();
    store.get(op_id).cloned()
}
