use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct Settings {
    #[serde(default)]
    pub allowed_profiles: HashSet<String>,
}
