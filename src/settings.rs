use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use chimera_kube_policy_sdk::settings::Trusties;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct Settings {
    #[serde(default)]
    pub allowed_profiles: HashSet<String>,

    #[serde(default)]
    pub allowed_groups: HashSet<String>,

    #[serde(default)]
    pub allowed_users: HashSet<String>,
}

impl Trusties for Settings {
    fn trusted_users(&self) -> HashSet<String> {
        self.allowed_users.clone()
    }

    fn trusted_groups(&self) -> HashSet<String> {
        self.allowed_groups.clone()
    }
}
