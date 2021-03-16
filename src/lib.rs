extern crate wapc_guest as guest;
use guest::prelude::*;

use anyhow::anyhow;
use std::collections::HashSet;

mod settings;
use settings::Settings;

use chimera_kube_policy_sdk::{accept_request, reject_request, request::ValidationRequest};

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_req = ValidationRequest::<Settings>::new(payload)?;

    let apparmor_profiles = get_apparmor_profiles(&validation_req)
        .map_err(|e| anyhow!("Error while searching request: {:?}", e,))?;

    if apparmor_profiles.is_empty() {
        return accept_request();
    }

    let not_allowed: Vec<String> = apparmor_profiles
        .difference(&validation_req.settings.allowed_profiles)
        .map(String::from)
        .collect();
    if not_allowed.is_empty() {
        return accept_request();
    }

    reject_request(
        Some(format!(
            "These AppArmor profiles are not allowed: {:?}",
            not_allowed
        )),
        None,
    )
}

fn get_apparmor_profiles(
    validation_req: &ValidationRequest<Settings>,
) -> anyhow::Result<HashSet<String>> {
    let query = "metadata.annotations";
    let mut res = HashSet::<String>::new();

    let containers_query = jmespatch::compile(query)
        .map_err(|e| anyhow!("Cannot parse jmespath expression: {:?}", e,))?;

    let raw_search_result = validation_req
        .search(containers_query)
        .map_err(|e| anyhow!("Error while searching request: {:?}", e,))?;
    if raw_search_result.is_null() {
        return Ok(res);
    }

    let search_result = raw_search_result.as_object().ok_or_else(|| {
        anyhow!(
            "Expected search matches to be an Object, got {:?} instead",
            raw_search_result
        )
    })?;

    for (key, value) in search_result {
        if !key.starts_with("container.apparmor.security.beta.kubernetes.io/") {
            continue;
        }

        if let Some(s) = value.as_string() {
            res.insert(s.clone());
        }
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    use chimera_kube_policy_sdk::test::Testcase;

    macro_rules! configuration {
        (allowed_profiles: $allowed_profiles:expr) => {
            Settings {
                allowed_profiles: $allowed_profiles.split(",").map(String::from).collect(),
            };
        };
    }

    #[test]
    fn no_apparmor_profile() -> Result<()> {
        let request_file = "test_data/req_pod_without_apparmor_profile.json";
        let tests = vec![
            Testcase {
                name: String::from("Accept request when allowed_profiles is empty"),
                fixture_file: String::from(request_file),
                settings: configuration!(allowed_profiles: ""),
                expected_validation_result: true,
            },
            Testcase {
                name: String::from("Accept request when allowed_profiles is not empty"),
                fixture_file: String::from(request_file),
                settings: configuration!( allowed_profiles: "localhost/special-profile"),
                expected_validation_result: true,
            },
        ];

        for tc in tests.iter() {
            let _ = tc.eval(validate);
        }

        Ok(())
    }

    #[test]
    fn not_allowed_apparmor_profile() -> Result<()> {
        let request_file = "test_data/req_pod_with_custom_apparmor_profile.json";
        let tests = vec![
            Testcase {
                name: String::from("Reject because allowed_profiles is empty"),
                fixture_file: String::from(request_file),
                settings: configuration!(allowed_profiles: ""),
                expected_validation_result: false,
            },
            Testcase {
                name: String::from("Reject because not all the profiles are allowed"),
                fixture_file: String::from(request_file),
                settings: configuration!(allowed_profiles: "runtime/default"),
                expected_validation_result: false,
            },
        ];

        for tc in tests.iter() {
            let _ = tc.eval(validate);
        }

        Ok(())
    }

    #[test]
    fn allowed_apparmor_profile() -> Result<()> {
        let request_file = "test_data/req_pod_with_custom_apparmor_profile.json";
        let tc = Testcase {
            name: String::from("Accept "),
            fixture_file: String::from(request_file),
            settings: configuration!(
                allowed_profiles: "runtime/default,localhost/cognac-cointreau-lemon,localhost/another-profile"
            ),
            expected_validation_result: true,
        };

        let _ = tc.eval(validate);

        Ok(())
    }
}
