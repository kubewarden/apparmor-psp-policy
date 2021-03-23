extern crate wapc_guest as guest;
use guest::prelude::*;

use anyhow::anyhow;
use std::collections::{HashMap, HashSet};

mod settings;
use settings::Settings;

use jsonpath_lib as jsonpath;

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
        return accept_request(None);
    }

    let not_allowed: Vec<String> = apparmor_profiles
        .difference(&validation_req.settings.allowed_profiles)
        .map(String::from)
        .collect();
    if not_allowed.is_empty() {
        return accept_request(None);
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
    let mut selector =
        jsonpath::selector_as::<HashMap<String, String>>(&validation_req.request.object);

    let annotations: HashSet<String> = selector("$.metadata.annotations")
        .map_err(|e| anyhow!("error querying metadata: {:?}", e))?
        .pop()
        .unwrap_or_default()
        .iter()
        .filter(|&(k, _v)| k.starts_with("container.apparmor.security.beta.kubernetes.io/"))
        .map(|(_k, v)| v.to_owned())
        .collect();
    Ok(annotations)
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
