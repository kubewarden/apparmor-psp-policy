use guest::prelude::*;
use kubewarden_policy_sdk::wapc_guest as guest;

use std::collections::HashSet;

mod settings;
use settings::Settings;

use kubewarden_policy_sdk::{
    accept_request, protocol_version_guest, reject_request, request::ValidationRequest,
    validate_settings,
};

use k8s_openapi::api::core::v1 as apicore;

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_req = ValidationRequest::<Settings>::new(payload)?;
    let pod = serde_json::from_value::<apicore::Pod>(validation_req.request.object)?;

    let apparmor_profiles = get_apparmor_profiles(&pod);
    if apparmor_profiles.is_empty() {
        return accept_request();
    }

    let disallowed_profiles: Vec<&String> = apparmor_profiles
        .difference(&validation_req.settings.allowed_profiles)
        .collect();

    if disallowed_profiles.is_empty() {
        accept_request()
    } else {
        reject_request(
            Some(format!(
                "These AppArmor profiles are not allowed: {disallowed_profiles:?}"
            )),
            None,
            None,
            None,
        )
    }
}

fn get_apparmor_profiles(pod: &apicore::Pod) -> HashSet<String> {
    pod.metadata
        .annotations
        .as_ref()
        .unwrap_or(&std::collections::BTreeMap::new())
        .iter()
        .filter_map(|(annotation_key, annotation_value)| {
            if annotation_key.starts_with("container.apparmor.security.beta.kubernetes.io/") {
                Some(annotation_value.clone())
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    use kubewarden_policy_sdk::test::Testcase;

    macro_rules! configuration {
        (allowed_profiles: $allowed_profiles:expr) => {
            Settings {
                allowed_profiles: $allowed_profiles.split(",").map(String::from).collect(),
            }
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
