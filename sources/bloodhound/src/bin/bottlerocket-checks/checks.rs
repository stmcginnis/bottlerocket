use bloodhound::results;
use bloodhound::*;

const PROC_MODULES_FILE: &str = "/proc/modules";
const MODPROBE_CMD: &str = "/bin/modprobe";

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=

pub struct BR01010101Checker {}

impl results::Checker for BR01010101Checker {
    fn execute(&self) -> results::CheckerResult {
        let mut result = results::CheckerResult {
            error: String::new(),
            status: results::CheckStatus::SKIP,
        };

        check_udf_loaded(&mut result);
        check_modprobe(&mut result);

        result
    }

    fn metadata(&self) -> results::CheckerMetadata {
        results::CheckerMetadata {
            title: "Ensure mounting of udf filesystems is disabled".to_string(),
            id: "1.1.1.1".to_string(),
            level: 2,
            name: "br01010101".to_string(),
            mode: results::Mode::Automatic,
        }
    }
}

/// Parses the loaded modules to see if the udf module is already loaded.
fn check_udf_loaded(result: &mut results::CheckerResult) {
    if result.status == results::CheckStatus::FAIL {
        return;
    }

    if let Some(found) = look_for_string_in_file(PROC_MODULES_FILE, " udf,") {
        if found {
            result.error = "udf is currently loaded".to_string();
            result.status = results::CheckStatus::FAIL;
        } else {
            result.status = results::CheckStatus::PASS;
        }
    } else {
        result.error = "unable to parse modules to check for udf".to_string();
    }
}

/// Checks whether UDF is prevented from being loaded by modprobe. If disabled,
/// `modprobe -n -v udf` will return a line matching 'install /bin/true` in its
/// output.
fn check_modprobe(result: &mut results::CheckerResult) {
    if result.status == results::CheckStatus::FAIL {
        return;
    }

    if let Some(found) =
        look_for_string_in_output(MODPROBE_CMD, ["-n", "-v", "udf"], "install /bin/true")
    {
        if !found {
            result.error = "modprobe for udf is not disabled".to_string();
            result.status = results::CheckStatus::FAIL;
        } else {
            result.status = results::CheckStatus::PASS;
        }
    } else {
        result.error = "unable to parse modprobe output to check if udf is enabled".to_string();
    }
}
