use bloodhound::results;
use bloodhound::*;
use std::process::Command;

const PROC_MODULES_FILE: &str = "/proc/modules";
const PROC_CMDLINE_FILE: &str = "/proc/cmdline";
const SYSCTL_CMD: &str = "/usr/sbin/sysctl";
const MODPROBE_CMD: &str = "/bin/modprobe";
const SESTATUS_CMD: &str = "/usr/bin/sestatus";

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

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=

pub struct BR01030100Checker {}

impl results::Checker for BR01030100Checker {
    fn execute(&self) -> results::CheckerResult {
        let mut result = results::CheckerResult {
            error: String::new(),
            status: results::CheckStatus::SKIP,
        };

        let mut enabled = true;
        let mut skipped = false;
        // This isn't the most efficient because it results in the proc file being opened, read, and closed three times.
        // It is a single line, so there shouldn't be too much extra overhead compared to the simplicity of doing it
        // this way, but if needed this should be changed to read the contents once, then check each expected value in
        // the same content string.
        if let Some(found) = look_for_string_in_file(PROC_CMDLINE_FILE, "dm-mod.create=root,,,ro,0")
        {
            if !found {
                enabled = false;
            }
        } else {
            skipped = true;
        }

        if let Some(found) = look_for_string_in_file(PROC_CMDLINE_FILE, "root=/dev/dm-0") {
            if !found {
                enabled = false;
            }
        } else {
            skipped = true;
        }

        if let Some(found) = look_for_string_in_file(PROC_CMDLINE_FILE, "restart_on_corruption") {
            if !found {
                enabled = false;
            }
        } else {
            skipped = true;
        }

        if skipped {
            result.error = "unable to verify cmdline includes dm-verity settings".to_string();
        } else if enabled {
            result.status = results::CheckStatus::PASS;
        } else {
            result.error = "unable to verify dm-verity enforcement, settings not found".to_string();
            result.status = results::CheckStatus::FAIL;
        }

        result
    }

    fn metadata(&self) -> results::CheckerMetadata {
        results::CheckerMetadata {
            title: "Ensure dm-verity is configured".to_string(),
            id: "1.3.1".to_string(),
            level: 1,
            name: "br01030100".to_string(),
            mode: results::Mode::Automatic,
        }
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=

pub struct BR01040100Checker {}

impl results::Checker for BR01040100Checker {
    fn execute(&self) -> results::CheckerResult {
        let mut result = results::CheckerResult {
            error: String::new(),
            status: results::CheckStatus::SKIP,
        };

        if let Some(found) =
            look_for_string_in_output(SYSCTL_CMD, ["fs.suid_dumpable"], "fs.suid_dumpable = 0")
        {
            if !found {
                result.error = "setuid core dumps are not disabled".to_string();
                result.status = results::CheckStatus::FAIL;
            } else {
                result.status = results::CheckStatus::PASS;
            }
        } else {
            result.error = "unable to verify fs.suid_dumpable setting".to_string();
        }

        result
    }

    fn metadata(&self) -> results::CheckerMetadata {
        results::CheckerMetadata {
            title: "Ensure setuid programs do not create core dumps".to_string(),
            id: "1.4.1".to_string(),
            level: 1,
            name: "br01040100".to_string(),
            mode: results::Mode::Automatic,
        }
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=

pub struct BR01040200Checker {}

impl results::Checker for BR01040200Checker {
    fn execute(&self) -> results::CheckerResult {
        let mut result = results::CheckerResult {
            error: String::new(),
            status: results::CheckStatus::SKIP,
        };

        if let Some(found) = look_for_string_in_output(
            SYSCTL_CMD,
            ["kernel.randomize_va_space"],
            "kernel.randomize_va_space = 2",
        ) {
            if !found {
                result.error = "Address space layout randomization is not enabled".to_string();
                result.status = results::CheckStatus::FAIL;
            } else {
                result.status = results::CheckStatus::PASS;
            }
        } else {
            result.error = "unable to verify kernel.randomize_va_space setting".to_string();
        }

        result
    }

    fn metadata(&self) -> results::CheckerMetadata {
        results::CheckerMetadata {
            title: "Ensure address space layout randomization (ASLR) is enabled".to_string(),
            id: "1.4.2".to_string(),
            level: 1,
            name: "br01040200".to_string(),
            mode: results::Mode::Automatic,
        }
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=

pub struct BR01040300Checker {}

impl results::Checker for BR01040300Checker {
    fn execute(&self) -> results::CheckerResult {
        let mut result = results::CheckerResult {
            error: String::new(),
            status: results::CheckStatus::SKIP,
        };

        if let Some(found) = look_for_string_in_output(
            SYSCTL_CMD,
            ["kernel.unprivileged_bpf_disabled"],
            "kernel.unprivileged_bpf_disabled = 1",
        ) {
            if !found {
                result.error = "Unprivileged eBPF is not disabled".to_string();
                result.status = results::CheckStatus::FAIL;
            } else {
                result.status = results::CheckStatus::PASS;
            }
        } else {
            result.error = "unable to verify kernel.unprivileged_bpf_disabled setting".to_string();
        }

        result
    }

    fn metadata(&self) -> results::CheckerMetadata {
        results::CheckerMetadata {
            title: "Ensure unprivileged eBPF is disabled".to_string(),
            id: "1.4.3".to_string(),
            level: 1,
            name: "br01040300".to_string(),
            mode: results::Mode::Automatic,
        }
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=

pub struct BR01040400Checker {}

impl results::Checker for BR01040400Checker {
    fn execute(&self) -> results::CheckerResult {
        let mut result = results::CheckerResult {
            error: String::new(),
            status: results::CheckStatus::SKIP,
        };

        if let Some(found) = look_for_string_in_output(
            SYSCTL_CMD,
            ["user.max_user_namespaces"],
            "user.max_user_namespaces = 0",
        ) {
            if !found {
                result.error = "User namespaces are not disabled".to_string();
                result.status = results::CheckStatus::FAIL;
            } else {
                result.status = results::CheckStatus::PASS;
            }
        } else {
            result.error = "unable to verify user.max_user_namespaces setting".to_string();
        }

        result
    }

    fn metadata(&self) -> results::CheckerMetadata {
        results::CheckerMetadata {
            title: "Ensure user namespaces are disabled".to_string(),
            id: "1.4.4".to_string(),
            level: 2,
            name: "br01040400".to_string(),
            mode: results::Mode::Automatic,
        }
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=

pub struct BR01050100Checker {}

impl results::Checker for BR01050100Checker {
    fn execute(&self) -> results::CheckerResult {
        let mut result = results::CheckerResult {
            error: String::new(),
            status: results::CheckStatus::SKIP,
        };

        // Trying to avoid bringing in regex for now
        let to_match = &vec![
            ("SELinux status: ", " enabled"),
            ("Loaded policy name: ", " fortified"),
            ("Current mode: ", " enforcing"),
            ("Mode from config file: ", " enforcing"),
            ("Policy MLS status: ", " enabled"),
            ("Policy deny_unknown status: ", " denied"),
            ("Memory protection checking: ", " actual (secure)"),
        ];

        if let Ok(output) = Command::new(SESTATUS_CMD).output() {
            let mut matched = 0;

            if output.status.success() {
                let mp_output = String::from_utf8_lossy(&output.stdout).to_string();
                for line in mp_output.lines() {
                    for match_line in to_match {
                        if line.contains(match_line.0) && line.contains(match_line.1) {
                            matched += 1;
                            break;
                        }
                    }
                }

                if to_match.len() == matched {
                    result.status = results::CheckStatus::PASS;
                } else {
                    result.error = "Unable to find expected SELinux values".to_string();
                    result.status = results::CheckStatus::FAIL;
                }
            }
        } else {
            result.error = "unable to verify selinx settings".to_string();
        }

        result
    }

    fn metadata(&self) -> results::CheckerMetadata {
        results::CheckerMetadata {
            title: "Ensure SELinux is configured".to_string(),
            id: "1.5.1".to_string(),
            level: 1,
            name: "br01050100".to_string(),
            mode: results::Mode::Automatic,
        }
    }
}
