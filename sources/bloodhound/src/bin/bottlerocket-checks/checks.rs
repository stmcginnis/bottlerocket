use bloodhound::results;
use bloodhound::*;
use std::process::Command;

const PROC_MODULES_FILE: &str = "/proc/modules";
const PROC_CMDLINE_FILE: &str = "/proc/cmdline";
const LOCKDOWN_FILE: &str = "/sys/kernel/security/lockdown";
const SYSCTL_CMD: &str = "/usr/sbin/sysctl";
const SYSTEMCTL_CMD: &str = "/usr/bin/systemctl";
const MODPROBE_CMD: &str = "/bin/modprobe";
const SESTATUS_CMD: &str = "/usr/bin/sestatus";
const APICLIENT_CMD: &str = "/usr/bin/apiclient";

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

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=

pub struct BR01050200Checker {}

impl results::Checker for BR01050200Checker {
    fn execute(&self) -> results::CheckerResult {
        let mut result = results::CheckerResult {
            error: String::new(),
            status: results::CheckStatus::SKIP,
        };

        if let Some(found) = look_for_string_in_file(LOCKDOWN_FILE, "[integrity]") {
            if !found {
                result.error = "lockdown integrity mode is not enabled".to_string();
                result.status = results::CheckStatus::FAIL;
            } else {
                result.status = results::CheckStatus::PASS;
            }
        } else {
            result.error = "unable to verify lockdown mode".to_string();
        }

        result
    }

    fn metadata(&self) -> results::CheckerMetadata {
        results::CheckerMetadata {
            title: "Ensure Lockdown is configured".to_string(),
            id: "1.5.2".to_string(),
            level: 2,
            name: "br01050200".to_string(),
            mode: results::Mode::Automatic,
        }
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=

pub struct BR02010101Checker {}

impl results::Checker for BR02010101Checker {
    fn execute(&self) -> results::CheckerResult {
        let mut result = results::CheckerResult {
            error: String::new(),
            status: results::CheckStatus::SKIP,
        };

        if let Some(found) = look_for_string_in_output(
            APICLIENT_CMD,
            ["get", "settings.ntp.time-servers"],
            "\"time-servers\": []",
        ) {
            if found {
                result.error = "no ntp servers are configured".to_string();
                result.status = results::CheckStatus::FAIL;
            } else {
                result.status = results::CheckStatus::PASS;
            }
        } else {
            result.error = "unable to verify time-servers setting".to_string();
        }

        // Check if we need to continue
        if result.status == results::CheckStatus::FAIL {
            return result;
        }

        if let Some(found) =
            look_for_string_in_output(SYSTEMCTL_CMD, ["is-active", "chronyd"], "active")
        {
            if !found {
                result.error = "chronyd NTP service is not enabled".to_string();
                result.status = results::CheckStatus::FAIL;
            } else {
                result.status = results::CheckStatus::PASS;
            }
        } else {
            result.error = "unable to verify chronyd service enabled".to_string();
        }

        result
    }

    fn metadata(&self) -> results::CheckerMetadata {
        results::CheckerMetadata {
            title: "Ensure chrony is configured".to_string(),
            id: "2.1.1.1".to_string(),
            level: 1,
            name: "br02010101".to_string(),
            mode: results::Mode::Automatic,
        }
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=

pub struct BR03010100Checker {}

impl results::Checker for BR03010100Checker {
    fn execute(&self) -> results::CheckerResult {
        let mut result = results::CheckerResult {
            error: String::new(),
            status: results::CheckStatus::SKIP,
        };

        let settings = vec![
            "net.ipv4.conf.all.send_redirects",
            "net.ipv4.conf.default.send_redirects",
        ];

        for setting in settings {
            if let Some(found) = look_for_string_in_output(
                SYSCTL_CMD,
                [setting],
                format!("{} = 0", setting).as_str(),
            ) {
                if !found {
                    result.error = format!("{} not disabled", setting);
                    result.status = results::CheckStatus::FAIL;
                } else {
                    result.status = results::CheckStatus::PASS;
                }
            } else {
                result.error = format!("unable to verify {} setting", setting);
            }

            // Check if we need to continue
            if result.status == results::CheckStatus::FAIL {
                return result;
            }
        }

        result
    }

    fn metadata(&self) -> results::CheckerMetadata {
        results::CheckerMetadata {
            title: "Ensure packet redirect sending is disabled".to_string(),
            id: "3.1.1".to_string(),
            level: 2,
            name: "br03010100".to_string(),
            mode: results::Mode::Automatic,
        }
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=

pub struct BR03020100Checker {}

impl results::Checker for BR03020100Checker {
    fn execute(&self) -> results::CheckerResult {
        let mut result = results::CheckerResult {
            error: String::new(),
            status: results::CheckStatus::SKIP,
        };

        let settings = vec![
            "net.ipv4.conf.all.accept_source_route",
            "net.ipv4.conf.default.accept_source_route",
            "net.ipv6.conf.all.accept_source_route",
            "net.ipv6.conf.default.accept_source_route",
        ];

        for setting in settings {
            if let Some(found) = look_for_string_in_output(
                SYSCTL_CMD,
                [setting],
                format!("{} = 0", setting).as_str(),
            ) {
                if !found {
                    result.error = format!("{} not disabled", setting);
                    result.status = results::CheckStatus::FAIL;
                } else {
                    result.status = results::CheckStatus::PASS;
                }
            } else {
                result.error = format!("unable to verify {} setting", setting);
            }

            // Check if we need to continue
            if result.status == results::CheckStatus::FAIL {
                return result;
            }
        }

        result
    }

    fn metadata(&self) -> results::CheckerMetadata {
        results::CheckerMetadata {
            title: "Ensure source routed packets are not accepted".to_string(),
            id: "3.2.1".to_string(),
            level: 2,
            name: "br03020100".to_string(),
            mode: results::Mode::Automatic,
        }
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=

pub struct BR03020200Checker {}

impl results::Checker for BR03020200Checker {
    fn execute(&self) -> results::CheckerResult {
        let mut result = results::CheckerResult {
            error: String::new(),
            status: results::CheckStatus::SKIP,
        };

        let settings = vec![
            "net.ipv4.conf.all.accept_redirects",
            "net.ipv4.conf.default.accept_redirects",
            "net.ipv6.conf.all.accept_redirects",
            "net.ipv6.conf.default.accept_redirects",
        ];

        for setting in settings {
            if let Some(found) = look_for_string_in_output(
                SYSCTL_CMD,
                [setting],
                format!("{} = 0", setting).as_str(),
            ) {
                if !found {
                    result.error = format!("{} not disabled", setting);
                    result.status = results::CheckStatus::FAIL;
                } else {
                    result.status = results::CheckStatus::PASS;
                }
            } else {
                result.error = format!("unable to verify {} setting", setting);
            }

            // Check if we need to continue
            if result.status == results::CheckStatus::FAIL {
                return result;
            }
        }

        result
    }

    fn metadata(&self) -> results::CheckerMetadata {
        results::CheckerMetadata {
            title: "Ensure ICMP redirects are not accepted".to_string(),
            id: "3.2.2".to_string(),
            level: 2,
            name: "br03020200".to_string(),
            mode: results::Mode::Automatic,
        }
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=

pub struct BR03020300Checker {}

impl results::Checker for BR03020300Checker {
    fn execute(&self) -> results::CheckerResult {
        let mut result = results::CheckerResult {
            error: String::new(),
            status: results::CheckStatus::SKIP,
        };

        let settings = vec![
            "net.ipv4.conf.all.secure_redirects",
            "net.ipv4.conf.default.secure_redirects",
        ];

        for setting in settings {
            if let Some(found) = look_for_string_in_output(
                SYSCTL_CMD,
                [setting],
                format!("{} = 0", setting).as_str(),
            ) {
                if !found {
                    result.error = format!("{} not disabled", setting);
                    result.status = results::CheckStatus::FAIL;
                } else {
                    result.status = results::CheckStatus::PASS;
                }
            } else {
                result.error = format!("unable to verify {} setting", setting);
            }

            // Check if we need to continue
            if result.status == results::CheckStatus::FAIL {
                return result;
            }
        }

        result
    }

    fn metadata(&self) -> results::CheckerMetadata {
        results::CheckerMetadata {
            title: "Ensure secure ICMP redirects are not accepted".to_string(),
            id: "3.2.3".to_string(),
            level: 2,
            name: "br03020300".to_string(),
            mode: results::Mode::Automatic,
        }
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=

pub struct BR03020400Checker {}

impl results::Checker for BR03020400Checker {
    fn execute(&self) -> results::CheckerResult {
        let mut result = results::CheckerResult {
            error: String::new(),
            status: results::CheckStatus::SKIP,
        };

        let settings = vec![
            "net.ipv4.conf.all.log_martians",
            "net.ipv4.conf.default.log_martians",
        ];

        for setting in settings {
            if let Some(found) = look_for_string_in_output(
                SYSCTL_CMD,
                [setting],
                format!("{} = 1", setting).as_str(),
            ) {
                if !found {
                    result.error = format!("{} not enabled", setting);
                    result.status = results::CheckStatus::FAIL;
                } else {
                    result.status = results::CheckStatus::PASS;
                }
            } else {
                result.error = format!("unable to verify {} setting", setting);
            }

            // Check if we need to continue
            if result.status == results::CheckStatus::FAIL {
                return result;
            }
        }

        result
    }

    fn metadata(&self) -> results::CheckerMetadata {
        results::CheckerMetadata {
            title: "Ensure suspicious packets are logged".to_string(),
            id: "3.2.4".to_string(),
            level: 2,
            name: "br03020400".to_string(),
            mode: results::Mode::Automatic,
        }
    }
}
