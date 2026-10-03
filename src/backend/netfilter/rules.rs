//! Coarse SDK process-name selection. Runtime process matching remains authoritative.
//! The SDK supports a case-insensitive tail mask with `*`, while our matcher also
//! supports `?` and full paths. Widen those patterns here so the prefilter cannot
//! exclude a process that the Rust matcher would select.
use super::ffi::{self, Api, RuleEx};
use crate::config::AppConfig;
use anyhow::{bail, Result};
use std::collections::HashSet;

pub(super) fn install(api: &Api, config: &AppConfig) -> Result<()> {
    // Validate every mask before changing driver state.
    let rules = compile(config)?;
    let mut own_process = RuleEx {
        process_id: std::process::id(),
        direction: 2,
        ..RuleEx::default()
    };
    let result = unsafe { (api.add_rule)(&mut own_process, 1) };
    if result != 0 {
        bail!("NetFilter add self-bypass rule failed: {result}");
    }
    for mut rule in rules {
        let protocol = rule.protocol;
        let result = unsafe { (api.add_rule)(&mut rule, 0) };
        if result != 0 {
            bail!("NetFilter add process rule for protocol {protocol} failed: {result}");
        }
    }
    Ok(())
}

fn compile(config: &AppConfig) -> Result<Vec<RuleEx>> {
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    for configured in &config.rules {
        if !configured.accelerate_tcp && !configured.accelerate_udp {
            continue;
        }
        for pattern in &configured.process_names {
            let mask = prefilter_mask(pattern)?;
            let mut process_name = [0u16; 260];
            for (index, unit) in mask.encode_utf16().enumerate() {
                process_name[index] = unit;
            }
            for (protocol, enabled, filtering_flag) in [
                (6, configured.accelerate_tcp, ffi::CONNECT_REQUESTS),
                (17, configured.accelerate_udp, ffi::FILTER),
            ] {
                if !enabled || !seen.insert((protocol, mask.to_lowercase())) {
                    continue;
                }
                result.push(RuleEx {
                    protocol,
                    direction: 2,
                    filtering_flag,
                    process_name,
                    ..RuleEx::default()
                });
            }
        }
    }
    Ok(result)
}

fn prefilter_mask(pattern: &str) -> Result<String> {
    // SDK process paths can use device names, unlike the DOS paths accepted by
    // the configuration. Only the executable tail is safe as a coarse prefilter.
    let basename = pattern.trim().rsplit(['\\', '/']).next().unwrap_or("");
    if basename.is_empty() {
        bail!("NetFilter process pattern must contain an executable name: {pattern:?}");
    }
    let mut mask = String::new();
    for character in basename.chars() {
        if character == '\0' {
            bail!("NetFilter process pattern cannot contain a NUL character");
        }
        let character = if character == '?' { '*' } else { character };
        // Consecutive wildcards have the same meaning and should deduplicate.
        if character != '*' || !mask.ends_with('*') {
            mask.push(character);
        }
    }
    if mask.encode_utf16().count() >= 260 {
        // Truncation could exclude a valid configured name or broaden it to a
        // different process. Reject it explicitly, preserving the terminating NUL.
        bail!("NetFilter process filename pattern exceeds 259 UTF-16 code units");
    }
    Ok(mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BackendKind, Rule, Socks5Config};
    use std::sync::Mutex;

    fn config(rules: Vec<Rule>) -> AppConfig {
        AppConfig {
            backend: BackendKind::Netfilter,
            udp_transport: Default::default(),
            gpux: Default::default(),
            socks5: Socks5Config {
                host: "127.0.0.1".into(),
                port: 1080,
                user: String::new(),
                pass: String::new(),
            },
            rules,
        }
    }

    fn configured(names: &[&str], tcp: bool, udp: bool) -> Rule {
        Rule {
            process_names: names.iter().map(|name| (*name).into()).collect(),
            accelerate_tcp: tcp,
            accelerate_udp: udp,
        }
    }

    fn name(rule: &RuleEx) -> String {
        // Copy the packed field before borrowing it.
        let value = rule.process_name;
        let length = value.iter().position(|unit| *unit == 0).unwrap();
        String::from_utf16(&value[..length]).unwrap()
    }

    #[test]
    fn process_prefilter_deduplicates_per_enabled_protocol() {
        let config = config(vec![
            configured(&["bf6.exe", "BF6.EXE", r"C:\Games\bf6.exe"], true, false),
            configured(&["bf6.exe", "ea*.exe"], false, true),
            configured(&["ignored.exe"], false, false),
        ]);
        let rules = compile(&config).unwrap();
        assert_eq!(rules.len(), 3);
        assert!(rules[0].protocol == 6);
        assert!(rules[0].filtering_flag == ffi::CONNECT_REQUESTS);
        assert!(rules[1].protocol == 17 && rules[2].protocol == 17);
        assert!(rules[1].filtering_flag == ffi::FILTER);
        assert_eq!(name(&rules[0]), "bf6.exe");
        assert_eq!(name(&rules[1]), "bf6.exe");
        assert_eq!(name(&rules[2]), "ea*.exe");
        assert!(rules
            .iter()
            .all(|rule| rule.direction == 2 && rule.process_id == 0));
    }

    #[test]
    fn path_and_question_patterns_are_widened_without_accidental_empty_rules() {
        assert_eq!(
            prefilter_mask(r"C:\Games\任意目录\bf?.exe").unwrap(),
            "bf*.exe"
        );
        assert_eq!(prefilter_mask("/games/bf??*.exe").unwrap(), "bf*.exe");
        assert_eq!(prefilter_mask("*").unwrap(), "*");
        for invalid in ["", " ", "C:\\Games\\", "game\0.exe"] {
            assert!(prefilter_mask(invalid).is_err(), "{invalid:?}");
        }
        assert!(compile(&config(Vec::new())).unwrap().is_empty());
        let rules = compile(&config(vec![configured(&["*", "**", "?"], true, true)])).unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|rule| name(rule) == "*"));
    }

    #[test]
    fn utf16_capacity_is_checked_after_basename_extraction() {
        assert!(prefilter_mask(&"a".repeat(259)).is_ok());
        assert!(prefilter_mask(&"a".repeat(260)).is_err());
        assert!(prefilter_mask(&"😀".repeat(130)).is_err());
        assert_eq!(
            prefilter_mask(&format!("C:\\{}\\bf6.exe", "目录".repeat(300))).unwrap(),
            "bf6.exe"
        );
    }

    #[test]
    fn install_puts_self_bypass_first_and_filters_at_tail() {
        static CALLS: Mutex<Vec<(u32, i32, String, i32)>> = Mutex::new(Vec::new());
        unsafe extern "C" fn add_rule(rule: *mut RuleEx, to_head: i32) -> i32 {
            let rule = unsafe { &*rule };
            CALLS
                .lock()
                .unwrap()
                .push((rule.process_id, rule.protocol, name(rule), to_head));
            0
        }
        let mut api = Api::test_stub();
        api.add_rule = add_rule;
        let config = config(vec![configured(&["bf6.exe"], true, true)]);
        install(&api, &config).unwrap();
        let calls = CALLS.lock().unwrap();
        assert_eq!(
            calls.as_slice(),
            [
                (std::process::id(), 0, String::new(), 1),
                (0, 6, "bf6.exe".into(), 0),
                (0, 17, "bf6.exe".into(), 0),
            ]
        );
    }
}
