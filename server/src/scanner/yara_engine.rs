/// yara_engine.rs — Moteur de règles par patterns (étendu : 13 → 38 règles).
/// Couvre : packers, ransomware, injection, keyloggers, stealers, RATs,
/// cryptominers, webshells, reverse shells, bypass AV/AMSI, persistance,
/// frameworks offensifs (Mimikatz, Cobalt Strike, Metasploit), malware Linux.
use crate::types::{Severity, YaraMatch};

struct Rule {
    name: &'static str,
    description: &'static str,
    severity: Severity,
    patterns: Vec<Pattern>,
    require_all: bool,
}

enum Pattern {
    Bytes(&'static [u8]),
    StringInsensitive(&'static str),
}

fn match_pattern_desc(data: &[u8], lower_data: &[u8], pattern: &Pattern) -> Option<String> {
    match pattern {
        Pattern::Bytes(needle) => {
            if data.windows(needle.len()).any(|w| w == *needle) {
                let desc = if needle.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
                    format!("\"{}\"", std::str::from_utf8(needle).unwrap_or("?"))
                } else {
                    format!(
                        "hex: {}",
                        needle.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
                    )
                };
                Some(desc)
            } else {
                None
            }
        }
        Pattern::StringInsensitive(s) => {
            let needle = s.to_lowercase();
            if lower_data.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                Some(format!("\"{}\"", s))
            } else {
                None
            }
        }
    }
}

fn build_rules() -> Vec<Rule> {
    use Pattern::{Bytes, StringInsensitive as Si};
    use Severity::{Critical, High, Medium};

    vec![
        // ── Packers ───────────────────────────────────────────────────────────
        Rule {
            name: "UPX_Packer",
            description: "Packer UPX détecté (compression PE)",
            severity: Medium,
            patterns: vec![Bytes(b"UPX0"), Bytes(b"UPX!")],
            require_all: false,
        },
        Rule {
            name: "MPRESS_Packer",
            description: "Packer MPRESS détecté",
            severity: Medium,
            patterns: vec![Bytes(b"MPRESS1")],
            require_all: false,
        },
        Rule {
            name: "VMProtect_Packer",
            description: "Protection VMProtect (virtualisation de code)",
            severity: Medium,
            patterns: vec![Bytes(b".vmp0"), Bytes(b".vmp1")],
            require_all: false,
        },
        Rule {
            name: "ASPack_Packer",
            description: "Packer ASPack détecté",
            severity: Medium,
            patterns: vec![Bytes(b".aspack"), Bytes(b".adata")],
            require_all: true,
        },
        // ── Ransomware ────────────────────────────────────────────────────────
        Rule {
            name: "Ransomware_Strings",
            description: "Chaînes caractéristiques de ransomware (message victime)",
            severity: Critical,
            patterns: vec![
                Si("your files have been encrypted"),
                Si("decrypt your files"),
            ],
            require_all: true,
        },
        Rule {
            name: "Ransomware_Payment",
            description: "Instructions paiement ransom (BTC + Tor)",
            severity: Critical,
            patterns: vec![Si("bitcoin"), Si("tor browser")],
            require_all: true,
        },
        Rule {
            name: "Ransomware_ShadowCopy",
            description: "Suppression des shadow copies (prélude au chiffrement)",
            severity: Critical,
            patterns: vec![Si("vssadmin delete shadows"), Si("wmic shadowcopy delete")],
            require_all: false,
        },
        Rule {
            name: "Ransomware_Note_Names",
            description: "Noms de fichiers de note de rançon connus",
            severity: Critical,
            patterns: vec![
                Si("README_FOR_DECRYPT"), Si("HOW_TO_DECRYPT"), Si("DECRYPT_INSTRUCTIONS"),
                Si("RESTORE_FILES"),
            ],
            require_all: false,
        },
        // ── Injection / shellcode ─────────────────────────────────────────────
        Rule {
            name: "Process_Injection",
            description: "Signatures d'injection de processus (CreateRemoteThread)",
            severity: Critical,
            patterns: vec![Si("createremotethread"), Si("virtualallocex")],
            require_all: true,
        },
        Rule {
            name: "Process_Hollowing",
            description: "Process hollowing (NtUnmapViewOfSection + Resume)",
            severity: Critical,
            patterns: vec![Si("ntunmapviewofsection"), Si("resumethread")],
            require_all: true,
        },
        Rule {
            name: "Shellcode_Patterns",
            description: "NOP sled extrême (64+ bytes) — shellcode probable",
            severity: High,
            patterns: vec![Bytes(&[0x90; 64])],
            require_all: true,
        },
        Rule {
            name: "Reflective_DLL",
            description: "Chargement réflexif de DLL en mémoire",
            severity: Critical,
            patterns: vec![Si("ReflectiveLoader"), Si("reflective_dll")],
            require_all: false,
        },
        // ── Keylogger / stealer ───────────────────────────────────────────────
        Rule {
            name: "Keylogger_Strings",
            description: "APIs capture clavier (GetAsyncKeyState + GetKeyboardState)",
            severity: Medium,
            patterns: vec![Si("getasynckeystate"), Si("getkeyboardstate")],
            require_all: true,
        },
        Rule {
            name: "Browser_Password_Theft",
            description: "Accès aux mots de passe stockés des navigateurs",
            severity: Critical,
            patterns: vec![
                Si("Login Data"), Si("encrypted_key"), Si("CryptUnprotectData"),
            ],
            require_all: true,
        },
        Rule {
            name: "Discord_Token_Stealer",
            description: "Vol de tokens Discord",
            severity: Critical,
            patterns: vec![Si("discord"), Si("leveldb"), Si("dQw4w9WgXcQ")],
            require_all: false,
        },
        Rule {
            name: "Crypto_Wallet_Theft",
            description: "Ciblage de wallets crypto (Exodus, Electrum, MetaMask)",
            severity: Critical,
            patterns: vec![
                Si("wallet.dat"), Si("electrum"), Si("exodus"), Si("metamask"),
            ],
            require_all: false,
        },
        Rule {
            name: "Telegram_Session_Theft",
            description: "Vol de session Telegram (tdata)",
            severity: High,
            patterns: vec![Si("tdata"), Si("telegram desktop")],
            require_all: true,
        },
        // ── RATs / frameworks offensifs ───────────────────────────────────────
        Rule {
            name: "Mimikatz_Strings",
            description: "Signatures de l'outil de vol de credentials Mimikatz",
            severity: Critical,
            patterns: vec![Bytes(b"mimikatz"), Bytes(b"sekurlsa"), Si("lsadump")],
            require_all: false,
        },
        Rule {
            name: "CobaltStrike_Beacon",
            description: "Signatures Cobalt Strike Beacon",
            severity: Critical,
            patterns: vec![Si("beacon.dll"), Si("%%IMPORT%%"), Si("ReflectiveLoader@4")],
            require_all: false,
        },
        Rule {
            name: "Metasploit_Payload",
            description: "Payload Metasploit/Meterpreter",
            severity: Critical,
            patterns: vec![Si("meterpreter"), Si("metsrv.dll"), Si("ext_server_stdapi")],
            require_all: false,
        },
        Rule {
            name: "Common_RAT_Strings",
            description: "Signatures de RATs courants (njRAT, AsyncRAT, QuasarRAT)",
            severity: Critical,
            patterns: vec![
                Si("njrat"), Si("asyncrat"), Si("quasar.client"), Si("dcrat"),
                Si("remcos"), Si("nanocore"),
            ],
            require_all: false,
        },
        // ── Cryptominers ──────────────────────────────────────────────────────
        Rule {
            name: "CryptoMiner_Strings",
            description: "Mineur de cryptomonnaie embarqué",
            severity: High,
            patterns: vec![
                Si("stratum+tcp://"), Si("xmrig"), Si("minerd"), Si("cryptonight"),
                Si("--donate-level"),
            ],
            require_all: false,
        },
        // ── Webshells ─────────────────────────────────────────────────────────
        Rule {
            name: "PHP_Webshell",
            description: "Webshell PHP (eval + entrée utilisateur)",
            severity: Critical,
            patterns: vec![Si("eval($_post"), Si("eval($_get"), Si("eval(base64_decode")],
            require_all: false,
        },
        Rule {
            name: "ASP_Webshell",
            description: "Webshell ASP/ASPX",
            severity: Critical,
            patterns: vec![Si("eval(request"), Si("execute(request")],
            require_all: false,
        },
        Rule {
            name: "JSP_Webshell",
            description: "Webshell JSP (Runtime.exec sur paramètre requête)",
            severity: Critical,
            patterns: vec![Si("runtime.getruntime().exec(request")],
            require_all: false,
        },
        // ── Reverse shells / réseau ───────────────────────────────────────────
        Rule {
            name: "Bash_Reverse_Shell",
            description: "Reverse shell bash (/dev/tcp)",
            severity: Critical,
            patterns: vec![Si("/dev/tcp/"), Si("bash -i")],
            require_all: true,
        },
        Rule {
            name: "Netcat_Exec_Shell",
            description: "Netcat avec exécution de shell",
            severity: Critical,
            patterns: vec![Si("nc -e /bin/sh"), Si("nc -e /bin/bash"), Si("nc.exe -e")],
            require_all: false,
        },
        Rule {
            name: "Network_Downloader",
            description: "Téléchargement réseau suspect (URLDownloadToFile)",
            severity: High,
            patterns: vec![Si("urldownloadtofile")],
            require_all: false,
        },
        Rule {
            name: "PowerShell_Download_Cradle",
            description: "Download cradle PowerShell (IEX + WebClient)",
            severity: Critical,
            patterns: vec![Si("iex"), Si("net.webclient"), Si("downloadstring")],
            require_all: true,
        },
        // ── Bypass / évasion ──────────────────────────────────────────────────
        Rule {
            name: "AntiDebug_Techniques",
            description: "Anti-debug actif : IsDebuggerPresent + CheckRemoteDebugger",
            severity: High,
            patterns: vec![Si("isdebuggerpresent"), Si("checkremotedebuggerpresent")],
            require_all: true,
        },
        Rule {
            name: "AntiVM_Techniques",
            description: "Détection de machine virtuelle (évasion sandbox)",
            severity: High,
            patterns: vec![
                Si("vboxservice"), Si("vmtoolsd"), Si("sbiedll"), Si("vmware_check"),
            ],
            require_all: false,
        },
        Rule {
            name: "AMSI_Bypass",
            description: "Bypass AMSI (antimalware scan interface)",
            severity: Critical,
            patterns: vec![Si("amsiutils"), Si("amsiinitfailed"), Si("amsiscanbuffer")],
            require_all: false,
        },
        Rule {
            name: "Defender_Tampering",
            description: "Désactivation de Windows Defender",
            severity: Critical,
            patterns: vec![Si("set-mppreference -disablerealtimemonitoring")],
            require_all: false,
        },
        Rule {
            name: "PowerShell_Encoded_Cmd",
            description: "Commande PowerShell encodée (-EncodedCommand)",
            severity: Medium,
            patterns: vec![Si("powershell"), Si("-encodedcommand")],
            require_all: true,
        },
        Rule {
            name: "Suspicious_Certutil",
            description: "Utilisation de certutil pour decode/téléchargement",
            severity: High,
            patterns: vec![Si("certutil"), Si("-decode")],
            require_all: true,
        },
        Rule {
            name: "Base64_PE_Header",
            description: "Exécutable PE encodé en Base64 (TVqQ = MZ)",
            severity: High,
            patterns: vec![Si("TVqQAAMAAAAEAAAA")],
            require_all: false,
        },
        // ── Persistance ───────────────────────────────────────────────────────
        Rule {
            name: "Persistence_Registry",
            description: "Accès clés de démarrage du registre",
            severity: Medium,
            patterns: vec![
                Si("software\\microsoft\\windows\\currentversion\\run"),
                Si("software\\microsoft\\windows nt\\currentversion\\winlogon"),
            ],
            require_all: false,
        },
        Rule {
            name: "Persistence_ScheduledTask",
            description: "Création de tâche planifiée (persistance)",
            severity: High,
            patterns: vec![Si("schtasks /create"), Si("register-scheduledtask")],
            require_all: false,
        },
        Rule {
            name: "Linux_Persistence",
            description: "Persistance Linux (crontab / rc.local / systemd)",
            severity: High,
            patterns: vec![
                Si("crontab -"), Si("/etc/rc.local"), Si("systemctl enable"),
                Si("/etc/systemd/system/"),
            ],
            require_all: false,
        },
        Rule {
            name: "Linux_History_Wipe",
            description: "Effacement de traces Linux (history, logs)",
            severity: High,
            patterns: vec![Si("history -c"), Si("rm -rf /var/log"), Si("shred -u")],
            require_all: false,
        },
    ]
}

pub struct YaraEngine {
    rules: Vec<Rule>,
}

impl YaraEngine {
    pub fn new() -> Self {
        Self { rules: build_rules() }
    }

    pub fn scan(&self, data: &[u8]) -> Vec<YaraMatch> {
        // Pré-calcul lowercase une seule fois (vs 1x par pattern dans le desktop)
        let lower_data: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();

        let mut matches = Vec::new();

        for rule in &self.rules {
            let matched_strings: Vec<String> = rule
                .patterns
                .iter()
                .filter_map(|p| match_pattern_desc(data, &lower_data, p))
                .collect();

            let triggered = if rule.require_all {
                matched_strings.len() == rule.patterns.len()
            } else {
                !matched_strings.is_empty()
            };

            if triggered {
                matches.push(YaraMatch {
                    rule_name: rule.name.to_string(),
                    description: rule.description.to_string(),
                    severity: rule.severity.clone(),
                    matched_strings,
                });
            }
        }

        matches
    }
}

impl Default for YaraEngine {
    fn default() -> Self {
        Self::new()
    }
}
