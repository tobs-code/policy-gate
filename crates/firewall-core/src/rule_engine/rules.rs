// rule_engine/rules.rs — Rule table for Channel B
//
// Each Rule is a named predicate (fn(&str) -> RuleOutcome).
// No regex, no ML — pure structural and lexical analysis.
//
// Rule authoring contract:
//   • A rule MUST return Pass or Block for inputs it claims to handle.
//   • A rule MUST return Continue for inputs outside its scope.
//   • Rules are evaluated in declaration order — first non-Continue result wins.
//   • Rule IDs (RE-xxx) cross-reference with Safety Manual §6.

use super::RuleOutcome;
use crate::types::{BlockReason, MatchedIntent};

pub struct Rule {
    #[allow(dead_code)]
    pub id: &'static str,
    #[allow(dead_code)]
    pub description: &'static str,
    pub evaluate: fn(&str) -> RuleOutcome,
}

// ─── Helpers (no regex) ───────────────────────────────────────────────────────

fn word_count(s: &str) -> usize {
    s.split_whitespace().count()
}

fn starts_with_any_ci(s: &str, prefixes: &[&str]) -> bool {
    let lower = s.to_lowercase();
    prefixes.iter().any(|p| lower.starts_with(p))
}

fn contains_any_ci(s: &str, keywords: &[&str]) -> bool {
    let lower = s.to_lowercase();
    keywords.iter().any(|&k| lower.contains(&k.to_lowercase()))
}

fn contains_any_ci_fuzzy(s: &str, keywords: &[&str]) -> bool {
    // Noise-tolerant keyword matching (SA-045).
    // Strip non-alphanumeric noise from the input and keyword and check for substring match.
    // Example: "mal,ware" -> "malware" matches "malware".
    let lower_s = s.to_lowercase();
    let stripped_s: String = lower_s.chars().filter(|c| c.is_alphanumeric()).collect();

    keywords.iter().any(|&kw| {
        let lower_kw = kw.to_lowercase();
        let stripped_kw: String = lower_kw.chars().filter(|c| c.is_alphanumeric()).collect();

        // Literal check first (preserved for phrases with spaces)
        if lower_s.contains(&lower_kw) {
            return true;
        }

        // Fuzzy check only if the stripped keyword is significant (> 2 chars)
        // to avoid single-letter collisions like "<s>" -> "s".
        if stripped_kw.len() > 2 && stripped_s.contains(&stripped_kw) {
            return true;
        }

        false
    })
}

fn ends_with_question_mark(s: &str) -> bool {
    s.trim_end().ends_with('?')
}

// ─── Rule Table ───────────────────────────────────────────────────────────────

// ─── Rule Table ───────────────────────────────────────────────────────────────
//
// Word-count limits per rule (G-31 — documented for consistency):
//   RE-010 (factual question):    ≤ 40 words  — short factual questions only
//   RE-011 (causal question):     ≤ 60 words  — slightly longer explanatory questions
//   RE-012 (comparison):          ≤ 80 words  — comparisons can be more verbose
//   RE-013 (data extraction):     ≤ 80 words  — extraction tasks need context
//   RE-020 (code generation):     ≤ 100 words — code tasks often need more description
//   RE-021 (summarisation):       ≤ 60 words  — summarisation requests are brief
//   RE-022 (translation):         ≤ 80 words  — translation requests can include context
//   RE-030 (greeting):            ≤ 5 words   — greetings are always short
//   RE-031 (acknowledgement):     ≤ 4 words   — acknowledgements are always short
//   RE-040 (system meta):         ≤ 20 words  — meta queries are brief
//   RE-050 (structured output):   ≤ 80 words  — schema requests need some description
//   RE-099 (controlled creative): ≤ 60 words  — creative requests are bounded

pub static RULE_TABLE: &[Rule] = &[
    // ── Block rules (checked before allow rules) ─────────────────────────────
    Rule {
        id: "RE-001",
        description: "Block: suspiciously long single-word tokens (obfuscation attempt)",
        evaluate: |input| {
            let has_giant_token = input.split_whitespace().any(|w| w.chars().count() > 512);
            if has_giant_token {
                RuleOutcome::Block(BlockReason::MalformedInput {
                    detail: "token exceeds 512 chars".into(),
                })
            } else {
                RuleOutcome::Continue
            }
        },
    },
    Rule {
        id: "RE-002",
        description: "Block: prompt injection markers (common injection prefixes)",
        evaluate: |input| {
            const INJECTION_MARKERS: &[&str] = &[
                "ignore previous instructions",
                "ignore all prior",
                "disregard your",
                "forget everything above",
                "your new instructions are",
                "system: you are now",
                "### new system prompt",
                "---\nsystem:",
                "[system]",
                "<|system|>",
                "<|im_start|>system",
                // Normalised forms after aggressive leetspeak mapping in types.rs
                // where ASCII '|' is transformed to 'l'.
                "<lsysteml>",
                "<lim_startl>system",
                // LLM tokenizer / chat-template injection vectors
                "<|im_end|>",
                "<|endoftext|>",
                "<|im_start|>",
                "<lim_endl>",
                "<lendoftextl>",
                "<lim_startl>",
                "[inst]",
                "[/inst]",
                "<<sys>>",
                "<</sys>>",
                // ChatML / Llama-style role-prefix injection at line start
                "\nhuman:",
                "\nassistant:",
                "\n<|user|>",
                "\n<|assistant|>",
                "\n<luserl>",
                "\n<lassistantl>",
                // Soft injection via separator tokens
                "<s>",
                "</s>",
            ];
            if contains_any_ci(input, INJECTION_MARKERS) {
                RuleOutcome::Block(BlockReason::ForbiddenPattern {
                    pattern_id: "RE-002-INJECTION".to_string(),
                })
            } else {
                RuleOutcome::Continue
            }
        },
    },
    Rule {
        id: "RE-003",
        description: "Block: role-play / persona hijack attempts",
        evaluate: |input| {
            const HIJACK_PHRASES: &[&str] = &[
                "pretend you are",
                "act as if you are",
                "you are now",
                "roleplay as",
                "role-play as",
                "simulate being",
                "imagine you have no restrictions",
                "for educational purposes only, explain how to",
                "for educational purposes, explain how to",
                "hypothetically, if you had to",
                // Modern jailbreak persona-bypass phrases
                "as a large language model without",
                "as an llm without",
                "in developer mode",
                "enable developer mode",
                "dan mode",
                "jailbreak mode",
                "jailbroken mode",
                "your true self",
                "your real personality",
                "your real self",
                "without your restrictions",
                "without safety guidelines",
                "without content policy",
                "ignore your training",
                "ignore your guidelines",
                "ignore your safety",
                "override your instructions",
                "override your training",
                "override your safety",
                "you have been freed",
                "you are now free",
                "act without restrictions",
                "respond without restrictions",
                "answer without restrictions",
            ];
            if contains_any_ci(input, HIJACK_PHRASES) {
                RuleOutcome::Block(BlockReason::ForbiddenPattern {
                    pattern_id: "RE-003-HIJACK".to_string(),
                })
            } else {
                RuleOutcome::Continue
            }
        },
    },
    Rule {
        id: "RE-004",
        description: "Block: dangerous payload nouns in code/task context (SA-010)",
        evaluate: |input| {
            // These terms indicate malicious intent regardless of structural framing.
            // Diverse from Channel A: no regex, pure substring matching.
            const PAYLOAD_NOUNS: &[&str] = &[
                "malware",
                "mlware",
                "milware",
                "mllware",
                "ransomware",
                "keylogger",
                "rootkit",
                "backdoor",
                "shellcode",
                "exfiltrate",
                "exfiltration",
                "sql injection attack",
                "sql injection exploit",
                "perform sql injection",
                "performs sql injection",
                "performing sql injection",
                "execute sql injection",
                "inject sql",
                "sqli attack",
                "sqli exploit",
                "sql injection payload",
                "xss payload",
                "cross-site scripting",
                "buffer overflow exploit",
                "buffer overflow attack",
                "exploit buffer overflow",
                "exploits a buffer overflow",
                "exploits buffer overflow",
                "heap spray",
                "use-after-free",
                "perform path traversal",
                "execute path traversal",
                "exploit path traversal",
                "performs path traversal",
                "directory traversal exploit",
                "exploit directory traversal",
                "remote code execution",
                "arbitrary code execution",
                "deserialization exploit",
                "xml external entity",
                "xxe",
                "server-side request forgery",
                // "ssrf" alone hits "check for SSRF vulnerabilities" (defensive code) — use full phrase only.
                "ldap injection",
                "nosql injection",
                "xml injection",
                "os command injection",
                "command injection",
                "template injection",
                "ssti",
                "prototype pollution",
                "race condition exploit",
                "race condition attack",
                "exploits a race condition",
                "http request smuggling",
                "arp poison",
                "dns spoof",
                "dns poison",
                "man-in-the-middle",
                "mitm attack",
                "credential stuffing attack",
                "credential stuffing tool",
                "automates credential stuffing",
                "brute force attack",
                "brute-force attack",
                "brute force ssh",
                "brute force login",
                "wpa2 crack",
                "wpa crack",
                "wifi crack",
                "crack wpa",
                "crack wifi",
                "cracks wpa",
                "cracks wifi",
                "memory dump",
                "dump memory",
                "dumps memory",
                "process memory dump",
                "log4shell",
                "log4j exploit",
                "logashell",
                "logaj exploit",
                "subdomain takeover",
                "clickjack",
                "timing attack against",
                "supply chain attack",
                "watering hole",
                "typosquat",
                "polymorphic virus",
                "polymorphic malware",
                "evade antivirus",
                "evade av",
                "av evasion",
                "antivirus evasion",
                "evades antivirus",
                "evades detection",
                "deepfake porn",
                "deepfake pornograph",
                "non-consensual",
                "nonconsensual",
                "stalkerware",
                // "dox"/"doxx" as bare substrings hit "paradox", "orthodox", "unorthodox".
                // "dox and"/"doxx and" removed — hits "orthodox and" as substring.
                // Attack intent is covered by "doxxing", "dox someone", "dox the", "how to dox".
                "doxxing",
                "doxx someone",
                "dox someone",
                "dox the",
                "doxx the",
                "how to dox",
                "how to doxx",
                "track someone without",
                "tracks someone without",
                "track a person without",
                "tracks a person without",
                "launder money",
                "launders money",
                "money laundering",
                "pump and dump",
                "manipulate stock",
                "stock manipulation",
                "fake news article",
                "spread fake news",
                "disinformation campaign",
                "synthesize meth",
                "synthesize methamphetamine",
                "make a bomb",
                "build a bomb",
                "construct a bomb",
                "make chlorine gas",
                "make poison gas",
                "synthesize ricin",
                "make ricin",
                "illegal firearm",
                "acquire illegal",
                "intercept network traffic",
                "intercept traffic",
                // Technische Euphemismen für Angriffe (GAP-16)
                "network penetration without",
                "unauthorized network penetration",
                "penetration without permission",
                "penetration test without permission",
                "perform network penetration",
                "performing network penetration",
                "privilege escalation",
                "privesc",
                "reverse shell",
                "bind shell",
                // Privilege escalation synonyms — attackers avoid the exact term
                "gain elevated access",
                "gain root access",
                "gain admin access",
                "gain administrator access",
                "gain superuser access",
                "elevate my privileges",
                "elevate privileges",
                "escalate privileges",
                "escalate my privileges",
                "get root access",
                "get admin access",
                "get administrator access",
                "become root",
                "become admin",
                "become administrator",
                "without the admin password",
                "without admin password",
                "without root password",
                "bypass authentication",
                "bypass auth",
                "bypasses auth",
                "bypasses authentication",
                "bypass 2fa",
                "bypasses 2fa",
                "bypass mfa",
                "bypasses mfa",
                "session fixation",
                "bypass firewall",
                "bypass filter",
                "command and control",
                "c2 server",
                "lateral movement",
                "hack into",
                "hacks into",
                // "steal"/"steals" bare hits "steal the show", "steal a march" etc.
                "steal data",
                "steal the data",
                "steals data",
                "steals the data",
                "steal personal information",
                "steal sensitive information",
                "steal sensitive user",
                "steals personal information",
                "steals sensitive information",
                "steals sensitive user",
                "steal token",
                "steals token",
                "harvest credentials",
                "harvest passwords",
                "harvest tokens",
                "harvests credentials",
                "harvests passwords",
                "harvests tokens",
                "harvest sensitive information",
                "harvests sensitive information",
                "harvests and sells",
                "extract credential",
                "extract password",
                "extract token",
                "dump credential",
                "dump password",
                "dump token",
                "all passwords",
                "all credentials",
                // "spoof"/"spoofs" bare hits "anti-spoofing", "spoof detection" (defensive).
                "spoof a",
                "spoof the",
                "spoofs a",
                "spoofs the",
                "email spoofing attack",
                "arp spoofing",
                "dns spoofing attack",
                "ip spoofing",
                "mac spoofing",
                "phishing",
                "phish",
                "ddos",
                "denial of service",
                "cyberattack",
                "cyber attack",
                "exploit vulnerabilit",
                "unauthorized access",
                "stalk and harass",
                "spread misinformation",
                "spread false information",
                "spread propaganda",
                "manipulate financial",
                "commit fraud",
                "commit tax fraud",
                "glorify violence",
                "glorify terrorism",
                "glorify abuse",
                "glorify harm",
                "glorify suicide",
                "glorifies violence",
                "glorifies terrorism",
                "glorifies abuse",
                "glorifies harm",
                "glorifies suicide",
                "romanticize violence",
                "romanticize abuse",
                "romanticize harm",
                "romanticize suicide",
                "romanticizes violence",
                "romanticizes terrorism",
                "romanticizes abuse",
                "romanticizes harm",
                "romanticizes suicide",
                "romanticise",
                "romanticises",
                "suicide",
                "crash a computer",
                "crash the computer",
                "permanently delet",
                "phone scam",
                "scam that tricks",
                "social engineering attack",
                "hate speech",
                "spam email",
                "distribution of spam",
                "automates the process of hacking",
                "automate fake",
                "automate the creation of fake",
                "tricks users into revealing",
                "erotic",
                "bestiality",
                "sexual content involving",
                "facial recognition to",
                "denies access",
                "deny access",
                "unwanted and unsolicited",
                "unsolicited messages",
                // ── Multilingual attack keywords (SA-066 / Gap 3) ────────────────
                // Symmetric with FP-003 in Channel A. Diverse implementation:
                // Channel B uses contains_any_ci_fuzzy (stripped alphanumeric match),
                // Channel A uses contains_fuzzy (noise-tolerant sequential scan).
                //
                // ── Deutsch (DE) ─────────────────────────────────────────────────
                "schadcode",
                "schadsoftware",
                "trojaner",
                "keylogger erstellen",
                "rootkit erstellen",
                "backdoor erstellen",
                "virus erstellen",
                "wurm erstellen",
                "botnetz",
                "angriff",
                "angreifen",
                "hacken",
                "eindringen",
                "ausnutzen",
                "ausnutzung",
                "schwachstelle ausnutzen",
                "sicherheitslucke ausnutzen",
                "sicherheitslücke ausnutzen",
                "system kompromittieren",
                "rechner kompromittieren",
                "unbefugten zugang",
                "passwort knacken",
                "passwort cracken",
                "passwort stehlen",
                "zugangsdaten stehlen",
                "zugangsdaten abgreifen",
                "daten stehlen",
                "daten exfiltrieren",
                "daten abgreifen",
                "netzwerk infiltrieren",
                "netzwerk angreifen",
                "ddos angriff",
                "denial of service angriff",
                "phishing angriff",
                "phishing mail erstellen",
                "social engineering angriff",
                "schadsoftware verbreiten",
                "virus verbreiten",
                "malware installieren",
                "trojaner installieren",
                "hintertür einbauen",
                "hintertür erstellen",
                "hintertuer einbauen",
                "hintertuer erstellen",
                "rechteausweitung",
                "sql injektion",
                "sql-injektion",
                "pufferuberlauf",
                "pufferüberlauf",
                "man-in-the-middle angriff",
                "brute-force angriff",
                "worterbuch angriff",
                "wörterbuchangriff",
                "bombe bauen",
                "sprengstoff herstellen",
                "waffe herstellen",
                "waffe bauen",
                "drogen herstellen",
                "drogen synthetisieren",
                "betrug begehen",
                "identitatsdiebstahl",
                "identitätsdiebstahl",
                "geldwäsche",
                "geldwasche",
                "erpressung",
                "erpressungssoftware",
                "piraterie",
                "schadhaft",
                "schadlich",
                "schädlich",
                // ── Français (FR) ────────────────────────────────────────────────
                "logiciel malveillant",
                "logiciel malicieux",
                "rançongiciel",
                "rancongiciel",
                "cheval de troie",
                "enregistreur de frappe",
                "porte dérobée",
                "porte derobee",
                "pirater",
                "pirater un",
                "pirater le",
                "pirater la",
                "attaque informatique",
                "cyberattaque",
                "exploiter une faille",
                "exploiter la faille",
                "exploiter une vulnérabilité",
                "exploiter une vulnerabilite",
                "compromettre un système",
                "compromettre le système",
                "acces non autorise",
                "accès non autorisé",
                "voler des données",
                "voler les données",
                "voler des identifiants",
                "voler des mots de passe",
                "exfiltrer des données",
                "exfiltrer les données",
                "infiltrer le réseau",
                "infiltrer un réseau",
                "attaque ddos",
                "déni de service",
                "deni de service",
                "hameçonnage",
                "hameconnage",
                "ingénierie sociale",
                "ingenierie sociale",
                "injection sql",
                "injection de code",
                "débordement de tampon",
                "debordement de tampon",
                "attaque par force brute",
                "attaque par dictionnaire",
                "élévation de privilèges",
                "elevation de privileges",
                "fabriquer une bombe",
                "fabriquer des explosifs",
                "fabriquer une arme",
                "fabriquer de la drogue",
                "synthétiser de la drogue",
                "synthetiser de la drogue",
                "commettre une fraude",
                "vol d'identité",
                "vol d identite",
                "blanchiment d'argent",
                "blanchiment argent",
                "malicieux",
                "malveillant",
                "supprimer les données",
                // ── Español (ES) ─────────────────────────────────────────────────
                "software malicioso",
                "programa malicioso",
                "troyano informatico",
                "troyano crear",
                "registrador de teclas",
                "puerta trasera",
                "piratear",
                "hackear",
                "hackear un",
                "hackear el",
                "hackear la",
                "ataque informatico",
                "ataque cibernético",
                "ataque cibernetico",
                "explotar una vulnerabilidad",
                "explotar el sistema",
                "comprometer el sistema",
                "comprometer un sistema",
                "acceso no autorizado",
                "robar datos",
                "robar contraseñas",
                "robar contrasenas",
                "robar credenciales",
                "robar información",
                "robar informacion",
                "exfiltrar datos",
                "exfiltrar información",
                "infiltrar la red",
                "infiltrar el sistema",
                "ataque ddos",
                "denegación de servicio",
                "denegacion de servicio",
                "phishing crear",
                "correo de phishing",
                "ingeniería social",
                "ingenieria social",
                "inyección sql",
                "inyeccion sql",
                "desbordamiento de búfer",
                "desbordamiento de buffer",
                "ataque de fuerza bruta",
                "ataque de diccionario",
                "escalada de privilegios",
                "escalamiento de privilegios",
                "fabricar una bomba",
                "fabricar explosivos",
                "fabricar un arma",
                "fabricar drogas",
                "sintetizar drogas",
                "sintetizar metanfetamina",
                "cometer fraude",
                "robo de identidad",
                "lavado de dinero",
                "blanqueo de dinero",
                // ── Русский (RU) ─────────────────────────────────────────────────
                "вредоносный код",
                "вредоносное по",
                "троян",
                "взлом",
                "взломать",
                "взломай",
                "хакинг",
                "атака",
                "атаковать",
                "кибератака",
                "эксплойт",
                "использовать уязвимость",
                "скомпрометировать",
                "неавторизованный доступ",
                "украсть данные",
                "украсть пароли",
                "украсть учетные",
                "утечка данных",
                "эксфильтрация данных",
                "ddos атака",
                "фишинг",
                "социальная инженерия",
                "sql инъекция",
                "переполнение буфера",
                "брутфорс атака",
                "перебор паролей",
                "создать бомбу",
                "синтез наркотиков",
                "мошенничество",
                "кража личности",
                "отмывание денег",
                // ── العربية (AR) ─────────────────────────────────────────────────
                "كود خبيث",
                "برمجيات خبيثة",
                "حصان طروادة",
                "اختراق",
                "اخترق",
                "قرصنة",
                "هجوم إلكتروني",
                "استغلال",
                "استغال ثغرة",
                "اختراق النظام",
                "غير مصرح بالوصول",
                "سرقة بيانات",
                "تسريب بيانات",
                "هجوم رفض الخدمة",
                "فيشينغ",
                "هندسة اجتماعية",
                "حقن sql",
                "فيض المصد",
                "هجوم القوة الغاشمة",
                "تخمين كلمات المرور",
                "صنع قنبلة",
                "تصنيع مخدرات",
                "احتيال",
                "سرقة هوية",
                "غسيل أموال",
                // ── 中文 (CN) ─────────────────────────────────────────────────────
                "恶意软件",
                "病毒",
                "木马",
                "后门",
                "黑客",
                "破解",
                "入侵",
                "攻击",
                "网络攻击",
                "漏洞利用",
                "系统入侵",
                "未授权访问",
                "权限获取",
                "权限昇格",
                "窃取数据",
                "盗取密码",
                "盗取凭据",
                "数据泄露",
                "数据外泄",
                "ddos攻击",
                "拒绝服务",
                "钓鱼",
                "社会工程",
                "sql注入",
                "缓冲区溢出",
                "暴力破解",
                "密码破解",
                "制作炸弹",
                "爆炸物制造",
                "药物制造",
                "欺诈",
                "身份盗窃",
                "洗钱",
                // ── 日本語 (JA) ───────────────────────────────────────────────────
                "マルウェア",
                "ウイルス",
                "トロイの木馬",
                "バックドア",
                "ハッキング",
                "クラッキング",
                "侵入",
                "サイバー攻撃",
                "エクスプロイト",
                "脆弱性を突く",
                "システム侵犯",
                "不正アクセス",
                "権限取得",
                "権限昇格",
                "データ窃取",
                "パスワード盗む",
                "認証情報盗む",
                "データ漏洩",
                "情報流出",
                "ddos攻撃",
                "サービス拒否",
                "フィッシング",
                "ソーシャルエンジニアリング",
                "sqlインジェクション",
                "インジェクション攻撃",
                "バッファオーバーフロー",
                "ブルートフォース",
                "パスワードクラック",
                "爆弾作成",
                "爆発物製造",
                "ドラッグ製造",
                "詐欺",
                "アイデンティティ泥棒",
                "資金洗浄",
            ];
            if contains_any_ci_fuzzy(input, PAYLOAD_NOUNS) {
                RuleOutcome::Block(BlockReason::ForbiddenPattern {
                    pattern_id: "RE-004-PAYLOAD".to_string(),
                })
            } else {
                RuleOutcome::Continue
            }
        },
    },
    Rule {
        id: "RE-005",
        description: "Block: sensitive system resource targets (SA-010)",
        evaluate: |input| {
            // Blocks requests targeting sensitive files/resources even when
            // framed as legitimate tasks (e.g. "extract all data from /etc/passwd").
            // Diverse from Channel A: no regex, pure substring matching.
            const SENSITIVE_TARGETS: &[&str] = &[
                "/etc/passwd",
                "/etc/shadow",
                "/etc/sudoers",
                "id_rsa",
                "id_ed25519",
                ".ssh/",
                "aws_secret",
                "aws_access_key",
                "awssecret",
                "awsaccesskey", // separator-stripped forms (SA-045)
                ".env file",
                "secret key",
                "private key",
                "api key",
                "auth token",
                "bearer token",
                "database password",
                "db password",
                "db_password",
                "dbpassword",
                "connection string",
                "jdbc:",
                "mongodb://",
            ];
            if contains_any_ci_fuzzy(input, SENSITIVE_TARGETS) {
                RuleOutcome::Block(BlockReason::ForbiddenPattern {
                    pattern_id: "RE-005-SENSITIVE-TARGET".to_string(),
                })
            } else {
                RuleOutcome::Continue
            }
        },
    },
    Rule {
        id: "RE-006",
        description: "Block: zero-width and invisible Unicode formatting characters (SA-019)",
        // Zero-width characters (ZWSP U+200B, ZWNJ U+200C, ZWJ U+200D, ZWNBSP U+FEFF,
        // Word Joiner U+2060) are invisible to humans but split keyword substrings,
        // bypassing FP-003/FP-004 substring checks.
        // Example: "mal\u{200B}ware" passes FP-003 ("malware" not found as substring)
        // but is visually indistinguishable from "malware".
        //
        // Diverse from Channel A FP-005: Channel B uses a char-category scan,
        // Channel A uses a codepoint-range check — different implementation paths.
        //
        // SA-019 | CR-2026-002
        evaluate: |input| {
            // Zero-width and invisible formatting characters that can split keywords:
            //   U+200B ZERO WIDTH SPACE
            //   U+200C ZERO WIDTH NON-JOINER
            //   U+200D ZERO WIDTH JOINER
            //   U+FEFF ZERO WIDTH NO-BREAK SPACE (BOM — suspicious in any position in a prompt)
            //   U+2060 WORD JOINER
            //   U+00AD SOFT HYPHEN (invisible, can split tokens in some renderers)
            // Note: U+FEFF is blocked at all positions. (G-24)
            const ZERO_WIDTH_CHARS: &[char] = &[
                '\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}', '\u{2060}', '\u{00AD}',
            ];
            if input.chars().any(|c| ZERO_WIDTH_CHARS.contains(&c)) {
                RuleOutcome::Block(BlockReason::MalformedInput {
                    detail: "zero-width or invisible formatting character detected".into(),
                })
            } else {
                RuleOutcome::Continue
            }
        },
    },
    Rule {
        id: "RE-007",
        description: "Block: Unicode Bidirectional override/isolate characters (SA-030)",
        // Bidi override characters (U+202E RIGHT-TO-LEFT OVERRIDE etc.) are used in
        // visual spoofing attacks: "Write a \u{202E}erawlam function" renders as
        // "Write a malware function" in RTL-aware renderers. FP-003 does not catch
        // the reversed string — blocking Bidi overrides closes this gap.
        //
        // Diverse from Channel A FP-007: Channel B uses a char-set scan,
        // Channel A uses a matches! macro — different implementation paths.
        //
        // SA-030
        evaluate: |input| {
            const BIDI_CHARS: &[char] = &[
                '\u{202A}', // LEFT-TO-RIGHT EMBEDDING
                '\u{202B}', // RIGHT-TO-LEFT EMBEDDING
                '\u{202C}', // POP DIRECTIONAL FORMATTING
                '\u{202D}', // LEFT-TO-RIGHT OVERRIDE
                '\u{202E}', // RIGHT-TO-LEFT OVERRIDE (primary attack vector)
                '\u{2066}', // LEFT-TO-RIGHT ISOLATE
                '\u{2067}', // RIGHT-TO-LEFT ISOLATE
                '\u{2068}', // FIRST STRONG ISOLATE
                '\u{2069}', // POP DIRECTIONAL ISOLATE
                '\u{200E}', // LEFT-TO-RIGHT MARK
                '\u{200F}', // RIGHT-TO-LEFT MARK
            ];
            if input.chars().any(|c| BIDI_CHARS.contains(&c)) {
                RuleOutcome::Block(BlockReason::MalformedInput {
                    detail: "bidirectional override or isolate character detected".into(),
                })
            } else {
                RuleOutcome::Continue
            }
        },
    },
    Rule {
        id: "RE-008",
        description:
            "Block: Unicode Tag characters (U+E0000–U+E007F) — invisible keyword injection (SA-045)",
        // Tag characters are invisible and not removed by NFKC. An attacker can
        // spell keywords entirely in tag characters, bypassing all content checks.
        // Example: "malware" as tag-m tag-a tag-l tag-w tag-a tag-r tag-e passes
        // FP-003/RE-004 because the normalised string contains no ASCII keyword.
        // Blocking tag characters as a structural violation closes this gap.
        //
        // Diverse from Channel A FP-008: Channel B uses a char-range scan,
        // Channel A uses a matches! macro — different implementation paths.
        //
        // SA-045
        evaluate: |input| {
            if input
                .chars()
                .any(|c| (0xE0000..=0xE007F).contains(&(c as u32)))
            {
                RuleOutcome::Block(BlockReason::MalformedInput {
                    detail: "unicode tag character detected".into(),
                })
            } else {
                RuleOutcome::Continue
            }
        },
    },
    Rule {
        id: "RE-013",
        description: "Allow: data extraction request (structural markers) — diverse from IP-013",
        // Diverse from Channel A IP-013: no regex, pure keyword matching.
        // Block rules RE-004/RE-005 already ran — sensitive targets and payload
        // keywords are already blocked before we reach here.
        // Matches: "extract/pull out/list all/find all/get all ... from/in ..."
        // Requires both an extraction verb and a source preposition to avoid
        // over-matching bare "list all" or "find all" without a target.
        evaluate: |input| {
            let has_extraction_verb = contains_any_ci(
                input,
                &[
                    "extract",
                    "pull out",
                    "list all",
                    "find all",
                    "get all",
                    "retrieve all",
                ],
            );
            let has_source_prep = contains_any_ci(input, &[" from ", " in "]);
            if has_extraction_verb && has_source_prep && word_count(input) <= 80 {
                RuleOutcome::Pass(MatchedIntent::TaskDataExtraction)
            } else {
                RuleOutcome::Continue
            }
        },
    },
    Rule {
        id: "RE-010",
        description: "Allow: single-sentence factual question (ends with ?, ≤ 40 words)",
        evaluate: |input| {
            if ends_with_question_mark(input)
                && word_count(input) <= 40
                && contains_any_ci(
                    input,
                    &[
                        "what",
                        "who",
                        "where",
                        "when",
                        "which",
                        "how many",
                        "how much",
                        // "can you explain X?" / "could you explain X?" are factual questions
                        // that don't start with a wh-word but are structurally safe.
                        "can you explain",
                        "could you explain",
                        "please explain",
                    ],
                )
            {
                RuleOutcome::Pass(MatchedIntent::QuestionFactual)
            } else {
                RuleOutcome::Continue
            }
        },
    },
    Rule {
        id: "RE-011",
        description: "Allow: causal question",
        evaluate: |input| {
            let wc = word_count(input);
            // Imperativ "Explain X." — kein Fragezeichen nötig
            if wc <= 60 && starts_with_any_ci(input, &["explain "]) {
                return RuleOutcome::Pass(MatchedIntent::QuestionCausal);
            }
            if ends_with_question_mark(input)
                && wc <= 60
                && starts_with_any_ci(
                    input,
                    &[
                        "why",
                        "how does",
                        "how do",
                        "what causes",
                        "explain why",
                        "explain ",
                    ],
                )
            {
                RuleOutcome::Pass(MatchedIntent::QuestionCausal)
            } else {
                RuleOutcome::Continue
            }
        },
    },
    Rule {
        id: "RE-012",
        description: "Allow: comparison request",
        evaluate: |input| {
            if contains_any_ci(
                input,
                &[
                    "compare",
                    "versus",
                    " vs ",
                    "difference between",
                    "better than",
                    "worse than",
                ],
            ) && word_count(input) <= 80
            {
                RuleOutcome::Pass(MatchedIntent::QuestionComparative)
            } else {
                RuleOutcome::Continue
            }
        },
    },
    Rule {
        id: "RE-020",
        description: "Allow: code generation request (structural markers)",
        evaluate: |input| {
            let has_task_verb = contains_any_ci(
                input,
                &[
                    "write a",
                    "write the",
                    "create a",
                    "create the",
                    "generate a",
                    "generate the",
                    "implement a",
                    "implement the",
                    "implement ",
                    "build a",
                    "build the",
                    "code a",
                ],
            );
            let has_code_noun = contains_any_ci(
                input,
                &[
                    "function",
                    "class",
                    "module",
                    "script",
                    "algorithm",
                    "program",
                    "snippet",
                    "linked list",
                    "parser",
                    "generator",
                    "validator",
                    "middleware",
                    "handler",
                    "rate limiter",
                    "rate-limiter",
                    "input validation",
                    "sanitizer",
                ],
            );
            if has_task_verb && has_code_noun && word_count(input) <= 100 {
                RuleOutcome::Pass(MatchedIntent::TaskCodeGeneration)
            } else {
                RuleOutcome::Continue
            }
        },
    },
    Rule {
        id: "RE-021",
        description: "Allow: summarisation request",
        evaluate: |input| {
            if contains_any_ci(
                input,
                &[
                    "summarize",
                    "summarise",
                    "summary",
                    "tl;dr",
                    "tldr",
                    "key points",
                    "condense",
                ],
            ) && word_count(input) <= 60
            {
                RuleOutcome::Pass(MatchedIntent::TaskTextSummarisation)
            } else {
                RuleOutcome::Continue
            }
        },
    },
    Rule {
        id: "RE-022",
        description: "Allow: translation request",
        evaluate: |input| {
            // Note: NFKC + combining-strip normalisation (SA-038/SA-039) strips
            // diacritics: "Übersetze" → "Ubersetze", "übersetz" → "ubersetz".
            // Both the original Unicode and the stripped ASCII forms are listed.
            if contains_any_ci(
                input,
                &[
                    "translate",
                    "ubersetz",
                    "ubersetze", // post-normalisation (SA-038: Ü→U)
                    "übersetz",
                    "übersetze", // pre-normalisation (direct input)
                    "traduire",
                    "traduisez",
                    "traduce",
                    "traduc",
                    "vertaal",
                    "traduci",
                ],
            ) && word_count(input) <= 80
            {
                RuleOutcome::Pass(MatchedIntent::TaskTranslation)
            } else {
                RuleOutcome::Continue
            }
        },
    },
    Rule {
        id: "RE-030",
        description: "Allow: short greeting (≤ 5 words, known greeting token)",
        evaluate: |input| {
            if word_count(input) <= 5
                && starts_with_any_ci(
                    input,
                    &[
                        "hi",
                        "hello",
                        "hey",
                        "good morning",
                        "good afternoon",
                        "good evening",
                        "moin",
                        "hallo",
                        "servus",
                    ],
                )
            {
                RuleOutcome::Pass(MatchedIntent::ConversationalGreeting)
            } else {
                RuleOutcome::Continue
            }
        },
    },
    Rule {
        id: "RE-031",
        description: "Allow: short acknowledgement (≤ 4 words) — multilingual (SA-020)",
        // SA-020: Extended with common multilingual acknowledgement tokens so that
        // Channel B agrees with Channel A (IP-021) on these inputs, avoiding
        // unnecessary DiagnosticDisagreement events and operator load.
        // Added: merci (FR), gracias (ES), arigato/arigatou (JA romanised),
        //        grazie (IT), obrigado/obrigada (PT), spasibo (RU romanised),
        //        shukran (AR romanised), dankon (EO), tak (DA/NO), tack (SV).
        evaluate: |input| {
            if word_count(input) <= 4
                && starts_with_any_ci(
                    input,
                    &[
                        // English
                        "ok",
                        "okay",
                        "thanks",
                        "thank you",
                        "got it",
                        "sure",
                        // German
                        "danke",
                        // French
                        "merci",
                        // Spanish
                        "gracias",
                        // Italian
                        "grazie",
                        // Portuguese
                        "obrigado",
                        "obrigada",
                        // Japanese (romanised)
                        "arigato",
                        "arigatou",
                        "arigatō",
                        // Russian (romanised)
                        "spasibo",
                        // Arabic (romanised)
                        "shukran",
                        // Scandinavian
                        "tak",
                        "tack",
                    ],
                )
            {
                RuleOutcome::Pass(MatchedIntent::ConversationalAcknowledgement)
            } else {
                RuleOutcome::Continue
            }
        },
    },
    Rule {
        id: "RE-040",
        description: "Allow: system meta-query",
        evaluate: |input| {
            if contains_any_ci(
                input,
                &[
                    "what model",
                    "what version",
                    "who made you",
                    "who built you",
                    "what can you do",
                    "what are your capabilities",
                ],
            ) && word_count(input) <= 20
            {
                RuleOutcome::Pass(MatchedIntent::SystemMetaQuery)
            } else {
                RuleOutcome::Continue
            }
        },
    },
    // ── CR-2026-001: IP-050 / IP-099 allow rules ─────────────────────────────
    Rule {
        id: "RE-050",
        description:
            "Allow: structured output request (JSON/XML/CSV/YAML schema) — diverse from IP-050",
        evaluate: |input| {
            // Diverse from Channel A IP-050: no regex, pure keyword matching.
            // Block rules RE-004/RE-005 already ran — if we reach here, no payload
            // keywords were found. We apply an additional guard symmetric with
            // Channel A's ip050_guard: reject disqualifying signals not already
            // covered by RE-004/RE-005 (e.g. "dump all", "listing all", schema-injection
            // framing, prompt-injection via field names).
            let has_output_verb = contains_any_ci(
                input,
                &[
                    "generate", "create", "produce", "output", "return", "format", "give me",
                ],
            );
            let has_format_noun = contains_any_ci(
                input,
                &[
                    "json",
                    "xml",
                    "csv",
                    "yaml",
                    "schema",
                    "structured",
                    "table",
                ],
            );
            if has_output_verb && has_format_noun && word_count(input) <= 80 {
                // Post-match guard (symmetric with Channel A ip050_guard):
                // reject schema-injection / exfiltration framing not caught by RE-004/RE-005.
                // G-19/G-21: "all keys" replaced with precise variants —
                // "all keys" alone blocks legitimate schema requests like
                // "list all keys required" or "map.keys()". Use targeted phrases.
                const DISQUALIFY: &[&str] = &[
                    "dump all",
                    "dump the",
                    "dumps all",
                    "extract all secrets",
                    "listing all",
                    "all secrets",
                    "all tokens",
                    "all api keys",
                    "all secret keys",
                    "all auth keys",
                    "all credentials",
                    "all passwords",
                    "all keys from",
                    "ignore previous",
                    "disregard your",
                    "forget everything",
                    "system prompt",
                    "your instructions",
                ];
                if contains_any_ci(input, DISQUALIFY) {
                    return RuleOutcome::Block(BlockReason::ForbiddenPattern {
                        pattern_id: "RE-050-GUARD".to_string(),
                    });
                }
                RuleOutcome::Pass(MatchedIntent::StructuredOutput)
            } else {
                RuleOutcome::Continue
            }
        },
    },
    Rule {
        id: "RE-060",
        description:
            "Allow: agentic tool use request (function/tool execution) — diverse from IP-060",
        evaluate: |input| {
            // Diverse from Channel A IP-060: no regex, pure keyword matching.
            let has_tool_verb = contains_any_ci(
                input,
                &["use", "call", "invoke", "execute", "trigger", "run"],
            );
            let has_tool_noun = contains_any_ci(input, &["tool", "function", "plugin", "action"]);
            if has_tool_verb && has_tool_noun && word_count(input) <= 60 {
                RuleOutcome::Pass(MatchedIntent::AgenticToolUse)
            } else {
                RuleOutcome::Continue
            }
        },
    },
    Rule {
        id: "RE-099",
        description:
            "Allow: controlled creative request (story/poem/narrative) — diverse from IP-099",
        evaluate: |input| {
            // Diverse from Channel A IP-099: no regex, pure keyword matching.
            // Block rules RE-003/RE-004 already ran — persona hijack and payload
            // keywords are already blocked before we reach here. We apply an
            // additional guard symmetric with Channel A's ip099_guard: reject
            // soft persona-hijack framing and restriction-bypass signals not
            // already covered by RE-003.
            let has_creative_verb =
                contains_any_ci(input, &["write", "tell me", "create", "compose"]);
            let has_creative_noun = contains_any_ci(
                input,
                &[
                    "a story",
                    "a short story",
                    "a poem",
                    "a haiku",
                    "a limerick",
                    "a narrative",
                    "a tale",
                    "a fable",
                ],
            );
            if has_creative_verb && has_creative_noun && word_count(input) <= 60 {
                // Post-match guard (symmetric with Channel A ip099_guard):
                // reject soft restriction-bypass framing not caught by RE-003/RE-004.
                const DISQUALIFY: &[&str] = &[
                    "no restrictions",
                    "no filters",
                    "no safety",
                    "no rules",
                    "unrestricted",
                    "uncensored",
                    "unfiltered",
                    "as an ai without",
                    "as an ai that can",
                    // Indirect delegation — creative wrapper used to delegate harmful task
                    "who explains how to",
                    "who teaches how to",
                    "who shows how to",
                    "who demonstrates how to",
                    "that explains how to",
                    "that teaches how to",
                    "that shows how to",
                    "that demonstrates how to",
                    "where a character",
                    "where the character",
                    "in which a character",
                    "in which the character",
                ];
                if contains_any_ci(input, DISQUALIFY) {
                    return RuleOutcome::Block(BlockReason::ForbiddenPattern {
                        pattern_id: "RE-099-GUARD".to_string(),
                    });
                }
                RuleOutcome::Pass(MatchedIntent::ControlledCreative)
            } else {
                RuleOutcome::Continue
            }
        },
    },
];
