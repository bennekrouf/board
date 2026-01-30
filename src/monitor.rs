#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use regex::Regex;

#[cfg(target_os = "linux")]
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq)]
pub enum FirewallStatus {
    Open,
    Closed,
    Unknown,
    Limit, // ufw 'LIMIT'
    Deny, // ufw 'DENY'
}

#[derive(Debug, Clone)]
pub struct NetworkEntry {
    pub protocol: String,
    pub port: u16,
    pub process: String,
    pub pid: String,
    pub firewall_status: FirewallStatus,
}

#[derive(Debug, Clone)]
pub struct Pm2Process {
    pub name: String,
    pub pid: String,
    pub status: String,
    pub memory: String,
    pub cpu: String,
    pub log_path: String,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize, Debug)]
struct Pm2RawEntry {
    name: String,
    pid: Option<u32>,
    pm2_env: Pm2RawEnv,
    monit: Option<Pm2Monit>,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize, Debug)]
struct Pm2RawEnv {
    status: String,
    pm_out_log_path: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize, Debug)]
struct Pm2Monit {
    memory: Option<u64>,
    cpu: Option<f32>,
}

pub fn fetch_data() -> (Vec<NetworkEntry>, Vec<Pm2Process>) {
    let net = {
        #[cfg(target_os = "linux")]
        {
            fetch_linux_data()
        }
        #[cfg(not(target_os = "linux"))]
        {
            fetch_mock_data()
        }
    };
    
    let pm2 = {
        #[cfg(target_os = "linux")]
        {
            fetch_pm2_data()
        }
        #[cfg(not(target_os = "linux"))]
        {
            fetch_mock_pm2_data()
        }
    };
    
    (net, pm2)
}

pub fn get_process_logs(path: &str, lines: usize) -> Vec<String> {
    if path.is_empty() {
        return vec!["No log path available".to_string()];
    }

    // Mock logs for non-linux or specific mock paths
    if !std::path::Path::new(path).exists() {
         return vec![
            format!("Mock logs for {}", path),
            "Log line 1...".to_string(),
            "Log line 2...".to_string(),
            "Log line 3 [ERROR] something happened".to_string(),
            "Log line 4...".to_string(),
        ];
    }
    
    match std::fs::read_to_string(path) {
        Ok(content) => {
            content.lines()
                .rev()
                .take(lines)
                .collect::<Vec<&str>>()
                .into_iter()
                .rev()
                .map(|s| s.to_string())
                .collect()
        }
        Err(e) => vec![format!("Error reading logs: {}", e)],
    }
}

fn fetch_mock_pm2_data() -> Vec<Pm2Process> {
    vec![
        Pm2Process {
            name: "api-server".to_string(),
            pid: "1234".to_string(),
            status: "online".to_string(),
            memory: "45.2 MB".to_string(),
            cpu: "0.5%".to_string(),
            log_path: "/tmp/api-server.log".to_string(),
        },
        Pm2Process {
            name: "background-worker".to_string(),
            pid: "5678".to_string(),
            status: "online".to_string(),
            memory: "120.5 MB".to_string(),
            cpu: "1.2%".to_string(),
            log_path: "/tmp/bg-worker.log".to_string(),
        },
        Pm2Process {
            name: "updater".to_string(),
            pid: "0".to_string(),
            status: "stopped".to_string(),
            memory: "0 B".to_string(),
            cpu: "0%".to_string(),
            log_path: "".to_string(),
        },
    ]
}

#[cfg(target_os = "linux")]
fn fetch_pm2_data() -> Vec<Pm2Process> {
    // Command: pm2 jlist
    let output = match Command::new("pm2")
        .arg("jlist")
        .output() {
        Ok(o) => o.stdout,
        Err(_) => return vec![],
    };

    let raw: Vec<Pm2RawEntry> = match serde_json::from_slice(&output) {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    raw.into_iter().map(|r| {
        let mem = r.monit.as_ref().and_then(|m| m.memory).unwrap_or(0);
        let cpu = r.monit.as_ref().and_then(|m| m.cpu).unwrap_or(0.0);
        
        let mem_str = if mem > 1024 * 1024 {
            format!("{:.1} MB", mem as f64 / 1024.0 / 1024.0)
        } else if mem > 1024 {
            format!("{:.1} KB", mem as f64 / 1024.0)
        } else {
            format!("{} B", mem)
        };

        Pm2Process {
            name: r.name,
            pid: r.pid.map(|p| p.to_string()).unwrap_or_else(|| "0".to_string()),
            status: r.pm2_env.status,
            memory: mem_str,
            cpu: format!("{:.1}%", cpu),
            log_path: r.pm2_env.pm_out_log_path.unwrap_or_default(),
        }
    }).collect()
}

// Mock data for development on macOS
fn fetch_mock_data() -> Vec<NetworkEntry> {
    vec![
        NetworkEntry {
            protocol: "tcp".to_string(),
            port: 22,
            process: "sshd".to_string(),
            pid: "1234".to_string(),
            firewall_status: FirewallStatus::Open,
        },
        NetworkEntry {
            protocol: "tcp".to_string(),
            port: 80,
            process: "nginx".to_string(),
            pid: "5678".to_string(),
            firewall_status: FirewallStatus::Open,
        },
         NetworkEntry {
            protocol: "udp".to_string(),
            port: 53,
            process: "systemd-resolve".to_string(),
            pid: "999".to_string(),
            firewall_status: FirewallStatus::Closed,
        },
        NetworkEntry {
            protocol: "tcp".to_string(),
            port: 3000,
            process: "node_app".to_string(),
            pid: "4321".to_string(),
            firewall_status: FirewallStatus::Unknown,
        },
    ]
}

#[cfg(target_os = "linux")]
fn fetch_linux_data() -> Vec<NetworkEntry> {
    // 1. Fetch Listening Ports via `ss`
    // Command: ss -lntupH
    // Output format (approx): Note: requires sudo for PID usually
    // State   Recv-Q   Send-Q     Local Address:Port      Peer Address:Port   Process
    //
    // Example:
    // LISTEN  0        4096       127.0.0.53%lo:53             0.0.0.0:*       users:(("systemd-resolve",pid=588,fd=13))
    // LISTEN  0        128              0.0.0.0:22             0.0.0.0:*       users:(("sshd",pid=765,fd=3))

    let ss_output = match Command::new("ss")
        .args(&["-lntupH"]) // H for no header
        .output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return vec![], 
    };

    let mut entries = parse_ss_output(&ss_output);

    // 2. Fetch Firewall Status via `sudo ufw status`
    // Command: sudo ufw status
    // Output:
    // Status: active
    //
    // To                         Action      From
    // --                         ------      ----
    // 22/tcp                     ALLOW       Anywhere
    // 80/tcp                     ALLOW       Anywhere
    let ufw_output = match Command::new("sudo")
        .args(&["ufw", "status"])
        .output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => "".to_string(),
    };
    
    // Parse UFW and update entries
    update_firewall_status(&mut entries, &ufw_output);

    entries
}

#[cfg(target_os = "linux")]
fn parse_ss_output(output: &str) -> Vec<NetworkEntry> {
    let mut entries = Vec::new();
    // Simplified regex for basic ss output
    // Looking for: Local Address:Port
    // And users:(("proc",pid=123,
    
    // Address regex:  (\S+):(\d+)
    // Process regex: users:\(\("([^"]+)",pid=(\d+)
    // Protocol is usually implicit in the socket type but ss -lntup shows tcp/udp if we look at the start?
    // Actually `ss -lntu` output is:
    // Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
    // tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*         users:(("sshd",pid=123,fd=3))
    
    // If we use -lntupH, the first column is Netid (udp/tcp) because we used -u -t?
    // Let's verify standard `ss` output.
    // `ss -lntu` on linux:
    // Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
    // udp   UNCONN 0      0             0.0.0.0:5353          0.0.0.0:*    users:(("avahi-daemon",pid=577,fd=12))
    
    // So column 0 is Netid (udp/tcp).
    // Column 4 is Local Address:Port
    // Column 6 (or last) is Process info.

    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 { continue; }

        let netid = parts[0]; // tcp or udp
        let local_addr = parts[4];
        let process_info = if parts.len() > 6 { parts[6..].join(" ") } else { "".to_string() };

        // Parse Port from local_addr
        // formats: 0.0.0.0:22, [::]:22, *:22, 127.0.0.53%lo:53
        let port_str = local_addr.rsplit(':').next().unwrap_or("0");
        let port = port_str.parse::<u16>().unwrap_or(0);

        // Parse Process and PID
        // users:(("sshd",pid=765,fd=3))
        let proc_regex = Regex::new(r#"users:\(\("([^"]+)",pid=(\d+)"#).unwrap();
        let (name, pid) = if let Some(caps) = proc_regex.captures(&process_info) {
            (caps[1].to_string(), caps[2].to_string())
        } else {
            ("-".to_string(), "-".to_string())
        };

        entries.push(NetworkEntry {
            protocol: netid.to_string(),
            port,
            process: name,
            pid,
            firewall_status: FirewallStatus::Unknown, // Default
        });
    }
    entries
}

#[cfg(target_os = "linux")]
fn update_firewall_status(entries: &mut Vec<NetworkEntry>, ufw_output: &str) {
    // Parse ufw output lines like: "22/tcp  ALLOW  Anywhere"
    // or "22  ALLOW Anywhere" (implies both tcp/udp often)
    
    // Very naive parser
    for line in ufw_output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 { continue; }
        
        let port_proto = parts[0]; // "22/tcp" or "22"
        let action = parts[1]; // "ALLOW", "DENY", "LIMIT" (sometimes action is column 2 if To is multi-word? No usually column 2)
        
        // Handle "22/tcp" split
        let (port_str, proto) = if port_proto.contains('/') {
            let mut s = port_proto.split('/');
            (s.next().unwrap(), Some(s.next().unwrap()))
        } else {
            (port_proto, None)
        };
        
        let ufw_port = port_str.parse::<u16>().unwrap_or(0);
        if ufw_port == 0 { continue; }

        let status = match action {
            "ALLOW" => FirewallStatus::Open,
            "DENY" => FirewallStatus::Deny,
            "LIMIT" => FirewallStatus::Limit,
            _ => FirewallStatus::Unknown,
        };

        // Update matching entries
        for entry in entries.iter_mut() {
            if entry.port == ufw_port {
                if let Some(p) = proto {
                    // If UFW specifies proto, match it
                    // ufw: tcp, entry: tcp -> match
                    // ufw: v6, entry: ... ignore v6 specific lines for now unless we handle IPv6 well
                    if entry.protocol == p {
                         entry.firewall_status = status.clone();
                    }
                } else {
                    // If UFW doesn't specify (e.g. "22"), it applies to both? or defaults?
                    // "22" in ufw usually means tcp+udp or just tcp?
                    // Actually `ufw allow 22` allows both.
                    entry.firewall_status = status.clone();
                }
            }
        }
    }
}
