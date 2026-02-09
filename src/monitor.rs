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
    PermissionDenied,
    Error(String),
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
    // Use sh -c to ensure we pick up the user's PATH where pm2 might be installed
    let output = match Command::new("sh")
        .arg("-c")
        .arg("pm2 jlist")
        .output() {
        Ok(o) => o,
        Err(e) => {
            return vec![Pm2Process {
                name: "PM2 Exec Error".to_string(),
                pid: "0".to_string(),
                status: "Error".to_string(),
                memory: "0 B".to_string(),
                cpu: "0%".to_string(),
                log_path: "".to_string(),
            }]
        }
    };

    if !output.status.success() {
         let stderr = String::from_utf8_lossy(&output.stderr);
         return vec![Pm2Process {
                name: "PM2 Failed".to_string(),
                pid: "0".to_string(),
                status: "Error".to_string(),
                memory: "0 B".to_string(),
                cpu: "0%".to_string(),
                log_path: "".to_string(), // Could put stderr here if we had a way to show it
            }];
    }

    let raw: Vec<Pm2RawEntry> = match serde_json::from_slice(&output.stdout) {
        Ok(r) => r,
        Err(e) => {
             return vec![Pm2Process {
                name: "PM2 Parse Error".to_string(),
                pid: "0".to_string(),
                status: "Error".to_string(),
                memory: "0 B".to_string(),
                cpu: "0%".to_string(),
                log_path: "".to_string(),
            }];
        },
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
pub fn restart_process(name: &str) {
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!("pm2 restart {}", name))
        .output();
}

#[cfg(not(target_os = "linux"))]
pub fn restart_process(name: &str) {
    println!("Mock restart: {}", name);
}

#[cfg(target_os = "linux")]
pub fn delete_process(name: &str) {
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!("pm2 delete {}", name))
        .output();
}

#[cfg(not(target_os = "linux"))]
pub fn delete_process(name: &str) {
    println!("Mock delete: {}", name);
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
        Ok(o) => {
            if o.status.success() {
                String::from_utf8_lossy(&o.stdout).to_string()
            } else {
                let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                if stderr.contains("root") || stderr.contains("permission") {
                     // Set all to PermissionDenied
                     for entry in entries.iter_mut() {
                         entry.firewall_status = FirewallStatus::PermissionDenied;
                     }
                } else {
                     // Set all to Error
                     for entry in entries.iter_mut() {
                         entry.firewall_status = FirewallStatus::Error(stderr.clone());
                     }
                }
                return entries;
            }
        },
        Err(e) => {
             for entry in entries.iter_mut() {
                 entry.firewall_status = FirewallStatus::Error(format!("Exec failed: {}", e));
             }
             return entries;
        }
    };
    
    // Parse UFW and update entries
    update_firewall_status(&mut entries, &ufw_output);

    entries
}

#[cfg(target_os = "linux")]
fn get_proc_cmdline(pid: &str) -> Option<String> {
    let path = format!("/proc/{}/cmdline", pid);
    match std::fs::read_to_string(path) {
        Ok(content) => {
            // cmdline is null-separated
            let args: Vec<&str> = content.split('\0').collect();
            if args.is_empty() { return None; }
            
            // Return "binary arg1" or just "binary"
            // Filter out empty strings which can happen with split('\0')
            let valid_args: Vec<&str> = args.into_iter().filter(|s| !s.is_empty()).collect();
            
            if valid_args.is_empty() { return None; }

            let binary = std::path::Path::new(valid_args[0])
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(valid_args[0]);

            if valid_args.len() > 1 {
                Some(format!("{} {}", binary, valid_args[1]))
            } else {
                Some(binary.to_string())
            }
        },
        Err(_) => None,
    }
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
        // Relaxed regex to handle potential variations
        let proc_regex = Regex::new(r#"users:\(\("?([^",]+)"?,pid=(\d+)"#).unwrap();
        let (name, pid) = if let Some(caps) = proc_regex.captures(&process_info) {
            (caps[1].to_string(), caps[2].to_string())
        } else {
             // Fallback: try to see if there is any user info
             if process_info.contains("users:") {
                 ("?".to_string(), "?".to_string())
             } else {
                 ("-".to_string(), "-".to_string())
             }
        };

        // Try to get enhanced process name with args
        let enhanced_name = if pid != "?" && pid != "-" {
             get_proc_cmdline(&pid).unwrap_or(name)
        } else {
             name
        };

        entries.push(NetworkEntry {
            protocol: netid.to_string(),
            port,
            process: enhanced_name,
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
        
        // Skip header lines
        if line.starts_with("To") || line.starts_with("--") { continue; }
        
        let port_proto = parts[0]; // "22/tcp" or "22"
        let action = parts[1]; // "ALLOW", "DENY", "LIMIT"
        
        // Handle (v6) which shifts action to parts[2]
        // Example: 22/tcp (v6) ALLOW Anywhere (v6)
        let (action, _is_v6) = if action == "(v6)" {
            if parts.len() < 3 { continue; }
            (parts[2], true)
        } else {
            (action, false)
        };

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
                    // Normalize tcp6/udp6 to tcp/udp for comparison
                    let entry_proto_norm = entry.protocol.replace("6", "");
                    
                    if entry.protocol == p || entry_proto_norm == p {
                         entry.firewall_status = status.clone();
                    }
                } else {
                    entry.firewall_status = status.clone();
                }
            }
        }
    }
}
