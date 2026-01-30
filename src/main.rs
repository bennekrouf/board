mod monitor;

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};


use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Layout, Direction},
    style::{Color, Modifier, Style, Stylize},
    widgets::{Block, Borders, Row, Table, Cell, Paragraph, TableState},
    Terminal,
};
use std::{io, time::{Duration, Instant}};
use monitor::{fetch_data, NetworkEntry, FirewallStatus, Pm2Process, get_process_logs};

fn main() -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let (mut net_entries, mut pm2_entries) = fetch_data();
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_secs(2);
    
    // PM2 Selection State
    let mut pm2_state = TableState::default();
    if !pm2_entries.is_empty() {
        pm2_state.select(Some(0));
    }
    
    // Logs State
    let mut logs: Vec<String> = Vec::new();

    let res = run_app(
        &mut terminal,
        &mut net_entries,
        &mut pm2_entries,
        &mut pm2_state,
        &mut logs,
        &mut last_tick,
        tick_rate
    );

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err)
    }

    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    net_entries: &mut Vec<NetworkEntry>,
    pm2_entries: &mut Vec<Pm2Process>,
    pm2_state: &mut TableState,
    logs: &mut Vec<String>,
    last_tick: &mut Instant,
    tick_rate: Duration,
) -> io::Result<()>
where
    std::io::Error: From<B::Error>,
{
    loop {
        // Fetch logs for selection if needed (could be optimized to not fetch every frame if no change)
        // But for now, let's fetch on tick or selection change.
        // Actually, fetching on every frame is bad for IO.
        // We'll update logs in the tick loop or input loop.
        
        terminal.draw(|f| {
             // Vertical Split (Top: Monitoring, Bottom: Logs)
            let main_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .margin(1)
                .split(f.area());
            
            // Top Split (Horizontal: PM2 | Net)
            let top_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .split(main_chunks[0]);

            // --- PM2 Table (Top Left) ---
            let pm2_rows: Vec<Row> = pm2_entries.iter().map(|entry| {
                let status_style = if entry.status == "online" {
                   Style::default().fg(Color::Green)
                } else {
                   Style::default().fg(Color::Red)
                };
                
                let cells = vec![
                    Cell::from(entry.name.clone()).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Cell::from(entry.pid.clone()),
                    Cell::from(entry.status.clone()).style(status_style),
                    Cell::from(entry.memory.clone()),
                    Cell::from(entry.cpu.clone()),
                ];
                Row::new(cells)
            }).collect();

            let pm2_table = Table::new(pm2_rows)
                .widths(&[
                    Constraint::Percentage(30),
                    Constraint::Percentage(15),
                    Constraint::Percentage(20),
                    Constraint::Percentage(20),
                    Constraint::Percentage(15),
                ])
                .header(
                Row::new(vec!["Name", "PID", "Status", "Mem", "CPU"])
                    .style(Style::default().fg(Color::Yellow))
                    .bottom_margin(1)
            )
            .block(Block::default().title("PM2 Processes (↑/↓ to select)").borders(Borders::ALL))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

            f.render_stateful_widget(pm2_table, top_chunks[0], pm2_state);

            // --- Network Table (Top Right) ---
            let net_rows: Vec<Row> = net_entries.iter().map(|entry| {
                let status_style = match entry.firewall_status {
                    FirewallStatus::Open => Style::default().fg(Color::Green),
                    FirewallStatus::Closed => Style::default().fg(Color::Red),
                    FirewallStatus::Deny => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    FirewallStatus::Limit => Style::default().fg(Color::Yellow),
                    FirewallStatus::Unknown => Style::default().fg(Color::Gray),
                };
                
                let cells = vec![
                    Cell::from(entry.process.clone()),
                    Cell::from(entry.pid.clone()),
                    Cell::from(entry.protocol.clone()),
                    Cell::from(entry.port.to_string()),
                    Cell::from(format!("{:?}", entry.firewall_status)).style(status_style),
                ];
                Row::new(cells)
            }).collect();

            let net_table = Table::new(net_rows)
                .widths(&[
                    Constraint::Percentage(20),
                    Constraint::Percentage(10),
                    Constraint::Percentage(10),
                    Constraint::Percentage(10),
                    Constraint::Percentage(20),
                ])
            .header(
                Row::new(vec!["Process", "PID", "Proto", "Port", "Firewall"])
                    .style(Style::default().fg(Color::Yellow))
                    .bottom_margin(1)
            )
            .block(Block::default().title("Net / Firewall").borders(Borders::ALL));

            f.render_widget(net_table, top_chunks[1]);
            
            // --- Log View (Bottom) ---
            let log_text = logs.join("\n");
            let selected_name = if let Some(i) = pm2_state.selected() {
                if i < pm2_entries.len() {
                    format!("Logs: {}", pm2_entries[i].name)
                } else {
                    "Logs".to_string()
                }
            } else {
                 "Logs".to_string()
            };
            
            let log_paragraph = Paragraph::new(log_text)
                .block(Block::default().title(selected_name).borders(Borders::ALL));
            f.render_widget(log_paragraph, main_chunks[1]);
            
        })?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Down => {
                         let next = match pm2_state.selected() {
                            Some(i) => {
                                if i >= pm2_entries.len().saturating_sub(1) {
                                    0
                                } else {
                                    i + 1
                                }
                            }
                            None => 0,
                        };
                        pm2_state.select(Some(next));
                        update_logs(pm2_entries, pm2_state, logs);
                    }
                    KeyCode::Up => {
                        let next = match pm2_state.selected() {
                            Some(i) => {
                                if i == 0 {
                                    pm2_entries.len().saturating_sub(1)
                                } else {
                                    i - 1
                                }
                            }
                            None => 0,
                        };
                        pm2_state.select(Some(next));
                         update_logs(pm2_entries, pm2_state, logs);
                    }
                    _ => {}
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            let (new_net, new_pm2) = fetch_data();
            *net_entries = new_net;
            *pm2_entries = new_pm2;
            
            // Adjust selection if out of bounds
            if let Some(i) = pm2_state.selected() {
                if i >= pm2_entries.len() && !pm2_entries.is_empty() {
                    pm2_state.select(Some(pm2_entries.len() - 1));
                }
            }
             update_logs(pm2_entries, pm2_state, logs);
            *last_tick = Instant::now();
        }
    }
}

fn update_logs(entries: &[Pm2Process], state: &TableState, logs: &mut Vec<String>) {
    if let Some(i) = state.selected() {
        if i < entries.len() {
            let entry = &entries[i];
            *logs = get_process_logs(&entry.log_path, 20); // 20 lines
        } else {
             logs.clear();
        }
    } else {
        logs.clear();
    }
}
