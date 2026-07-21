use std::process::Command;

fn run_command() {
    let command = std::env::var("COMMAND").unwrap();
    let _ = Command::new(command).status();
}
