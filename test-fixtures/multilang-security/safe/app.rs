use std::process::Command;

fn run_command(value: &str) {
    let _ = Command::new("/usr/bin/printf").arg("%s").arg(value).status();
}
