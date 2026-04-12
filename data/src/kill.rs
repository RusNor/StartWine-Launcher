#![allow(unused_imports)]

use std::env;
use std::path::PathBuf;
use std::process::Command;
use sysinfo::{Process, System, Pid};
use gettextrs::*;
use std::sync::LazyLock;
use crate::tray::get_menu_data_value;
use crate::tray::get_menu_data;

static STR_TERMINATE: LazyLock<String> = LazyLock::new(|| {
    gettext("Termination of active processes...")
});

static SCRIPTS: LazyLock<PathBuf> = LazyLock::new(|| {
    let mut path = env::current_exe().unwrap();
    path.pop();
    path
});

pub fn main() {

    let mut lang = get_menu_data_value(
        &"en_US".to_string(), &get_menu_data(), "language"
    );
    lang.push_str(".UTF-8");

    if let Err(domain_err) = TextDomain::new("StartWine")
        .skip_system_data_paths()
        .prepend(&*SCRIPTS)
        .locale(&lang)
        .init() {
            eprintln!("Failed to set locale: {:?}", domain_err);
        }

    let s = System::new_all();
    for process in s.processes().values() {
        if let Some(proc_exe) = process.exe() {
            let exe_str = proc_exe.to_str();
            if let Some(string) = exe_str {
                let founded = string;
                if founded.contains("wine-preloader")
                || founded.contains("wine64-preloader") {
                    println!("Terminate process {} {:?}", process.pid(), process.name());
                    process.kill();
                }
            }
        }
    }
    let mut proc = Command::new("notify-send");
    proc.args(["-t", "1500", "-a", "StartWine", &STR_TERMINATE]);

    if let Err(_out) = proc.status() {
        println!("failed to spawn process notify");
    }
}
