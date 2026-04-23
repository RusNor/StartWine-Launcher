//#![allow(non_upper_case_globals)]
//#![allow(non_snake_case)]
//#![allow(unused_variables)]
//#![allow(unused_imports)]
#![allow(dead_code)]

mod cube;
mod tray;
mod kill;
mod pe;
use image::ImageFormat;
use file_format::FileFormat;
use std::{env, ffi, io, thread, time, process};
use std::io::prelude::*;
use std::path::PathBuf;
use std::process::Command;
use clap::Parser;
use clap::builder::styling::{Color, Style, AnsiColor};
use colored::Colorize;
use which::which;
use anyhow::{anyhow, Error};

pub fn get_styles() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .usage(
            Style::new()
                .bold()
                .underline()
                .fg_color(Some(Color::Ansi(AnsiColor::Yellow))),
        )
        .header(
            Style::new()
                .bold()
                .underline()
                .fg_color(Some(Color::Ansi(AnsiColor::Yellow))),
        )
        .literal(
            Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green))),
        )
        .invalid(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Red))),
        )
        .error(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Red))),
        )
        .valid(
            Style::new()
                .bold()
                .underline()
                .fg_color(Some(Color::Ansi(AnsiColor::Green))),
        )
        .placeholder(
            Style::new().fg_color(Some(Color::Ansi(AnsiColor::Blue))),
        )
}
///StartWine:
///Is a Windows application launcher for GNU/Linux operating systems.
///Includes many features, extensions, and fixes to improve performance,
///visuals, and usability.
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None, styles = get_styles())]
pub struct Args {
    /// Path to executable file or path to input file/directory or text message.
    #[arg(default_value = "StartWine")]
    executable: PathBuf,
    /// Executable parameters or path to output file or directory.
    #[arg(default_value = "")]
    parameters: Vec<String>,
    /// Name of the confirm button for the dialog question.
    #[arg(long="accept", default_value = "Ok")]
    accept: String,
    /// Name of the cancel button for the dialog question.
    #[arg(long="cancel", default_value = "Cancel")]
    cancel: String,
    /// Run in direct mode (without dbus).
    #[arg(long = "direct")]
    direct: bool,
    /// Run in service mode (gdbus daemon).
    #[arg(long = "service")]
    service: bool,
    /// Run executable in silent mode (without grafical interface).
    #[arg(long = "run")]
    run: bool,
    /// Run interface in fullscreen mode if possible.
    #[arg(long = "fullscreen")]
    fullscreen: bool,
    /// Run StartWine Cube with MangoHud overlay.
    #[arg(short, long = "cube")]
    cube: bool,
    /// Run with Vulkan rendering.
    #[arg(short, long = "vulkan")]
    vulkan: bool,
    /// Run with OpenGL rendering.
    #[arg(short, long = "opengl")]
    opengl: bool,
    /// Run StartWine in tray.
    #[arg(short, long = "tray")]
    tray: bool,
    /// Run StartWine terminal shell.
    #[arg(long = "shell")]
    shell: bool,
    /// Run StartWine Path Manager.
    #[arg(short, long = "path")]
    path: bool,
    /// Print help for Crier tools (various dialog boxes and other tools).
    #[arg(long = "crier")]
    crier: bool,
    /// Crier dialog window with information text.
    #[arg(short, long = "info")]
    info: bool,
    /// Crier dialog window with error text.
    #[arg(short, long = "error")]
    error: bool,
    /// Crier dialog window with warning text.
    #[arg(short, long = "warning")]
    warning: bool,
    /// Crier dialog window with question.
    #[arg(short, long = "question")]
    question: bool,
    /// Show text or open file in text editor.
    #[arg(long = "edit")]
    edit: bool,
    /// File chooser dialog window.
    #[arg(short, long = "file")]
    file: bool,
    /// Download content with gui progress bar.
    #[arg(short, long = "download")]
    download: bool,
    /// Download content with console progress bar.
    #[arg(long = "silent-download")]
    silent_download: bool,
    /// Tar archive extraction with gui progress bar.
    #[arg(long = "tar")]
    tar: bool,
    /// Tar archive extraction with console progress bar.
    #[arg(long = "silent-tar")]
    silent_tar: bool,
    /// Zip archive extraction with gui progress bar.
    #[arg(long = "zip")]
    zip: bool,
    /// Zip archive extraction with console progress bar.
    #[arg(long = "silent-zip")]
    silent_zip: bool,
    /// Extract icon from DLL or EXE file.
    #[arg(long = "ico")]
    ico: bool,
    /// Extract metadata from DLL or EXE file.
    #[arg(long = "metadata")]
    metadata: bool,
    /// Extract audio tags from audio file.
    #[arg(long = "audiotags")]
    audiotags: bool,
    /// Determine file MIME type.
    #[arg(long = "mimetype")]
    mimetype: bool,
    /// Print MangoHud font size.
    #[arg(long = "hud")]
    hud: bool,
    /// Set of tools for handling input devices.
    #[arg(long = "input")]
    input: bool,
    /// Run screen recording tool.
    #[arg(long = "record")]
    record: bool,
    /// Terminate all wine processes.
    #[arg(long = "kill")]
    kill: bool,
    /// Get application list.
    #[arg(long = "app-list")]
    app_list: bool,
    /// Get installed Steam app list.
    #[arg(long = "steam-list")]
    steam_list: bool,
    /// Get GOG Games app library list.
    #[arg(long = "gog-list")]
    gog_list: bool,
    /// Get Epic Games app library list.
    #[arg(long = "epic-list")]
    epic_list: bool,
    /// Update python environment and dependencies.
    #[arg(long = "update")]
    update: bool,
    /// Shutdown StartWine.
    #[arg(long = "shutdown")]
    shutdown: bool,
}

const SW_MENU: &str = "sw_menu.py";
const SW_CRIER: &str = "sw_crier.py";
const SW_PACURL: &str = "sw_pacurl.py";
const SW_SHELL: &str = "sw_term.py";
const SW_INPUT: &str = "sw_input.py";
const SW_CAST: &str = "sw_cast.py";
const REQUIREMENTS: [&str; 16] = [
    "pygobject",
    "pycairo",
    "PyOpenGL",
    "PyOpenGL-accelerate",
    "pillow",
    "psutil",
    "zstandard",
    "evdev",
    "markdown",
    "textual",
    "rich",
    "pychromecast",
    "requests",
    "zeroconf",
    "pulsectl",
    "pydbus",
];
const CMD_SHOW: &str = "gdbus call -e --dest ru.launcher.StartWine \
--object-path /ru/launcher/StartWine --method ru.launcher.StartWine.Show";

const CMD_RUN: &str = "gdbus call -e --dest ru.launcher.StartWine \
--object-path /ru/launcher/StartWine --method ru.launcher.StartWine.Run";

const CMD_PING: &str = "gdbus call -e --dest ru.launcher.StartWine \
--object-path /ru/launcher/StartWine --method ru.launcher.StartWine.Ping";

const CMD_SHUTDOWN: &str = "gdbus call -e --dest ru.launcher.StartWine \
--object-path /ru/launcher/StartWine --method ru.launcher.StartWine.Shutdown";

fn print_type<T>(_: &T) {
    println!("{:?}", std::any::type_name::<T>());
}

fn get_env(key: &str) -> Result<ffi::OsString, env::VarError> {
    match env::var(key) {
        Ok(val) => Ok(val.into()),
        Err(e) => Err(e)
    }
}

fn silent_start(args: Args)
 -> Result<(), Error>
{
    let x_exec: &PathBuf = &args.executable;
    let x_args: Vec<String> = args.parameters;
    let x_full: bool = args.fullscreen;
    let path = get_path(SW_MENU);
    let mut proc_args: Vec::<&str> = vec![];

    if args.service {
        proc_args.push("--service")
    }
    else {
        proc_args.push("--silent")
    }
    if x_full {
        proc_args.push("--fullscreen");
    }
    if let Ok(true) = x_exec.try_exists() {
        let mut proc = Command::new(path);
        let x_exec = format!("{:?}", &x_exec);
        proc_args.push(&x_exec);
        for x in &x_args {
            proc_args.push(x);
        }
        proc.args(&proc_args);
        if let Err(err) = proc.status() {
            println!("{} {}", "Failed to silent start".red(), err);
            process::exit(1)
        }
    }
    else if which(x_exec).ok().is_some() {
        let mut proc = Command::new(path);
        let x_exec = format!("{:?}", &which(x_exec)?);
        proc_args.push(&x_exec);
        for x in &x_args {
            proc_args.push(x);
        }
        proc.args(&proc_args);
        if let Err(err) = proc.status() {
            println!("{} {}", "Failed to silent start".red(), err);
            process::exit(1)
        }
    }
    else {
        let mut proc = Command::new(path);
        proc.args(&proc_args);
        if let Err(err) = proc.status() {
            println!("{} {}", "Failed to silent start".red(), err);
            process::exit(1)
        }
    }
    Ok(())
}

fn on_direct_start(x_exec: PathBuf, x_args: Vec<String>, x_full: bool)
 -> Result<(), Error>
{
    if !get_path("env/bin/python3").exists() {
        create_env()?
    }
    let python_path = get_path("env/bin/python3");

    if python_path.exists() {
        direct_start(python_path, x_exec, x_args, x_full)?
    }
    else {
        eprintln!("{}", "Python virtual environment not found!".red());
        process::exit(1)
    }
    Ok(())
}

fn direct_start(x_python: PathBuf, x_exec: PathBuf, x_args: Vec<String>, x_full: bool)
 -> Result<(), Error>
{
    let path = get_path(SW_MENU);
    let sw_menu = path.to_str().ok_or(anyhow!("error"))?;
    let mut proc_args: Vec::<&str> = vec![sw_menu, "--direct"];

    if x_full {
        proc_args.push("--fullscreen");
    }
    if let Ok(true) = x_exec.try_exists() {
        let mut proc = Command::new(x_python);
        let exec = format!("{:?}", &x_exec);
        proc_args.push(&exec);
        for x in &x_args {
            proc_args.push(x);
        }
        proc.args(&proc_args);

        if let Err(err) = proc.status() {
            println!("{} {}", "Failed to direct start".red(), err);
            process::exit(1)
        }
    }
    else if which(&x_exec).ok().is_some() {
        let mut proc = Command::new(x_python);
        let exec = format!("{:?}", &which(&x_exec)?);
        proc_args.push(&exec);
        for x in &x_args {
            proc_args.push(x);
        }
        proc.args(&proc_args);
        if let Err(err) = proc.status() {
            println!("{} {}", "Failed to direct start".red(), err);
            process::exit(1)
        }
    }
    else {
        let mut proc = Command::new(x_python);
        proc.args(&proc_args);
        if let Err(err) = proc.status() {
            println!("{} {}", "Failed to direct start".red(), err);
            process::exit(1)
        }
    }
    Ok(())
}

fn create_env() -> Result<(), Error>
{
    let mut env_ = Command::new("python3");
    let mut env_dir = get_dir();
    env_dir.push("env");
    env_.args(["-m", "venv", env_dir.to_str().ok_or(anyhow!("error"))?]);

    if let Err(err) = env_.status() {
        println!("{} {}", "Failed to create python virtual environment".red(), err);
        process::exit(1)
    }
    else {
        println!("{}", "Python virtual environment creation completed.".green());
        on_python_update();
    }
    Ok(())
}

fn update_env() -> Result<(), Error>
{
    let pip = get_path("env/bin/pip");
    let mut update = Command::new(&pip);
    update.args(["install", "--upgrade", "pip"]);

    if let Err(err) = update.status() {
        eprintln!("{} {}", "Failed to update python environment!".red(), err);
    }
    else {
        let mut install = Command::new(&pip);
        let mut install_args: Vec::<&str> = vec!["install"];
        let requirements = get_path("requirements.txt");

        if !requirements.exists() {
            install_args.extend_from_slice(&REQUIREMENTS);
            install.args(&install_args);
        }
        else {
            install_args.push("-r");
            install_args.push(requirements.to_str().ok_or(anyhow!("error"))?);
            install.args(&install_args);
        }
        if let Err(err) = install.status() {
            println!("{} {}", "Failed to install python dependencies!".red(), err);
            process::exit(1)
        }
    }
    Ok(())
}

fn on_python_update()
{
    if !get_path("env/bin/python3").exists() {
        if let Err(e) = create_env() {
            eprintln!("{:?}", e);
        }
    }
    else if let Err(e) = update_env() {
        eprintln!("{:?}", e);
    }
}

fn gdbus_run(x_exec: PathBuf, _x_args: Vec<String>, x_cmd: &'static str)
{
    let cmd = format!("{} {:?} 2>/dev/null", x_cmd, &x_exec);
    let mut proc = Command::new("bash");
    proc.args(["-c", &cmd]);
    if let Err(_out) = proc.status() {
        println!("{} {:?}", "gdbus call failed!".red(), &cmd);
    }
}

fn get_path(file: &str) -> PathBuf
{
    let mut path = env::current_exe().unwrap_or(PathBuf::from(""));
    path.pop();
    path.push(file);
    if let Ok(true) = path.try_exists() {
        if path.to_str().is_some() {
            path
        }
        else {
            eprintln!("{:?} {}", path, "not exists!".red());
            PathBuf::from("")
        }
    }
    else {
        eprintln!("{:?} {}", path, "not exists!".red());
        PathBuf::from("")
    }
}

fn get_dir() -> PathBuf
{
    let mut path = env::current_exe().unwrap_or(PathBuf::from(""));
    path.pop();
    if let Ok(true) = path.try_exists() {
        if path.to_str().is_some() {
            path
        }
        else {
            eprintln!("{:?} {}", path, "not exists!".red());
            PathBuf::from("")
        }
    }
    else {
        eprintln!("{:?} {}", path, "not exists!".red());
        PathBuf::from("")
    }
}

fn run_cmd(cmd: &str, arg: &[&str])
{
    let mut proc = Command::new(cmd);
    proc.args(arg);
    if let Err(_out) = proc.status() {
        println!("{} {:?}", "Failed to start".red(), &cmd);
    }
}

fn on_start(args: Args)
{
    let args_clone = args.clone();
    let x_exec: PathBuf = args.executable;
    let x_args: Vec<String> = args.parameters;
    let x_run: bool = args.run;

    let active = Command::new("bash")
        .args(["-c", CMD_PING, "2>/dev/null"])
        .output()
        .expect("Failed to spawn process");

    let out: Vec<u8> = active.stdout;
    if out.is_empty() {
        let duration = time::Duration::from_millis(100);
        let thread_silent_start = thread::spawn(move || {
            if let Err(e) = silent_start(args_clone) {
                eprintln!("{:?}", e);
            }
        });
        loop {
            let active = Command::new("bash")
                .args(["-c", CMD_PING, "2>/dev/null"])
                .output()
                .expect("Failed to spawn process");

            let out: Vec<u8> = active.stdout;
            if ! out.is_empty() {
                break;
            }
            thread::sleep(duration);
        }
        if x_run {
            println!("cmd StartWine.Run...");
            gdbus_run(x_exec, x_args, CMD_RUN)
        }
        else {
            println!("cmd StartWine.Show...");
            gdbus_run(x_exec, x_args, CMD_SHOW)
        }
        let _res = thread_silent_start.join();
    }
    else if x_run {
        println!("cmd StartWine.Run...");
        gdbus_run(x_exec, x_args, CMD_RUN)
    }
    else {
        println!("cmd StartWine.Show...");
        gdbus_run(x_exec, x_args, CMD_SHOW)
    }
}

fn on_cube() { cube::main(); }

fn on_tray() { tray::main(); }

fn on_shell(x_exec: PathBuf, x_args: Vec<String>) -> Result<(), Error>
{
    let env_path = get_path("env/bin/python3");
    let python_path = if env_path.exists() { env_path }
    else {
        PathBuf::from("python3")
    };
    let cmd = python_path.to_str().ok_or(anyhow!("error"))?;

    let shell = get_path(SW_SHELL);
    let shell = shell.to_str().ok_or(anyhow!("error"))?;

    let exe = x_exec.to_str().ok_or(anyhow!("error"))?;
    let mut arg_list = vec![shell];

    if let Ok(true) = x_exec.try_exists() {
        arg_list.push(exe)
    }
    for x_arg in &x_args {
        arg_list.push(x_arg)
    }
    run_cmd(cmd, &arg_list);

    Ok(())
}

fn on_crier(
    option: &str,
    args: Args,
    arg_type: Option<&str>,
) -> Result<(), Error>
{
    let path = get_path(SW_CRIER);
    let cmd = path.to_str().ok_or(anyhow!("error"))?;
    let mut arg: Vec<&str> = vec![option];

    if let Some(x) = arg_type && x == "message" {
        arg.push(args.executable.to_str().ok_or(anyhow!("error"))?);
    }
    else if let Some(x) = arg_type && x == "output" {
        arg.push(args.executable.to_str().ok_or(anyhow!("error"))?);
        for x in &args.parameters {
            if !x.is_empty() {
                arg.push(x);
            }
        }
    }
    else if let Some(x) = arg_type && x == "question" {
        arg.push(args.executable.to_str().ok_or(anyhow!("error"))?);
        for x in &args.parameters {
            if !x.is_empty() {
                arg.push(x);
            }
        }
        arg.push(&args.accept);
        arg.push(&args.cancel);
    }
    run_cmd(cmd, &arg);
    Ok(())
}

fn on_pacurl(option: &str, args: Args) -> Result<(), Error>
{
    let path = get_path(SW_PACURL);
    let cmd = path.to_str().ok_or(anyhow!("error"))?;
    let mut arg: Vec<&str> = vec![option];

    arg.push(args.executable.to_str().ok_or(anyhow!("error"))?);
    for x in &args.parameters {
        if !x.is_empty() {
            arg.push(x);
        }
    }
    run_cmd(cmd, &arg);
    Ok(())
}

fn on_extract_icon(x_path: PathBuf, x_args: Vec<String>) -> Result<(), Error>
{
    let mut file_list: Vec<PathBuf> = vec![x_path.clone()];
    let out_dir = if let Some(x) = &x_args.clone().pop() {
        if x == &"".to_string() {
            PathBuf::from(".")
        } else {
            PathBuf::from(x)
        }
    } else {
        PathBuf::from(".")
    };
    for x in &x_args {
        let file = PathBuf::from(x);
        file_list.push(file);
    }
    let mut thread_pool = Vec::new();
    for exe_path in file_list {
        if exe_path.is_file() {
            let fmt = FileFormat::from_file(&exe_path)?;
            if fmt == FileFormat::PortableExecutable
            || fmt == FileFormat::DynamicLinkLibrary {
                let mut out_path = pe::get_out_path(
                    &exe_path, &out_dir, &".png".to_string()
                );
                let t = thread::spawn(move || {
                    if let Err(e) = pe::extract_icon(
                        &exe_path, &mut out_path, ImageFormat::Png
                    ) {
                        println!("{:?}", e);
                    }
                });
                thread_pool.push(t);
            }
        }
    }
    for t in thread_pool {
        let _t = t.join();
    }
    Ok(())
}

fn on_extract_metadata(x_path: PathBuf, x_args: Vec<String>) -> Result<(), Error>
{
    let mut file_list: Vec<PathBuf> = vec![x_path.clone()];
    for x in &x_args {
        let file = PathBuf::from(x);
        file_list.push(file);
    }
    let mut thread_pool = Vec::new();
    for file in file_list {
        if file.is_file() {
            let t = thread::spawn(move || {
                if let Err(e) = pe::extract_metadata(&file) {
                    println!("{:?}", e);
                }
            });
            thread_pool.push(t);
        }
    }
    for t in thread_pool {
        let _t = t.join();
    }
    Ok(())
}

fn on_extract_audiotags(x_path: PathBuf, x_args: Vec<String>) -> Result<(), Error>
{
    let mut file_list: Vec<PathBuf> = vec![x_path.clone()];
    for x in &x_args {
        let file = PathBuf::from(x);
        file_list.push(file);
    }
    let mut thread_pool = Vec::new();
    for file in file_list {
        if file.is_file() {
            let t = thread::spawn(move || {
                if let Err(e) = pe::extract_audiotags(&file) {
                    println!("{:?}", e);
                }
            });
            thread_pool.push(t);
        }
    }
    for t in thread_pool {
        let _t = t.join();
    }
    Ok(())
}

fn on_determine_mimetype(x_path: PathBuf, x_args: Vec<String>) -> Result<(), Error>
{
    let mut file_list: Vec<PathBuf> = vec![x_path.clone()];
    for x in &x_args {
        let file = PathBuf::from(x);
        file_list.push(file);
    }
    let mut thread_pool = Vec::new();
    for file in file_list {
        if file.is_file() {
            let t = thread::spawn(move || {
                if let Err(e) = pe::determine_type(&file, "type") {
                    println!("{:?}", e);
                }
            });
            thread_pool.push(t);
        }
    }
    for t in thread_pool {
        let _t = t.join();
    }
    Ok(())
}

fn on_path() -> Result<(), Error>
{
    let home = get_env("HOME")?;
    let mut default_path = PathBuf::from(home);
    default_path.push(".local");
    default_path.push("share");

    let path = get_path(SW_CRIER);
    let mut arg: String = String::from("");

    if env::args().nth(2).is_some() {
        arg.push_str(&env::args().nth(2).ok_or(anyhow!("error"))?);
    } else {
        arg.push_str(default_path.to_str().ok_or(anyhow!("error"))?);
    }
    let cmd = path.to_str().ok_or(anyhow!("error"))?;
    run_cmd(cmd, &["-p", &arg]);
    Ok(())
}

fn on_input() -> Result<(), Error>
{
    let path = get_path(SW_INPUT);
    if path.exists() {
        let arg = ["-h"];
        let cmd = path.to_str().ok_or(anyhow!("error"))?;
        run_cmd(cmd, &arg);
        let mut input=String::new();
        println!("{}", "Enter Input options:".yellow());
        let _= io::stdout().flush();
        io::stdin().read_line(&mut input).expect("Error: incorrect options");
        let options: Vec<&str> = input.split_whitespace().collect();
        run_cmd(cmd, &options);
    }
    Ok(())
}

fn on_cast() -> Result<(), Error>
{
    let path = get_path(SW_CAST);
    let arg = [];
    let cmd = path.to_str().ok_or(anyhow!("error"))?;
    run_cmd(cmd, &arg);
    Ok(())
}

fn on_kill() {
    kill::main();
}

fn on_shutdown() {
    let proc = Command::new("bash")
        .args(["-c", CMD_SHUTDOWN, "2>/dev/null"])
        .output()
        .expect("Failed to spawn process");

    let out: Vec<u8> = proc.stdout;
    if out.is_empty() {
        println!("App is not running or is not reponding...");
        process::exit(1)
    } else {
        println!("Shutdown...");
        process::exit(0)
    }
}

fn main()
{
    let args = Args::parse();

    if args.cube || args.vulkan {
        unsafe { env::set_var("GSK_RENDERER", "vulkan"); }
        on_cube()
    }
    else if args.opengl {
        unsafe { env::set_var("GSK_RENDERER", "opengl"); }
        on_cube()
    }
    else if args.tray {
        on_tray();
    }
    else if args.crier {
        if let Err(e) = on_crier("-h", args, None) {
            eprintln!("{:?}", e);
        }
    }
    else if args.info {
        if let Err(e) = on_crier("-i", args, Some("message")) {
            eprintln!("{:?}", e);
        }
    }
    else if args.warning {
        if let Err(e) = on_crier("-w", args, Some("message")) {
            eprintln!("{:?}", e);
        }
    }
    else if args.question {
        if let Err(e) = on_crier("-q", args, Some("question")) {
            eprintln!("{:?}", e);
        }
    }
    else if args.error {
        if let Err(e) = on_crier("-e", args, Some("message")) {
            eprintln!("{:?}", e);
        }
    }
    else if args.edit {
        if let Err(e) = on_crier("--edit", args, Some("message")) {
            eprintln!("{:?}", e);
        }
    }
    else if args.file {
        if let Err(e) = on_crier("-f", args, Some("message")) {
            eprintln!("{:?}", e);
        }
    }
    else if args.tar {
        if let Err(e) = on_crier("--tar", args, Some("output")) {
            eprintln!("{:?}", e);
        }
    }
    else if args.silent_tar {
        if let Err(e) = on_pacurl("--silent-tar", args) {
            eprintln!("{:?}", e);
        }
    }
    else if args.zip {
        if let Err(e) = on_crier("--zip", args, Some("output")) {
            eprintln!("{:?}", e);
        }
    }
    else if args.silent_zip {
        if let Err(e) = on_pacurl("--silent-zip", args) {
            eprintln!("{:?}", e);
        }
    }
    else if args.ico {
        if let Err(e) = on_extract_icon(args.executable, args.parameters) {
            eprintln!("{:?}", e);
        }
    }
    else if args.metadata {
        if let Err(e) = on_extract_metadata(args.executable, args.parameters) {
            eprintln!("{:?}", e);
        }
    }
    else if args.audiotags {
        if let Err(e) = on_extract_audiotags(args.executable, args.parameters) {
            eprintln!("{:?}", e);
        }
    }
    else if args.mimetype {
        if let Err(e) = on_determine_mimetype(args.executable, args.parameters) {
            eprintln!("{:?}", e);
        }
    }
    else if args.download {
        if let Err(e) = on_crier("-d", args, Some("output")) {
            eprintln!("{:?}", e);
        }
    }
    else if args.silent_download {
        if let Err(e) = on_pacurl("--silent-download", args) {
            eprintln!("{:?}", e);
        }
    }
    else if args.hud {
        if let Err(e) = on_crier("--hud", args, None) {
            eprintln!("{:?}", e);
        }
    }
    else if args.app_list {
        if let Err(e) = on_crier("--app-list", args, None) {
            eprintln!("{:?}", e);
        }
    }
    else if args.steam_list {
        if let Err(e) = on_crier("--steam-list", args, None) {
            eprintln!("{:?}", e);
        }
    }
    else if args.gog_list {
        if let Err(e) = on_crier("--gog-list", args, None) {
            eprintln!("{:?}", e);
        }
    }
    else if args.epic_list {
        if let Err(e) = on_crier("--epic-list", args, None) {
            eprintln!("{:?}", e);
        }
    }
    else if args.input {
        if let Err(e) = on_input() {
            eprintln!("{:?}", e);
        }
    }
    else if args.record {
        if let Err(e) = on_cast() {
            eprintln!("{:?}", e);
        }
    }
    else if args.shell {
        if let Err(e) = on_shell(args.executable, args.parameters) {
            eprintln!("{:?}", e);
        }
    }
    else if args.path {
        if let Err(e) = on_path() {
            eprintln!("{:?}", e);
        }
    }
    else if args.kill {
        on_kill()
    }
    else if args.update {
        on_python_update()
    }
    else if args.direct {
        if let Err(e) = on_direct_start(
            args.executable, args.parameters, args.fullscreen) {
                eprintln!("{:}", e);
        }
    }
    else if args.service {
        if let Err(e) = silent_start(args) {
            eprintln!("{:?}", e);
        }
    }
    else if args.shutdown {
        on_shutdown()
    }
    else {
        on_start(args)
    }
}

