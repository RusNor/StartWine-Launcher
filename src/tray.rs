//#![allow(non_upper_case_globals)]
//#![allow(non_snake_case)]
//#![allow(unused_variables)]
//#![allow(unused_imports)]
#![allow(dead_code)]

use crate::kill;
use ksni::menu::*;
use ksni::Icon;
use ksni::TrayMethods;
use std::sync::{Arc, LazyLock};
use std::{process, env, fs, time};
use std::process::Command;
use std::path::{Path, PathBuf};
use std::ffi::OsStr;
use serde_json::json;
use image::GenericImageView;
use gettextrs::*;
use colored::Colorize;

static ROOT: LazyLock<PathBuf> = LazyLock::new(|| {
    let mut path = env::current_exe().unwrap();
    path.pop();
    path.pop();
    path.pop();
    path
});

static SCRIPTS: LazyLock<PathBuf> = LazyLock::new(|| {
    let mut path = env::current_exe().unwrap();
    path.pop();
    path
});

static HOME: LazyLock<String> = LazyLock::new(|| {
    env::var("HOME").unwrap_or(String::from(""))
});

static APP_ID: &str = "StartWine";

static STR_SHOWHIDE: LazyLock<String> = LazyLock::new(|| {
    gettext("Show/Hide StartWine")
});
static STR_RUN: LazyLock<String> = LazyLock::new(|| {
    gettext("Run...")
});
static STR_STOP: LazyLock<String> = LazyLock::new(|| {
    gettext("Stop Wine processes")
});
static STR_SHUTDOWN: LazyLock<String> = LazyLock::new(|| {
    gettext("Shutdown")
});

static SW_START: &str = "sw_start";
static SW_EXE_DATA: &str = "exe_data.json";
static SW_MENU_JSON: &str = "sw_menu.json";
static SW_SHORTCUTS: &str = "Shortcuts";

const SW_FM_CACHE: [&str;2] = [".cache", "sw_fm"];
const SW_APP_DEFAULT_ICONS: [&str;4] = ["data", "img", "app_icons", "default"];

static PNG: LazyLock<ksni::Icon> = LazyLock::new(|| {
    let img = image::load_from_memory_with_format(
        include_bytes!("../img/gui_icons/sw_tray_icon.png"),
        image::ImageFormat::Png,
    ).expect("valid image");

    let (width, height) = img.dimensions();
    let mut data = img.into_rgba8().into_vec();

    assert_eq!(data.len() % 4, 0);

    for pixel in data.chunks_exact_mut(4) {
        pixel.rotate_right(1)
    }
    ksni::Icon {
        width: width as i32,
        height: height as i32,
        data,
    }
});

static SVG: LazyLock<ksni::Icon> = LazyLock::new(|| {
    let path = &std::path::absolute("../img/gui_icons/sw_icon.svg").unwrap();
    let path = path.as_path();
    let svg = nsvg::parse_file(path, nsvg::Units::Pixel, 96.0).unwrap();
    let scale = 1.0;
    let (width, height, mut data) = svg.rasterize_to_raw_rgba(scale).unwrap_or(
        (0, 0, vec![])
    );
    assert_eq!(data.len() % 4, 0);
    for pixel in data.chunks_exact_mut(4) {
        pixel.rotate_right(1)
    }
    ksni::Icon {
        width: width as i32,
        height: height as i32,
        data,
    }
});

const CMD_SHOW: &str = "Show";
const CMD_SHOWHIDE: &str = "ShowHide";
const CMD_RUN: &str = "Run";
const CMD_SHUTDOWN: &str = "Shutdown";
const CMD: &str = "gdbus call -e --dest ru.launcher.StartWine \
--object-path /ru/launcher/StartWine --method ru.launcher.StartWine";

enum SwItem {
    MenuItem {
        label: String,
        icon: String,
        activate: Arc<dyn Fn() + Send + Sync + 'static>,
    },
}

struct SwTray {
    items: Vec<SwItem>,
}

impl ksni::Tray for SwTray {
    fn id(&self) -> String {
        APP_ID.into()
    }
    fn icon_pixmap(&self) -> Vec<Icon> {
        vec![Icon {
            width: PNG.width,
            height: PNG.height,
            data: PNG.data.clone(),
        }]
    }
    fn title(&self) -> String {
        APP_ID.into()
    }
    fn activate(&mut self, _x: i32, _y: i32) {
        gdbus_run(&Some(PathBuf::from(APP_ID)), CMD_SHOWHIDE)
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        vec![
            StandardItem {
                label: STR_SHOWHIDE.to_string(),
                icon_name: "application-menu".into(),
                activate: Box::new(
                    |_| gdbus_run(&Some(PathBuf::from(APP_ID)), CMD_SHOWHIDE)
                ),
                ..Default::default()
            }
            .into(),
            SubMenu {
                label: STR_RUN.to_string(),
                icon_name: "media-playback-start".into(),
                submenu: self.items.iter().map(|item| match item {
                    SwItem::MenuItem { label, icon, activate, .. } => {
                        let activate = activate.clone();
                        StandardItem {
                            label: label.clone(),
                            icon_name: icon.clone(),
                            activate: Box::new(move |_| {
                                activate();
                            }),
                            ..Default::default()
                        }.into()
                    }
                }).collect(),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: STR_STOP.to_string(),
                icon_name:"media-playback-stop".into(),
                activate: Box::new(|_| stop()),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: STR_SHUTDOWN.to_string(),
                icon_name: "application-exit".into(),
                activate: Box::new(|_| shutdown()),
                ..Default::default()
            }
            .into(),
        ]
    }
}

fn print_type<T>(_: &T) {
    println!("{:?}", std::any::type_name::<T>());
}

fn get_path(file: &str) -> PathBuf {
    let mut path = env::current_exe().unwrap_or(PathBuf::from(""));
    path.pop();
    path.push(file);
    if path.try_exists().ok().unwrap() {
        if path.to_str().is_some() {
            path
        } else {
            eprintln!("{:?} {}", path, "not exists!".red());
            PathBuf::from("")
        }
    } else {
        eprintln!("{:?} {}", path, "not exists!".red());
        PathBuf::from("")
    }
}

pub fn get_menu_data() -> serde_json::Value {
    let path_cache: PathBuf = SW_FM_CACHE.iter().collect();
    let menu_data = Path::new(&*HOME).join(&path_cache).join(SW_MENU_JSON);
    let res: Result<String, std::io::Error> = fs::read_to_string(menu_data);
    let string = res.ok().unwrap_or(String::from(""));
    let json_data: serde_json::Value = serde_json::from_str(&string)
        .unwrap_or(json!(null)
    );
    json_data
}

pub fn get_menu_data_value(
    default_value: &String, data: &serde_json::Value, key: &'static str) -> String
{
    let res = &data[key];
    if &res.to_string() == "null" {
        (default_value).into()
    } else {
        (res.as_str().unwrap().trim_matches('"')).into()
    }
}

fn get_exe_data() -> serde_json::Value {
    let path_cache: PathBuf = SW_FM_CACHE.iter().collect();
    let exe_data = Path::new(&*HOME).join(&path_cache).join(SW_EXE_DATA);
    let res: Result<String, std::io::Error> = fs::read_to_string(exe_data);
    let string = res.ok().unwrap_or(String::from(""));
    let json_data: serde_json::Value = serde_json::from_str(&string)
        .unwrap_or(json!(null)
    );
    json_data
}

fn get_exe_data_value(
    exe: &Option<&OsStr>, data: &serde_json::Value, key: &'static str) -> String
{
    let app_name = exe.unwrap().to_str().unwrap();
    let app_name_isalnum = app_name
        .matches(|c| { char::is_alphanumeric(c) })
        .collect::<Vec<_>>()
        .join("");
    let res = &data[&app_name_isalnum][key];
    if &res.to_string() == "null" {
        app_name_isalnum
    }
    else {
        (res.as_str().unwrap().trim_matches('"')).into()
    }
}

fn get_items() -> Vec<SwItem> {
    let data = get_exe_data();
    let shortcuts = Path::new(&*ROOT).join(SW_SHORTCUTS);
    let path_icons: PathBuf = SW_APP_DEFAULT_ICONS.iter().collect();
    let mut default_icons = Path::new(&*ROOT).join(&path_icons);
    let mut items = vec![];
    if shortcuts.try_exists().ok().unwrap() {
        for shortcut in shortcuts.read_dir().ok().unwrap() {
            let shortcut = shortcut.unwrap();
            if shortcut.path().is_file() {
                let name = get_exe_data_value(
                    &shortcut.path().file_stem(), &data, "name");
                let icon = get_exe_data_value(
                    &shortcut.path().file_stem(), &data, "default");
                default_icons.push(icon);
                let data_clone = data.clone();
                let item = SwItem::MenuItem {
                    label: name,
                    icon: default_icons.display().to_string(),
                    activate: Arc::new(
                        move || item_activate(&shortcut.path(), &data_clone)),
                };
                items.push(item);
                default_icons.pop();
            }
        }
    }
    items
}

async fn update_items(handle: &ksni::Handle<SwTray>) {
    loop {
        tokio::time::sleep(time::Duration::from_secs(1)).await;
        handle.update(|tray: &mut SwTray| {
            tray.items = get_items();
        }).await.unwrap();
    }
}

fn item_activate(swd_path: &Path, data: &serde_json::Value) {
    let swd_name = swd_path.file_stem().unwrap();
    let app_name = swd_name.to_str().unwrap();
    let app_name_isalnum = app_name
        .matches(|c| { char::is_alphanumeric(c) })
        .collect::<Vec<_>>()
        .join("");
    let exe_path = &data[&app_name_isalnum]["path"];
    if *exe_path == "null" {
        eprintln!("{:?} {}", app_name_isalnum, "not found in exe_data!".red());
    }
    else {
        let x = PathBuf::from(&exe_path.as_str().unwrap().trim_matches('"'));
        if x.try_exists().ok().unwrap() {
            println!("{:?}", &x);
            gdbus_run(&Some(x), CMD_SHOW);
        }
    }
}

fn gdbus_run(x_arg: &Option<PathBuf>, x_cmd: &'static str) {
    let mut cmd_str = String::new();
    if x_arg.is_some() {
        let arg = x_arg.clone().unwrap_or("".into());
        cmd_str.push_str(format!("{}.{} {:?}", CMD, x_cmd, arg).as_str());
    } else {
        cmd_str.push_str(format!("{}.{}", CMD, x_cmd).as_str());
    }
    let mut cmd = Command::new("bash");
    cmd.args(["-c", &cmd_str]);
    if let Ok(out) = cmd.output() {
        println!("process with {:?}", &out);
        if ! out.stderr.is_empty() && x_cmd != CMD_SHUTDOWN {
            let mut run = Command::new(get_path(SW_START));
            let arg = &x_arg.clone().unwrap_or("".into());
            let arg = arg.to_str().unwrap().trim_matches('"');
            run.args([arg]);
            if let Ok(out) = run.spawn() {
                println!("{} {:?}","process done".green(), &out);
            } else if let Err(out) = run.spawn() {
                println!("{} {:?}", "failed to spawn".red(), &out);
            }
        } else {
            println!("{}", "process done".green());
        }
    } else if let Err(out) = cmd.output() {
        println!("{} {:?}", "failed to spawn".red(), &out);
    }
}

fn stop() {
    kill::main()
}

fn shutdown() {
    gdbus_run(&None, CMD_SHUTDOWN);
    process::exit(0)
}

#[tokio::main(flavor = "current_thread")]
pub async fn main() {
    let mut lang = get_menu_data_value(
        &"en_US".to_string(), &get_menu_data(), "language"
    );
    lang.push_str(".UTF-8");

    let init_msg = match TextDomain::new("StartWine")
        .skip_system_data_paths()
        .prepend(&*SCRIPTS)
        .locale(&lang)
        .init()
    {
        Ok(_locale) => {
            format!("{:?}", &lang)
        }
        Err(error) => {
            format!("{} {:?}", "an error occurred:".red(), error)
        }
    };
    println!("Locale: {}", init_msg);

    let tray = SwTray { items: get_items() };
    if let Ok(handle) = tray.spawn().await {
        tokio::spawn(async move {
            update_items(&handle).await;
        });
        std::future::pending().await
    }
    process::exit(0)
}
