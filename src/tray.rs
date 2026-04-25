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
use serde_json::json;
use image::GenericImageView;
use gettextrs::*;
use colored::Colorize;

static ROOT: LazyLock<PathBuf> = LazyLock::new(|| {
    let mut path = env::current_exe().unwrap_or_default();
    path.pop();
    path.pop();
    path.pop();
    path
});

static SCRIPTS: LazyLock<PathBuf> = LazyLock::new(|| {
    let mut path = env::current_exe().unwrap_or_default();
    path.pop();
    path
});

static HOME: LazyLock<String> = LazyLock::new(|| {
    env::var("HOME").unwrap_or(String::from("."))
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
    ).expect("invalid image");

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
        APP_ID.to_string()
    }
    fn icon_pixmap(&self) -> Vec<Icon> {
        vec![Icon {
            width: PNG.width,
            height: PNG.height,
            data: PNG.data.clone(),
        }]
    }
    fn title(&self) -> String {
        APP_ID.to_string()
    }
    fn activate(&mut self, _x: i32, _y: i32) {
        gdbus_run(&Some(APP_ID.to_string()), CMD_SHOWHIDE)
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        vec![
            StandardItem {
                label: STR_SHOWHIDE.to_string(),
                icon_name: "application-menu".into(),
                activate: Box::new(
                    |_| gdbus_run(&Some(APP_ID.to_string()), CMD_SHOWHIDE)
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
    if let Ok(true) = path.try_exists() {
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
    if &res.to_string() == "Null" || &res.to_string() == "null" {
        (default_value).into()
    }
    else if let Some(x) = res.as_str() {
        (x.trim_matches('"')).into()
    }
    else {
        (default_value).into()
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
    exe: &String, data: &serde_json::Value, key: &'static str) -> String
{
    let res = &data[exe][key];
    if &res.to_string() == "Null" || &res.to_string() == "null" {
        res.to_string()
    }
    else if let Some(x) = res.as_str() {
        (x.trim_matches('"')).into()
    }
    else {
        res.to_string()
    }
}

fn get_items() -> Vec<SwItem> {
    let data = get_exe_data();
    let path_icons: PathBuf = SW_APP_DEFAULT_ICONS.iter().collect();
    let mut default_icons = Path::new(&*ROOT).join(&path_icons);
    let mut items = vec![];

    if let Some(shortcuts) = data.as_object() {
        for (hash, _) in shortcuts {
            let name = get_exe_data_value(hash, &data, "name");
            let icon = get_exe_data_value(hash, &data, "default");
            let path = get_exe_data_value(hash, &data, "path");

            if name != "null" && name != "Null" {
                let x = PathBuf::from(&path.trim_matches('"'));
                if let Ok(true) = x.try_exists() {
                    default_icons.push(icon);
                    let item = SwItem::MenuItem {
                        label: name,
                        icon: default_icons.display().to_string(),
                        activate: Arc::new(
                            move || gdbus_run(&Some(path.clone()), CMD_SHOW),
                    )};
                    items.push(item);
                    default_icons.pop();
                }
            }
        }
    }
    items
}

async fn update_items(handle: &ksni::Handle<SwTray>) {
    loop {
        tokio::time::sleep(time::Duration::from_secs(1)).await;
        match handle.update(|tray: &mut SwTray| {
            tray.items = get_items();
        }).await {
            Some(_) => (),
            None => { eprintln!("Error: {:?}", "Failed to get tray items".red()) }
        }
    }
}

fn gdbus_run(x_arg: &Option<String>, x_cmd: &'static str) {
    let mut cmd = Command::new("bash");
    let cmd_string =
        if let Some(arg) = x_arg {
            format!("{}.{} {:?}", CMD, x_cmd, arg)
        } else {
            format!("{}.{}", CMD, x_cmd)
        };
    cmd.args(["-c", &cmd_string]);

    if let Ok(out) = cmd.output() {
        println!("process with {:?}", &out);
        if !out.stderr.is_empty() && x_cmd != CMD_SHUTDOWN {
            let mut run = Command::new(get_path(SW_START));
            if let Some(arg) = &x_arg {
                let arg = arg.as_str().trim_matches('"');
                run.args([arg]);
                if let Ok(out) = run.spawn() {
                    println!("{} {:?}","process done".green(), &out);
                } else if let Err(out) = run.spawn() {
                    println!("{} {:?}", "failed to spawn".red(), &out);
                }
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
