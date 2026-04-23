// #![allow(non_upper_case_globals)]
// #![allow(non_snake_case)]
// #![allow(unused_imports)]
// #![allow(unused_variables)]
// #![allow(dead_code)]

use zerocopy::FromBytes;
use byteorder::{LittleEndian, WriteBytesExt};
use std::io::{Write, Cursor};
use std::path::{Path, PathBuf};
use std::ffi::OsStr;
use std::time::SystemTime;
use editpe::{Image, ResourceEntryName, ResourceTable };
use editpe::constants::{RT_GROUP_ICON, RT_ICON};
use editpe::types::IconDirectoryEntry;
use image::{self, ImageFormat};
use anyhow::{anyhow, Error};
use serde::{Deserialize, Serialize};
use clap::Parser;
use clap::builder::styling::{Color, Style, AnsiColor};
use file_format::FileFormat;
use audiotags::Tag;

const COMPANYNAME: &str = "CompanyName";
const LEGALCOPYRIGHT: &str = "LegalCopyright";
const INTERNALNAME: &str = "InternalName";
const PRODUCTNAME: &str = "ProductName";
const ORIGINALFILENAME: &str = "OriginalFilename";
const FILEDESCRIPTION: &str = "FileDescription";
const PRODUCTVERSION: &str = "ProductVersion";

pub fn get_styles() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .usage(
            Style::new()
                .bold()
                .underline()
                .fg_color(Some(Color::Ansi(AnsiColor::BrightYellow))),
        )
        .header(
            Style::new()
                .bold()
                .underline()
                .fg_color(Some(Color::Ansi(AnsiColor::BrightYellow))),
        )
        .placeholder(
            Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightCyan))),
        )
        .literal(
            Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightGreen))),
        )
        .invalid(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::BrightRed))),
        )
        .error(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::BrightRed))),
        )
        .valid(
            Style::new()
                .bold()
                .underline()
                .fg_color(Some(Color::Ansi(AnsiColor::BrightGreen))),
        )
        .context(
            Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightCyan))),
        )
}

#[derive(Parser, Debug, Clone, PartialEq)]
#[command(
    version,
    long_about = None,
    styles = get_styles(),
    )
]
///A command-line interface for reading and extracting data
///from MS Portable Executable or Dynamic Link Library.
struct Args {
    ///Determine file format.
    #[arg(short, long="format")]
    format: bool,
    ///Determine file MIME media type.
    #[arg(short, long="type")]
    type_: bool,
    ///Determine file extension.
    #[arg(short, long="extension")]
    extension: bool,
    ///Extract metadata from Portable Executable or DLL.
    #[arg(short, long="metadata")]
    metadata: bool,
    ///Extract tags from audio file.
    #[arg(short, long="audiotags")]
    audiotags: bool,
    ///Extract icon from Portable Executable or DLL.
    #[arg(short, long="icon")]
    icon: bool,
    ///Path to output directory.
    #[arg(short, long="output", default_value=".")]
    out_dir: PathBuf,
    ///Path to portable executable or dll.
    #[arg(required=true)]
    file_list: Vec<PathBuf>,
    ///Set extension for output file."
    #[arg(short, long="suffix", default_value=".png")]
    suffix: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ExeInfo {
    #[serde(rename = "CompanyName")]
    company: Option<String>,
    #[serde(rename = "LegalCopyright")]
    copyright: Option<String>,
    #[serde(rename = "InternalName")]
    internal: Option<String>,
    #[serde(rename = "ProductName")]
    product: Option<String>,
    #[serde(rename = "OriginalFilename")]
    original: Option<String>,
    #[serde(rename = "FileDescription")]
    description: Option<String>,
    #[serde(rename = "ProductVersion")]
    version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AudioInfo {
    album: Option<String>,
    title: Option<String>,
    artist: Option<String>,
    year: Option<i32>,
}

#[derive(Debug, Clone, PartialEq)]
struct IconData {
    id: ResourceEntryName,
    format: ImageFormat,
    buffer: Vec<u8>,
}

fn save_data_to_image(buf: Vec<u8>, out_path: &PathBuf, format: ImageFormat)
 -> Result<(), Error>
{
    let data = buf.clone();
    let reader = image::ImageReader::new(Cursor::new(&data))
        .with_guessed_format()?;

    match format {
        ImageFormat::Png => {
            match reader.decode() {
                Ok(dynamic_image) => {
                    if dynamic_image.height() < 256 {
                        let resize = image::imageops::resize(
                            &dynamic_image,
                            256,
                            256,
                            image::imageops::FilterType::Lanczos3
                        );
                        let mut file = std::fs::File::create(out_path)?;
                        resize.write_to(&mut file, format)?;
                        println!("\x1b[92mSaved to {:?}\x1b[0m", out_path);
                    }
                    else {
                        let mut file = std::fs::File::create(out_path)?;
                        dynamic_image.write_to(&mut file, format)?;
                        println!("\x1b[92mSaved to {:?}\x1b[0m", out_path);
                    }
                },
                Err(e) => {
                    eprintln!("{:?}", e);
                    let mut file = std::fs::File::create(out_path)?;
                    file.write_all(&buf)?;
                    println!("\x1b[92mSaved to {:?}\x1b[0m", out_path);
                },
            }
        },
        ImageFormat::Ico => {
            let mut file = std::fs::File::create(out_path)?;
            file.write_all(&buf)?;
            println!("\x1b[92mSaved to {:?}\x1b[0m", out_path);
        },
        _ => {
            let dynamic_image = reader.decode()?;
            let mut file = std::fs::File::create(out_path)?;
            dynamic_image.write_to(&mut file, format)?;
            println!("\x1b[92mSaved to {:?}\x1b[0m", out_path);
        },
    }
    Ok(())
}

fn get_groups(root: &ResourceTable) -> Result<Vec<Vec<IconDirectoryEntry>>, Error>
{
    let mut groups: Vec<Vec<IconDirectoryEntry>> = Vec::new();
    let entry = root.get(ResourceEntryName::ID(RT_GROUP_ICON as u32)).ok_or(
        anyhow!("RT_GROUP_ICON not found!")
    )?;
    if entry.is_table() {
        let group_table = entry.as_table().ok_or(
            anyhow!("Failed to get ResourceTable!")
        )?;
        let group_entries = group_table.entries();
        // println!("RT_GROUP_ICON_COUNT: {:?}", group_entries.len());
        if let Some(group_name) = group_entries.into_iter().next() {
            let res_entry = group_table.get(group_name).ok_or(
                anyhow!("Failed to get ResourceEntry!")
            )?;
            if res_entry.is_table() {
                let res_table = res_entry.as_table().ok_or(
                    anyhow!("Failed to get ResourceTable!")
                )?;
                let res_entries = res_table.entries();
                for entry_name in res_entries {
                    let res_entry = res_table.get(entry_name).ok_or(
                        anyhow!("Failed to get ResourceEntry!")
                    )?;
                    if res_entry.is_data() {
                        let res_data = res_entry.as_data().ok_or(
                            anyhow!("Failed to get ResourceData!")
                        )?;
                        let data = res_data.data().to_vec();
                        let data = &data[6..].to_owned();
                        let mut group: Vec<IconDirectoryEntry> = Vec::new();
                        for chunk in data.chunks(14) {
                            let (_, ico_entry) =
                                IconDirectoryEntry::read_from_suffix(chunk)
                                    .unwrap();
                            group.push(ico_entry);
                        }
                        groups.push(group);
                    }
                }
            }
        }
    }
    Ok(groups)
}

fn get_icons(root: &ResourceTable) -> Result<Vec<IconData>, Error>
{
    let mut icons: Vec<IconData> = Vec::new();
    let entry = root.get(ResourceEntryName::ID(RT_ICON as u32)).ok_or(
        anyhow!("RT_ICON source not found")
    )?;
    if entry.is_table() {
        let table = entry.as_table().ok_or(
            anyhow!("Failed to get ResourceTable!")
        )?;
        let entries = table.entries();
        for entry in entries {
            let res_entry = table.get(entry).ok_or(
                anyhow!("Failed to get ResourceEntry!")
            )?;
            if res_entry.is_table() {
                let res_table = res_entry.as_table().ok_or(
                    anyhow!("Failed to get ResourceTable!")
                )?;
                let res_entries = res_table.entries();
                if let Some(res_name) = res_entries.first()
                && let Some(res_entry) = res_table.get(*res_name)
                && res_entry.is_data() {
                    let data = res_entry.as_data().ok_or(
                        anyhow!("Failed to get ResourceEntry!")
                    )?;
                    let data = data.data();

                    match image::guess_format(data) {
                        Ok(ImageFormat::Png) => {
                            let icon_data = IconData {
                                id: entry.clone(),
                                format: ImageFormat::Png,
                                buffer: data.to_vec(),
                            };
                            icons.push(icon_data);
                        },
                        _ => {
                            let icon_data = IconData {
                                id: entry.clone(),
                                format: ImageFormat::Ico,
                                buffer: data.to_vec(),
                            };
                            icons.push(icon_data);
                        },
                    }
                }
            }
        }
    }
    Ok(icons)
}

fn get_buffer(groups: Vec<IconDirectoryEntry>, icons: Vec<&IconData>)
 -> Result<Vec<u8>, Error>
{
    let mut buf: Vec<u8> = vec![];
    buf.write_all(&[0, 0])?;
    buf.write_u16::<LittleEndian>(1)?;
    buf.write_u16::<LittleEndian>(groups.len() as u16)?;
    let mut offset = 6 + (groups.len() * 16) as u32;

    for group_icon in &groups {
        buf.write_u8(group_icon.width)?;
        buf.write_u8(group_icon.height)?;
        buf.write_u8(group_icon.color_count)?;
        buf.write_u8(group_icon.reserved)?;
        buf.write_u16::<LittleEndian>(group_icon.planes)?;
        buf.write_u16::<LittleEndian>(group_icon.bit_count)?;
        buf.write_u32::<LittleEndian>(group_icon.bytes)?;
        buf.write_u32::<LittleEndian>(offset)?;
        offset += group_icon.bytes;
    }
    for data in &icons {
        buf.write_all(&data.buffer)?;
    }
    Ok(buf)
}

pub fn extract_audiotags(file_path: &PathBuf) -> Result<(), Error>
{
    let mut tags = AudioInfo {
        album: None,
        title: None,
        artist: None,
        year: None,
    };
    if let Ok(tag) = Tag::default().read_from_path(file_path) {
        tags.album = tag.album_title().map(|album| album.to_string());
        tags.title = tag.title().map(|title| title.to_string());
        tags.artist = tag.artist().map(|artist| artist.to_string());
        tags.year = tag.year();
    }
    let json_data = serde_json::to_string_pretty(&tags)?;
    println!("{}", json_data);
    Ok(())
}

pub fn extract_metadata(exe_path: &PathBuf) -> Result<(), Error>
{
    let mut exe_info = ExeInfo {
        company: None,
        copyright: None,
        internal: None,
        product: None,
        original: None,
        description: None,
        version: None,
    };

    let img = Image::parse_file(exe_path)?;
    let rsrc = img.resource_directory()
        .ok_or(anyhow!("\x1b[91mResource directory not found!\x1b[0m"))?;

    if let Ok(ver) = rsrc.get_version_info() {
        let inf = ver.ok_or(anyhow!("\x1b[91mVersionInfo not found!\x1b[0m"))?;
        for version_table in &inf.strings {
            for (k, v) in &version_table.strings {
                if  k.as_str() == COMPANYNAME {
                    exe_info.company = Some(v.clone())
                };
                if  k.as_str() == LEGALCOPYRIGHT {
                    exe_info.copyright = Some(v.clone())
                };
                if  k.as_str() == INTERNALNAME {
                    exe_info.internal = Some(v.clone())
                };
                if  k.as_str() == PRODUCTNAME {
                    exe_info.product = Some(v.clone())
                };
                if  k.as_str() == ORIGINALFILENAME {
                    exe_info.original = Some(v.clone())
                };
                if  k.as_str() == FILEDESCRIPTION {
                    exe_info.description = Some(v.clone())
                };
                if  k.as_str() == PRODUCTVERSION {
                    exe_info.version = Some(v.clone())
                };
            }
        }
        let json_data = serde_json::to_string_pretty(&exe_info)?;
        println!("{}", json_data);
    }
    Ok(())
}

pub fn extract_icon(exe_path: &PathBuf, out_path: &mut PathBuf, format: ImageFormat)
 -> Result<(), Error>
{
    let img = Image::parse_file(exe_path)?;

    if let Some(rsrc) = img.resource_directory() {
        let root = rsrc.root();
        let groups = get_groups(root)?;
        let icons = get_icons(root)?;

        let png_data: Vec<&IconData> = icons
            .iter()
            .filter(|d| d.format == ImageFormat::Png)
            .collect();

        let ico_data: Vec<&IconData> = icons
            .iter()
            .filter(|d| d.format == ImageFormat::Ico)
            .collect();

        let mut group_icon_data: Vec<(Vec<IconDirectoryEntry>, Vec<&IconData>)> = Vec::new();

        for group in groups {
            let mut group_data: Vec<IconDirectoryEntry> = Vec::new();
            let mut icon_data: Vec<&IconData> = Vec::new();
            for g in group {
                for d in &ico_data {
                    if d.id == ResourceEntryName::ID(g.id as u32) {
                        group_data.push(g);
                        icon_data.push(*d);
                        break
                    }
                }
            }
            group_icon_data.push((group_data, icon_data))
        }

        if let Some(max_val) = png_data.iter().max_by_key(|d| d.buffer.len()) {
            for (group_, icon_) in group_icon_data {
                let png_buf = max_val.buffer.clone();
                let ico_buf = get_buffer(group_, icon_)?;

                if png_buf.len() >= ico_buf.len() {
                    if let Err(e) = save_data_to_image(png_buf, out_path, ImageFormat::Png) {
                        println!("{:?} {:?}", out_path, e);
                        if let Err(e) = save_data_to_image(ico_buf, out_path, format) {
                            println!("{:?} {:?}", out_path, e);
                        }
                        else{
                            break
                        }
                    }
                    else {
                        break
                    }
                }
                else if png_buf.len() <= ico_buf.len() {
                    if let Err(e) = save_data_to_image(ico_buf, out_path, format) {
                        println!("{:?} {:?}", out_path, e);
                        let _ = save_data_to_image(png_buf, out_path, ImageFormat::Png);
                        break
                    }
                    else {
                        break
                    }
                }
            }
        }
        else if !ico_data.is_empty() {
            for (group_, icon_) in group_icon_data {
                let buf = get_buffer(group_, icon_)?;
                if let Err(e) = save_data_to_image(buf, out_path, format) {
                    println!("{:?}", e);
                }
                else {
                    break
                }
            }
        }
        Ok(())
    }
    else {
        Err(anyhow!("Icon source not found in portable executable!"))?
    }
}

pub fn determine_type(exe_path: &PathBuf, option: &str) -> Result<(), Error>
{
    let fmt = FileFormat::from_file(exe_path)?;
    if option == "format" {
        println!("\x1b[92m{:?}", fmt);
    }
    if option == "type" {
        println!("\x1b[93m{:?}", fmt.media_type());
    }
    if option == "extension" {
        println!("\x1b[96m{:?}\x1b[0m", fmt.extension());
    }
    Ok(())
}

pub fn get_out_path(exe_path: &Path, out_dir: &Path, suffix: &String) -> PathBuf
{
    let mut out_buf = out_dir.to_path_buf();
    let extension = suffix.trim_matches('.');
    let out_path: PathBuf =
        if let Some(exe_name) = exe_path.file_stem() && out_buf.is_dir() {
            let mut name = exe_name.to_os_string();
            name.push(suffix);
            out_buf.push(name.as_os_str());
            out_buf
        }
        else if let Some(ext) = out_buf.extension()
            && ext == OsStr::new(extension) {
                out_buf
        }
        else if let Some(ext) = out_buf.extension()
            && ext != OsStr::new(extension) {
                out_buf.set_extension(extension);
                out_buf
        }
        else if out_buf.extension().is_none()
            && let Ok(false) = out_buf.try_exists() {
                out_buf.set_extension(extension);
                out_buf
        }
        else {
            let epoch = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Time went backwards");

            let timestamp = epoch.as_millis();
            let fmt_name = format!("{}-{}{}", "output", timestamp, suffix);
            PathBuf::from(fmt_name)
        };
    out_path
}

fn run(arg: Args) -> Result<(), Error> {
    let format =
        if arg.suffix == ".png" { ImageFormat::Png }
        else if arg.suffix == ".jpg" { ImageFormat::Jpeg }
        else if arg.suffix == ".ico" { ImageFormat::Ico }
        else { ImageFormat::Png };

    for exe_path in arg.file_list {
        if exe_path.is_file() {
            let fmt = FileFormat::from_file(&exe_path)?;
            if fmt == FileFormat::PortableExecutable
            || fmt == FileFormat::DynamicLinkLibrary {
                let mut out_path = get_out_path(&exe_path, &arg.out_dir, &arg.suffix);

                if arg.metadata {
                    if let Err(e) = extract_metadata(&exe_path) {
                        println!("{:?}", e);
                    };
                }
                else if arg.icon {
                    extract_icon(&exe_path, &mut out_path, format)?;
                }
            }
            if arg.audiotags {
                let _ = extract_audiotags(&exe_path);
            }
            if arg.format {
                println!("\x1b[92m{:?}", fmt);
            }
            if arg.type_ {
                println!("\x1b[93m{:?}", fmt.media_type());
            }
            if arg.extension {
                println!("\x1b[96m{:?}\x1b[0m", fmt.extension());
            }
        }
        else {
            eprintln!(
                "\x1b[91mArgument must be a valid file path! \
                \n\x1b[92mSee --help for more info\x1b[0m"
            )
        }
    }
    Ok(())
}

fn main() {
    let arg = Args::parse();
    let mut cmd = <Args as clap::CommandFactory>::command();
    if let Err(e) = run(arg) {
        eprintln!("{:?}", e);
    }
    if std::env::args().len() <= 2 {
        cmd.print_help().expect("Failed to print help");
    }
}

