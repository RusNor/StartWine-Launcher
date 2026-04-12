//#![allow(non_upper_case_globals)]
//#![allow(non_snake_case)]
//#![allow(unused_imports)]
//#![allow(unused_variables)]
//#![allow(dead_code)]

use std::ffi::CString;
use std::os::raw::c_void;
use std::{env, ffi, io, mem, ptr};
use std::process;
use image::GenericImageView;

use gtk4::prelude::*;
use gtk4::gdk;
use gtk4::gdk_pixbuf::Pixbuf;
use gtk4::gdk_pixbuf::Colorspace;
use gtk4::glib;

extern crate gl;
use gl::types::*;

extern crate walkdir;
use walkdir::WalkDir;

const APP_ID: &str = "ru.launcher.StartWine.Cube";
const APP_NAME: &str = "Cube";

// term colors
const G: &str = "\x1b[30m";
const R: &str = "\x1b[31m";
const M: &str = "\x1b[32m";
const Y: &str = "\x1b[33m";
const B: &str = "\x1b[34m";
const V: &str = "\x1b[35m";
const T: &str = "\x1b[36m";
const W: &str = "\x1b[37m";
const END: &str = "\x1b[0m";

const MANGOHUD_CONFIG: &str = "fps_color_change,round_corners=10,cpu_load_change,\
    gpu_load_change,core_load_change,background_alpha=0.2,background_color=020202,\
    toggle_fps_limit=Shift_L+F1,position=top-right,toggle_hud=Shift_R+F12,\
    toggle_hud_position=Shift_R+F11,core_load,font_size=14";

const MESA_OVERLAY_CONFIG: &str = "position=top-left";

const GALLIUM_HUD_CONFIG: &str = ".d.w320fps+.d.w320frametime+.d.w320cpu+\
        .d.w320GPU-load+.d.w320memory-clock+.d.w320VRAM-usage+.d.w320temperature";

const CSS_SRC: &str = r#"
@define-color sw_bg_color rgba(30,30,36,0.85);
@define-color sw_accent_fg_color rgba(80,176,251,0.85);
@define-color sw_accent_bg_color rgba(40,40,46,0.85);
@define-color sw_header_bg_color rgba(15,15,17,0.99);
@define-color sw_invert_header_bg_color rgba(128,128,128, 1.0);
sw_window.sw_background {
    border: 1px solid @sw_bg_color;
    border-radius: 16px;
    background-color: @sw_bg_color;
    background-image: image(@sw_bg_color);
    box-shadow: none;
}
sw_header_top {
    color: @sw_invert_header_bg_color;
    background-color: @sw_header_bg_color;
    background-image: image(@sw_header_bg_color);
    min-height: 38px;
    margin-left: -1px;
    margin-right: -1px;
    box-shadow: none;
    background-image: none;
    border-color: transparent;
    border-bottom: 1px solid transparent;
    padding-right: 2px;
    padding-left: 3px;
}
sw_wc_close,
sw_wc_minimize,
sw_wc_maximize {
    min-width: 18px;
    min-height: 18px;
    padding: 0px;
    margin-right: 4px;
    color: white;
    border-radius: 9999px;
    border-width: 0px;
    background-size: cover;
    background-position: center;
    background-color: rgba(255, 255, 255, 0.05);
    background-image: image(rgba(255, 255, 255, 0.05));
}
sw_wc_close.wc_color,
sw_wc_minimize.wc_color,
sw_wc_maximize.wc_color {
    background-color: @sw_accent_fg_color;
    background-image: image(@sw_accent_fg_color);
}
sw_wc_close.wc_mac {
    background-color: #ff3030;
    background-image: image(#ff3030);
}
sw_wc_minimize.wc_mac{
    background-color: #ffaa00;
    background-image: image(#ffaa00);
}
sw_wc_maximize.wc_mac {
    background-color: #30ff30;
    background-image: image(#30ff30);
}
sw_wc_close.wc_image image {
    background-color: @sw_accent_bg_color;
}
sw_wc_minimize.wc_image image {
    background-color: @sw_accent_bg_color;
}
sw_wc_maximize.wc_image image {
    background-color: @sw_accent_bg_color;
}
sw_wc_close:hover {
    background-color: #ff303040;
    background-image: image(#ff000040);
}
sw_wc_minimize:hover{
    background-color: #ffaa0040;
    background-image: image(#ffaa0040);
}
sw_wc_maximize:hover {
    background-color: #30ff3040;
    background-image: image(#30ff3040);
}
sw_wc_close:active,
sw_wc_minimize:active,
sw_wc_maximize:active {
    background-color: rgba(255, 255, 255, 0.1);
    color: white;
    background-color: @sw_accent_bg_color;
}
"#;

const VERTEX_SRC: &str = r#"
#version 330

layout(location = 0) in vec3 position;
layout(location = 1) in vec3 color;
layout(location = 2) in vec2 texture;

uniform float iTime;

out vec3 vColor;
out vec2 fragCoord;

mat4 rotX( in float angle ) {

    float c = cos(angle);
    float s = sin(angle);

    return mat4(1.0, 0, 0, 0,
                0, c, -s, 0,
                0, s, c, 0,
                0, 0, 0, 1);
}

mat4 rotY( in float angle ) {

    float c = cos(angle);
    float s = sin(angle);

    return mat4( c, 0, s, 0,
                0, 1.0, 0, 0,
                -s, 0, c, 0,
                0, 0, 0, 1);
}

mat4 rotZ( in float angle ) {
    float c = cos(angle);
    float s = sin(angle);

    return mat4(c, -s, 0, 0,
                s, c, 0, 0,
                0, 0, 1, 0,
                0, 0, 0, 1);
}

void main()
{
    gl_Position = rotX(iTime * 1.0) * rotZ(iTime * 1.0) * vec4(position, 1.0);
    // gl_Position = vec4(position, 1.0);
    vColor = color;
    fragCoord = texture;
}
"#;

const FRAGMENT_SRC: &str = r#"
#version 330

uniform vec3      iResolution;
uniform float     iTime;
uniform float     iTimeDelta;
uniform int       iFrame;
uniform float     iFrameRate;
uniform float     iChannelTime[4];
uniform vec3      iChannelResolution[4];
uniform vec4      iMouse;
uniform sampler2D iChannel0;
uniform sampler2D iChannel1;
uniform sampler2D iChannel2;
uniform sampler2D iChannel3;
uniform vec4      iDate;
uniform float     iSampleRate;

in vec2 fragCoord;
in vec3 vColor;

uniform sampler2D sTexture;
out vec4 fragColor;

void main()
{
    fragColor = texture(sTexture, fragCoord);
}
"#;

const VERTICES: [f32; 192] = [
    -0.5, -0.5, 0.5, 1.0, 0.0, 0.0, 0.0, 0.0,
    0.5, -0.5, 0.5, 0.0, 1.0, 0.0, 1.0, 0.0,
    0.5, 0.5, 0.5, 0.0, 0.0, 1.0, 1.0, 1.0,
    -0.5, 0.5, 0.5, 1.0, 1.0, 1.0, 0.0, 1.0,
    -0.5, -0.5, -0.5, 1.0, 0.0, 0.0, 0.0, 0.0,
    0.5, -0.5, -0.5, 0.0, 1.0, 0.0, 1.0, 0.0,
    0.5, 0.5, -0.5, 0.0, 0.0, 1.0, 1.0, 1.0,
    -0.5, 0.5, -0.5, 1.0, 1.0, 1.0, 0.0, 1.0,
    0.5, -0.5, -0.5, 1.0, 0.0, 0.0, 0.0, 0.0,
    0.5, 0.5, -0.5, 0.0, 1.0, 0.0, 1.0, 0.0,
    0.5, 0.5, 0.5, 0.0, 0.0, 1.0, 1.0, 1.0,
    0.5, -0.5, 0.5, 1.0, 1.0, 1.0, 0.0, 1.0,
    -0.5, 0.5, -0.5, 1.0, 0.0, 0.0, 0.0, 0.0,
    -0.5, -0.5, -0.5, 0.0, 1.0, 0.0, 1.0, 0.0,
    -0.5, -0.5, 0.5, 0.0, 0.0, 1.0, 1.0, 1.0,
    -0.5, 0.5, 0.5, 1.0, 1.0, 1.0, 0.0, 1.0,
    -0.5, -0.5, -0.5, 1.0, 0.0, 0.0, 0.0, 0.0,
    0.5, -0.5, -0.5, 0.0, 1.0, 0.0, 1.0, 0.0,
    0.5, -0.5, 0.5, 0.0, 0.0, 1.0, 1.0, 1.0,
    -0.5, -0.5, 0.5, 1.0, 1.0, 1.0, 0.0, 1.0,
    0.5, 0.5, -0.5, 1.0, 0.0, 0.0, 0.0, 0.0,
    -0.5, 0.5, -0.5, 0.0, 1.0, 0.0, 1.0, 0.0,
    -0.5, 0.5, 0.5, 0.0, 0.0, 1.0, 1.0, 1.0,
    0.5, 0.5, 0.5, 1.0, 1.0, 1.0, 0.0, 1.0,
];

const INDICES: [i32; 36] = [
    0, 1, 2, 2, 3, 0, 4, 5, 6, 6, 7, 4, 8, 9, 10, 10, 11, 8, 12, 13, 14, 14, 15,
    12, 16, 17, 18, 18, 19, 16, 20, 21, 22, 22, 23, 20,
];


fn screen_size() -> Result<ffi::OsString, io::Error> {
    let mut string = ffi::OsString::new();
    let display = gdk::Display::default().unwrap_or_else(|| {
        eprintln!("GdkDisplay not found");
        process::exit(1);
    });
    let primary = display.monitors().item(0).unwrap_or_else(|| {
        eprintln!("GdkMonitor not found");
        process::exit(1);
    });
    let monitor = primary.downcast_ref::<gdk::Monitor>().unwrap_or_else(|| {
        eprintln!("GdkMonitor not found");
        process::exit(1);
    });
    let height = monitor.geometry().height();
    let size = height / 55;
    string.push(size.to_string());
    println!("MANGOHUD_FONT_SIZE: {:?}", string);
    Ok(string)
}


fn get_env(key: &str) -> Result<ffi::OsString, env::VarError> {
    match env::var(key) {
        Ok(val) => Ok(val.into()),
        Err(e) => Err(e)
    }
}


fn walk_dir(dir: &str) {
    for e in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if e.metadata().unwrap().is_file() {
            println!("{}", e.path().display())
        };
    }
}


fn init_opengl() {
    #[cfg(target_os = "macos")]
    let library = unsafe {
        libloading::os::unix::Library::new("libepoxy.0.dylib")
    }.unwrap();
    #[cfg(all(unix, not(target_os = "macos")))]
    let library = unsafe {
        libloading::os::unix::Library::new("libepoxy.so.0")
    }.unwrap();
    #[cfg(windows)]
    let library = unsafe {
        libloading::os::windows::Library::open_already_loaded("libepoxy-0.dll")
        .or_else(
            |_| libloading::os::windows::Library::open_already_loaded("epoxy-0.dll"))
            .unwrap();
    };
    epoxy::load_with(|name| {
        unsafe { library.get::<_>(name.as_bytes()) }
            .map(|symbol| *symbol)
            .unwrap_or(ptr::null())
    });
    gl::load_with(|name| { epoxy::get_proc_addr(name) });
}


fn build_ui(app: &gtk4::Application) {

    let gl_area = gtk4::GLArea::builder()
        .hexpand(true)
        .vexpand(true)
        .auto_render(true)
        .has_depth_buffer(true)
        .has_stencil_buffer(true)
        .build();

    gl_area.connect_realize(move |_area| {
        let ctx = _area.context().unwrap_or_else(|| {
            eprintln!("{R}Error: context not created!{M}");
            process::exit(1)
        }).type_();
        let api = _area.api();
        let auto_render = _area.is_auto_render();
        let depth_buffer = _area.has_depth_buffer();
        let stensil_buffer = _area.has_stencil_buffer();

        println!("{W}OpenGL Context:{M}\t{:?}", ctx);
        println!("{W}Renderer:{M}\t{:?}", get_env("GSK_RENDERER"));
        println!("{W}GLArea api:{M}\t{:?}", api);
        println!("{B}Auto render:{M}\t{:?}", auto_render);
        println!("{B}Depth buffer:{M}\t{:?}", depth_buffer);
        println!("{R}Stensil buffer:{M}\t{:?}", stensil_buffer);
        println!("{R}Context error:{M}\t{:?}", _area.error().is_some());

        if _area.error().is_some() {
            println!("<< context error!!! >>");
        }
    });

    let img = image::load_from_memory_with_format(
        include_bytes!("../img/gui_icons/cube.png"),
        image::ImageFormat::Png,
        ).expect("valid image");

    let (width, height) = &img.dimensions();
    let bytes = glib::Bytes::from(&img.into_bytes());
    let image = Pixbuf::from_bytes(
        &bytes,
        Colorspace::Rgb,
        true,
        8_i32,
        *width as i32,
        *height as i32,
        4_i32,
    );

    gl_area.connect_render(move |_area, _context| unsafe {
        // Vertex shader
        let v = gl::CreateShader(gl::VERTEX_SHADER);
        let c_str_vert = CString::new(VERTEX_SRC.as_bytes()).unwrap();
        gl::ShaderSource(v, 1, &c_str_vert.as_ptr(), ptr::null());
        gl::CompileShader(v);

        // Fragment shader
        let f = gl::CreateShader(gl::FRAGMENT_SHADER);
        let c_str_frag = CString::new(FRAGMENT_SRC.as_bytes()).unwrap();
        gl::ShaderSource(f, 1, &c_str_frag.as_ptr(), ptr::null());
        gl::CompileShader(f);

        // Link shaders
        let shader = gl::CreateProgram();
        gl::AttachShader(shader, v);
        gl::AttachShader(shader, f);
        gl::LinkProgram(shader);

        // Set up vertex data and buffers
        let (mut vbo, mut vao, mut ebo) = (0, 0, 0);

        // Vertex Arrays Object
        gl::GenVertexArrays(1, &mut vao);
        gl::BindVertexArray(vao);

        // Vertex Buffer Object
        gl::GenBuffers(1, &mut vbo);
        gl::BindBuffer(gl::ARRAY_BUFFER, vbo);
        gl::BufferData(
            gl::ARRAY_BUFFER,
            (VERTICES.len() * mem::size_of::<GLfloat>()) as GLsizeiptr,
            &VERTICES[0] as *const f32 as *const c_void,
            gl::STATIC_DRAW,
        );

        // Element Buffer Object
        gl::GenBuffers(1, &mut ebo);
        gl::BindBuffer(gl::ELEMENT_ARRAY_BUFFER, ebo);
        gl::BufferData(
            gl::ELEMENT_ARRAY_BUFFER,
            (INDICES.len() * mem::size_of::<GLfloat>()) as GLsizeiptr,
            &INDICES[0] as *const i32 as *const c_void,
            gl::STATIC_DRAW,
        );

        // Position attribute
        let stride = 8 * mem::size_of::<GLfloat>() as GLsizei;

        gl::VertexAttribPointer(0, 3, gl::FLOAT, gl::FALSE, stride, ptr::null());
        gl::EnableVertexAttribArray(0);

        gl::VertexAttribPointer(1, 3, gl::FLOAT, gl::FALSE, stride, 12 as *const c_void);
        gl::EnableVertexAttribArray(1);

        gl::VertexAttribPointer(2, 2, gl::FLOAT, gl::FALSE, stride, 24 as *const c_void);
        gl::EnableVertexAttribArray(2);

        // Generate Textures
        let mut texture = 0;
        gl::GenTextures(1, &mut texture);
        gl::BindTexture(gl::TEXTURE_2D, texture);

        // Set the texture wrapping parameters
        gl::TexParameteri(gl::TEXTURE_2D, gl::TEXTURE_WRAP_S, gl::REPEAT as i32);
        gl::TexParameteri(gl::TEXTURE_2D, gl::TEXTURE_WRAP_T, gl::REPEAT as i32);

        // Set texture filtering parameters
        gl::TexParameteri(gl::TEXTURE_2D, gl::TEXTURE_MIN_FILTER, gl::LINEAR as i32);
        gl::TexParameteri(gl::TEXTURE_2D, gl::TEXTURE_MAG_FILTER, gl::LINEAR as i32);

        // Load image, create texture and generate mipmaps
        let width = image.clone().width();
        let height = image.clone().height();

        gl::TexImage2D(
            gl::TEXTURE_2D,
            0,
            gl::RGBA as i32,
            width as i32,
            height as i32,
            0,
            gl::RGBA,
            gl::UNSIGNED_BYTE,
            &image.clone().pixels()[0] as *const u8 as *const c_void,
        );
        gl::GenerateMipmap(gl::TEXTURE_2D);

        // Use shader program
        gl::UseProgram(shader);
        gl::ClearColor(0.0, 0.0, 0.0, 0.5);
        gl::Clear(gl::COLOR_BUFFER_BIT);
        gl::Clear(gl::DEPTH_BUFFER_BIT);
        gl::Enable(gl::DEPTH_TEST);
        gl::Enable(gl::BLEND);
        gl::BlendFunc(gl::SRC_ALPHA, gl::ONE_MINUS_SRC_ALPHA);

        let c_itime = CString::new("iTime").expect("CString::new failed");
        let time_location = gl::GetUniformLocation(shader, c_itime.as_ptr());
        let frame_counter = _area.frame_clock().unwrap().frame_counter();
        let itime = frame_counter as f32 / 100.0;

        if time_location != -1 {
            gl::Uniform1f(time_location, itime);
        };

        // Draw elements
        gl::DrawElements(
            gl::TRIANGLES,
            INDICES.len() as i32,
            gl::UNSIGNED_INT,
            ptr::null(),
        );

        // Disable program
        gl::BindVertexArray(0);
        gl::DisableVertexAttribArray(0);
        gl::BindBuffer(gl::ARRAY_BUFFER, 0);
        gl::UseProgram(0);

        // Delete shaders
        gl::DetachShader(shader, v);
        gl::DetachShader(shader, f);
        gl::DeleteShader(v);
        gl::DeleteShader(f);

        // delete buffers, textures and vertices
        gl::DisableVertexAttribArray(0);
        gl::DisableVertexAttribArray(1);
        gl::DisableVertexAttribArray(2);
        gl::DeleteBuffers(1, &vbo as *const u32);
        gl::DeleteBuffers(1, &ebo as *const u32);
        gl::DeleteVertexArrays(1, &vao as *const u32);
        gl::DeleteTextures(1, &texture as *const u32);
        gl::DeleteProgram(shader);

        true.into()
    });

    gl_area.connect_resize(move |_area, width, height| {
        unsafe {
            gl::Viewport(0, 0, width, height);
        }
    });

    gl_area.add_tick_callback(move |_area, _frame_clock| {
        _area.queue_render();
        true.into()
    });

    let wc_close = gtk4::Button::builder()
        .css_name("sw_wc_close")
        .valign(gtk4::Align::Center)
        .build();

    let wc_minimize = gtk4::Button::builder()
        .css_name("sw_wc_minimize")
        .valign(gtk4::Align::Center)
        .build();

    let wc_maximize = gtk4::Button::builder()
        .css_name("sw_wc_maximize")
        .valign(gtk4::Align::Center)
        .build();

    let headerbar_end_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .build();

    headerbar_end_box.append(&wc_minimize);
    headerbar_end_box.append(&wc_maximize);
    headerbar_end_box.append(&wc_close);

    let headerbar = gtk4::HeaderBar::builder()
        .css_name("sw_header_top")
        .show_title_buttons(false)
        .build();

    headerbar.set_size_request(-1, 46);
    headerbar.pack_end(&headerbar_end_box);

    let window = gtk4::Window::builder()
        .application(app)
        .name("parent")
        .css_name("sw_window")
        .title("Cube")
        .default_width(720_i32)
        .default_height(720_i32)
        .resizable(false)
        .decorated(false)
        //.titlebar(&headerbar)
        .child(&gl_area)
        .build();

    let ctrl_key = gtk4::EventControllerKey::new();
    window.remove_css_class("background");
    window.add_css_class("sw_background");
    window.add_controller(ctrl_key.clone());

    let w = window.clone();
    ctrl_key.connect_key_pressed(move |_ctrl: &gtk4::EventControllerKey,
        keyval: gdk::Key, _keycode: u32, _state: gdk::ModifierType| {
            if keyval == gtk4::gdk::Key::Escape {
                w.close()
            }
            true.into()
        }
    );

    let w = window.clone();
    wc_close.connect_clicked(move |_| {
        w.close();
    });

    let w = window.clone();
    wc_minimize.connect_clicked(move |_| {
        w.minimize();
    });

    let w = window.clone();
    wc_maximize.connect_clicked(move |_| {
        if w.is_maximized() {
            w.unmaximize()
        } else {
            w.maximize()
        };
    });

    let css_provider = gtk4::CssProvider::new();
    css_provider.load_from_string(CSS_SRC);
    gtk4::style_context_add_provider_for_display(
        &gdk::Display::default().unwrap(),
        &css_provider,
        gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
    window.clone().present();
}

pub fn main() -> glib::ExitCode {
    if get_env("MANGOHUD_CONFIG").ok().is_none() {
        unsafe {
            env::set_var("MANGOHUD", "1");
            env::set_var("MANGOHUD_LOG_LEVEL", "off");
            env::set_var("MANGOHUD_CONFIG", MANGOHUD_CONFIG);
        }
        println!("MANGOHUD_CONFIG: {:?}", MANGOHUD_CONFIG);
    }
    if get_env("SW_USE_MESA_OVERLAY_HUD").ok().is_some() {
        unsafe {
            env::set_var("VK_LAYER_MESA_OVERLAY_CONFIG", MESA_OVERLAY_CONFIG);
            env::set_var("VK_INSTANCE_LAYERS", "$VK_INSTANCE_LAYERS:VK_LAYER_MESA_overlay");
            env::set_var("VK_LOADER_LAYERS_ENABLE", "$VK_LOADER_LAYERS_ENABLE:VK_LAYER_MESA_overlay");
        }
    }
    if get_env("SW_USE_GALLIUM_HUD").ok().is_some() {
        unsafe {
            env::set_var("GALLIUM_HUD_PERIOD", "0.1");
            env::set_var("GALLIUM_HUD", GALLIUM_HUD_CONFIG);
        }
    }
    unsafe { env::set_var("GDK_DEBUG", "gl-prefer-gl") };

    if get_env("WAYLAND_DISPLAY").ok().is_some() {
        if let Ok(render) = get_env("GSK_RENDERER") {
            match render.to_str() {
                Some("vulkan") => unsafe { env::set_var("GDK_BACKEND", "wayland") },
                _ => unsafe {
                    env::set_var("GDK_BACKEND", "x11");
                    env::set_var("GDK_DISABLE", "egl");
                },
            }
        } else {
            unsafe {
                env::set_var("GDK_BACKEND", "x11");
                env::set_var("GDK_DISABLE", "egl");
            }
        }
    } else {
        unsafe {
            env::set_var("GDK_BACKEND", "x11");
            env::set_var("GDK_DISABLE", "egl");
        }
    }
    init_opengl();
    glib::set_prgname(Some(APP_NAME));
    glib::set_application_name(APP_NAME);
    let app = gtk4::Application::builder().application_id(APP_ID).build();
    let empty: Vec<String> = vec![];
    app.connect_activate(build_ui);
    app.run_with_args(&empty)
}

