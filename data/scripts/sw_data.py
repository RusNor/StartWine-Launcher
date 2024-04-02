#!/usr/bin/env python3
################################

# Core modules.
from os import environ, pathsep, getenv
from sys import argv, orig_argv
from pathlib import Path
import shutil
import json
#import csv

# Third party modules.
import gi
from gi.repository import GLib
import psutil
from psutil import Process

# Local modules.
from sw_shaders import Shaders as sdr

################################

sw_program_name = 'StartWine'

################################

class TermColors():
    '''___terminal colors pallete___'''

    END = '\33[0m'
    BOLD = '\33[1m'
    ITALIC = '\33[3m'
    URL = '\33[4m'
    BLINK = '\33[5m'
    BLINK2 = '\33[6m'
    SELECTED = '\33[7m'

    BLACK = '\33[30m'
    RED = '\33[31m'
    GREEN = '\33[32m'
    YELLOW = '\33[33m'
    BLUE = '\33[34m'
    VIOLET = '\33[35m'
    BEIGE = '\33[36m'
    WHITE = '\33[37m'

    BLACKBG = '\33[40m'
    REDBG = '\33[41m'
    GREENBG = '\33[42m'
    YELLOWBG = '\33[43m'
    BLUEBG = '\33[44m'
    VIOLETBG = '\33[45m'
    BEIGEBG = '\33[46m'
    WHITEBG = '\33[47m'

    GREY = '\33[90m'
    RED2 = '\33[91m'
    GREEN2 = '\33[92m'
    YELLOW2 = '\33[93m'
    BLUE2 = '\33[94m'
    VIOLET2 = '\33[95m'
    BEIGE2 = '\33[96m'
    WHITE2 = '\33[97m'

    GREYBG = '\33[100m'
    REDBG2 = '\33[101m'
    GREENBG2 = '\33[102m'
    YELLOWBG2 = '\33[103m'
    BLUEBG2 = '\33[104m'
    VIOLETBG2 = '\33[105m'
    BEIGEBG2 = '\33[106m'
    WHITEBG2 = '\33[107m'

################################___Paths___:

sw_link = Path(argv[0]).absolute().parent
sw_scripts = f"{sw_link}"
sw_crier_path = Path(f"{sw_scripts}/sw_crier.py")
sw_fsh = Path(f"{sw_scripts}/sw_function.sh")
sw_rsh = Path(f"{sw_scripts}/sw_run.sh")
sw_run = Path(f"{sw_scripts}/sw_run")
sw_start = Path(f"{sw_scripts}/sw_start")
sw_menu = Path(f"{sw_scripts}/sw_menu.py")
sw_runlib = Path(f"{sw_scripts}/sw_runlib")
sw_tray = Path(f"{sw_scripts}/sw_tray.py")
sw_cube = Path(f"{sw_scripts}/sw_cube.py")
sw_localedir = Path(f"{sw_scripts}/locale")
sw_version = Path(f'{sw_scripts}/version')
sw_winever_json = Path(f'{sw_scripts}/wine_version.json')

sw_path = Path(sw_scripts).parent.parent
sw_default_path = Path(f"{Path.home()}/.local/share/StartWine")
sw_data_dir = Path(f"{sw_path}/data")
sw_app_config = Path(f"{sw_data_dir}/app_config")
sw_app_patches = Path(f"{sw_data_dir}/app_patches")
sw_default_config = Path(f"{sw_app_config}/.default/default")
sw_img = Path(f"{sw_data_dir}/img")
sw_gui_icons = Path(f"{sw_data_dir}/img/gui_icons")
sw_symbolic_icons = Path(f"{sw_data_dir}/img/gui_icons/hicolor/symbolic/apps")
sw_app_icons = Path(f'{sw_img}/app_icons')
sw_app_vicons = Path(f'{sw_img}/app_icons/vertical')
sw_app_hicons = Path(f'{sw_img}/app_icons/horizontal')
sw_launchers = Path(f'{sw_img}/launcher_icons/install_launchers')
sw_launchers_vertical = Path(f'{sw_img}/launcher_icons/vertical')
sw_launchers_horizontal = Path(f'{sw_img}/launcher_icons/horizontal')
sw_default_icon = f"{sw_gui_icons}/sw_icon.png"
sw_pfx = Path(f"{sw_data_dir}/pfx")
sw_pfx_default = Path(f"{sw_pfx}/pfx_default")
sw_pfx_backup = Path(f"{sw_data_dir}/pfx_backup")
sw_tmp = Path(f"{sw_data_dir}/tmp")
sw_logs = Path(f"{sw_tmp}/logs")
sw_tools = Path(f"{sw_data_dir}/tools")
sw_wine = Path(f"{sw_data_dir}/wine")
sw_wine_custom = Path(f"{sw_data_dir}/wine/wine_custom")
sw_games = Path(f"{sw_path}/Games")
sw_shortcuts = Path(f"{sw_path}/Shortcuts")
sw_themes = Path(f"{sw_img}/sw_themes")
sw_css = Path(f"{sw_img}/sw_themes/css")
sw_local = Path(f"{Path.home()}/.local/share/applications")
sw_css_dark = Path(f'{sw_link.parent}/img/sw_themes/css/dark/gtk.css')
sw_css_light = Path(f'{sw_link.parent}/img/sw_themes/css/light/gtk.css')
sw_css_custom = Path(f'{sw_link.parent}/img/sw_themes/css/custom/gtk.css')
sw_fm_cache = Path(f'{Path.home()}/.cache/sw_fm')
sw_fm_cache_thumbnail = Path(f'{Path.home()}/.cache/sw_fm/thumbnail')
sw_fm_cache_database = Path(f'{Path.home()}/.cache/sw_fm/database')
sw_fm_cache_donloads = Path(f'{Path.home()}/.cache/sw_fm/downloads')
sw_runtime = Path(f"{sw_path}/data/runtime/sw_runtime")
sw_appid_source = Path(f'{sw_scripts}/appid_source.json')
sw_appid_json = Path(f'{sw_scripts}/appid.json')
sw_menu_json = Path(f'{sw_scripts}/sw_menu.json')
sys_sounds = Path(f'/usr/share/sounds/freedesktop/stereo')
sw_sounds = Path(f'{sw_themes}/sounds')
sw_startup_sounds = f'{sw_sounds}/startup'
sw_bookmarks = Path(f'{Path.home()}/.cache/sw_fm/bookmarks')
sw_background = Path(f'{sw_themes}/background')
sw_mesa_shader_cache = Path(f'{sw_tmp}/mesa_shader_cache_sf')
sw_gl_shader_cache = Path(f'{sw_tmp}/gl_shader_cache')
sw_vkd3d_shader_cache = Path(f'{sw_tmp}/vkd3d_cache')
sw_dxvk_shader_cache = Path(f'{sw_tmp}/dxvk_cache')
sw_gst_cache = Path(f'{sw_tmp}/gstreamer-1.0')
sw_gst_home_cache = Path(f'{Path.home()}/.cache/gstreamer-1.0')

if not sw_shortcuts.exists():
    try:
        sw_shortcuts.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(TermColors.RED, e, TermColors.END)

dir_home = GLib.get_home_dir()
if dir_home is None:
    dir_home = f'{Path.home()}'

dir_docs = GLib.get_user_special_dir(GLib.USER_DIRECTORY_DOCUMENTS)
if dir_docs is None:
    dir_docs = f'{Path.home()}/Documents'

dir_desktop = GLib.get_user_special_dir(GLib.USER_DIRECTORY_DESKTOP)
if dir_desktop is None:
    dir_desktop = f'{Path.home()}/Desktop'

dir_pics = GLib.get_user_special_dir(GLib.USER_DIRECTORY_PICTURES)
if dir_pics is None:
    dir_pics = f'{Path.home()}/Pictures'

dir_videos = GLib.get_user_special_dir(GLib.USER_DIRECTORY_VIDEOS)
if dir_videos is None:
    dir_videos = f'{Path.home()}/Video'

dir_music = GLib.get_user_special_dir(GLib.USER_DIRECTORY_MUSIC)
if dir_music is None:
    dir_music = f'{Path.home()}/Music'

dir_downloads = GLib.get_user_special_dir(GLib.USER_DIRECTORY_DOWNLOAD)
if dir_downloads is None:
    dir_downloads = f'{Path.home()}/Downloads'

dir_public = GLib.get_user_special_dir(GLib.USER_DIRECTORY_PUBLIC_SHARE)
if dir_public is None:
    dir_public = f'{Path.home()}/Public'

dir_templates = GLib.get_user_special_dir(GLib.USER_DIRECTORY_TEMPLATES)
if dir_templates is None:
    dir_templates = f'{Path.home()}/Templates'

xdg_config_home = GLib.get_user_config_dir()
if xdg_config_home is None:
    xdg_config_home = f'{Path.home()}/.config'

user_name = GLib.get_user_name()
if user_name is None:
    user_name = getenv('USER')

dir_autostart = f'{xdg_config_home}/autostart'
sw_tray_autostart = Path(f'{xdg_config_home}/autostart/StartWine-Tray.desktop')

if Path(f'/usr/bin/vendor_perl/exiftool').exists() is True:
    sw_exiftool = Path(f'/usr/bin/vendor_perl/exiftool')
else:
    sw_exiftool = Path(f'/usr/bin/exiftool')

if sw_version.exists():
    version = sw_version.read_text().splitlines()[0]
    str_sw_version = '.'.join([e for e in version])
else:
    str_sw_version = ''

################################___Default_samples___:

gdbus_node_sample = (
    "<node>"
    "  <interface name='ru.project.StartWine'>"
    "    <method name='Message'>"
    "      <arg type='s' name='msg' direction='in'>"
    "      </arg>"
    "    </method>"
    "    <method name='Active'>"
    "      <arg type='s' name='question' direction='in'/>"
    "      <arg type='s' name='answer' direction='out'/>"
    "    </method>"
    "    <method name='Terminal'/>"
    "    <method name='Run'/>"
    "    <method name='Show'/>"
    "    <method name='ShowHide'/>"
    "    <method name='Shutdown'/>"
    "  </interface>"
    "</node>"
)

fshread = sw_fsh.read_text().split('\n')

default_bookmarks = str(
    f'{dir_home}\n'
    + f'{dir_desktop}\n'
    + f'{dir_videos}\n'
    + f'{dir_docs}\n'
    + f'{dir_downloads}\n'
    + f'{dir_pics}\n'
    + f'{dir_music}\n'
    + f'{sw_shortcuts}\n'
    + f'{sw_games}\n'
    + f'{sw_pfx}\n'
    + f'{sw_app_config}\n'
    + f'{sw_pfx_backup}\n'
    + f'{sw_wine}\n'
    + f'{sw_tmp}/logs\n'
)
default_ini = '''
{
"view_mode": "grid",
"view_widget": "files",
"icon_size": "72",
"icon_position": "horizontal",
"color_scheme": "dark",
"control_panel": "show",
"expand_menu": "True",
"autostart": "0",
"compact_mode": "False",
"restore_menu": "on",
"width": "1280",
"height": "720",
"hidden_files": "True",
"opengl_bg": "True",
"shader_src": "0",
"on_tray": "True",
"language": "ru_RU",
"icons": "builtin",
"sound": "on",
"auto_stop": "on",
"default_dir": "'''f"{Path.home()}"'''",
"current_dir": "'''f"{Path.home()}"'''"
}
'''
default_dark_css = '''
/* GLOBAL COLOR DEFINITIONS */
@define-color sw_text_color #a0a0a0;
@define-color sw_text_hover_color shade(@sw_text_color, 1.3);
@define-color sw_accent_fg_color rgba(0,160,255,0.8); /*#0099ff;*/
@define-color sw_accent_bg_color rgba(28,40,48,0.5);
@define-color sw_bg_color rgba(10,14,18,0.8);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color rgba(0,0,0,0.5);
@define-color sw_header_bg_color #000000;
@define-color sw_pop_bg_color #243240;
@import url("../default.css");
'''
default_light_css = '''
/* GLOBAL COLOR DEFINITIONS */
@define-color sw_text_color #505060;
@define-color sw_text_hover_color shade(@sw_text_color, 1.3);
@define-color sw_accent_fg_color rgba(0,160,255,0.8);
@define-color sw_accent_bg_color rgba(210,210,220,0.8);
@define-color sw_bg_color rgba(210,210,220,0.8);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color rgba(0,0,0,0.5);
@define-color sw_header_bg_color rgba(240,240,250,1);
@define-color sw_pop_bg_color rgba(220,220,230,1);
@import url("../default.css");
'''
default_custom_css_brown = '''
/* Global color definitions */
@define-color sw_text_color rgba(198,198,198,0.8);
@define-color sw_accent_fg_color rgba(175,120,60,0.8);
@define-color sw_accent_bg_color rgba(80,70,60,0.1);
@define-color sw_bg_color rgba(28,24,20,0.8);
@define-color sw_header_bg_color #181614;
@define-color sw_pop_bg_color #302824;
@define-color sw_text_hover_color shade(@sw_text_color, 1.3);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color @sw_view_bg_color;
@import url("../default.css");
'''
default_custom_css_red = '''
/* Global color definitions */
@define-color sw_text_color rgba(199,189,189,0.8);
@define-color sw_accent_fg_color rgba(249,50,100,0.8);
@define-color sw_accent_bg_color rgba(56,40,48,0.2);
@define-color sw_bg_color rgba(28,20,24,0.8);
@define-color sw_header_bg_color #000000;
@define-color sw_pop_bg_color #302028;
@define-color sw_text_hover_color shade(@sw_text_color, 1.3);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color @sw_view_bg_color;
@import url("../default.css");
'''
default_custom_css_teal = '''
/* Global color definitions */
@define-color sw_text_color rgba(180,200,200,0.8);
@define-color sw_accent_fg_color rgba(100,200,200,0.8);
@define-color sw_accent_bg_color rgba(48,56,56,0.2);
@define-color sw_bg_color rgba(24,28,28,0.8);
@define-color sw_header_bg_color #000000;
@define-color sw_pop_bg_color #283030;
@define-color sw_text_hover_color shade(@sw_text_color, 1.3);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color @sw_view_bg_color;
@import url("../default.css");
'''
default_custom_css_mint = '''
/* Global color definitions */
@define-color sw_text_color rgba(190,200,180,0.8);
@define-color sw_accent_fg_color rgba(160,200,100,0.8);
@define-color sw_accent_bg_color rgba(44,48,40,0.1);
@define-color sw_bg_color rgba(24,28,24,0.8);
@define-color sw_header_bg_color #000000;
@define-color sw_pop_bg_color #2c3028;
@define-color sw_text_hover_color shade(@sw_text_color, 1.3);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color @sw_view_bg_color;
@import url("../default.css");
'''
default_custom_css_blue = '''
/* Global color definitions */
@define-color sw_text_color rgba(180,190,200,0.8);
@define-color sw_accent_fg_color rgba(80,180,255,0.8);
@define-color sw_accent_bg_color rgba(40,50,60,0.1);
@define-color sw_bg_color rgba(20,24,28,0.8);
@define-color sw_header_bg_color #000000;
@define-color sw_pop_bg_color #28323c;
@define-color sw_text_hover_color shade(@sw_text_color, 1.3);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color @sw_view_bg_color;
@import url("../default.css");
'''
default_custom_css_yellow = '''
/* Global color definitions */
@define-color sw_text_color rgba(200,200,180,0.8);
@define-color sw_accent_fg_color rgba(200,200,100,0.8);
@define-color sw_accent_bg_color rgba(48,48,40,0.1);
@define-color sw_bg_color rgba(28,28,24,0.8);
@define-color sw_header_bg_color #000000;
@define-color sw_pop_bg_color #303028;
@define-color sw_text_hover_color shade(@sw_text_color, 1.3);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color @sw_view_bg_color;
@import url("../default.css");
'''
default_custom_css_grey = '''
/* Global color definitions */
@define-color sw_text_color rgba(199,199,199,0.8);
@define-color sw_accent_fg_color rgba(159,159,169,0.8);
@define-color sw_accent_bg_color rgba(44,48,56,0.2);
@define-color sw_bg_color rgba(28,32,36,0.8);
@define-color sw_header_bg_color #000000;
@define-color sw_pop_bg_color #282c30;
@define-color sw_text_hover_color shade(@sw_text_color, 1.3);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color @sw_view_bg_color;
@import url("../default.css");
'''
default_custom_css_purple = '''
/* Global color definitions */
@define-color sw_text_color rgba(189,179,199,0.8);
@define-color sw_accent_fg_color rgba(160,80,225,0.8);
@define-color sw_accent_bg_color rgba(56,48,64,0.1);
@define-color sw_bg_color rgba(28,24,32,0.8);
@define-color sw_header_bg_color #000000;
@define-color sw_pop_bg_color #302838;
@define-color sw_text_hover_color shade(@sw_text_color, 1.3);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color @sw_view_bg_color;
@import url("../default.css");
'''
sample_bash = '''#!/usr/bin/env bash'''
sample_python = '''#!/usr/bin/env python3'''
sample_desktop = '''[Desktop Entry]
Name=sample
Exec=
Comment=sample
Type=Application
MimeType=
Categories=
Icon=sample
'''
sample_tray_desktop = '''[Desktop Entry]
Name=StartWine-Tray
Exec=env '''f'"{sw_runtime}" "{sw_start}"'''' -t %F
Comment=StartWine-Launcher
Type=Application
MimeType=text/x-python3
Categories=Game
Icon='''f"{sw_path}/data/img/gui_icons/sw_icon.svg"'''
'''

default_mangohud = (
'fps_color_change,round_corners=12,cpu_load_change,gpu_load_change,core_load_change\
,background_alpha=0.2,font_size=20,background_color=020202,position=top-right\
,toggle_hud_position='
)

default_mangohud_colors = {
    'text_color': 'FFFFFF',
    'gpu_color': '2E9762',
    'cpu_color': '2E97CB',
    'vram_color': 'AD64C1',
    'ram_color': 'C26693',
    'engine_color': 'EB5B5B',
    'io_color': 'A491D3',
    'frametime_color': '00FF00',
    'background_color': '020202',
    'media_player_color': 'FFFFFF',
    'wine_color': 'EB5B5B',
    'battery_color': 'FF9078',
}

default_themes = {
    'blue': default_custom_css_blue,
    'brown': default_custom_css_brown,
    'grey': default_custom_css_grey,
    'mint': default_custom_css_mint,
    'purple': default_custom_css_purple,
    'red': default_custom_css_red,
    'teal': default_custom_css_teal,
    'yellow': default_custom_css_yellow,
}

def check_sw_version():

    if sw_version.exists():
        version = sw_version.read_text().splitlines()[0]
        str_sw_version = '.'.join([e for e in version])
    else:
        str_sw_version = ''

    return str_sw_version

def read_wine_ver_data():

    if sw_winever_json.exists():
        with open(sw_winever_json, 'r', encoding='utf-8') as f:
            winever_data = json.load(f)
            f.close()

        return winever_data
    else:
        winever_dict = None
        return winever_data

####___Create cache directory___.

def check_cache_dir():
    '''___create file manager cache directory___'''

    if not sw_fm_cache.exists():
        try:
            sw_fm_cache.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(TermColors.RED, e, TermColors.END)

    if not sw_fm_cache_thumbnail.exists():
        try:
            sw_fm_cache_thumbnail.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(TermColors.RED, e, TermColors.END)

    if not sw_fm_cache_database.exists():
        try:
            sw_fm_cache_database.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(TermColors.RED, e, TermColors.END)

    if not sw_fm_cache_donloads.exists():
        try:
            sw_fm_cache_donloads.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(TermColors.RED, e, TermColors.END)

####___Clear cache directory___.

def clear_cache_dir():
    '''___clear file manager cache directory___'''
    for f in sw_fm_cache.iterdir():
        if f.is_file():
            try:
                f.unlink()
            except IOError as e:
                print(f'{TermColors.RED}{e}{TermColors.END}')
        else:
            try:
                shutil.rmtree(f)
            except IOError as e:
                print(f'{TermColors.RED}{e}{TermColors.END}')
    else:
        print(f'{TermColors.VIOLET2}SW_FM_CACHE: {TermColors.GREEN}clear_cache_directory: done{TermColors.END}')

####___Create css custom file___.

def check_css_dark():
    '''___create css colorscheme samples___'''
    try:
        sw_css_dark.parent.mkdir(parents=True, exist_ok=True)
    except IOError as e:
        print(f'{TermColors.VIOLET2}SW_CSS:  {TermColors.RED}{e}')
    else:
        try:
            sw_css_dark.write_text(default_dark_css)
        except IOError as e:
            print(f'{TermColors.VIOLET2}SW_CSS:  {TermColors.RED}{e}')
        else:
            print(f'{TermColors.VIOLET2}SW_CSS:  {TermColors.GREEN}create sw_css_dark: done')

def check_css_light():
    '''___create css colorscheme samples___'''
    try:
        sw_css_light.parent.mkdir(parents=True, exist_ok=True)
    except IOError as e:
        print(f'{TermColors.VIOLET2}SW_CSS:  {TermColors.RED}{e}')
    else:
        try:
            sw_css_light.write_text(default_light_css)
        except IOError as e:
            print(f'{TermColors.VIOLET2}SW_CSS:  {TermColors.RED}{e}')
        else:
            print(f'{TermColors.VIOLET2}SW_CSS:  {TermColors.GREEN}create sw_css_light: done')

def check_css_custom():
    '''___create css colorscheme samples___'''
    try:
        sw_css_custom.parent.mkdir(parents=True, exist_ok=True)
    except IOError as e:
        print(f'{TermColors.VIOLET2}SW_CSS:  {TermColors.RED}{e}')
    else:
        try:
            sw_css_custom.write_text(default_custom_css_brown)
        except IOError as e:
            print(f'{TermColors.VIOLET2}SW_CSS:  {TermColors.RED}{e}')
        else:
            print(f'{TermColors.VIOLET2}SW_CSS:  {TermColors.GREEN}create sw_css_custom: done')

####___Create bookmarks file___.

def check_bookmarks():
    '''___create default bookmarks list___'''
    try:
        with open(sw_bookmarks, 'w', encoding='utf-8') as f:
            f.write(default_bookmarks)
            f.close()
    except IOError as e:
        print(f'{TermColors.VIOLET2}SW_BOOKMARKS: {TermColors.RED}{e}' + TermColors.END)
    else:
        print(f'{TermColors.VIOLET2}SW_BOOKMARKS: {TermColors.GREEN}create bookmarks: done' + TermColors.END)

####___Create application icons directory___.

def create_app_icons():
    '''___create application icons directory___'''
    try:
        sw_app_hicons.mkdir(parents=True, exist_ok=True)
    except IOError as e:
        print(f'{TermColors.RED}{e}{TermColors.END}')
    try:
        sw_app_vicons.mkdir(parents=True, exist_ok=True)
    except IOError as e:
        print(f'{TermColors.RED}{e}{TermColors.END}')
    try:
        Path(f'{sw_app_icons}/tmp').mkdir(parents=True, exist_ok=True)
    except IOError as e:
        print(f'{TermColors.RED}{e}{TermColors.END}')

def clear_app_icons():
    '''___clear application icons directory___'''

    for f in sw_app_hicons.iterdir():
        try:
            f.unlink()
        except IOError as e:
            print(f'{TermColors.RED}{e}{TermColors.END}')
        else:
            print(f'{TermColors.VIOLET2}SW_ICONS: {TermColors.GREEN}remove_icon {f.name}: done{TermColors.END}')

    for f in sw_app_vicons.iterdir():
        try:
            f.unlink()
        except IOError as e:
            print(f'{TermColors.RED}{e}{TermColors.END}')
        else:
            print(f'{TermColors.VIOLET2}SW_ICONS: {TermColors.GREEN}remove_icon {f.name}: done{TermColors.END}')

####___Create sw_menu.json file___.

def check_menu_json():
    '''___create menu configuration file___'''
    try:
        with open(sw_menu_json, 'w', encoding='utf-8') as f:
            f.write(default_ini)
            f.close()
    except IOError as e:
        print(f'{TermColors.VIOLET2}SW_MENU_JSON: {TermColors.RED}{e}' + TermColors.END)
    else:
        print(f'{TermColors.VIOLET2}SW_MENU_JSON: {TermColors.GREEN}create sw_menu.json: done' + TermColors.END)

def set_menu_json_default():
    '''___reset menu configuration file to default___'''
    try:
        Path(sw_menu_json).unlink()
    except IOError as e:
        print(f'{TermColors.VIOLET2}SW_MENU_JSON: {TermColors.RED}{e}' + TermColors.END)
    else:
        try:
            with open(sw_menu_json, 'w', encoding='utf-8') as f:
                f.write(default_ini)
                f.close()
        except IOError as e:
            print(f'{TermColors.VIOLET2}SW_MENU_JSON: {TermColors.RED}{e}' + TermColors.END)
        else:
            print(f'{TermColors.VIOLET2}SW_MENU_JSON: {TermColors.GREEN}create sw_menu.json: done' + TermColors.END)

def read_menu_conf():
    '''___return dict from menu configuration file___'''

    with open(sw_menu_json, 'r', encoding='utf-8') as f:
        json_data = json.load(f)
        dict_ini = json_data
        f.close()

    return dict_ini

def write_menu_conf(dict_ini):
    '''___write menu configuration file___'''

    with open(sw_menu_json, 'w') as f:
        f.write(json.dumps(dict_ini))
        f.close()

def get_roman(number):
    roman = ''
    number = int(number)
    for letter, value in roman_numbers.items():
        while number >= value:
            roman += letter
            number -= value

    return roman

def str_to_roman(string):

    for e in string:
        if e.isdigit():
            try:
                arabic = int(e)
            except:
                pass
            else:
                roman = romans[int(e)]
                string = string.replace(str(arabic), str(roman))

    return string

def get_print_mem_info(mapped):
    '''___print used memory info___'''

    mem_info = Process().memory_full_info()
    mem_map = Process().memory_maps(grouped=True)

    print(
        TermColors.SELECTED + TermColors.YELLOW
        + "\n----------------< MEMORY_INFO >----------------\n"
        + TermColors.END, "\n",
        TermColors.VIOLET2 + 'RSS MEMORY:    ' + TermColors.GREEN
        + str(round(mem_info.rss / (1024**2), 2)) + TermColors.END, "\n",
        TermColors.VIOLET2 + 'VMS_MEMORY:    ' + TermColors.GREEN
        + str(round(mem_info.vms / (1024**2), 2)) + TermColors.END, "\n",
        TermColors.VIOLET2 + 'TEXT_MEMORY:   ' + TermColors.GREEN
        + str(round(mem_info.text / (1024**2), 2)) + TermColors.END, "\n",
        TermColors.VIOLET2 + 'SHARED_MEMORY: ' + TermColors.GREEN
        + str(round(mem_info.shared / (1024**2), 2)) + TermColors.END, "\n",
        TermColors.VIOLET2 + 'LIB_MEMORY:    ' + TermColors.GREEN
        + str(round(mem_info.lib / (1024**2), 2)) + TermColors.END, "\n",
        TermColors.VIOLET2 + 'DATA_MEMORY:   ' + TermColors.GREEN
        + str(round(mem_info.data / (1024**2), 2)) + TermColors.END, "\n",
        TermColors.VIOLET2 + 'USS_MEMORY:    ' + TermColors.GREEN
        + str(round(mem_info.uss / (1024**2), 2)) + TermColors.END, "\n",
        TermColors.VIOLET2 + 'PSS_MEMORY:    ' + TermColors.GREEN
        + str(round(mem_info.pss / (1024**2), 2)) + TermColors.END, "\n",
        TermColors.VIOLET2 + 'SWAP_MEMORY:   ' + TermColors.GREEN
        + str(round(mem_info.swap / (1024**2), 2)) + TermColors.END, "\n"
        )

    if mapped is True:
        for x in mem_map:
            try:
                print(x[0], x[1])
            except:
                pass

################################___Checking_config_files___:

check_cache_dir()

if not sw_css_dark.exists():
    check_css_dark()

if not sw_css_light.exists():
    check_css_light()

if not sw_css_custom.exists():
    check_css_custom()

if not sw_bookmarks.exists():
    check_bookmarks()

if (not sw_app_vicons.exists()
    or not sw_app_hicons.exists()
    or not Path(f'{sw_app_icons}/tmp').exists()):
        create_app_icons()

if not sw_menu_json.exists():
    check_menu_json()

################################___Menu_settings___:

dict_ini = read_menu_conf()
sw_view_mode = dict_ini['view_mode']
sw_view_widget = dict_ini['view_widget']
sw_icon_size = int(dict_ini['icon_size'])
sw_color_scheme = dict_ini['color_scheme']
sw_control_panel = dict_ini['control_panel']
sw_expand_menu = dict_ini['expand_menu']
sw_autostart = dict_ini['autostart']
sw_compact_mode = dict_ini['compact_mode']
sw_width = int(dict_ini['width'])
sw_height = int(dict_ini['height'])
sw_opengl_bg = dict_ini['opengl_bg']
sw_shader_src = dict_ini['shader_src']
environ['FRAGMENT_NUM'] = sw_shader_src
environ['FRAGMENT_INDEX'] = sw_shader_src
sw_on_tray = dict_ini['on_tray']
sw_lang = dict_ini['language']
sw_default_dir = dict_ini['default_dir']
sw_current_dir = dict_ini['current_dir']

################################___Mangohud_csv___:

#csv_file = Path(f'{sw_tmp}/log/mangohud/HaveaNiceDeath_2023-08-31_02-17-16.csv')

#with open(csv_file, newline='') as f:
#    reader = csv.DictReader(f)
#    avg = 0
#    num = -1
#    for row in reader:
#        num += 1
#        if num > 1:
#            avg += float(row['os'])

#    print(avg/reader.line_num)

################################____Locale___:

import locale
import gettext

_ = gettext.gettext

domain = 'StartWine'
locale.textdomain(domain)
locale.bindtextdomain(domain, sw_localedir)

lang_en = gettext.translation(domain, localedir=sw_localedir, languages=['en:en'])
lang_ru = gettext.translation(domain, localedir=sw_localedir, languages=['ru:en'])
lang_labels = ['ru_RU', 'en_US']

if sw_lang == 'ru_RU':

    try:
        locale.setlocale(locale.LC_MESSAGES, (sw_lang, 'UTF-8'))
    except:
        try:
            locale.setlocale(locale.LC_MESSAGES, ('en_US', 'UTF-8'))
        except IOError as e:
            raise ValueError(f'{TermColors.RED}{e}{TermColors.END}')
        else:
            lang_en.install
            _ = lang_en.gettext
    else:
        lang_ru.install
        _ = lang_ru.gettext

if sw_lang == 'en_US':

    try:
        locale.setlocale(locale.LC_MESSAGES, (sw_lang, 'UTF-8'))
    except:
        try:
            locale.setlocale(locale.LC_MESSAGES, ('ru_RU', 'UTF-8'))
        except IOError as e:
            raise ValueError(f'{TermColors.RED}{e}{TermColors.END}')
        else:
            lang_ru.install
            _ = lang_ru.gettext
    else:
        lang_en.install
        _ = lang_en.gettext

################################___Icon data___:

class IconPath:
    icon_app = f'{sw_gui_icons}/sw_icon.png'
    icon_sw_svg = f'{sw_gui_icons}/sw.svg'
    icon_playback = f'{sw_symbolic_icons}/media-playback-start-symbolic.svg'
    icon_settings = f'{sw_symbolic_icons}/application-menu-symbolic.svg'
    icon_next = f'{sw_symbolic_icons}/go-next-symbolic.svg'
    icon_prev = f'{sw_symbolic_icons}/go-previous-symbolic.svg'
    icon_up = f'{sw_symbolic_icons}/go-up-symbolic.svg'
    icon_save = f'{sw_symbolic_icons}/floppy-symbolic.svg'
    icon_search = f'{sw_symbolic_icons}/edit-find-symbolic.svg'
    icon_back = f'{sw_symbolic_icons}/go-previous-symbolic.svg'
    icon_wine = f'{sw_symbolic_icons}/folder-wine-symbolic.svg'
    icon_create = f'{sw_symbolic_icons}/document-new-symbolic.svg'
    icon_remove = f'{sw_symbolic_icons}/edit-delete-symbolic.svg'
    icon_install = f'{sw_symbolic_icons}/run-build-install.svg'
    icon_clear = f'{sw_symbolic_icons}/edit-clear-all-symbolic.svg'
    icon_scale = f'{sw_symbolic_icons}/resize-symbolic.svg'
    icon_view_more = f'{sw_symbolic_icons}/view-more-symbolic.svg'
    icon_colors = f'{sw_symbolic_icons}/theme.svg'
    icon_winehq = f'{sw_symbolic_icons}/folder-wine-symbolic.svg'
    icon_protondb = f'{sw_symbolic_icons}/folder-steam-symbolic.svg'
    icon_add = f'{sw_symbolic_icons}/appointment-new-symbolic.svg'
    icon_hide = f'{sw_symbolic_icons}/application-exit-symbolic.svg'
    icon_toolbox = f'{sw_symbolic_icons}/toolbox.svg'
    icon_backup =f'{sw_symbolic_icons}/backup.svg'
    icon_backup_restore = f'{sw_symbolic_icons}/backup-restore-symbolic.svg'
    icon_tool = f'{sw_symbolic_icons}/tool-symbolic.svg'
    icon_update = f'{sw_symbolic_icons}/update.svg'
    icon_shortcuts = f'{sw_symbolic_icons}/applications-games-symbolic.svg'
    icon_debug = f'{sw_symbolic_icons}/hammer-symbolic.svg'
    icon_info = f'{sw_symbolic_icons}/dialog-information-symbolic.svg'
    icon_global = f'{sw_symbolic_icons}/global.svg'
    icon_github = f'{sw_symbolic_icons}/github.svg'
    icon_discord = f'{sw_symbolic_icons}/discord.svg'
    icon_telegram = f'{sw_symbolic_icons}/telegram.svg'
    icon_toolbars = f'{sw_symbolic_icons}/toolbars.svg'
    icon_terminal = f'{sw_symbolic_icons}/cm_runterm.svg'
    icon_resize = f'{sw_symbolic_icons}/resizer-symbolic.svg'
    icon_grid_view = f'{sw_symbolic_icons}/view-grid-symbolic.svg'
    icon_symlink = f'{sw_symbolic_icons}/emblem-symbolic-link.svg'
    icon_eject = f'{sw_symbolic_icons}/media-eject-symbolic.svg'
    icon_rotate = f'{sw_symbolic_icons}/transform-rotate.svg'
    icon_bookmarks = f'{sw_symbolic_icons}/bookmarks.svg'
    icon_new_bookmark = f'{sw_symbolic_icons}/bookmark-new-symbolic.svg'
    icon_rm_bookmark = f'{sw_symbolic_icons}/bookmark-remove.svg'
    icon_home = f'{sw_symbolic_icons}/user-home-symbolic.svg'
    icon_desktop = f'{sw_symbolic_icons}/user-desktop-symbolic.svg'
    icon_download = f'{sw_symbolic_icons}/document-save-symbolic.svg'
    icon_pictures = f'{sw_symbolic_icons}/folder-pictures-symbolic.svg'
    icon_video = f'{sw_symbolic_icons}/folder-video-symbolic.svg'
    icon_docs = f'{sw_symbolic_icons}/folder-documents-symbolic.svg'
    icon_music = f'{sw_symbolic_icons}/folder-music-symbolic.svg'
    icon_folder = f'{sw_symbolic_icons}/folder-symbolic.svg'
    icon_games = f'{sw_symbolic_icons}/folder-games-symbolic.svg'
    icon_regedit = f'{sw_symbolic_icons}/regedit.svg'
    icon_harddisk = f'{sw_symbolic_icons}/drive-harddisk.svg'
    icon_ssd = f'{sw_symbolic_icons}/drive-harddisk-solidstate.svg'
    icon_usb = f'{sw_symbolic_icons}/drive-harddisk-usb.svg'
    icon_cdrom = f'{sw_symbolic_icons}/cdrom.svg'
    icon_home_color = f'{sw_symbolic_icons}/home.svg'
    icon_unchecked = f'{sw_css}/assets/radio-unchecked-symbolic.svg'
    icon_checked = f'{sw_css}/assets/check-menuitem@2.png'
    icon_wine_staging = f'{sw_gui_icons}/wine_staging.jpg'
    icon_wine_steam_proton = f'{sw_gui_icons}/wine_steam_proton.jpg'
    icon_wine_proton_ge = f'{sw_gui_icons}/wine_proton_ge.jpg'
    icon_menu = f'{sw_symbolic_icons}/menu.svg'
    icon_taxes = f'{sw_symbolic_icons}/taxes-finances.svg'

################################___Lists___:

dict_ini = dict()
app_dict = dict()
app_conf_dict = dict()
app_id_dict = dict()
name_dict = dict()
sound_dict = dict()
env_dict = dict()
thread_result = []

global timeout_list
timeout_list = list()

global flap_locked
flap_locked = True

global f_mon_event
f_mon_event = list()

global scheme
scheme = ''

#if not Path(sw_sounds).exists():
#    set_menu_json_default()
#    try:
#        sound_list = sorted(list(Path(sw_sounds).iterdir()))
#    except IOError as e:
#        print(TermColors.RED, f'{e}', TermColors.END)
#    else:
#        for i, x in enumerate(sound_list):
#            sound_dict[str(x)] = i
#else:
#    try:
#        sound_list = sorted(list(Path(sw_sounds).iterdir()))
#    except IOError as e:
#        print(TermColors.RED, f'{e}', TermColors.END)
#    else:
#        for i, x in enumerate(sound_list):
#            sound_dict[str(x)] = i

################################___Themes___:

theme_dict = dict(
    [
    ('dark', _('Dark')),
    ('light', _('Light')),
    ('custom', _('Custom')),
    ]
)

################################___Tray___:

str_tray_open = _('Show/Hide StartWine')
str_tray_hide = _('Show/Hide StartWine')
str_tray_run = _('Run...')
str_tray_shortcuts = _('Shortcuts')
str_tray_stop = _('Stop wine processes')
str_tray_shutdown = _('Shutdown')

#str_tray_open = _('Be or not to be...')
#str_tray_run = _('Run Forest run...')
#str_tray_shortcuts = _('My Minions')
#str_tray_stop = _('Drink all the wine')
#str_tray_exit = _("I'll be back'")

#str_tray_open = _('Гюльчатай, открой личико')
#str_tray_hide = _('Оставь меня, старушка, я в печали...')
#str_tray_run = _('Ну ты это... Заходи если что')
#str_tray_shortcuts = _('Огласите весь список, пожалуйста')
#str_tray_stop = _('И тебя вылечат, и меня вылечат… Всех вылечат!')
#str_tray_exit = _('Все, кина не будет, электричество кончилось')

################################___Contexts___:

ctx_dict = dict(
    [
    ('run', _('Run')),
    ('open', _('Open')),
    ('open_with', _('Open with...')),
    ('open_location', _('Open file location')),
    ('app_settings', _('App settings')),
    ('remove', _('Remove')),
    ('app_to_menu', _('App to menu')),
    ('app_to_desktop', _('App to desktop')),
    ('app_to_steam', _('App to Steam Deck menu')),
    ('change_wine', _('Change wine')),
    ('winehq', _('Winehq')),
    ('protondb', _('Protondb')),
    ('griddb', _('Search for an image')),
    ('staging', 'wine staging'),
    ('steam_proton', 'wine steam proton'),
    ('proton_ge', 'wine proton ge'),
    ('lutris_ge', 'wine lutris ge'),
    ('staging_tkg', 'wine staging tkg'),
    ('create', _('Create file')),
    ('create_dir', _('Create directory')),
    ('link', _('Create link')),
    ('rename', _('Rename')),
    ('cut', _('Cut')),
    ('copy', _('Copy')),
    ('paste', _('Paste')),
    ('select_all', _('Select all')),
    ('trash', _('Move to trash')),
    ('remove', _('Delete permanently')),
    ('properties', _('Properties')),
    ('txt', _('Text')),
    ('sh', _('Bourne shell')),
    ('py', _('Python')),
    ('desktop', _('Desktop')),
    ('copy_path', _('Copy current path')),
    ('add_bookmark', _('Add to bookmark')),
    ('compress', _('Compress...')),
    ('extract', _('Extract...')),
    ('show_hidden_files', (_('Hidden files'), 'Ctrl+H')),
    ('show_hotkeys', (_('Hotkeys'), 'Ctrl+K')),
    ('about', (_('About'), 'F3')),
    ('help', (_('Help'), 'F1')),
    ('shutdown', (_('Shutdown'), 'Ctrl+Shift+END')),
    ]
)
str_sample = _('sample')

################################___View_widgets___:

view_widgets = [
    'shortcuts',
    'install_launchers',
    'install_wine',
    'launch_settings',
    'mangohud_settings',
    'vkbasalt_settings',
    'colors_settings',
    'global_settings',
    'files',
    'winetricks',
    'terminal',
    'text_view',
    'web_view'
]

vw_dict = {}

for w in view_widgets:
    vw_dict[w] = w

view_labels = [
    _('Shortcuts'),
    _('Install launchers'),
    _('Install Wine'),
    _('Launch settings'),
    _('Mangohud settings'),
    _('Vkbasalt settings'),
    _('Colors settings'),
    _('Global settings'),
    _('Files'),
    _('Winetricks'),
    _('Terminal'),
    _('Text view'),
    _('Web view')
]
vl_dict = {}

for l, w in zip(view_labels, view_widgets):
    vl_dict[w] = l

view_icons = [
    IconPath.icon_shortcuts,
    IconPath.icon_install,
    IconPath.icon_settings,
    IconPath.icon_settings,
    IconPath.icon_settings,
    IconPath.icon_settings,
    IconPath.icon_settings,
    IconPath.icon_folder,
    IconPath.icon_wine,
    IconPath.icon_terminal,
]

################################_Start_mode___:

sw_logo_dark = 'sw_large_dark.svg'
sw_logo_light = 'sw_large_light.svg'

str_prefix = _('Prefix: ')
str_current_prefix = _('Current prefix:\n')
str_current_wine = _('Current wine:\n')
str_oops = _('Oops! Nothing to run...')

################################___About___:

about_widgets = [
    'about_news',
    'about_details',
    'about_authors',
    'about_license',
    'about_donation',
    'about_update',
    'about_code',
    'about_projects',
    'about_members',
    'about_design',
    'about_website',
    'about_github',
    'about_discord',
    'about_telegram',
]
about_labels = [
    _('New'),
    _('Details'),
    _('Authors'),
    _('License'),
    _('Donations and help'),
    _('Check for updates'),
    _('Code'),
    _('Projects'),
    _('Members'),
    _('Design'),
    _('Website'),
    _('Github'),
    _('Discord'),
    _('Telegram'),
]
about_dict = {}

for l, w in zip(about_labels, about_widgets):
    about_dict[w] = l

str_about = _(
'Is a Windows application launcher '
'for GNU/Linux operating systems. '
'Includes many features, extensions, and fixes '
'to improve performance, visuals, and usability.'
)
str_news = _('''This release adds the following features, updates, and fixes:
Bug fixes and performance improvements.
Updated locales.
Updated prefix configurations.
Updated wine version list.
Updated libraries, drivers in the sw_runtime container.
Auto-installation updated for Eve Online and Yuzu.
Added extended support for executable files (.bat, .lnk, .appimage).
Changed the type of shortcuts for installed applications.
Changed interaction with the tray, management in one process to speed up interaction and menu access.
Added header menu.
Added keyboard shortcuts to open the About, Help and others.
Added regedit patches.
Added fix for detecting SDROM when installing applications.
Added resources for faster Wine downloading.
Added auto suggestion to launch and create a shortcut when opening an executable .exe file from the system file manager.
Added Open with... option to the file manager context menu.
Added fixes to prefix structure.
Added vkd3d shader cache distribution for each application.
Fixed multiple launches of the sw_runtime container and incorrect termination of the process.
Fixed installation error on NixOS and Astra Linux.
Fixed an error in downloading an uninstalled version of Wine when launching applications.
Fixed a bug when deleting shortcuts from the desktop and system menu when removing the application prefix.
Fixed incorrect display of the Cyrillic alphabet in some applications.'''
)
str_authors = _(
'Rustam Normatov\n'
'Nikita Maslov'
)
str_developers = _(
'Rustam Normatov\n'
'Nikita Maslov\n'
'Maksim Tarasov'
)
str_members = (
'StartWine Community\n'
'Андрей\n'
'3y6HuK\n'
'Alexandrdrdr\n'
'Fanchji (Виталий)\n'
'Huskysoul\n'
'kazbek\n'
'Kot41ru\n'
'Lex\n'
'Lintech\n'
'LinuxShef\n'
'Sheridan\n'
'Wik'
)
list_projects = [
'Winehq project',
'ValveSoftware/Proton',
'Kron4ek/Wine-Builds',
'GloriousEggroll/proton-ge-custom',
'GloriousEggroll/wine-ge-custom',
'Winetricks/winetricks',
'flightlessmango/MangoHud',
'DadSchoorse/vkBasalt',
'FeralInteractive/gamemode',
'Gtk Project',
'HansKristian-Work/vkd3d-proton',
'doitsujin/dxvk',
'VHSgunzo/runimage',
]
str_projects = str('\n'.join(sorted(list_projects)))

str_design = _(
'StartWine Design Team'
)
str_gpl = _('GNU General Public License')

str_license = _(
'StartWine is free software. '
'You can redistribute it and/or '
'modify it under the terms of '
'the GNU General Public License '
'as published by the Free Software '
'Foundation; '
'either version 3 of the License, '
'or (at your option) any later version. '

'StartWine is distributed without '
'any warranty. '
'See the GNU Lesser General Public License '
'for more details.'
)
str_contribute = _('Contribute to the project')
str_donation = _(
'You can contribute to the project by spreading information about it, offering \
for discussion any ideas related to improving the functionality and appearance \
of the StartWine application. You can also help by contributing \
to the development by submitting bug reports. And you can always donate any \
amount to the development of the project using the link below.'
)

donation_source = {
    _('Card'): _('The service is unavailable.'),
    'BTC': 'bc1q3h8lfs3l3r8jmt8ev0pwl9nueqttlep6ktvd02',
}

website_source='https://startwine-project.ru'
github_source = 'https://github.com/RusNor'
telegram_source = 'https://t.me/StartWine'
discord_source = 'https://discord.com/invite/37FrGUpDEj'
license_source = 'https://www.gnu.org/licenses/gpl-3.0.html'
#donation_source = 'https://my.qiwi.com/form/Nykyta-MhrLvGVgb3'
str_btc = 'BTC: bc1q3h8lfs3l3r8jmt8ev0pwl9nueqttlep6ktvd02'
winehq_source = 'https://www.winehq.org/search?q='
protondb_source = 'https://www.protondb.com/search?q='
griddb_source = 'https://www.steamgriddb.com/search/grids?term='
griddb = 'https://www.steamgriddb.com'
home_page = github_source
home_html = f'file://{sw_scripts}/StartWine-Launcher_handbook_README-RU.md at main · RusNor_StartWine-Launcher · GitHub.html'

url_source = {
#    'google': ['https://google.com', f'{sw_symbolic_icons}/google.png'],
#    'yandex': ['https://ya.ru', f'{sw_symbolic_icons}/yandex.png'],
#    'duckduckgo': ['https://duckduckgo.com', f'{sw_symbolic_icons}/duckduckgo.png'],
#    'startwine': ['https://startwine-project.ru', f'{sw_gui_icons}/sw_icon.png'],
#    'github': ['https://github.com/RusNor', f'{sw_symbolic_icons}/github.png'],
#    'vkontakte': [' https://vk.com/club213719866', f'{sw_symbolic_icons}/vk.png'],
#    'telegram': ['https://t.me/StartWine', f'{sw_symbolic_icons}/telegram.png'],
#    'discord': ['https://discord.com/invite/37FrGUpDEj', f'{sw_symbolic_icons}/discord.png'],
#    'license': ['https://www.gnu.org/licenses/gpl-3.0.html', f'{sw_symbolic_icons}/gnu.png'],
#    'donation': ['https://my.qiwi.com/form/Nykyta-MhrLvGVgb3', f'{sw_symbolic_icons}/qiwi.png'],
#    'winehq': ['https://www.winehq.org', f'{sw_symbolic_icons}/winehq.png'],
#    'protondb': ['https://www.protondb.com', f'{sw_symbolic_icons}/protondb.png'],
#    'griddb': ['https://www.steamgriddb.com', f'{sw_symbolic_icons}/griddb.png'],
}

################################___Tools___:

changed_wine = 'wine_steam_proton'

prefix_tools_icons = [
    IconPath.icon_remove,
    IconPath.icon_update,
    IconPath.icon_update,
    IconPath.icon_backup,
    IconPath.icon_backup_restore,
    IconPath.icon_backup,
    IconPath.icon_backup_restore,
]
wine_tools_icons = [
    IconPath.icon_download,
    IconPath.icon_settings,
    IconPath.icon_terminal,
    IconPath.icon_regedit,
    IconPath.icon_folder,
    IconPath.icon_remove,
    IconPath.icon_playback,
    IconPath.icon_update,
]
btn_widgets = [
    'start',
    'shortcuts',
    'create_shortcut',
    'prefix_tools',
    'wine_tools',
    'download_wine',
    'install_launchers',
    'settings',
    'debug',
    'stop',
    'about',
    'files_info',
    'bookmarks',
]
btn_labels = [
    _('Start'),
    _('Shortcuts'),
    _('Create shortcut'),
    _('Prefix tools'),
    _('Wine tools'),
    _('Download wine'),
    _('Install launchers'),
    _('Settings'),
    _('Debug'),
    _('Terminate all processes'),
    _('About'),
    _('Properties'),
    _('Bookmarks'),
]
btn_dict = {}

for l, w in zip(btn_labels, btn_widgets):
    btn_dict[w] = l

prefix_labels = [
    _('Default prefix'),
    _('Application prefix'),
]
prefix_list = [
    'pfx_default',
    'pfx_app_name'
]
prefix_dict = {}

for p, l in zip(prefix_list, prefix_labels):
    prefix_dict[p] = l

str_sw_use_pfx = 'SW_USE_PFX'

prefix_tools_labels = [
    _('Remove current prefix'),
    _('Clear current prefix'),
    _('Reinstall current prefix'),
    _('Prefix backup'),
    _('Prefix recovery'),
    _('Backup all prefixes'),
    _('Recovery all prefixes')
]
prefix_tools_widgets = [
    'pfx_remove',
    'pfx_clear',
    'pfx_reinstall',
    'pfx_backup',
    'pfx_restore',
    'pfx_full_backup',
    'pfx_full_restore'
]
prefix_tools_dict = {}

for w, l in zip(prefix_tools_widgets, prefix_tools_labels):
    prefix_tools_dict[w] = l

wine_tools_labels = [
    _('Download wine'),
    _('Wine settings'),
    _('Wine console'),
    _('Regedit'),
    _('File explorer'),
    _('Uninstaller'),
    _('Winetricks'),
]
wine_tools_widgets = [
    'download_wine',
    'wine_settings',
    'wine_console',
    'regedit',
    'file_explorer',
    'uninstaller',
    'winetricks',
]
wine_tools_dict = {}

for l, w in zip(wine_tools_labels, wine_tools_widgets):
    wine_tools_dict[w] = l

################################___Files_info___:

str_title_file_path = _('Path')
str_title_file_modified = _('Modified date')
str_title_file_created = _('Creation date')
str_title_file_uid = _('Owner / Group')
str_title_file_rw = _('Access')
str_title_file_permission = _('Permission')
str_title_file_execute = _('Executable')
str_readable = _('Can-readable')
str_writable = _('Can-writable')
str_non_readable = _('Non-readable')
str_non_writable = _('Non-writable')
str_symbolic_link = _('Symbolic link to')

attrs = {
    'type': 'standard::type',
    'symlink': 'standard::is-symlink',
    'is_hidden': 'standard::is-hidden',
    'name': 'standard::name',
    'display_name': 'standard::display-name',
    'edit_name': 'standard::edit-name',
    'copy_name': 'standard::copy-name',
    'icon': 'standard::icon',
    'content_type': 'standard::content-type',
    'size': 'standard::size',
    'read': 'access::can-read',
    'write': 'access::can-write',
    'exec': 'access::can-execute',
    'delete': 'access::can-delete',
    'trash': 'access::can-trash',
    'rename': 'access::can-rename',
    'changed': 'time::changed',
    'created': 'time::created',
    'modified': 'time::modified',
    'user': 'owner::user',
    'real_user': 'owner::user-real',
    'group': 'owner::group',
}
access_attrs = [
    'access::can-read',
    'access::can-write',
    'access::can-execute',
    'access::can-delete',
    'access::can-trash',
    'access::can-rename',
]
time_attrs = [
    'time::changed',
    'time::created',
    'time::modified',
]
owner_attrs = [
    'owner::user',
    'owner::user-real',
    'owner::group',
]

################################___Bookmarks___:

bmark_list = []
str_create_new_bookmark = _('Adding a new bookmark completed successfully')
str_remove_bookmark = _('Remove bookmark completed successfully')
str_bookmark_exists = _('Bookmark is already exists!')

bmark_dict = {
    dir_home: [IconPath.icon_home, None],
    dir_desktop: [IconPath.icon_desktop, None],
    dir_videos: [IconPath.icon_video, None],
    dir_docs: [IconPath.icon_docs, None],
    dir_downloads: [IconPath.icon_download, None],
    dir_pics: [IconPath.icon_pictures, None],
    dir_music: [IconPath.icon_music, None],
    str(sw_wine): [IconPath.icon_wine, None],
    str(sw_games): [IconPath.icon_games, _('Games')],
    str(sw_shortcuts): [IconPath.icon_shortcuts, _('Shortcuts')],
    str(sw_pfx): [IconPath.icon_toolbox, _('Prefixes')],
    str(sw_pfx_backup): [IconPath.icon_backup_restore, _('Backups')],
    str(sw_app_config): [IconPath.icon_settings, _('Prefix configurations')],
    str(sw_logs): [IconPath.icon_regedit, _('Logs')],
}

################################___Install_wine___:

str_iw_title_desc = _('Wine (originally an acronym for "Wine Is Not an Emulator") \
is a compatibility layer capable of running Windows applications on several \
POSIX-compliant operating systems, such as Linux, macOS, & BSD. Instead of \
simulating internal Windows logic like a virtual machine or emulator, Wine \
translates Windows API calls into POSIX calls on-the-fly, eliminating the \
performance and memory penalties of other methods and allowing you to cleanly \
integrate Windows applications into your desktop.')

str_iw_subtitle = _('List of wines to download and install')
wine_descriptions = {
    'wine_staging': _('Wine Staging contains bug fixes and features, which have \
not been integrated into the development branch yet. The idea of Wine Staging \
is to provide experimental features faster to end users and to give developers \
the possibility to discuss and improve their patches before they are integrated \
into the main branch.'),
    'wine_staging_tkg': _('Staging-TkG is a Wine build with the Staging patchset \
applied and with many additional useful patches. A complete list of patches is \
in wine-tkg-config.txt inside the build directory.'),
    'wine_steam_proton': _('Is a Wine build modified by Valve and other \
contributors. It contains many useful patches (primarily for a better gaming \
experience), some of them are unique and not present in other builds.'),
    'wine_proton_ge': _("Proton with the most recent bleeding-edge Proton \
Experimental WINE. Things it contains that Valve's Proton does not: Additional \
media foundation patches for better video playback support, AMD FSR patches, \
Nvidia CUDA support for PhysX and NVAPI, raw input mouse support and various \
wine-staging patches applied as they become needed."),
    'wine_lutris_ge': _('WINE based on/forked from the most recent bleeding-edge \
proton experimental wine repo. This is meant to be used with non-steam games \
outside of Steam.'),
}

wine_list = [
    'wine_staging',
    'wine_steam_proton',
    'wine_proton_ge',
    'wine_staging_tkg',
    'wine_lutris_ge',
]
wine_custom_list = [
    'wine_custom_1',
    'wine_custom_2',
    'wine_custom_3',
    'wine_custom_4',
    'wine_custom_5'
]
wine_labels = [
    f'Wine Staging',
    f'Wine Steam Proton',
    f'Wine Proton GE',
    f'Wine Staging TKG',
    f'Wine Lutris GE'
]
str_sw_use_wine = 'SW_USE_WINE'

wine_list_dict = {}

for w, l in zip(wine_list, wine_labels):
    wine_list_dict[l] = w

wine_func_list = [
    'WINE_1',
    'WINE_2',
    'WINE_3',
    'WINE_4',
    'WINE_5',
]
wine_source = [
    'https://github.com/Kron4ek/Wine-Builds',
    'https://github.com/RusNor/Wine-Steam-Proton/releases',
    'https://github.com/GloriousEggroll/proton-ge-custom',
    'https://github.com/Kron4ek/Wine-Builds',
    'https://github.com/GloriousEggroll/wine-ge-custom',
]
wine_source_dict = {}

for w, s in zip(wine_list, wine_source):
    wine_source_dict[w] = s

wine_dict = {}

for w in wine_list:
    wine_dict[w] = w

wine_func_dict = {}
for w, f in zip(wine_list, wine_func_list):
    wine_func_dict[w] = f

wine_image_list = [
    IconPath.icon_wine_staging,
    IconPath.icon_wine_steam_proton,
    IconPath.icon_wine_proton_ge,
    IconPath.icon_wine_staging,
    IconPath.icon_wine_proton_ge,
]

winever_data = read_wine_ver_data()
latest_wine_dict = dict()
wine_download_dict = dict()

for wine, func in zip(wine_list, wine_func_list):
    latest_wine_dict[wine] = Path(Path(winever_data[wine].split(' ')[0]).stem).stem

    for x in winever_data[wine].split(' '):
        x = Path(Path(x).stem).stem
        wine_download_dict[x] = func

################################___Install_launchers___:

str_il_subtitle = _('List of launchers and stores available for installation')
launchers_list = [str(x) for x in sw_launchers.iterdir()]
launchers_descriptions = {
#    'Ankama': _("Ankama Launcher is a portal that lets you access all of Ankama's \
#many universes with just a single click! Connect to our video games, VOD animations, \
#webtoons, and even our livestreams! Download updates, stay up to date with the \
#latest news, and chat with your friends!"),
    'Anomaly_Zone': _('Anomaly Zone - MMORPG, open world game, successor to "stalker online". \
You can remain alone or conquer the Zone in the company of other daredevils, \
playing online with friends. Play in a clan, take part in PvP and PvE battles, \
use crafting, modifications, follow a large, interesting, global plot.'),
    'Battle_Net': _('Battle.net is an online gaming service, including digital \
distribution and social platform functions, developed by Blizzard Entertainment.'),
#    'Battle_State_Games': _('Escape from Tarkov is a hardcore realistic story-driven \
#massively multiplayer online game developed and published by Battlestate Games. \
#Combines the features of the FPS/TPS, combat simulator and RPG genres with MMO elements.'),
    'Caliber': _('Caliber is a third-person and first-person multiplayer online \
game about modern special forces. The project belongs to the genre of tactical \
team action, offering battles in PvP, PvE and PvPvE modes. "Caliber" is distributed \
according to the free-to-play business model'),
    'Crossout': _('Crossout is a computer multiplayer online game in the genre \
of post-apocalyptic action with a third-person view. The core of the game is \
session PvP battles in armored vehicles assembled by the players themselves.'),
    'EA': _('EA app is Electronic Arts latest and most advanced PC platform where \
you can play your favorite games without any hassle. The app features an improved \
and optimized user interface, making it easy to find and play games in seconds.'),
    'Epic_Games': _('Epic Games Store is an online digital distribution service \
for computer games developed and managed by the American company Epic Games'),
    'Eve': _('EVE Online is a space massively multiplayer online game developed \
by the Icelandic company CCP Games. PvE and PvP battles, research, resource \
extraction, production and a realistic economy.'),
    'Galaxy': _('GOG GALAXY 2.0 is a program that will help you combine multiple \
game libraries and communicate with friends regardless of the gaming platform, \
including consoles! If you play with friends on different platforms and have \
to use multiple launchers, GOG GALAXY 2.0 is for you!'),
    'GameXP': _('Client online games (MMORPG) and browser games (BBMMORPG), as \
well as games for mobile phones and tablets. RPG, Fantasy, Simulation, Adventure, \
Strategy, there is even a real life simulator (a la Sims).'),
    'Game_Center': _('VK Play is a platform for game lovers, developers and \
content creators. VK Play combines all the services necessary for the gaming \
community and offers entertainment for everyone: a catalog of games, cloud gaming, \
streaming and e-sports and much more.'),
#    'Gameforge': _('Online Gaming Platform. All Gameforge games in one place. \
#The latest news and updates. Multi-account support.'),
    'Genshin_Impact': _('Genshin Impact is an action-adventure computer game with \
an open world and RPG elements, developed by the Chinese company miHoYo Limited. \
The game is distributed through digital distribution using a free-to-play model, \
but has an in-game store that uses real currency.'),
#    'Itch': _('The itch.io app, itch, lets you effortlessly download and run games \
#and software from itch.io. All of your downloads are kept in a single place and \
#are automatically updated. Access your collections and purchases, or browse for \
#new games via the in-app browser.'),
    'Lesta_Games': _('Lesta Game Center is part of the platform distribution \
(game launcher app) that brings together all your Lesta games, as well as read \
news about upcoming features and functions, watch videos and get amazing discounts!'),
    'Lineage': _('Game Coast is a client for Lineage 2 - classic free-to-play \
MMORPG with a third-person perspective.'),
    'Lost_Light': _('Lost Light is a highly realistic hardcore shooter, focused \
on surviving and gathering loot with other players, as well as defending yourself from the unknown.'),
    'Nintendo_Switch': _('Yuzu is a free and open source emulator of the \
Nintendo Switch console. Developed since January 2018 by the team responsible for \
Citra, a Nintendo 3DS emulator. Written in C++. The list of games compatible with \
the emulator is on the official website.'),
    'Osu': _('Osu! is a free and open source music game developed and published \
by Dean Herbert. The gameplay is based on various popular games including Osu! Tatakae!'),
    'Path_of_Exile': _('Path of Exile is an online action role-playing game \
developed and published by Grinding Gear Games. The game is based on: a powerful \
barter economy, rich customization options for heroes, exciting PvP battles and \
races for ratings. The game is completely free.'),
    'Plarium_Play': _('Plarium Play is a Light and Secure Desktop Game Launcher \
for PC. Play Free Games with Blazing HD Graphics and a Worldwide Gaming Community.'),
    'Popcotime': _('Popcorn Time is a cross-platform free BitTorrent client that \
includes a media player. Watch popular series and series for people unfamiliar \
with movie file sharing technologies and accustomed to video streaming services.'),
    'RPG_Club': _('The project www.RPG-club.net is a voluntary non-profit \
association of fans of RPG games. Our site does not aim to distribute any RPG games, \
but is a means of communication for all interested legal owners of licensed versions of games.'),
    'Riot_Games': _('Riot Games - client for League of Legends, abbreviated as LoL, is a \
multiplayer computer game in the MOBA genre developed and published by the \
American company Riot Games.'),
#    'Roblox_Player': _('Roblox Player'),
    'Rockstar_Games': _('Rockstar Games Launcher is an application that allows \
you to quickly and easily manage your collection of Rockstar PC games, both \
digital and physical versions, including those purchased from various digital \
stores. You can also use this app to purchase new games from Rockstar.'),
    'Stalcraft': _('EXBO launcher for StalCraft - bright and promising adaptation \
of a familiar setting in the format of a massive online first-person shooter. \
Successfully combining the complete freedom of PvP and interesting PvE elements.'),
    'Stalker_Online': _('Stalker Online is an MMORPG with shooter elements, \
which is based on the spirit of stalking - exploration of mysterious, forgotten \
and abandoned areas of the planet by humanity.'),
#    'Star_Wars_TOR': _('Star Wars: The Old Republic is a story-driven massively \
#multiplayer online role-playing game developed by BioWare.'),
    'Steam': _('Steam is an online digital distribution service for computer \
games and programs developed and maintained by Valve. Steam serves as a technical \
copyright protection tool, a multiplayer gaming and streaming platform, and a \
social network for gamers.'),
    'Ubisoft_Connect': _('Ubisoft Connect is a digital game distribution, DRM, \
online gaming and communication service created by Ubisoft. Supports the \
achievement/trophy system used in other similar services.'),
    'Wargaming': _('Wargaming.net Game Center is part of a digital distribution \
platform (game launcher app) that allows you to keep all your Wargaming games \
in one place, get the latest news on upcoming features, watch videos and easily find great deals!'),
    'World_of_Sea_Battle': _('Client for World of Sea Battle - A large-scale \
online game with an open world in the setting of the Age of Sail! \
Become a pirate or merchant, team up with other players.'),
    'Zona': _('Zona is a BitTorrent client for watching streaming video content. \
In addition to on-demand movies and television series, Zona offers streaming music, \
live television channels, news, live sports, and games'),
}

################################___Settings___:

str_move_settings = _('Move settings')

settings_labels = [
    _('Launch settings'),
    _('Mangohud settings'),
    _('Vkbasalt settings'),
    _('Colors settings'),
    _('Global settings'),
    _('Reset app settings'),
    _('Reset menu settings'),
    _('Clear shader cache'),
]
settings_widgets = [
    'launch_settings',
    'mangohud_settings',
    'vkbasalt_settings',
    'colors_settings',
    'global_settings',
    'set_app_default',
    'set_menu_default',
    'clear_shader_cache',
]
settings_dict = {}

for w, l in zip(settings_widgets, settings_labels):
    settings_dict[w] = l

settings_icons = [
    IconPath.icon_tool,
    IconPath.icon_tool,
    IconPath.icon_tool,
    IconPath.icon_tool,
    IconPath.icon_tool,
    IconPath.icon_update,
    IconPath.icon_update,
    IconPath.icon_update,
]
str_lp_subtitle = _('Optimization, patches, tools, utilities and libraries')

lp_entry_list = [
    _('LAUNCH_PARAMETERS'),
    _('WINEDLLOVERRIDES'),
]
lp_combo_list = [
    _("WINEARCH"),
    _('WINDOWS_VER'),
    _('REGEDIT_PATCH'),
    _('DXVK_VER'),
    _('VKD3D_VER'),
    _('FSR_MODE'),
    _('LANG_MODE'),
]
str_fps_limit = _('FPS_LIMIT')
export_fps_limit = 'export SW_USE_FPS_LIMIT'

str_cpu_topology = _('CPU_TOPOLOGY')
export_cpu_topology = 'export SW_USE_WINE_CPU_TOPOLOGY'

str_example = [
    'Example: -d3d9, -d3d11, -opengl',
    'Example: amd_ags_x64=b,n'
]
lp_list = [
    'launch_parameters',
    'override_dll',
    'win_arch',
    'win_ver',
    'reg_patch',
    'dxvk_ver',
    'vkd3d_ver',
    'fsr_mode',
    'lang_mode',
    'fps_limit',
    'cpu_topology',
]
lp_title = [
    _('LAUNCH_PARAMETERS'),
    _('WINEDLLOVERRIDES'),
    _("WINEARCH"),
    _('WINDOWS_VER'),
    _('REGEDIT_PATCH'),
    _('DXVK_VER'),
    _('VKD3D_VER'),
    _('FSR_MODE'),
    _('LANG_MODE'),
    _('FPS_LIMIT'),
    _('CPU_TOPOLOGY'),
]
lp_title_dict = {}

for l, t in zip(lp_list, lp_title):
    lp_title_dict[l] = t

lp_desc = [
    _('Set launch parameters'),
    _('Override dll in the current prefix'),
    _("Set the architecture bit depth for the prefix"),
    _('Set windows version'),
    _('Add registry patch'),
    _('Set dxvk version'),
    _('Set vkd3d version'),
    _('Set AMD FSR scaling mode'),
    _('Set the language for the game or application'),
    _('Limit frame rate, value "0" - no limit'),
    _('Limit cpu core, value "0" - no limit'),
]
lp_desc_dict = {}

for t, d in zip(lp_list, lp_desc):
    lp_desc_dict[t] = d

winarch = [
    '64 bit architecture', '32 bit architecture'
]
arch_index = [
    'win64', 'win32'
]
winarch_dict = {}

for a,i in zip(winarch, arch_index):
    winarch_dict[a] = i

winver = [
    'Windows 11',
    'Windows 10',
    'Windows 8.1',
    'Windows 8',
    'Windows 7',
    'Windows XP'
]
ver_index = [
    '11', '10', '81', '8', '7', 'xp',
]
winver_dict = {}

for v,i in zip(winver, ver_index):
    winver_dict[v] = i

reg_patches = [''] + [
    str(reg.name) for reg in Path(sw_app_patches).iterdir()
]
dxvk_ver = [
    '1.9', '1.9.1', '1.9.2', '1.9.3', '1.9.4', '1.10', '1.10.1', '1.10.2',
    '1.10.3', '2.0', '2.1', '2.2', '2.3', '2.3.1',
]
vkd3d_ver = [
    '2.0', '2.1', '2.2', '2.3', '2.3.1', '2.4', '2.5', '2.6', '2.7', '2.8',
    '2.9', '2.10', '2.11', '2.11.1', '2.12',
]
combo_list = winarch + winver + reg_patches + dxvk_ver + vkd3d_ver
fsr_mode = [_('Ultra'), _('Quality'), _('Balanced'), _('Performance')]

lang_mode = ['', 'en_US', 'ru_RU.UTF-8']

################################___Switch_check___:

switch_labels = [
    'DXVK_GE',
    'VKD3D_GE',
    'GALLIUM_HUD',
    'OPENGL',
    'MANGOHUD',
    'MESA_OVERLAY_HUD',
    'GAMEMODE',
    'VIRTUAL_DESKTOP',
    'FSYNC',
    'ESYNC',
    'OLD_GL_STRING',
    'NVAPI_DISABLE',
    'WINEDBG_DISABLE',
    'LARGE_ADDRESS_AWARE',
    'STAGING_WRITECOPY',
    'WINE_SIMULATE_WRITECOPY',
    'STAGING_SHARED_MEMORY',
    'DXVK_HUD',
    'DXVK_ASYNC',
    'ENABLE_VKBASALT',
    'FSR',
    'GSTREAMER',
    'DRI_PRIME',
    'WINE_MONO',
    'BATTLEYE',
    'EASYANTICHEAT',
    'D3D_PLUGINS',
    'VSYNC_DISABLE',
    'HIDE_NVIDIA_GPU',
    'DGVOODOO2',
    'DLSS',
    'DISABLE_UPDATE_PFX',
    'SHADER_CACHE',
]

switch_descriptions = [
    _('Using dxvk version from wine-proton-ge'),
    _('Using vkd3d version from wine-proton-ge'),
    _('Sytem monitoring for OpenGL mode'),
    _("Force use opengl, for applications that d'nt run in dxvk and vkd3d"),
    _('System monitoring in opengl or vulkan (dxvk, vkd3d)'),
    _('System monitoring in vulkan (dxvk, vkd3d)'),
    _('Set of optimisations be temporarily applied a game process'),
    _('Enable windows desktop emulation'),
    _('Improving frame rates and responsiveness with scheduling policies'),
    _('Increase performance for some games, especially ones that rely heavily on the CPU'),
    _('For old games that crash on very long extension strings'),
    _('Disabling the nvapi library required by PhysX to enable GPU acceleration via CUDA'),
    _('Disable debugging mode for wine to improve performance'),
    _('Allocate to a 32-bit application more than 2 GB of RAM'),
    _('To simulate the memory management system of Windows'),
    _('Simulated Write Copy - Emulates how Windows loads DLLs into memory more accurately'),
    _('Сan optimize some wineserver calls by using shared memory'),
    _('System monitoring in dxvk'),
    _('Asynchronous compilation of shaders from the render process to prevent hangs while waiting'),
    _('vkBasalt is a Vulkan post processing layer to enhance the visual graphics in games'),
    _('AMD FidelityFX Super Resolution - advanced upscaling technologies for higher fps'),
    _('An open source library containing plugins and codecs for handling media in applications'),
    _('Used to manage hybrid graphics found on recent desktops and laptops'),
    _('Open-source and cross-platform implementation of the .NET Framework'),
    _('BattlEye anti-cheat service required to run online games that use this service'),
    _('EasyAntCheat service required to run online games that use this service'),
    _('Preload d3d libraries'),
    _('Forcibly disabling vsync solves performance issues in some apps'),
    _('Hides the definition of nvidia video cards. Required to run some applications'),
    _('To run games using directx 8 and below, in dxvk mode'),
    _('Nvidia DLSS - advanced upscaling technologies for higher fps for higher frame rate per second'),
    _('Disable prefix update on startup'),
    _('Enable or disable shader cache'),
]

################################___Mangohud_check___:

export_mangohud_config = 'export SW_USE_MANGOHUD_CONFIG'
app_conf_mh_list = list()

check_mh_labels = [
    'cpu_temp',
    'cpu_power',
    'core_load',
    'cpu_mhz',
    'fan',
    'gpu_name',
    'gpu_temp',
    'gpu_power',
    'gpu_core_clock',
    'gpu_mem_clock',
    'ram',
    'vram',
    'swap',
    'procmem',
    'procmem_shared',
    'procmem_virt',
    'io_read',
    'io_write',
    'full',
    'no_small_font',
    'media_player',
    'version',
    'arch',
    'histogram',
    'vulkan_driver',
    'engine_version',
    'wine',
    'frametime',
    'frame_count',
    'resolution',
    'show_fps_limit',
    'vkbasalt',
    'gamemode',
    'battery',
    'battery_icon',
    'gamepad_battery',
    'gamepad_battery_icon',
    'fps_only',
    'time',
]

check_mh_description = [
    _('Current CPU temperature'),
    _('CPU draw in watts'),
    _('Load and frequency per core'),
    _('Shows the CPUs current MHz'),
    _('Shows the Steam Deck fan rpm'),
    _('GPU name from pci.ids'),
    _('Current GPU temperature'),
    _('GPU draw in watts'),
    _('GPU core frequency'),
    _('GPU memory frequency'),
    _('System RAM usage'),
    _('System VRAM usage'),
    _('Swap space usage next to system RAM usage'),
    _('Process resident memory usage'),
    _('Process shared memory usage'),
    _('Process virtual memory usage'),
    _('Show non-cached IO read, in MiB/s'),
    _('Show non-cached IO write, in MiB/s'),
    _('Enables most of the toggleable parameters'),
    _('Use primary font size for smaller text like units'),
    _('Show media player metadata'),
    _('Shows current mangohud version'),
    _('Show if the application is 32 or 64 bit'),
    _('Change fps graph to histogram'),
    _('Displays used vulkan driver'),
    _("OpenGL or vulkan-based render engine's version"),
    _('Shows current Wine or Proton version in use'),
    _('Frametime next to fps text'),
    _('Frame count'),
    _('Current resolution'),
    _('Current fps limit'),
    _('Shows if vkbasalt is on'),
    _('Shows if gamemode is on'),
    _('Current battery percent and energy consumption'),
    _('Battery icon instead of percent'),
    _('Battey of wireless gamepads (xone,xpadneo,ds4)'),
    _('Gamepad battery percent with icon. *enabled by default'),
    _('Show FPS only'),
    _('Displays local time'),
]

str_mh_subtitle = _('System monitoring indicators')

################################___Vkbasalt_check___:

export_vkbasalt_effects = 'export SW_USE_VKBASALT_EFFECTS'
export_vkbasalt_cas = 'export SW_USE_VKBASALT_CAS'
app_conf_vk_list = list()

vkbasalt_dict = {
    '3DFX': _('Supposedly imitation of rendering on the legendary 3dfx video cards.'),
    'AdaptiveFog': _('Adaptive fog. Used most for creating a color background, or putting a subject in shadows.'),
    'AdaptiveSharpen': _('Contrast Adaptive Sharpening. An image sharpening method that observes the contrast of the local environment.'),
    'AmbientLight': _('Ambient light. Bloom mixed with the EyeAdaption shader effect and lens dirt.'),
    'ASCII': _('For those who miss text games and Matrix fans.'),
    'Aspect Ratio': _('Сorrects aspect ratio in stretched images.'),
    'Bloom': _('A shader for simulating image blur depending on the brightness of the scene.'),
    'Border': _('If you want to add borders in image but want the subject to hover over said border then try this shader.'),
    'Cartoon': _('Creates an outline effect that makes the image look more cartoonish.'),
    'ChromaKey': _('Setting a blue or green screen away from the camera.'),
    'Chromatic Aberration': _('It operates in HDR, simulating the physical effect of light passing through a prism inside a camera.'),
    'CinematicDOF': _('Based on the most realistic and most used Depth of Field shader.'),
    'Clarity': _('Shader for image enhancement, makes things look sharper. Can rid the picture of haze.'),
    'ColorMatrix': _('Editing colors using the color matrix. Essentially changes the brightness of the color channels: red, green and blue.'),
    'Colourfulness': _('Saturates faded colors without touching the bright ones.'),
    'CRT': _('To simulate a cathode ray tube monitor. The combination with the PerfectPerspective shader will shed a tear of nostalgia.'),
    'Curves': _('Increases the contrast of the image, while not touching the bright and dark areas, so that the detail in the shadows and the sky is not lost.'),
    'Daltonize': _('Removes some colors.'),
    'Deband': _('Remove banding - gradients that dont blend smoothly into each other when there arent enough tones available to recreate a smooth gradation.'),
    'Denoise': _('Remove dot noise. If possible, turn off the noise in the game itself, because the noise reduction shader reduces the frame rate.'),
    'Depth3D': _('Split screen for owners of virtual reality glasses.'),
    'DepthHaze': _('Simple depth-blur that makes far-away objects look slightly blurred, with fog based on depth and screen position.'),
    'DisplayDepth': _('This is a shader mostly useful for checking if the depth buffer is working as intended.'),
    'DOF': _('Loss of sharpness in distant objects with the effect of chromatic aberration.'),
    'DPX': _('Makes the image look like it was converted from film to Cineon DPX. Can be used to create a sunny look.'),
    'Emphasize': _('Make a part of the scene pop out more while other parts are de-emphasized. By default, it desaturates the areas which are not in focus.'),
    'EyeAdaption': _('This shader brightens or darkens the image depending on the average brightness of the screen.'),
    'FakeHDR': _('Should restore detail in too dark and bright areas of the frame. Darkens the image in practice.'),
    'FakeMotionBlur': _('Pseudo motion blur.'),
    'FilmGrain': _('Film grain without copying texture.'),
    'FilmGrain2': _('Film grain without copying texture.'),
    'FilmicAnamorphSharpen': _('Sharpering for more cinema-like look.'),
    'FilmicPass': _('Applies some common color adjustments to mimic a more cinema-like look.'),
    'FineSharp': _('Sharpering for more cinema-like look.'),
    'FXAA': _('The most primitive and fastest of the anti-aliasing filters (pixel smoothing).'),
    'GaussianBlur': _('Just blurs the image.'),
    'Glitch': _('To simulate a failing video card and cause nausea. People with epilepsy should not turn on this filter!'),
    'HighPassSharpen': _('Sharpering for more cinema-like look.'),
    'HQ4X': _('Smoothing nearby pixels with filling in the missing parts. Is useful for smoothing objects in pixel games.'),
    'HSLShift': _('Lightweight focus and sharpering effect.'),
    'Layer': _('Make own layer.png and overwrite on of the textures. It support alpha transparency.'),
    'Levels': _('Shifts white and black points. will help in the absence of real black (everything is whitish, as if in a fog) or white is too gray.'),
    'LevelsPlus': _('Shifts white and black points. will help in the absence of real black.'),
    'LiftGammaGain': _('Gamma correction in color channels: red, green and blue. Can stylization of some games under a certain color shade.'),
    'LightDOF': _('The most lightweight defocus shader in terms of function, which does not greatly reduce performance.'),
    'LumaSharpen': _('Sharpering for more cinema-like look.'),
    'LUT': _('In the context of game shaders, loot allows you to give the picture a cinema-like look.'),
    'MagicBloom': _('Shader based on scene luminosity. It uses a Gaussian blur applied on the fly. It blends the bloom with the rest using the Screen blending method.'),
    'Monochrome': _('The effect of simulating a black and white image.'),
    'MultiLUT': _('Hollywood preset LUT included.'),
    'MXAO': _('The effect of self-shadowing of objects, visually adding volume to them.'),
    'NightVision': _('For those who are nostalgic for a night vision device?'),
    'Nostalgia': _('Shader to create a 4-bit frame. Tries to mimic the look of very old computers or console systems.'),
    'PerfectPerspective': _('The shader tilts the image and changes the point of view of the image. Can be useful for owners of virtual reality glasses.'),
    'PPFX_Bloom': _('Filter that adds a glow around bright screen areas, adapting to the current scene brightness.'),
    'PPFX_Godrays': _('If you want to add godrays to a scene then this shader can help you with that.'),
    'Prism': _('Yet Another Chromatic Aberration: It operates in HDR, is the only shader with a correct spectral gradient.'),
    'ReflectiveBumpMapping': _('Adds reflections to objects in the frame. Can improve the picture in older games without reflection support, but is useless in modern ones.'),
    'Sepia': _('Applying a shade of brown. Color inherent in old black and white photographs.'),
    'SMAA': _('Advanced implementation of anti-aliasing. Highlight the objects in the frame and blur their boundaries without erasing the small details of the frame.'),
    'StageDepth': _('Resize image, positioning it, rotating it and use different blending modes.'),
    'SurfaceBlur': _('Reduction in object detail without blurring contrasting contours.'),
    'Technicolor': _('Makes the image look like it was processed using a three-strip Technicolor process.'),
    'Technicolor2': _('Like Technicolor, but Gives a different picture, more aggressively changing colors.'),
    'TiltShift': _('For simulating tilt-shift photography, but recommended to use CinematicDOF.'),
    'Tonemap': _('Tone map for brightness, color and gamma correction.'),
    'UIDetect': _('Detects the presence of a UI on the screen and switches the visibility of effects depending on its presence.'),
    'UIMask': _('Shader-mask that makes holes in the effects in the places of the menu items, provided that they do not move anywhere.'),
    'Vibrance': _('Saturates faded colors without touching the bright ones. The default settings are almost invisible.'),
    'Vignette': _('Adds vignetting, reducing the brightness of the frame at the edges.'),
}

str_vk_subtitle = _('Vulkan layer postprocessing visual effects')
str_vk_intensity = _('Effect intensity')

################################___Mangohud_colors___:

str_mh_colors_title = _('Mangohud colors')
str_mh_colors_subtitle = _('Mangohud indicator color scheme settings')

mh_colors = [
    'gpu_color',
    'cpu_color',
    'vram_color',
    'ram_color',
    'io_color',
    'engine_color',
    'frametime_color',
    'background_color',
    'text_color',
    'media_player_color',
    'wine_color',
    'gpu_load_color',
    'cpu_load_color',
    'battery_color',
]

mh_colors_description = [
    _('GPU indicator'),
    _('CPU indicator'),
    _('VRAM indicator'),
    _('RAM indicator'),
    _('IO indicator'),
    _('Render engines version'),
    _('Frametime indicator'),
    _('Overlay background'),
    _('Text color'),
    _('Media player color'),
    _('Wine color'),
    _('GPU load color'),
    _('CPU load color'),
    _('Battery indicator'),
]

################################___Custom_theme_colors___:

confirm_label = _('Confirm changes')
preview_label = _('Mangohud preview')

str_theme_colors_title = _('Custom theme')
str_theme_colors_subtitle = _('Custom interface color scheme settings')

str_define_color = '@define-color'
css_change_list = list()

dcolor_names = [
    '@define-color sw_text_color',
    '@define-color sw_bg_color',
    '@define-color sw_accent_fg_color',
    '@define-color sw_accent_bg_color',
    '@define-color sw_header_bg_color',
    '@define-color sw_pop_bg_color',
]

dcolor_labels = [
    _('Primary text'),
    _('Primary background'),
    _('Accent color'),
    _('Accent background'),
    _('Headerbars'),
    _('Popover context menu'),
]

################################___Global_settings___:

str_global_subtitle = _('Additional general parameters and keyboard shortcuts')

str_title_startup = _('Startup options')
str_subtitle_startup = _('Some settings will take effect the next time you start')

str_title_lang = _('Language')
str_subtitle_lang = _('Change the interface language')

str_title_autostart = _('Autostart')
str_subtitle_autostart = _('Run StartWine in the tray at system startup')

str_title_restore_menu = _('Restore menu')
str_subtitle_restore_menu = _('Restore the menu after exiting a game or application')

str_title_auto_stop = _('Auto Stop')
str_subtitle_auto_stop = _('Auto terminate all wine processes after exiting a game or application')

str_title_icons = _('Icons')
str_subtitle_icons = _('Use system icon theme')

str_title_menu_size = _('Compact mode')
str_subtitle_menu_size = _('Always run the menu in compact size mode')

str_title_def_dir = _('Default directory')
str_subtitle_def_dir = _('The default directory in which files will be opened in the StartWine file manager')

str_title_opengl = _('OpenGL background')
str_subtitle_opengl = _('Live background (opengl animation based on selected shaders). '
'Warning!!! This function can lead to slowdowns and additional load on the graphics card.')

str_title_shaders = _('Shaders')
str_subtitle_shaders = _('Select shaders for the live background from the list')

str_title_hotkeys = _('Hotkeys')
str_subtitle_hotkeys = _('List of default hotkeys settings')

str_wrong_path = _('Wrong path, path does not exist, specify the correct path to the directory')

hotkey_list = [
    ['Ctrl', 'K', ''],
    ['F1', '', ''],
    ['F3', '', ''],
    ['R_Shift', 'F12', ''],
    ['R_Shift','F11',''],
    ['HOME', '', ''],
    ['Ctrl', 'Shift', 'Q'],
    ['Ctrl', 'Escape', ''],
    ['Ctrl', 'R', ''],
    ['Ctrl', '+', ''],
    ['Ctrl', '-', ''],
    ['F5', '', ''],
    ['Ctrl', 'H', ''],
    ['Ctrl', 'L', ''],
    ['Ctrl', 'A', ''],
    ['Ctrl', 'N', ''],
    ['Shift', 'L', ''],
    ['Ctrl', 'C', ''],
    ['Ctrl', 'V', ''],
    ['Ctrl', 'X', ''],
    ['Ctrl', 'Shift', 'K'],
    ['Delete', '', ''],
    ['Shift', 'Delete', ''],
    ['F2', '', ''],
    ['Alt', 'Up', ''],
    ['Alt', 'Right', ''],
    ['Alt', 'Left', ''],
    ['Alt', 'S', ''],
    ['Alt', 'A', ''],
    ['Alt', 'F', ''],
    ['Alt', 'D', ''],
    ['Alt', 'B', ''],
    ['Alt', 'W', ''],
    ['Alt', 'L', ''],
    ['Alt', 'X', ''],
    ['Alt', 'M', ''],
    ['Alt', 'V', ''],
    ['Alt', 'C', ''],
    ['Alt', 'G', ''],
]

hotkey_desc = [
    _('show hotkey settings window'),
    _('show help'),
    _('about StartWine'),
    _('enable / disable mangohud overlay in the game'),
    _('toggle mangohud overlay postion in the game'),
    _('enable / disable vkbasalt effects in the game'),
    _('shutdown StartWine'),
    _('close StartWine window'),
    _('change the window size mode'),
    _('increase the size of the icons and shortcuts'),
    _('reduce the size of the icons and shortcuts'),
    _('update files or shortcuts list view'),
    _('to display or not to display hidden files'),
    _('show current directory path string'),
    _('select all files in file manager'),
    _('create new directory'),
    _('create symbolic links for selected files'),
    _('copy to clipboard'),
    _('paste from clipboard'),
    _('cut selected files'),
    _('terminate all processes'),
    _('move to trash selected files'),
    _('permanently delete selected files'),
    _('rename file or directory in file manager'),
    _('go to the directory up in the file manager'),
    _('go to the next menu page'),
    _('go to the previous menu page'),
    _('show or hide sidebar menu'),
    _('shortcuts view'),
    _('open file manager'),
    _('show or hide list of mounted volumes'),
    _('show or hide bookmarks list'),
    _('open winetricks menu'),
    _('launchers view'),
    _('open launch settings menu'),
    _('open mangohud settings menu'),
    _('open vkbasalt settings menu'),
    _('open colors settings menu'),
    _('open base settings menu'),
]

################################___Winetricks___:

btn_dll_list = list()
install_dll_list = list()
description_label = _('Description')
confirm_install_label = _('Confirm install')
libs_tab_label = _('Library')
fonts_tab_label = _('Fonts')
libs_column_label = _('Library list')
fonts_column_label = _('Fonts list')
str_winetricks_subtitle = _('Installing native windows library to the current prefix')

dll_templates_labels = [
    '',
    _('Recommended libraries kit'),
    _('MS .NET libraries kit'),
    _('D3D libraries kit'),
    _('Visual C++ libraries kit'),
]

dll_templates_desc = [
'',
'mfc120 mfc42 msvcirt openal physx vb6run vcrun2005 vcrun2008 vcrun2010 vcrun2012 \
vcrun2013 vcrun2022 vcrun6 vcrun6sp6 lucida nocrashdialog',
'dotnet20 dotnet40 dotnet48',
'd3dcompiler_42 d3dcompiler_43 d3dcompiler_47 d3dx10 d3dx10_43 d3dx11_42 d3dx11_43 d3dx9',
'vcrun2005 vcrun2008 vcrun2010 vcrun2012 vcrun2013 vcrun2022 vcrun6 vcrun6sp6',
]

dll_templates_dict = {}
for k, v in zip(dll_templates_labels, dll_templates_desc):
    dll_templates_dict[k] = v

sw_dll = '''allcodecs
amstream
art2k7min
art2kmin
atmlib
avifil32
binkw32
cabinet
cinepak
cmd
cnc_ddraw
comctl32
comctl32ocx
comdlg32ocx
crypt32
crypt32_winxp
d3dcompiler_42
d3dcompiler_43
d3dcompiler_46
d3dcompiler_47
d3drm
d3dx10
d3dx10_43
d3dx11_42
d3dx11_43
d3dx9
d3dx9_24
d3dx9_25
d3dx9_26
d3dx9_27
d3dx9_28
d3dx9_29
d3dx9_30
d3dx9_31
d3dx9_32
d3dx9_33
d3dx9_34
d3dx9_35
d3dx9_36
d3dx9_37
d3dx9_38
d3dx9_39
d3dx9_40
d3dx9_41
d3dx9_42
d3dx9_43
d3dxof
dbghelp
devenum
dinput
dinput8
dirac
directmusic
directplay
directshow
directx9
dmband
dmcompos
dmime
dmloader
dmscript
dmstyle
dmsynth
dmusic
dmusic32
dotnet11
dotnet11sp1
dotnet20
dotnet20sp1
dotnet20sp2
dotnet30
dotnet30sp1
dotnet35
dotnet35sp1
dotnet40
dotnet40_kb2468871
dotnet45
dotnet452
dotnet46
dotnet461
dotnet462
dotnet471
dotnet472
dotnet48
dotnet6
dotnet7
dotnet_verifier
dotnetcore2
dotnetcore3
dotnetcoredesktop3
dotnetdesktop6
dotnetdesktop7
dpvoice
dsdmo
dsound
dswave
dx8vb
dxdiag
dxdiagn
dxdiagn_feb2010
dxtrans
dxvk
dxvk0054
dxvk0060
dxvk0061
dxvk0062
dxvk0063
dxvk0064
dxvk0065
dxvk0070
dxvk0071
dxvk0072
dxvk0080
dxvk0081
dxvk0090
dxvk0091
dxvk0092
dxvk0093
dxvk0094
dxvk0095
dxvk0096
dxvk1000
dxvk1001
dxvk1002
dxvk1003
dxvk1011
dxvk1020
dxvk1021
dxvk1022
dxvk1023
dxvk1030
dxvk1031
dxvk1032
dxvk1033
dxvk1034
dxvk1040
dxvk1041
dxvk1042
dxvk1043
dxvk1044
dxvk1045
dxvk1046
dxvk1050
dxvk1051
dxvk1052
dxvk1053
dxvk1054
dxvk1055
dxvk1060
dxvk1061
dxvk1070
dxvk1071
dxvk1072
dxvk1073
dxvk1080
dxvk1081
dxvk1090
dxvk1091
dxvk1092
dxvk1093
dxvk1094
dxvk1100
dxvk1101
dxvk1102
dxvk1103
dxvk2000
dxvk2010
dxvk2020
dxvk2030
dxvk_nvapi0061
esent
faudio
faudio1901
faudio1902
faudio1903
faudio1904
faudio1905
faudio1906
faudio190607
ffdshow
filever
galliumnine
galliumnine02
galliumnine03
galliumnine04
galliumnine05
galliumnine06
galliumnine07
galliumnine08
galliumnine09
gdiplus
gdiplus_winxp
gfw
glidewrapper
glut
gmdls
hid
icodecs
ie6
ie7
ie8
ie8_kb2936068
ie8_tls12
iertutil
itircl
itss
jet40
l3codecx
lavfilters
lavfilters702
mdac27
mdac28
mdx
mf
mfc100
mfc110
mfc120
mfc140
mfc40
mfc42
mfc70
mfc71
mfc80
mfc90
msaa
msacm32
msasn1
msctf
msdelta
msdxmocx
msflxgrd
msftedit
mshflxgd
msls31
msmask
mspatcha
msscript
msvcirt
msvcrt40
msxml3
msxml4
msxml6
nuget
ogg
ole32
oleaut32
openal
pdh
pdh_nt4
peverify
physx
pngfilt
prntvpt
python26
python27
qasf
qcap
qdvd
qedit
quartz
quartz_feb2010
quicktime72
quicktime76
riched20
riched30
richtx32
sapi
sdl
secur32
setupapi
shockwave
speechsdk
tabctl32
ucrtbase2019
uiribbon
updspapi
urlmon
usp10
vb2run
vb3run
vb4run
vb5run
vb6run
vcrun2003
vcrun2005
vcrun2008
vcrun2010
vcrun2012
vcrun2013
vcrun2015
vcrun2017
vcrun2019
vcrun2022
vcrun6
vcrun6sp6
vjrun20
vkd3d
webio
windowscodecs
winhttp
wininet
wininet_win2k
wmi
wmp10
wmp11
wmp9
wmv9vcm
wsh57
xact
xact_x64
xinput
xmllite
xna31
xna40
xvid
'''

sw_dll_desc = '''All codecs (dirac, ffdshow, icodecs, cinepak, l3codecx, xvid) except wmp (various, 1995-2009)
MS amstream.dll (Microsoft, 2011)
MS Access 2007 runtime (Microsoft, 2007)
MS Access 2000 runtime (Microsoft, 2000)
Adobe Type Manager (Adobe, 2009)
MS avifil32 (Microsoft, 2004)
RAD Game Tools binkw32.dll (RAD Game Tools, Inc., 2000)
Microsoft cabinet.dll (Microsoft, 2002)
Cinepak Codec (Radius, 1995)
MS cmd.exe (Microsoft, 2004)
Reimplentation of ddraw for CnC games (CnCNet, 2021)
MS common controls 5.80 (Microsoft, 2001)
MS comctl32.ocx and mscomctl.ocx, comctl32 wrappers for VB6 (Microsoft, 2012)
Common Dialog ActiveX Control for VB6 (Microsoft, 2012)
MS crypt32 (Microsoft, 2011)
MS crypt32 (Microsoft, 2004)
MS d3dcompiler_42.dll (Microsoft, 2010)
MS d3dcompiler_43.dll (Microsoft, 2010)
MS d3dcompiler_46.dll (Microsoft, 2010)
MS d3dcompiler_47.dll (Microsoft, FIXME)
MS d3drm.dll (Microsoft, 2010)
MS d3dx10_??.dll from DirectX user redistributable (Microsoft, 2010)
MS d3dx10_43.dll (Microsoft, 2010)
MS d3dx11_42.dll (Microsoft, 2010)
MS d3dx11_43.dll (Microsoft, 2010)
MS d3dx9_??.dll from DirectX 9 redistributable (Microsoft, 2010)
MS d3dx9_24.dll (Microsoft, 2010)
MS d3dx9_25.dll (Microsoft, 2010)
MS d3dx9_26.dll (Microsoft, 2010)
MS d3dx9_27.dll (Microsoft, 2010)
MS d3dx9_28.dll (Microsoft, 2010)
MS d3dx9_29.dll (Microsoft, 2010)
MS d3dx9_30.dll (Microsoft, 2010)
MS d3dx9_31.dll (Microsoft, 2010)
MS d3dx9_32.dll (Microsoft, 2010)
MS d3dx9_33.dll (Microsoft, 2010)
MS d3dx9_34.dll (Microsoft, 2010)
MS d3dx9_35.dll (Microsoft, 2010)
MS d3dx9_36.dll (Microsoft, 2010)
MS d3dx9_37.dll (Microsoft, 2010)
MS d3dx9_38.dll (Microsoft, 2010)
MS d3dx9_39.dll (Microsoft, 2010)
MS d3dx9_40.dll (Microsoft, 2010)
MS d3dx9_41.dll (Microsoft, 2010)
MS d3dx9_42.dll (Microsoft, 2010)
MS d3dx9_43.dll (Microsoft, 2010)
MS d3dxof.dll from DirectX user redistributable (Microsoft, 2010)
MS dbghelp (Microsoft, 2008)
MS devenum.dll from DirectX user redistributable (Microsoft, 2010)
MS dinput.dll; breaks mouse, use only on Rayman 2 etc. (Microsoft, 2010)
MS DirectInput 8 from DirectX user redistributable (Microsoft, 2010)
The Dirac directshow filter v1.0.2 (Dirac, 2009)
MS DirectMusic from DirectX user redistributable (Microsoft, 2010)
MS DirectPlay from DirectX user redistributable (Microsoft, 2010)
DirectShow runtime DLLs (amstream, qasf, qcap, qdvd, qedit, quartz) (Microsoft, 2011)
MS DirectX 9 (Deprecated, no-op) (Microsoft, 2010)
MS dmband.dll from DirectX user redistributable (Microsoft, 2010)
MS dmcompos.dll from DirectX user redistributable (Microsoft, 2010)
MS dmime.dll from DirectX user redistributable (Microsoft, 2010)
MS dmloader.dll from DirectX user redistributable (Microsoft, 2010)
MS dmscript.dll from DirectX user redistributable (Microsoft, 2010)
MS dmstyle.dll from DirectX user redistributable (Microsoft, 2010)
MS dmsynth.dll from DirectX user redistributable (Microsoft, 2010)
MS dmusic.dll from DirectX user redistributable (Microsoft, 2010)
MS dmusic32.dll from DirectX user redistributable (Microsoft, 2006)
MS .NET 1.1 (Microsoft, 2003)
MS .NET 1.1 SP1 (Microsoft, 2004)
MS .NET 2.0 (Microsoft, 2006)
MS .NET 2.0 SP1 (Microsoft, 2008)
MS .NET 2.0 SP2 (Microsoft, 2009)
MS .NET 3.0 (Microsoft, 2006)
MS .NET 3.0 SP1 (Microsoft, 2007)
MS .NET 3.5 (Microsoft, 2007)
MS .NET 3.5 SP1 (Microsoft, 2008)
MS .NET 4.0 (Microsoft, 2011)
MS .NET 4.0 KB2468871 (Microsoft, 2011)
MS .NET 4.5 (Microsoft, 2012)
MS .NET 4.5.2 (Microsoft, 2012)
MS .NET 4.6 (Microsoft, 2015)
MS .NET 4.6.1 (Microsoft, 2015)
MS .NET 4.6.2 (Microsoft, 2016)
MS .NET 4.7.1 (Microsoft, 2017)
MS .NET 4.7.2 (Microsoft, 2018)
MS .NET 4.8 (Microsoft, 2019)
MS .NET Runtime 6.0 LTS (Microsoft, 2023)
MS .NET Runtime 7.0 LTS (Microsoft, 2023)
MS .NET Verifier (Microsoft, 2016)
MS .NET Core Runtime 2.1 LTS (Microsoft, 2020)
MS .NET Core Runtime 3.1 LTS (Microsoft, 2020)
MS .NET Core Desktop Runtime 3.1 LTS (Microsoft, 2020)
MS .NET Desktop Runtime 6.0 LTS (Microsoft, 2023)
MS .NET Desktop Runtime 7.0 LTS (Microsoft, 2023)
Microsoft dpvoice dpvvox dpvacm Audio dlls (Microsoft, 2002)
MS dsdmo.dll (Microsoft, 2010)
MS DirectSound from DirectX user redistributable (Microsoft, 2010)
MS dswave.dll from DirectX user redistributable (Microsoft, 2010)
MS dx8vb.dll from DirectX 8.1 runtime (Microsoft, 2001)
DirectX Diagnostic Tool (Microsoft, 2010)
DirectX Diagnostic Library (Microsoft, 2011)
DirectX Diagnostic Library (February 2010) (Microsoft, 2010)
MS dxtrans.dll (Microsoft, 2002)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (latest) (Philip Rebohle, 2023)
Vulkan-based D3D11 implementation for Linux / Wine (0.54) (Philip Rebohle, 2017)
Vulkan-based D3D11 implementation for Linux / Wine (0.60) (Philip Rebohle, 2017)
Vulkan-based D3D11 implementation for Linux / Wine (0.61) (Philip Rebohle, 2017)
Vulkan-based D3D11 implementation for Linux / Wine (0.62) (Philip Rebohle, 2017)
Vulkan-based D3D11 implementation for Linux / Wine (0.63) (Philip Rebohle, 2017)
Vulkan-based D3D11 implementation for Linux / Wine (0.64) (Philip Rebohle, 2017)
Vulkan-based D3D11 implementation for Linux / Wine (0.65) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (0.70) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (0.71) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (0.72) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (0.80) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (0.81) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (0.90) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (0.91) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (0.92) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (0.93) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (0.94) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (0.95) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (0.96) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.0) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.0.1) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.0.2) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.0.3) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.1.1) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.2) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.2.1) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.2.2) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.2.3) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.3) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.3.1) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.3.2) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.3.3) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.3.4) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.4) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.4.1) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.4.2) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.4.3) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.4.4) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.4.5) (Philip Rebohle, 2017)
Vulkan-based D3D10/D3D11 implementation for Linux / Wine (1.4.6) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.5) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.5.1) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.5.2) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.5.3) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.5.4) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.5.5) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.6) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.6.1) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.7) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.7.1) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.7.2) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.7.3) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.8) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.8.1) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.9) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.9.1) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.9.2) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.9.3) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.9.4) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.10) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.10.1) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.10.2) (Philip Rebohle, 2017)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (1.10.3) (Philip Rebohle, 2022)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (2.0) (Philip Rebohle, 2022)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (2.1) (Philip Rebohle, 2023)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (2.2) (Philip Rebohle, 2023)
Vulkan-based D3D9/D3D10/D3D11 implementation for Linux / Wine (2.3) (Philip Rebohle, 2023)
Alternative NVAPI Vulkan implementation on top of DXVK for Linux / Wine (0.6.1) (Jens Peters, 2023)
MS Extensible Storage Engine (Microsoft, 2011)
FAudio (xaudio reimplementation, with xna support) builds for win32 (20.07) (Kron4ek, 2019)
FAudio (xaudio reimplementation, with xna support) builds for win32 (19.01) (Kron4ek, 2019)
FAudio (xaudio reimplementation, with xna support) builds for win32 (19.02) (Kron4ek, 2019)
FAudio (xaudio reimplementation, with xna support) builds for win32 (19.03) (Kron4ek, 2019)
FAudio (xaudio reimplementation, with xna support) builds for win32 (19.04) (Kron4ek, 2019)
FAudio (xaudio reimplementation, with xna support) builds for win32 (19.05) (Kron4ek, 2019)
FAudio (xaudio reimplementation, with xna support) builds for win32 (19.06) (Kron4ek, 2019)
FAudio (xaudio reimplementation, with xna support) builds for win32 (19.06.07) (Kron4ek, 2019)
ffdshow video codecs (doom9 folks, 2010)
Microsoft's filever, for dumping file version info (Microsoft, 20??)
Gallium Nine Standalone (latest) (Gallium Nine Team, 2023)
Gallium Nine Standalone (v0.2) (Gallium Nine Team, 2019)
Gallium Nine Standalone (v0.3) (Gallium Nine Team, 2019)
Gallium Nine Standalone (v0.4) (Gallium Nine Team, 2019)
Gallium Nine Standalone (v0.5) (Gallium Nine Team, 2019)
Gallium Nine Standalone (v0.6) (Gallium Nine Team, 2020)
Gallium Nine Standalone (v0.7) (Gallium Nine Team, 2020)
Gallium Nine Standalone (v0.8) (Gallium Nine Team, 2021)
Gallium Nine Standalone (v0.9) (Gallium Nine Team, 2023)
MS GDI+ (Microsoft, 2011)
MS GDI+ (Microsoft, 2009)
MS Games For Windows Live (xlive.dll) (Microsoft, 2008)
GlideWrapper (Rolf Neuberger, 2005)
The glut utility library for OpenGL (Mark J. Kilgard, 2001)
General MIDI DLS Collection (Microsoft / Roland, 1999)
MS hid (Microsoft, 2003)
Indeo codecs (Intel, 1998)
Internet Explorer 6 (Microsoft, 2002)
Internet Explorer 7 (Microsoft, 2008)
Internet Explorer 8 (Microsoft, 2009)
Cumulative Security Update for Internet Explorer 8 (Microsoft, 2014)
TLS 1.1 and 1.2 for Internet Explorer 8 (Microsoft, 2017)
MS Runtime Utility (Microsoft, 2011)
MS itircl.dll (Microsoft, 1999)
MS itss.dll (Microsoft, 1999)
MS Jet 4.0 Service Pack 8 (Microsoft, 2003)
MPEG Layer-3 Audio Codec for Microsoft DirectShow (Microsoft, 2010)
LAV Filters (Hendrik Leppkes, 2019)
LAV Filters 0.70.2 (Hendrik Leppkes, 2017)
Microsoft Data Access Components 2.7 sp1 (Microsoft, 2006)
Microsoft Data Access Components 2.8 sp1 (Microsoft, 2005)
Managed DirectX (Microsoft, 2006)
MS Media Foundation (Microsoft, 2011)
Visual C++ 2010 mfc100 library; part of vcrun2010 (Microsoft, 2010)
Visual C++ 2012 mfc110 library; part of vcrun2012 (Microsoft, 2012)
Visual C++ 2013 mfc120 library; part of vcrun2013 (Microsoft, 2013)
Visual C++ 2015 mfc140 library; part of vcrun2015 (Microsoft, 2015)
MS mfc40 (Microsoft Foundation Classes from win7sp1) (Microsoft, 1999)
Visual C++ 6 SP4 mfc42 library; part of vcrun6 (Microsoft, 2000)
Visual Studio (.NET) 2002 mfc70 library (Microsoft, 2006)
Visual C++ 2003 mfc71 library; part of vcrun2003 (Microsoft, 2003)
Visual C++ 2005 mfc80 library; part of vcrun2005 (Microsoft, 2011)
Visual C++ 2008 mfc90 library; part of vcrun2008 (Microsoft, 2011)
MS Active Accessibility (oleacc.dll, oleaccrc.dll, msaatext.dll) (Microsoft, 2003)
MS ACM32 (Microsoft, 2003)
MS ASN1 (Microsoft, 2003)
MS Text Service Module (Microsoft, 2003)
MSDelta differential compression library (Microsoft, 2011)
MS Windows Media Player 2 ActiveX control for VB6 (Microsoft, 1999)
MS FlexGrid Control (msflxgrd.ocx) (Microsoft, 2012)
Microsoft RichEdit Control (Microsoft, 2011)
MS Hierarchical FlexGrid Control (mshflxgd.ocx) (Microsoft, 2012)
MS Line Services (Microsoft, 2001)
MS Masked Edit Control (Microsoft, 2009)
MS mspatcha (Microsoft, 2004)
MS Windows Script Control (Microsoft, 2004)
Visual C++ 6 SP4 msvcirt library; part of vcrun6 (Microsoft, 2000)
fixme (Microsoft, 2011)
MS XML Core Services 3.0 (Microsoft, 2005)
MS XML Core Services 4.0 (Microsoft, 2009)
MS XML Core Services 6.0 sp2 (Microsoft, 2014)
NuGet Package manager (Outercurve Foundation, 2013)
OpenCodecs 0.85: FLAC, Speex, Theora, Vorbis, WebM (Xiph.Org Foundation, 2011)
MS ole32 Module (ole32.dll) (Microsoft, 2004)
MS oleaut32.dll (Microsoft, 2011)
OpenAL Runtime (Creative, 2023)
MS pdh.dll (Performance Data Helper) (Microsoft, 2011)
MS pdh.dll (Performance Data Helper); WinNT 4.0 Version (Microsoft, 1997)
MS peverify (from .NET 2.0 SDK) (Microsoft, 2006)
PhysX (Nvidia, 2021)
pngfilt.dll (from winxp) (Microsoft, 2004)
prntvpt.dll (Microsoft, 2011)
Python interpreter 2.6.2 (Python Software Foundaton, 2009)
Python interpreter 2.7.16 (Python Software Foundaton, 2019)
qasf.dll (Microsoft, 2011)
qcap.dll (Microsoft, 2011)
qdvd.dll (Microsoft, 2011)
qedit.dll (Microsoft, 2011)
quartz.dll (Microsoft, 2011)
quartz.dll (February 2010) (Microsoft, 2010)
Apple QuickTime 7.2 (Apple, 2010)
Apple QuickTime 7.6 (Apple, 2010)
MS RichEdit Control 2.0 (riched20.dll) (Microsoft, 2004)
MS RichEdit Control 3.0 (riched20.dll, msls31.dll) (Microsoft, 2001)
MS Rich TextBox Control 6.0 (Microsoft, 2012)
MS Speech API (Microsoft, 2011)
Simple DirectMedia Layer (Sam Lantinga, 2012)
MS Security Support Provider Interface (Microsoft, 2011)
MS Setup API (Microsoft, 2004)
Shockwave (Adobe, 2018)
MS Speech SDK 5.1 (Microsoft, 2009)
Microsoft Tabbed Dialog Control 6.0 (tabctl32.ocx) (Microsoft, 2012)
Visual C++ 2019 library (ucrtbase.dll) (Microsoft, 2019)
Windows UIRibbon (Microsoft, 2011)
Windows Update Service API (Microsoft, 2004)
MS urlmon (Microsoft, 2011)
Uniscribe (Microsoft, 2011)
MS Visual Basic 2 runtime (Microsoft, 1993)
MS Visual Basic 3 runtime (Microsoft, 1998)
MS Visual Basic 4 runtime (Microsoft, 1998)
MS Visual Basic 5 runtime (Microsoft, 2001)
MS Visual Basic 6 runtime sp6 (Microsoft, 2004)
Visual C++ 2003 libraries (mfc71,msvcp71,msvcr71) (Microsoft, 2003)
Visual C++ 2005 libraries (mfc80,msvcp80,msvcr80) (Microsoft, 2011)
Visual C++ 2008 libraries (mfc90,msvcp90,msvcr90) (Microsoft, 2011)
Visual C++ 2010 libraries (mfc100,msvcp100,msvcr100) (Microsoft, 2010)
Visual C++ 2012 libraries (atl110,mfc110,mfc110u,msvcp110,msvcr110,vcomp110) (Microsoft, 2012)
Visual C++ 2013 libraries (mfc120,mfc120u,msvcp120,msvcr120,vcomp120) (Microsoft, 2013)
Visual C++ 2015 libraries (concrt140.dll,mfc140.dll,mfc140u.dll,mfcm140.dll,mfcm140u.dll,msvcp140.dll,msvcp140_1.dll,msvcp140_atomic_wait.dll,vcamp140.dll,vccorlib140.dll,vcomp140.dll,vcruntime140.dll,vcruntime140_1.dll) (Microsoft, 2015)
Visual C++ 2017 libraries (concrt140.dll,mfc140.dll,mfc140u.dll,mfcm140.dll,mfcm140u.dll,msvcp140.dll,msvcp140_1.dll,msvcp140_2.dll,msvcp140_atomic_wait.dll,vcamp140.dll,vccorlib140.dll,vcomp140.dll,vcruntime140.dll,vcruntime140_1.dll) (Microsoft, 2017)
Visual C++ 2015-2019 libraries (concrt140.dll,mfc140.dll,mfc140u.dll,mfcm140.dll,mfcm140u.dll,msvcp140.dll,msvcp140_1.dll,msvcp140_2.dll,msvcp140_atomic_wait.dll,msvcp140_codecvt_ids.dll,vcamp140.dll,vccorlib140.dll,vcomp140.dll,vcruntime140.dll,vcruntime140_1.dll (Microsoft, 2019)
Visual C++ 2015-2022 libraries (concrt140.dll,mfc140.dll,mfc140chs.dll,mfc140cht.dll,mfc140deu.dll,mfc140enu.dll,mfc140esn.dll,mfc140fra.dll,mfc140ita.dll,mfc140jpn.dll,mfc140kor.dll,mfc140rus.dll,mfc140u.dll,mfcm140.dll,mfcm140u.dll,msvcp140.dll,msvcp140_1.dll,msvcp140_2.dll,msvcp140_atomic_wait.dll,msvcp140_codecvt_ids.dll,vcamp140.dll,vccorlib140.dll,vcomp140.dll,vcruntime140.dll,vcruntime140_1.dll) (Microsoft, 2022)
Visual C++ 6 SP4 libraries (mfc42, msvcp60, msvcirt) (Microsoft, 2000)
Visual C++ 6 SP6 libraries (with fixes in ATL and MFC) (Microsoft, 2004)
MS Visual J# 2.0 SE libraries (requires dotnet20) (Microsoft, 2007)
Vulkan-based D3D12 implementation for Linux / Wine (latest) (Hans-Kristian Arntzen , 2020)
MS Windows Web I/O (Microsoft, 2011)
MS Windows Imaging Component (Microsoft, 2006)
MS Windows HTTP Services (Microsoft, 2005)
MS Windows Internet API (Microsoft, 2011)
MS Windows Internet API (Microsoft, 2008)
Windows Management Instrumentation (aka WBEM) Core 1.5 (Microsoft, 2000)
Windows Media Player 10 (Microsoft, 2006)
Windows Media Player 11 (Microsoft, 2007)
Windows Media Player 9 (Microsoft, 2003)
MS Windows Media Video 9 Video Compression Manager (Microsoft, 2013)
MS Windows Script Host 5.7 (Microsoft, 2007)
MS XACT Engine (32-bit only) (Microsoft, 2010)
MS XACT Engine (64-bit only) (Microsoft, 2010)
Microsoft XInput (Xbox controller support) (Microsoft, 2010)
MS xmllite dll (Microsoft, 2011)
MS XNA Framework Redistributable 3.1 (Microsoft, 2009)
MS XNA Framework Redistributable 4.0 (Microsoft, 2010)
Xvid Video Codec (xvid.org, 2019)
'''

dll_dict = {}

for d, l in zip(list(sw_dll.splitlines()),list(sw_dll_desc.splitlines())):
    dll_dict[d] = l

sw_fonts = '''allfonts
andale
arial
baekmuk
calibri
cambria
candara
cjkfonts
comicsans
consolas
constantia
corbel
corefonts
courier
droid
eufonts
fakechinese
fakejapanese
fakejapanese_ipamona
fakejapanese_vlgothic
fakekorean
georgia
impact
ipamona
liberation
lucida
meiryo
opensymbol
pptfonts
sourcehansans
tahoma
takao
times
trebuchet
uff
unifont
verdana
vlgothic
webdings
wenquanyi
wenquanyizenhei
'''

sw_fonts_desc = '''All fonts (various, 1998-2010)
MS Andale Mono font (Microsoft, 2008)
MS Arial / Arial Black fonts (Microsoft, 2008)
Baekmuk Korean fonts (Wooderart Inc. / kldp.net, 1999)
MS Calibri font (Microsoft, 2007)
MS Cambria font (Microsoft, 2009)
MS Candara font (Microsoft, 2009)
All Chinese, Japanese, Korean fonts and aliases (Various, )
MS Comic Sans fonts (Microsoft, 2008)
MS Consolas console font (Microsoft, 2011)
MS Constantia font (Microsoft, 2009)
MS Corbel font (Microsoft, 2009)
MS Arial, Courier, Times fonts (Microsoft, 2008)
MS Courier fonts (Microsoft, 2008)
Droid fonts (Ascender Corporation, 2009)
Updated fonts for Romanian and Bulgarian (Microsoft, 2008)
Creates aliases for Chinese fonts using Source Han Sans fonts (Adobe, 2019)
Creates aliases for Japanese fonts using Source Han Sans fonts (Adobe, 2019)
Creates aliases for Japanese fonts using IPAMona fonts (Jun Kobayashi, 2008)
Creates aliases for Japanese Meiryo fonts using VLGothic fonts (Project Vine / Daisuke Suzuki, 2014)
Creates aliases for Korean fonts using Source Han Sans fonts (Adobe, 2019)
MS Georgia fonts (Microsoft, 2008)
MS Impact fonts (Microsoft, 2008)
IPAMona Japanese fonts (Jun Kobayashi, 2008)
Red Hat Liberation fonts (Mono, Sans, SansNarrow, Serif) (Red Hat, 2008)
MS Lucida Console font (Microsoft, 1998)
MS Meiryo font (Microsoft, 2009)
OpenSymbol fonts (replacement for Wingdings) (OpenOffice.org, 2017)
All MS PowerPoint Viewer fonts (various, )
Source Han Sans fonts (Adobe, 2021)
MS Tahoma font (not part of corefonts) (Microsoft, 1999)
Takao Japanese fonts (Jun Kobayashi, 2010)
MS Times fonts (Microsoft, 2008)
MS Trebuchet fonts (Microsoft, 2008)
 Ubuntu Font Family (Ubuntu, 2010)
Unifont alternative to Arial Unicode MS (Roman Czyborra / GNU, 2021)
MS Verdana fonts (Microsoft, 2008)
VLGothic Japanese fonts (Project Vine / Daisuke Suzuki, 2014)
MS Webdings fonts (Microsoft, 2008)
WenQuanYi CJK font (wenq.org, 2009)
WenQuanYi ZenHei font (wenq.org, 2009)
'''

fonts_dict = {}

for f, l in zip(list(sw_fonts.splitlines()),list(sw_fonts_desc.splitlines())):
    fonts_dict[f] = l

################################___Mime types___:

dir_mime_types = [
    'inode/directory',
    'inode/symlink',
]

exe_mime_types = [
    'application/x-ms-dos-executable',
    'application/x-ms-shortcut',
    'application/x-bat',
    'application/x-msi',
    'application/x-msdownload',
    'application/vnd.microsoft.portable-executable'
]

bin_mime_types = [
    'application/x-executable',
    'application/vnd.appimage'
]

script_mime_types = [
    'text/x-python',
    'text/x-python3',
    'application/x-shellscript',
]

app_mime_types = [
    'application/x-desktop',
]

swd_mime_types = [
    '.swd',
]

text_mime_types = [
    'text/plain',
    'text/x-python'
]

image_mime_types = [
    'image/svg+xml',
    'image/png',
    'image/jpeg',
    'image/bmp',
    'image/x-bmp',
    'image/x-MS-bmp',
    'image/gif',
    'image/x-icon',
    'image/x-ico',
    'image/x-win-bitmap',
    'image/vnd.microsoft.icon',
    'application/ico',
    'image/ico',
    'image/icon',
    'text/ico',
    'application/x-navi-animation',
    'image/x-portable-anymap',
    'image/x-portable-bitmap',
    'image/x-portable-graymap',
    'image/x-portable-pixmap',
    'image/tiff',
    'image/x-xpixmap',
    'image/x-xbitmap',
    'image/x-tga',
    'image/x-icns',
    'image/x-quicktime',
    'image/qtif',
    'image/webp',
]

video_mime_types = [
    'video/mp4',
    'video/vnd.radgamettools.bink',
    'video/x-matroska'
]

iso_mime_types = [
    'application/x-cd-image',
    'image/x-panasonic-rw',
    'application/x-raw-disk-image'
]

archive_mime_types = [
    'application/x-compressed-tar',
    'application/x-xz-compressed-tar',
    'application/x-zstd-compressed-tar',
    'application/zstd',
    'application/x-tar',
    'application/zip',
]

archive_formats = [
    'zip', 'gz', 'bz2', 'xz',
]

################################___Messages___:

class Msg:
    msg_dict = dict([
        ('good_day_is', _('A good day is like a good wine...')),
        ('yes', _('Yes')),
        ('no', _('No')),
        ('ok', _('Ok')),
        ('add', _('Add')),
        ('cancel', _('Cancel')),
        ('accept', _('Accept')),
        ('select', _('Select')),
        ('open', _('Open')),
        ('save', _('Save')),
        ('run', _('Run')),
        ('install', _('Install')),
        ('installed', _('Installed')),
        ('cs', _('Create shortcut')),
        ('cw', _('Change wine')),
        ('rename', _('Rename')),
        ('create', _('Create')),
        ('create_dir', _('Create new directory')),
        ('new_dir', _('New directory')),
        ('add_shortcut', _('Add shortcut to desktop')),
        ('original_name', _('[ Original name ] + ')),
        ('files', _("File's")),
        ('rename_dir', _('Rename directory')),
        ('rename_file', _('Rename file')),
        ('replace_file', _('Replace file')),
        ('copy_completed', _('Copying completed successfully')),
        ('move_completed', _('Move completed successfully')),
        ('trash_completed', _('Move to trash completed successfully')),
        ('delete_completed', _('Deletion completed successfully')),
        ('rename_completed', _('Rename completed successfully')),
        ('download_completed', _('Download completed successfully')),
        ('compression_completed', _('Compression completed successfully')),
        ('choose', _('Choose an action')),
        ('choose_app', _('Choose the application to transfer settings')),
        ('reset_settings', _('Do you really want to reset settings?')),
        ('clear_shader_cache', _('Do you really want to clear shader cache?')),
        ('remove_file', _('Do you really want to remove\n')),
        ('oops_path', _('Oops! Wrong path...')),
        ('replace_override', _('Another file with the same name already exists. Replacing will overwrite content')),
        ('no_dll', _('You have not selected any libraries to install')),
        ('exist_desktop', _('Path not exist, try to create new shortcut')),
        ('same_name', _('You already have an executable and a prefix with the same name. \
To create a shortcut for this executable, rename it or delete the existing shortcut and prefix')),
        ('termination', _('Termination of active processes...')),
        ('equal_paths', _("You can't copy a directory to itself")),
        ('not_exists', _('is not installed, download it now?')),
        ('is_not_installed', _('is not installed')),
        ('impossible_create', _('It is impossible to create a file in the current directory')),
        ('correct_path', _('Path does not exist!!! Please select correct path')),
        ('select_sw_path', _('Select the location of the StartWine directory')),
        ('change_directory', _('Select directory')),
        ('create_archive', _('Create a compressed archive')),
        ('compression', _('Compression...')),
        ('extraction', _('Extraction...')),
        ('new_archive', _('New archive')),
        ('launch_error', _('Launch error')),
        ('remove', _('Remove')),
        ('install_title', _('Install')),
        ('install_desc', _('Launchers and game stores')),
        ('device_name', _('Volume name')),
        ('device_id', _('Device ID')),
        ('device_uuid', _('Device UUID')),
        ('device_drive', _('Drive name')),
        ('device_size', _('Device size')),
        ('mount_options', _('Mount options')),
        ('app_conf_incorrect', _('Incorrect launch parameters')),
        ('app_conf_reset', _('Reset the application settings?')),
        ('lnk_error', _('The path to the executable file was not found, launch is impossible'))
    ])

    ################################___Tooltips___:

    tt_dict = dict([
        ('go_home', _('Go to the home directory')),
        ('back_up', _('Move up directory')),
        ('view_more', _('Current directory menu')),
        ('back_main', _('Back to sidebar main menu')),
        ('resize_window', _('Change menu size')),
        ('change_theme', _('Change color scheme')),
        ('resize_icons', _('Change icons size')),
        ('sidebar', _('Show or hide sidebar')),
        ('icon_position', _('Vertical or horizontal icons')),
        ('remove', _('Remove')),
        ('search', _('Show search entry')),
        ('path', _('Show path entry')),
        ('save', _('Save')),
        ('color', _('Choose color')),
        ('edit', _('Edit color value')),
        ('current', _('Current rgb value')),
        ('directory', _('Choose directory')),
        ('gmount', _('Show or hide volume list')),
        ('bookmarks', _('Show or hide bookmarks list')),
        ('apply', _('Apply')),
        ('registry', _('registry patch')),
        ('download_wine', _('Download wine')),
        ('install_launchers', _('Install launchers and game stores')),
        ('settings', _('Settings')),
        ('debug', _('Debug')),
        ('stop', _('Terminate all processes')),
        ('about', _('About')),
        ('choose_app', _('Choose the application to transfer settings')),
        ('web', _('Show web entry')),
        ('view_menu', _('Menu')),
    ])

################################___Progress_and_file_ops___:

progress_dict = dict([
    ('search', _('Search...')),
    ('app_loaded', _('Loaded successfully')),
    ('app_loading', _('The app is loading...')),
    ('squashfs', _('Squashfs...')),
    ('install_launchers', _('installation in progress please wait...'))
])

str_deletion = _('Deletion')
str_copying = _('Сopying')
str_removal = _('Removal')
str_copy = _('copy')

################################___Shaders___:

fragments_list = [s.value for s in list(sdr)]
fragments_labels = [
    _('blue plasma waves'),
    _('red plasma waves'),
    _('teal plasma waves'),
    _('mint plasma waves'),
    _('golden plasma waves'),
    _('purple plasma waves'),
    _('brown plasma waves'),
    _('gray plasma waves'),
    _('teal damask rose'),
    _('red damask rose'),
    _('blue damask rose'),
    _('purple damask rose'),
    _('golden damask rose'),
    _('mint damask rose'),
    _('brown damask rose'),
    _('gray damask rose'),
    _('macos monterey'),
    _('neon road'),
    _('alien planet'),
    _('wallpaper'),
    _('ice and fire'),
    _('voronoi gradient'),
    _('pixelated rgb'),
    _('ps3 home background'),
    _('infinite hexes background'),
    _('floating playstation shapes'),
    _('abstract movement background'),
    _('dark chocolate'),
    _('red waves'),
    _('vista-esque wallpaper thing'),
    _('misty grid'),
    _('factory windows'),
    _('star nest'),
    _('neon triangle'),
    _('firestorm'),
    _('underwater bubbles'),
    _('universe within'),
    _('parabolic waves'),
    _('fractal galaxy'),
    _('glowing stars'),
    _('colored bagel'),
    _('protonophore'),
    _('simplicity'),
    _('melting colors'),
    _('generators redux'),
    _('water turbulence'),
    _('perspex web lattice'),
    _('monochrome waves'),
    _('galaxies of the universe'),
    _('auroras'),
    _('super mario bros'),
    _('fractal flythrough'),
    _('blue circles'),
    _('smiley'),
    _('water high light'),
    _('triangle gradients'),
    _('shadow dance'),
    _('neon sunset'),
    _('synthwave sunset logo'),
    _('portal'),
    _('jellow lights'),
    _('evil membrane'),
    _('abstract pattern'),
    _('sun rays'),
    _('spiral riders'),
    _('inside the matrix'),
    _('plexus particles'),
    _('windows 95'),
]

################################___APPS_ID___:

url_app_id = 'https://api.steampowered.com/ISteamApps/GetAppList/v2/'

request_headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101 Safari/537.36",
    "Accept-Language": "fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Connection": "keep-alive",
    "Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
    }

remove_json_list = [
    'Pack', 'Soundtrack', 'soundtrack', 'Trailer', 'trailer', 'DLC', 'Upgrade',
    'upgrade', 'Activation', 'activation', 'Dedicated Server', 'Bonus',
    'Pre-order', 'SDK', 'Pre-Purchase', ' Season Pass', ' Bundle', ' BUNDLE',
    ' Skin ', '(Skin)', ' Skin)', ' Skin:', ' Skins', ' BONUS', ' Customization',
    ' Content', '- Key', 'Game Key', ' Toolkit', ' Tools', 'Character', ' OST',
    ' Art Book', ' Artbook', ' ArtBook', ' Wallpaper', ' pack', ' Set ', ' Set: ',
    ' Weapon Set', ' Costume Set', ' Costumes Set' ' Armor Set', ' Item Set',
    ' Outfit Set', 'Accessory Set', ' Production Set', ' Starter Set',
]

disk_parts = psutil.disk_partitions()
mount_dirs = list()

for x in disk_parts:
    mount_dirs += list(Path(x[1]).parts)

dir_docs_parts = list(Path(dir_docs).parts)
dir_desktop_parts = list(Path(dir_desktop).parts)
dir_pics_parts = list(Path(dir_pics).parts)
dir_videos_parts = list(Path(dir_videos).parts)
dir_music_parts = list(Path(dir_music).parts)
dir_downloads_parts = list(Path(dir_downloads).parts)
dir_public_parts = list(Path(dir_public).parts)
dir_templates_parts = list(Path(dir_templates).parts)

special_dirs = (
                dir_docs_parts
                + dir_desktop_parts
                + dir_pics_parts
                + dir_videos_parts
                + dir_music_parts
                + dir_downloads_parts
                + dir_public_parts
                + dir_templates_parts
)

exclude_dirs = [
                '/', 'MNT', 'GAMES', 'DATA', 'HOME', '_X64', 'ENGINE', 'PH', 'WORK',
                'BIN', 'RUNTIME', 'MEDIA', 'SOURCE', 'GAME_INFO', 'RUN',
                'STARTWINE', 'DRIVE_C', 'PROGRAM FILES', 'PROGRAM FILES (X86)'
                'PROGRAMDATA', 'APPDATA', 'USERS', 'LOCAL', 'BINARIES', 'PUBLIC',
                'STEAMUSER', 'ROAMING', 'PORTAL', 'WIN32', 'WIN64', 'PROGRAMS',
                'JAVA', 'SYSTEM', 'EN_US', 'CLIENT', 'PC', 'WIN64_SHIPPING_CLIENT',
                'WIN64_SHIPPING', 'RETAIL',
                user_name,
]

exclude_names = (
                mount_dirs
                + exclude_dirs
                + special_dirs
)

exclude_single_words = [
    ('_x32', ''),
    ('_x64', ''),
    ('_rwdi', ''),
    ('Definitive', ''),
    ('Deluxe', ''),
    ('Gold', ''),
    ('Platinum', ''),
    ('Premiun', ''),
    ('Complete', ''),
    ('Digital', ''),
    ('Enhanced', ''),
    ('Extended', ''),
    ('Limited', ''),
    ('Steam', ''),
    ('Legendary', ''),
    ('Anniversary', ''),
    ('HD', ''),
    ('Remastered', ''),
    ('Edition', ''),
    ('Launcher', ''),
    ('Linux', ''),
    ('&', 'and'),
    ('InsaneRamZes', ''),
]

exclude_double_words = [
    ('Definitive Edition', ''),
    ('Deluxe Edition', ''),
    ('Gold Edition', ''),
    ('Platinum Edition', ''),
    ('Premiun Edition', ''),
    ('Complete Edition', ''),
    ('Digital Edition', ''),
    ('Enhanced Edition', ''),
    ('Extended Edition', ''),
    ('Limited Edition', ''),
    ('Steam Edition', ''),
    ('Legendary Edition', ''),
    ('Ultimate Edition', ''),
    ('Special Edition', ''),
    ('Anniversary Edition', ''),
    ("Collector's Edition", ''),
    ("Gold Classic", ''),
    ('HD', ''),
    ('Remastered', ''),
    ('Anniversary', ''),
    ('Edition', ''),
    ('Launcher', ''),
    ('Config App', ''),
    ('Single Player', ''),
]

exclude_letters = [
    ('à', 'a'), ('á', 'a'), ('â', 'a'), ('ã', 'a'), ('ä', 'a'), ('å', 'a'),
    ('æ', 'ae'), ('ç', 'c'), ('è', 'e'), ('é', 'e'), ('ê', 'e'), ('ë', 'e'),
    ('ì', 'i'), ('í', 'i'), ('î', 'i'), ('ï', 'i'), ('ð', 'd'), ('ñ', 'n'),
    ('ò', 'o'), ('ó', 'o'), ('ô', 'o'), ('õ', 'o'), ('ö', 'o'), ('ø', 'o'),
    ('ù', 'u'), ('ú', 'u'), ('û', 'u'), ('ü', 'u'), ('ý', 'y'), ('ÿ', 'y'),
    ('ß', 'ss'), ('Æ', 'AE'), ('Å', 'A'), ('Á', 'A'), ('Ä', 'A'), ('À', 'A'),
    ('Â', 'A'), ('Ç', 'C'), ('É', 'E'), ('È', 'E'), ('Ë', 'E'), ('Ê', 'E'),
    ('Ì', 'I'), ('Í', 'I'), ('Î', 'I'), ('Ï', 'I'), ('Ð', 'D'), ('Ñ', 'N'),
    ('Ô', 'O'), ('Ó', 'O'), ('Ö', 'O'), ('Ø', 'O'), ('Ò', 'O'), ('Õ', 'O'),
    ('Ω', 'Omega'), ('Ü', 'U'), ('Ù', 'U'), ('Ú', 'U'), ('Û', 'U'), ('Ý', 'Y'),
    (' & ', ' and '),
]

latin_letters = [
    'à', 'á', 'â', 'ã', 'ä', 'å',
    'æ', 'ç', 'è', 'é', 'ê', 'ë',
    'ì', 'í', 'î', 'ï', 'ð', 'ñ',
    'ò', 'ó', 'ô', 'õ', 'ö', 'ø',
    'ù', 'ú', 'û', 'ü', 'ý', 'ÿ',
    'ß', 'Æ', 'Å', 'Á', 'Ä', 'À',
    'Â', 'Ç', 'É', 'È', 'Ë', 'Ê',
    'Ì', 'Í', 'Î', 'Ï', 'Ð', 'Ñ',
    'Ô', 'Ó', 'Ö', 'Ø', 'Ò', 'Õ',
    'Ω', 'Ü', 'Ù', 'Ú', 'Û', 'Ý',
]

roman_numbers = {
    'M': 1000, 'CM': 900, 'D': 500, 'CD': 400,
    'C': 100, 'XC': 90, 'L': 50, 'XL': 40,
    'X': 10, 'IX': 9, 'V': 5, 'IV': 4, 'I': 1
}

romans = {
    0: 'X', 9: 'IX', 8: 'VIII', 7: 'VII', 6: 'VI',
    5: 'V', 4: 'IV', 3: 'III', 2: 'II', 1:'I'
}

