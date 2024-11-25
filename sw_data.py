#!/usr/bin/env python3

from os import environ, getenv, walk
from sys import argv
from pathlib import Path
import shutil
import json
import gi
from gi.repository import GLib
import psutil
from psutil import Process
from sw_shaders import Shaders


class TermColors:
    """___terminal colors pallete___"""

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

################################___Empty lists and dicts___:

app_dict = dict()
app_conf_dict = dict()
app_id_dict = dict()
name_dict = dict()
sound_dict = dict()
env_dict = dict()
latest_wine_dict = dict()
winever_data = dict()
wine_download_dict = dict()
btn_il_list = list()
btn_iw_list = list()
btn_iw_rm_list = list()
wine_dir_list = list()
dropdown_download_wine_list = list()
row_entry_list = list()
switch_ls_list = list()
row_combo_list = list()
check_btn_mh_list = list()
btn_mh_color_list = list()
entry_mh_color_list = list()
btn_theme_color_list = list()
entry_theme_color_list = list()
check_btn_vk_list = list()
thread_result = list()
search_is_empty = list()
thumbnail_exe_dict = dict()
thumbnail_video_dict = dict()
thumbnail_image_dict = dict()
action_list = list()
timeout_list = list()
parent_path_list = list()
process_workers = list()

################################___Paths___:

sw_program_name = 'StartWine'
sw_link = Path(__file__).absolute().parent
sw_scripts = f"{sw_link}"
sw_crier_path = Path(f"{sw_scripts}/sw_crier.py")
sw_fsh = Path(f"{sw_scripts}/sw_function.sh")
sw_run = Path(f"{sw_scripts}/sw_run")
sw_start = Path(f"{sw_scripts}/sw_start")
sw_menu = Path(f"{sw_scripts}/sw_menu.py")
sw_runlib = Path(f"{sw_scripts}/sw_runlib")
sw_tray = Path(f"{sw_scripts}/sw_tray.py")
sw_cube = Path(f"{sw_scripts}/sw_cube.py")
sw_localedir = Path(f"{sw_scripts}/locale")
sw_version = Path(f'{sw_scripts}/version')

sw_path = Path(sw_scripts).parent.parent
sw_default_path = Path(f"{Path.home()}/.local/share/StartWine")
sw_data_dir = Path(f"{sw_path}/data")
sw_app_config = Path(f"{sw_data_dir}/app_config")
sw_app_patches = Path(f"{sw_data_dir}/app_patches")
sw_default_config = Path(f"{sw_app_config}/.default/default")
sw_img = Path(f"{sw_data_dir}/img")
sw_gui_icons = Path(f"{sw_data_dir}/img/gui_icons")
sw_symbolic_icons = Path(f"{sw_data_dir}/img/gui_icons/hicolor/symbolic/apps")
sw_icon_apps_symbolic = Path(f"/usr/share/icons/SWSuru++/apps/symbolic")
sw_icon_action_symbolic = Path(f"/usr/share/icons/SWSuru++/actions/symbolic")
sw_icon_apps_16 = Path(f"/usr/share/icons/SWSuru++/apps/16")
sw_icon_action_16 = Path(f"/usr/share/icons/SWSuru++/actions/16")
sw_app_icons = Path(f'{sw_img}/app_icons')
sw_app_vicons = Path(f'{sw_img}/app_icons/vertical')
sw_app_hicons = Path(f'{sw_img}/app_icons/horizontal')
sw_app_heroes_icons = Path(f'{sw_img}/app_icons/heroes')
sw_app_default_icons = Path(f'{sw_img}/app_icons/default')
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
sw_games = Path(f"{sw_path}/Games")
sw_shortcuts = Path(f"{sw_path}/Shortcuts")
sw_themes = Path(f"{sw_img}/sw_themes")
sw_css = Path(f"{sw_img}/sw_themes/css")
sw_local = Path(f"{Path.home()}/.local/share/applications")
sw_css_dark = Path(f'{sw_link.parent}/img/sw_themes/css/dark/gtk.css')
sw_css_light = Path(f'{sw_link.parent}/img/sw_themes/css/light/gtk.css')
sw_css_custom = Path(f'{sw_link.parent}/img/sw_themes/css/custom/gtk.css')
sw_fm_cache = Path(f'{Path.home()}/.cache/sw_fm')
sw_fm_cache_thumbnail = Path(f'{sw_fm_cache}/thumbnail')
sw_fm_cache_database = Path(f'{sw_fm_cache}/database')
sw_fm_cache_donloads = Path(f'{sw_fm_cache}/downloads')
sw_fm_cache_stats = Path(f'{sw_fm_cache}/stats')
sw_runtime = Path(f"{sw_path}/data/runtime/sw_runtime")
sys_sounds = Path(f'/usr/share/sounds/freedesktop/stereo')
sw_sounds = Path(f'{sw_themes}/sounds')
sw_startup_sounds = f'{sw_sounds}/startup'
sw_bookmarks = Path(f'{Path.home()}/.cache/sw_fm/bookmarks')
sw_playlist = Path(f'{Path.home()}/.cache/sw_fm/playlist')
sw_background = Path(f'{sw_themes}/background')
sw_mesa_shader_cache = Path(f'{sw_tmp}/mesa_shader_cache_sf')
sw_gl_shader_cache = Path(f'{sw_tmp}/gl_shader_cache')
sw_vulkan_shader_cache = Path(f'{sw_tmp}/vulkan_shader_cache')
sw_gst_home_cache = Path(f'{Path.home()}/.cache/gstreamer-1.0')

sw_winever_json = Path(f'{sw_scripts}/wine_version.json')
sw_appid_source = Path(f'{sw_scripts}/appid_source.json')
sw_appid_json = Path(f'{sw_scripts}/appid.json')
sw_menu_json = Path(f'{sw_scripts}/sw_menu.json')
sw_external_json = Path(f'{sw_fm_cache}/external_data.json')
sw_exe_data_json = Path(f'{sw_fm_cache}/exe_data.json')
sw_dxvk_vkd3d_json = Path(f'{sw_scripts}/dxvk_vkd3d_version.json')
sw_input_json = Path(f'{sw_scripts}/sw_input.json')
sw_icons = f'/usr/share/icons'

if not sw_shortcuts.exists():
    sw_shortcuts.mkdir(parents=True, exist_ok=True)

try:
    dir_home = GLib.get_home_dir()
except (Exception,):
    dir_home = f'{Path.home()}'
else:
    if dir_home is None:
        dir_home = f'{Path.home()}'

try:
    dir_docs = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOCUMENTS)
except (Exception,):
    dir_docs = f'{Path.home()}/Documents'
else:
    if dir_docs is None:
        dir_docs = f'{Path.home()}/Documents'

try:
    dir_desktop = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DESKTOP)
except (Exception,):
    dir_desktop = f'{Path.home()}/Desktop'
else:
    if dir_desktop is None:
        dir_desktop = f'{Path.home()}/Desktop'

try:
    dir_pics = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_PICTURES)
except (Exception,):
    dir_pics = f'{Path.home()}/Pictures'
else:
    if dir_pics is None:
        dir_pics = f'{Path.home()}/Pictures'

try:
    dir_videos = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_VIDEOS)
except (Exception,):
    dir_videos = f'{Path.home()}/Video'
else:
    if dir_videos is None:
        dir_videos = f'{Path.home()}/Video'

try:
    dir_music = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_MUSIC)
except (Exception,):
    dir_music = f'{Path.home()}/Music'
else:
    if dir_music is None:
        dir_music = f'{Path.home()}/Music'

try:
    dir_downloads = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOWNLOAD)
except (Exception,):
    dir_downloads = f'{Path.home()}/Downloads'
else:
    if dir_downloads is None:
        dir_downloads = f'{Path.home()}/Downloads'

try:
    dir_public = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_PUBLIC_SHARE)
except (Exception,):
    dir_public = f'{Path.home()}/Public'
else:
    if dir_public is None:
        dir_public = f'{Path.home()}/Public'

try:
    dir_templates = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_TEMPLATES)
except (Exception,):
    dir_templates = f'{Path.home()}/Templates'
else:
    if dir_templates is None:
        dir_templates = f'{Path.home()}/Templates'

try:
    xdg_config_home = GLib.get_user_config_dir()
except (Exception,):
    xdg_config_home = f'{Path.home()}/.config'
else:
    if xdg_config_home is None:
        xdg_config_home = f'{Path.home()}/.config'

try:
    user_name = GLib.get_user_name()
except (Exception,):
    user_name = getenv('USER')
else:
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
    "  <interface name='ru.launcher.StartWine'>"
    "    <method name='Message'>"
    "      <arg type='s' name='msg' direction='in'>"
    "      </arg>"
    "    </method>"
    "    <method name='Active'>"
    "      <arg type='s' name='question' direction='in'/>"
    "      <arg type='s' name='answer' direction='out'/>"
    "    </method>"
    "    <method name='Terminal'/>"
    "    <method name='Run'>"
    "      <arg type='s' name='run' direction='in'>"
    "      </arg>"
    "    </method>"
    "    <method name='Show'>"
    "      <arg type='s' name='show' direction='in'>"
    "      </arg>"
    "    </method>"
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
default_playlist = str(
    f'{sw_startup_sounds}/ps.mp3\n'
)

default_ini = {
    "view_mode": "grid",
    "view_widget": "files",
    "icon_size": 60,
    "shortcut_size": 120,
    "icon_position": "horizontal",
    "icon_color": "blue",
    "wc_style": "default",
    "wc_color_scheme": "dark",
    "terminal_handle_position": -1,
    "color_scheme": "dark",
    "control_panel": "show",
    "autostart": 0,
    "restore_menu": "on",
    "width": 1280,
    "height": 720,
    "hidden_files": "True",
    "sorting_files": "name",
    "sorting_reverse": "False",
    "renderer": "opengl",
    "opengl_bg": "True",
    "shader_src": 38,
    "on_tray": "True",
    "language": "ru_RU",
    "icons": "builtin",
    "sound": "on",
    "auto_stop": "on",
    "auto_hide_top_header": "off",
    "auto_hide_bottom_header": "off",
    "default_dir": f"{Path.home()}",
    "current_dir": f"{Path.home()}"
}

default_app_bind_profile = {
    'BTN_JOYSTICK': ['BTN_LEFT'],
    'BTN_TRIGGER': ['BTN_LEFT'],
    'BTN_THUMB': ['BTN_RIGHT'],
    'BTN_THUMB2': ['KEY_ENTER'],
    'BTN_TOP': ['KEY_SPACE'],
    'BTN_TOP2': ['KEY_PAGEUP'],
    'BTN_PINKIE': ['KEY_PAGEDOWN'],
    'BTN_BASE': ['KEY_LEFTCTRL'],
    'BTN_BASE2': ['KEY_LEFTSHIFT'],
    'BTN_BASE3': ['KEY_LEFTALT'],
    'BTN_BASE4': ['KEY_TAB'],
    'BTN_BASE5': ['KEY_ESC'],
    'BTN_BASE6': ['KEY_GRAVE'],
    'BTN_A': ['KEY_ENTER'],
    'BTN_GAMEPAD': ['KEY_ENTER'],
    'BTN_SOUTH': ['KEY_ENTER'],
    'BTN_B': ['KEY_SPACE'],
    'BTN_EAST': ['KEY_SPACE'],
    'BTN_C': [],
    'BTN_NORTH': ['KEY_PAGEUP'],
    'BTN_X': ['KEY_PAGEUP'],
    'BTN_WEST': ['KEY_PAGEDOWN'],
    'BTN_Y': ['KEY_PAGEDOWN'],
    'BTN_Z': [],
    'BTN_TL': ['KEY_LEFTCTRL'],
    'BTN_TR': ['KEY_LEFTALT'],
    'BTN_TL2': [],
    'BTN_TR2': [],
    'BTN_SELECT': ['KEY_TAB'],
    'BTN_START': ['KEY_ESC'],
    'BTN_MODE': ['KEY_GRAVE'],
    'BTN_THUMBL': ['BTN_MIDDLE'],
    'BTN_THUMBR': ['KEY_RIGHTSHIFT'],
    'BTN_TRIGGER_HAPPY5': [],
    'BTN_TRIGGER_HAPPY6': [],
    'BTN_TRIGGER_HAPPY7': [],
    'BTN_TRIGGER_HAPPY8': [],
    'ABS_X': ['KEY_RIGHT', 'KEY_LEFT'],
    'ABS_RX': ['REL_X'],
    'ABS_Y': ['KEY_DOWN', 'KEY_UP'],
    'ABS_RY': ['REL_Y'],
    'ABS_Z': ['BTN_RIGHT'],
    'ABS_RZ': ['BTN_LEFT'],
    'ABS_THROTTLE': [],
    'ABS_RUDDER': [],
    'ABS_WHEEL': [],
    'ABS_GAS': [],
    'ABS_BRAKE': [],
    'ABS_HAT0X': ['KEY_RIGHT', 'KEY_LEFT'],
    'ABS_HAT0Y': ['KEY_DOWN', 'KEY_UP'],
    'ABS_HAT1X': ['KEY_RIGHT', 'KEY_LEFT'],
    'ABS_HAT1Y': ['KEY_DOWN', 'KEY_UP'],
    'ABS_HAT2X': ['KEY_RIGHT', 'KEY_LEFT'],
    'ABS_HAT2Y': ['KEY_DOWN', 'KEY_UP'],
    'ABS_HAT3X': ['KEY_RIGHT', 'KEY_LEFT'],
    'ABS_HAT3Y': ['KEY_DOWN', 'KEY_UP'],
    'ABS_PRESSURE': [],
    'ABS_DISTANCE': [],
    'ABS_TILT_X': [],
    'ABS_TILT_Y': [],
    'ABS_TOOL_WIDTH': [],
}

default_gui_bind_profile = {
    'BTN_JOYSTICK': ['BTN_LEFT'],
    'BTN_TRIGGER': ['BTN_LEFT'],
    'BTN_THUMB': ['BTN_RIGHT'],
    'BTN_THUMB2': ['KEY_ENTER'],
    'BTN_TOP': ['KEY_SPACE'],
    'BTN_TOP2': ['KEY_PAGEUP'],
    'BTN_PINKIE': ['KEY_PAGEDOWN'],
    'BTN_BASE': ['KEY_LEFTCTRL'],
    'BTN_BASE2': ['KEY_LEFTSHIFT'],
    'BTN_BASE3': ['KEY_LEFTALT'],
    'BTN_BASE4': ['KEY_TAB'],
    'BTN_BASE5': ['KEY_ESC'],
    'BTN_BASE6': ['KEY_GRAVE'],
    'BTN_A': ['KEY_ENTER'],
    'BTN_GAMEPAD': ['KEY_ENTER'],
    'BTN_SOUTH': ['KEY_ENTER'],
    'BTN_B': ['KEY_ESC'],
    'BTN_EAST': ['KEY_ESC'],
    'BTN_C': [],
    'BTN_NORTH': ['KEY_BACKSPACE'],
    'BTN_X': ['KEY_BACKSPACE'],
    'BTN_WEST': ['KEY_SPACE'],
    'BTN_Y': ['KEY_SPACE'],
    'BTN_Z': [],
    'BTN_TL': ['KEY_LEFTCTRL'],
    'BTN_TR': ['KEY_RIGHTALT'],
    'BTN_TL2': [],
    'BTN_TR2': [],
    'BTN_SELECT': ['KEY_TAB'],
    'BTN_START': ['KEY_COMPOSE'],
    'BTN_MODE': ['KEY_GRAVE'],
    'BTN_THUMBL': ['BTN_MIDDLE'],
    'BTN_THUMBR': ['KEY_RIGHTSHIFT'],
    'BTN_TRIGGER_HAPPY5': [],
    'BTN_TRIGGER_HAPPY6': [],
    'BTN_TRIGGER_HAPPY7': [],
    'BTN_TRIGGER_HAPPY8': [],
    'ABS_X': ['REL_WHEEL'],
    'ABS_Y': ['REL_WHEEL'],
    'ABS_RX': ['REL_X'],
    'ABS_RY': ['REL_Y'],
    'ABS_Z': ['BTN_RIGHT'],
    'ABS_RZ': ['BTN_LEFT'],
    'ABS_THROTTLE': [],
    'ABS_RUDDER': [],
    'ABS_WHEEL': [],
    'ABS_GAS': [],
    'ABS_BRAKE': [],
    'ABS_HAT0X': ['KEY_RIGHT', 'KEY_LEFT'],
    'ABS_HAT0Y': ['KEY_DOWN', 'KEY_UP'],
    'ABS_HAT1X': ['KEY_RIGHT', 'KEY_LEFT'],
    'ABS_HAT1Y': ['KEY_DOWN', 'KEY_UP'],
    'ABS_HAT2X': ['KEY_RIGHT', 'KEY_LEFT'],
    'ABS_HAT2Y': ['KEY_DOWN', 'KEY_UP'],
    'ABS_HAT3X': ['KEY_RIGHT', 'KEY_LEFT'],
    'ABS_HAT3Y': ['KEY_DOWN', 'KEY_UP'],
    'ABS_PRESSURE': [],
    'ABS_DISTANCE': [],
    'ABS_TILT_X': [],
    'ABS_TILT_Y': [],
    'ABS_TOOL_WIDTH': [],
}

sw_logo_dark = 'sw_large_dark.svg'
sw_logo_light = 'sw_large_light.svg'
sw_logo_custom = 'sw_large_custom.svg'
default_dark_logo = (0,160,255)
default_light_logo = (246,111,37)
default_custom_logo = (80,177,252)

default_dark_css = '''
/* Global color definitions */
@define-color sw_bg_color rgba(30,30,36,0.85);
@define-color sw_accent_fg_color rgba(80,176,251,0.85);
@define-color sw_accent_bg_color rgba(40,40,46,0.85);
@define-color sw_header_bg_color rgba(15,15,17,0.99);
@define-color sw_pop_bg_color rgba(40,40,46,0.99);
@define-color sw_invert_bg_color rgba(160,160,160, 1.0);
@define-color sw_invert_accent_fg_color rgba(41,41,41, 1.0);
@define-color sw_invert_accent_bg_color rgba(176,176,176, 1.0);
@define-color sw_invert_header_bg_color rgba(128,128,128, 1.0);
@define-color sw_invert_pop_bg_color rgba(176,176,176, 1.0);
@define-color sw_invert_progress_color rgba(175,79,4,1.0);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color rgba(0,0,0,0.5);
@import url("../default.css");
'''
default_light_css = '''
/* GLOBAL COLOR DEFINITIONS */
@define-color sw_bg_color rgba(210,210,220,0.99);
@define-color sw_accent_fg_color rgba(0,160,255,0.85);
@define-color sw_accent_bg_color rgba(220,220,230,0.99);
@define-color sw_header_bg_color rgba(240,240,250,0.99);
@define-color sw_pop_bg_color rgba(220,220,230,0.99);
@define-color sw_invert_bg_color rgba(60,60,60,1.0);
@define-color sw_invert_accent_fg_color rgba(60,60,60,1.0);
@define-color sw_invert_accent_bg_color rgba(60,60,60,1.0);
@define-color sw_invert_header_bg_color rgba(60,60,60,1.0);
@define-color sw_invert_pop_bg_color rgba(60,60,60,1.0);
@define-color sw_invert_progress_color rgba(255,95,0,1.0);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color rgba(0,0,0,0.5);
@import url("../default.css");
'''
default_custom_css_brown = '''
/* Global color definitions */
@define-color sw_bg_color rgba(35,31,32,0.85);
@define-color sw_accent_fg_color rgba(246,111,37,0.85);
@define-color sw_accent_bg_color rgba(43,39,40,0.85);
@define-color sw_header_bg_color rgba(0,0,0,1.0);
@define-color sw_pop_bg_color rgba(0,0,0,1.0);
@define-color sw_invert_bg_color rgba(160, 160, 160, 1.0);
@define-color sw_invert_accent_fg_color rgba(35, 35, 35, 1.0);
@define-color sw_invert_accent_bg_color rgba(168, 168, 168, 1.0);
@define-color sw_invert_header_bg_color rgba(128, 128, 128, 1.0);
@define-color sw_invert_pop_bg_color rgba(128, 128, 128, 1.0);
@define-color sw_invert_progress_color rgba(9, 144, 218, 1.0);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color rgba(0,0,0,0.5);
@import url("../default.css");
'''
default_custom_css_red = '''
/* Global color definitions */
@define-color sw_bg_color rgba(36,28,32,0.85);
@define-color sw_accent_fg_color rgba(247,50,100,0.85);
@define-color sw_accent_bg_color rgba(46,36,40,0.85);
@define-color sw_header_bg_color rgba(0,0,0,0.99);
@define-color sw_pop_bg_color rgba(46,36,40,0.99);
@define-color sw_invert_bg_color rgba(224,224,224, 1.0);
@define-color sw_invert_accent_fg_color rgba(36,36,36, 1.0);
@define-color sw_invert_accent_bg_color rgba(240,240,240, 1.0);
@define-color sw_invert_header_bg_color rgba(192,192,192, 1.0);
@define-color sw_invert_pop_bg_color rgba(240,240,240, 1.0);
@define-color sw_invert_progress_color rgba(8,205,155,1.0);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color rgba(0,0,0,0.5);
@import url("../default.css");
'''
default_custom_css_teal = '''
/* Global color definitions */
@define-color sw_bg_color rgba(28,36,36,0.85);
@define-color sw_accent_fg_color rgba(100,198,198,0.85);
@define-color sw_accent_bg_color rgba(40,46,46,0.85);
@define-color sw_header_bg_color rgba(0,0,0,0.99);
@define-color sw_pop_bg_color rgba(40,46,46,0.99);
@define-color sw_invert_bg_color rgba(225,225,225, 1.0);
@define-color sw_invert_accent_fg_color rgba(37,37,37, 1.0);
@define-color sw_invert_accent_bg_color rgba(245,245,245, 1.0);
@define-color sw_invert_header_bg_color rgba(192,192,192, 1.0);
@define-color sw_invert_pop_bg_color rgba(245,245,245, 1.0);
@define-color sw_invert_progress_color rgba(155,57,57,1.0);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color rgba(0,0,0,0.5);
@import url("../default.css");
'''
default_custom_css_mint = '''
/* Global color definitions */
@define-color sw_bg_color rgba(32,36,32,0.85);
@define-color sw_accent_fg_color rgba(158,198,100,0.85);
@define-color sw_accent_bg_color rgba(40,46,36,0.85);
@define-color sw_header_bg_color rgba(0,0,0,0.99);
@define-color sw_pop_bg_color rgba(40,46,36,0.99);
@define-color sw_invert_bg_color rgba(225,225,225, 1.0);
@define-color sw_invert_accent_fg_color rgba(56,56,56, 1.0);
@define-color sw_invert_accent_bg_color rgba(240,240,240, 1.0);
@define-color sw_invert_header_bg_color rgba(192,192,192, 1.0);
@define-color sw_invert_pop_bg_color rgba(240,240,240, 1.0);
@define-color sw_invert_progress_color rgba(97,57,155,1.0);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color rgba(0,0,0,0.5);
@import url("../default.css");
'''
default_custom_css_blue = '''
/* Global color definitions */
@define-color sw_bg_color rgba(28,32,36,0.85);
@define-color sw_accent_fg_color rgba(80,177,252,0.85);
@define-color sw_accent_bg_color rgba(40,40,46,0.85);
@define-color sw_header_bg_color rgba(0,0,0,0.99);
@define-color sw_pop_bg_color rgba(40,40,46,0.99);
@define-color sw_invert_bg_color rgba(224,224,224, 1.0);
@define-color sw_invert_accent_fg_color rgba(41,41,41, 1.0);
@define-color sw_invert_accent_bg_color rgba(240,240,240, 1.0);
@define-color sw_invert_header_bg_color rgba(192,192,192, 1.0);
@define-color sw_invert_pop_bg_color rgba(240,240,240, 1.0);
@define-color sw_invert_progress_color rgba(175,78,3,1.0);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color rgba(0,0,0,0.5);
@import url("../default.css");
'''
default_custom_css_yellow = '''
/* Global color definitions */
@define-color sw_bg_color rgba(36,36,32,0.85);
@define-color sw_accent_fg_color rgba(198,198,100,0.85);
@define-color sw_accent_bg_color rgba(46,46,40,0.85);
@define-color sw_header_bg_color rgba(0,0,0,0.99);
@define-color sw_pop_bg_color rgba(46,46,40,0.99);
@define-color sw_invert_bg_color rgba(226,226,226, 1.0);
@define-color sw_invert_accent_fg_color rgba(37,37,37, 1.0);
@define-color sw_invert_accent_bg_color rgba(242,242,242, 1.0);
@define-color sw_invert_header_bg_color rgba(192,192,192, 1.0);
@define-color sw_invert_pop_bg_color rgba(237,237,237, 1.0);
@define-color sw_invert_progress_color rgba(57,57,155,1.0);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color rgba(0,0,0,0.5);
@import url("../default.css");
'''
default_custom_css_grey = '''
/* Global color definitions */
@define-color sw_bg_color rgba(32,34,36,0.85);
@define-color sw_accent_fg_color rgba(157,157,167,0.85);
@define-color sw_accent_bg_color rgba(38,40,46,0.85);
@define-color sw_header_bg_color rgba(0,0,0,0.99);
@define-color sw_pop_bg_color rgba(38,40,46,0.99);
@define-color sw_invert_bg_color rgba(226,226,226, 1.0);
@define-color sw_invert_accent_fg_color rgba(32,32,32, 1.0);
@define-color sw_invert_accent_bg_color rgba(241,241,241, 1.0);
@define-color sw_invert_header_bg_color rgba(192,192,192, 1.0);
@define-color sw_invert_pop_bg_color rgba(241,241,241, 1.0);
@define-color sw_invert_progress_color rgba(98,98,88,1.0);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color rgba(0,0,0,0.5);
@import url("../default.css");
'''
default_custom_css_purple = '''
/* Global color definitions */
@define-color sw_bg_color rgba(32,28,36,0.85);
@define-color sw_accent_fg_color rgba(128,100,223,0.85);
@define-color sw_accent_bg_color rgba(40,36,46,0.85);
@define-color sw_header_bg_color rgba(0,0,0,0.99);
@define-color sw_pop_bg_color rgba(40,36,46,0.99);
@define-color sw_invert_bg_color rgba(224,224,224, 1.0);
@define-color sw_invert_accent_fg_color rgba(54,54,54, 1.0);
@define-color sw_invert_accent_bg_color rgba(240,240,240, 1.0);
@define-color sw_invert_header_bg_color rgba(192,192,192, 1.0);
@define-color sw_invert_pop_bg_color rgba(240,240,240, 1.0);
@define-color sw_invert_progress_color rgba(127,155,32,1.0);
@define-color sw_view_bg_color rgba(0,0,0,0.5);
@define-color sw_flow_bg_color rgba(0,0,0,0.5);
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

builtin_icon_colors = [
    "90ssummer", "aubergine", "aurora", "berriez", "black", "blue", "bluegrey",
    "bordeaux", "brown", "canonical", "cyan", "cyberneon", "discodingo", "indigo",
    "fitdance", "green", "grey", "magenta", "manjaro", "mint", "orange",
    "pink", "red", "teal", "vermillion", "violet", "white", "yellow"
]

default_mangohud = (
    'fps_color_change,round_corners=12,cpu_load_change,gpu_load_change,core_load_change'
    + ',background_alpha=0.2,font_size=20,background_color=020202,position=top-right'
    + ',toggle_hud_position='
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
    '': '',
    'blue': default_custom_css_blue,
    'brown': default_custom_css_brown,
    'grey': default_custom_css_grey,
    'mint': default_custom_css_mint,
    'purple': default_custom_css_purple,
    'red': default_custom_css_red,
    'teal': default_custom_css_teal,
    'yellow': default_custom_css_yellow,
}

folder_colors = {}
default_icon_themes = {}
for color in builtin_icon_colors:
    default_icon_themes[color] = f'{sw_icons}/SWSuru++{color}'
    folder_colors[color] = f'{sw_icons}/SWSuru++-{color}/places/scalable/folder-{color}.svg'


def create_svg_logo(rgb, colorscheme, svg_file):
    """___create an svg logo with a given color style___"""

    r0 = int(rgb[0] * 1.33) if int(rgb[0] * 1.33) <= 255 else 255
    g0 = int(rgb[1] * 1.33) if int(rgb[1] * 1.33) <= 255 else 255
    b0 = int(rgb[2] * 1.33) if int(rgb[2] * 1.33) <= 255 else 255
    r1 = int(rgb[0] * 0.66)
    g1 = int(rgb[1] * 0.66)
    b1 = int(rgb[2] * 0.66)
    svg_color = f'rgb({r0}, {g0}, {b0})'
    svg_stop_color = f'rgb({r1}, {g1}, {b1})'
    svg_text_color = 'white'
    if colorscheme == 'light':
        svg_text_color = '#292929'

    sample = '''<svg width="443" height="82" viewBox="0 0 443 82" fill="none" xmlns="http://www.w3.org/2000/svg">
<path d="M15.5358 43.6791C15.5358 50.1664 18.1129 56.3879 22.7 60.975C27.2872 65.5622 33.5087 68.1392 39.9959 68.1392C46.4832 68.1392 52.7047 65.5622 57.2919 60.975C61.879 56.3879 64.4561 50.1664 64.4561 43.6791C64.4561 43.6791 61.275 47.1757 56.2744 47.7275C46.2731 48.831 34.5285 40.1466 24.5272 41.2501C19.5265 41.8019 15.5358 43.6791 15.5358 43.6791Z" fill='''f'"{svg_color}"''''/>
<path d="M64.4559 43.6791C64.4559 50.1663 61.8788 56.3878 57.2917 60.975C52.7045 65.5621 46.483 68.1392 39.9958 68.1392C33.5085 68.1392 27.287 65.5621 22.6998 60.975C18.1127 56.3878 15.5356 50.1663 15.5356 43.6791C15.5356 43.6791 18.7167 47.1757 23.7173 47.7274C33.7186 48.831 42.1638 38.0112 52.2258 38.0114C63.0024 38.0115 64.4559 43.6791 64.4559 43.6791Z" fill="url(#paint0_linear_11_56)"/>
<path d="M24.0182 11.5583C23.2143 9.98041 21.2749 9.34178 19.7696 10.2745C13.3889 14.2281 8.28519 19.9803 5.12302 26.8395C1.51191 34.6726 0.643142 43.4934 2.6567 51.8805C4.67027 60.2676 9.44889 67.7325 16.2226 73.0725C22.9962 78.4124 31.3705 81.3163 39.9959 81.3163C48.6213 81.3163 56.9955 78.4124 63.7692 73.0725C70.5429 67.7325 75.3215 60.2676 77.3351 51.8805C79.3486 43.4934 78.4799 34.6726 74.8688 26.8395C71.7066 19.9802 66.6028 14.2281 60.2222 10.2745C58.7169 9.34178 56.7775 9.9804 55.9735 11.5582V11.5582C55.1696 13.1361 55.8078 15.0537 57.2972 16.0115C62.401 19.2935 66.4861 23.9737 69.045 29.5243C72.053 36.0493 72.7767 43.397 71.0994 50.3834C69.4221 57.3699 65.4415 63.5882 59.7991 68.0364C54.1566 72.4845 47.1809 74.9035 39.9959 74.9035C32.8109 74.9035 25.8352 72.4845 20.1927 68.0364C14.5502 63.5882 10.5696 57.3699 8.89235 50.3834C7.21505 43.397 7.93873 36.0493 10.9468 29.5243C13.5056 23.9738 17.5907 19.2935 22.6945 16.0115C24.184 15.0537 24.8222 13.1361 24.0182 11.5583V11.5583Z" fill="url(#paint1_linear_11_56)"/>
<rect x="35.8462" y="0.923218" width="8.2992" height="24.8976" rx="4.1496" fill='''f'"{svg_color}"''''/>
<path d="M133.48 24.3L129.28 28.38C128.4 27.18 127.22 26.22 125.74 25.5C124.3 24.78 122.72 24.42 121 24.42C118.84 24.42 116.92 25.02 115.24 26.22C113.56 27.38 112.72 29.08 112.72 31.32C112.72 32.44 112.92 33.4 113.32 34.2C113.72 34.96 114.4 35.64 115.36 36.24C116.32 36.8 117.18 37.24 117.94 37.56C118.7 37.84 119.86 38.24 121.42 38.76C122.98 39.24 124.16 39.64 124.96 39.96C125.8 40.24 126.88 40.74 128.2 41.46C129.52 42.18 130.52 42.94 131.2 43.74C131.92 44.5 132.54 45.52 133.06 46.8C133.62 48.08 133.9 49.54 133.9 51.18C133.9 55.34 132.46 58.54 129.58 60.78C126.74 62.98 123.28 64.08 119.2 64.08C116.44 64.08 113.8 63.56 111.28 62.52C108.8 61.44 106.78 59.9 105.22 57.9L109.84 54C110.84 55.48 112.18 56.68 113.86 57.6C115.58 58.52 117.4 58.98 119.32 58.98C121.56 58.98 123.54 58.36 125.26 57.12C126.98 55.84 127.84 54.04 127.84 51.72C127.84 50.72 127.64 49.82 127.24 49.02C126.84 48.22 126.4 47.58 125.92 47.1C125.44 46.62 124.66 46.14 123.58 45.66C122.5 45.14 121.62 44.76 120.94 44.52C120.3 44.28 119.24 43.94 117.76 43.5C116.16 42.98 114.8 42.48 113.68 42C112.6 41.48 111.46 40.78 110.26 39.9C109.1 38.98 108.22 37.82 107.62 36.42C107.02 35.02 106.72 33.4 106.72 31.56C106.72 28.88 107.46 26.6 108.94 24.72C110.42 22.8 112.22 21.44 114.34 20.64C116.5 19.84 118.82 19.44 121.3 19.44C123.74 19.44 126.04 19.88 128.2 20.76C130.4 21.64 132.16 22.82 133.48 24.3Z" fill='''f'"{svg_text_color}"''''/>
<path d="M156.863 25.74V63H150.923V25.74H137.303V20.52H170.483V25.74H156.863Z" fill='''f'"{svg_text_color}"''''/>
<path d="M179.169 52.56L174.909 63H168.309L186.729 20.52H192.129L210.369 63H203.649L199.329 52.56H179.169ZM189.249 27.42L181.269 47.34H197.169L189.249 27.42Z" fill='''f'"{svg_text_color}"''''/>
<path d="M222.365 44.1V63H216.425V20.52H230.045C234.525 20.52 238.165 21.46 240.965 23.34C243.765 25.22 245.165 28.2 245.165 32.28C245.165 35.32 244.225 37.82 242.345 39.78C240.465 41.74 237.965 42.98 234.845 43.5L246.725 63H239.525L228.725 44.1H222.365ZM222.365 25.56V39.12H229.205C235.845 39.12 239.165 36.84 239.165 32.28C239.165 27.8 235.985 25.56 229.625 25.56H222.365Z" fill='''f'"{svg_text_color}"''''/>
<path d="M268.057 25.74V63H262.117V25.74H248.497V20.52H281.677V25.74H268.057Z" fill='''f'"{svg_text_color}"''''/>
<path d="M289.797 20.52L299.157 54.36H299.277L309.237 20.52H315.777L325.677 54.36H325.797L335.157 20.52H341.457L328.977 63H322.797L312.477 28.86H312.357L302.037 63H295.857L283.377 20.52H289.797Z" fill='''f'"{svg_text_color}"''''/>
<path d="M353.774 20.52V63H347.834V20.52H353.774Z" fill='''f'"{svg_text_color}"''''/>
<path d="M372.463 20.52L394.663 54.48H394.783V20.52H400.723V63H393.223L370.783 28.32H370.663V63H364.723V20.52H372.463Z" fill='''f'"{svg_text_color}"''''/>
<path d="M417.611 43.56V57.72H439.811V63H411.671V20.52H438.911V25.74H417.611V38.46H437.651V43.56H417.611Z" fill='''f'"{svg_text_color}"''''/>
<defs>
<linearGradient id="paint0_linear_11_56" x1="46.9091" y1="68.1393" x2="42.5253" y2="36.4737" gradientUnits="userSpaceOnUse">
<stop stop-color='''f'"{svg_color}"''''/>
<stop offset="1" stop-color='''f'"{svg_stop_color}"''''/>
</linearGradient>
<linearGradient id="paint1_linear_11_56" x1="50.8492" y1="4.51557" x2="33.2455" y2="82.826" gradientUnits="userSpaceOnUse">
<stop stop-color='''f'"{svg_color}"''''/>
<stop offset="1" stop-color='''f'"{svg_stop_color}"''''/>
</linearGradient>
</defs>
</svg>'''

    try:
        with open(f'{svg_file}', 'w') as f:
            f.write(sample)
    except (IOError, OSError) as e:
        print(e)


def check_sw_version():
    """___reading StartWine version from version file___"""

    if sw_version.exists():
        version = sw_version.read_text().splitlines()[0]
        str_sw_version = '.'.join([e for e in version])
    else:
        str_sw_version = ''

    return str_sw_version


def read_wine_ver_data():
    """___reading Wine version from JSON file___"""

    if sw_winever_json.exists():
        with open(sw_winever_json, 'r', encoding='utf-8') as f:
            winever_data = json.load(f)
            f.close()
        return winever_data
    else:
        return None


def check_cache_dir():
    """___create file manager cache directory___"""

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

    if not sw_fm_cache_stats.exists():
        try:
            sw_fm_cache_stats.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(TermColors.RED, e, TermColors.END)


def clear_cache_dir():
    """___clear file manager cache directory___"""

    for f in sw_fm_cache.iterdir():
        if (str(f) != f'{sw_fm_cache}/stats' and str(f) != str(sw_exe_data_json)
                and str(f) != str(sw_external_json)):
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
            pass
    else:
        print(f'{TermColors.VIOLET2}SW_FM_CACHE: {TermColors.GREEN}clear_cache_directory: done{TermColors.END}')


def check_css_dark():
    """___create css colorscheme samples___"""

    try:
        sw_css_dark.parent.mkdir(parents=True, exist_ok=True)
    except IOError as e:
        print(f'{TermColors.VIOLET2} SW_CSS_DARK:  {TermColors.RED}{e}')
    else:
        try:
            sw_css_dark.write_text(default_dark_css)
        except IOError as e:
            print(f'{TermColors.VIOLET2} SW_CSS_DARK:  {TermColors.RED}{e}')
        else:
            print(f'{TermColors.VIOLET2} SW_CSS_DARK:  {TermColors.GREEN}create sw_css_dark: done')


def diff_css(current, default, css_name):
    """___check differences in CSS files___"""

    cur_css_lines = [x.split(' ')[1] for x in current.read_text().splitlines() if '@' in x]
    def_css_lines = [x for x in default.splitlines() if '@' in x]
    diff_list = []
    for line in def_css_lines:
        if not line.split(' ')[1] in cur_css_lines:
            diff_list.append(line)
    else:
        if len(diff_list) > 0:
            current.write_text(default)
            print(
                f'{TermColors.VIOLET2} {css_name}: {TermColors.GREEN}mismatches '
                + f'found, {current} overwritten by default{TermColors.END}'
            )
        else:
            print(
                f'{TermColors.VIOLET2} {css_name}: {TermColors.GREEN}Files have no '
                + f'differences{TermColors.END}'
            )


def check_css_light():
    """___create css colorscheme samples___"""

    try:
        sw_css_light.parent.mkdir(parents=True, exist_ok=True)
    except IOError as e:
        print(f'{TermColors.VIOLET2} SW_CSS:  {TermColors.RED}{e}')
    else:
        try:
            sw_css_light.write_text(default_light_css)
        except IOError as e:
            print(f'{TermColors.VIOLET2} SW_CSS:  {TermColors.RED}{e}')
        else:
            print(f'{TermColors.VIOLET2} SW_CSS:  {TermColors.GREEN}create sw_css_light: done')


def check_css_custom():
    """___create css colorscheme samples___"""

    try:
        sw_css_custom.parent.mkdir(parents=True, exist_ok=True)
    except IOError as e:
        print(f'{TermColors.VIOLET2} SW_CSS:  {TermColors.RED}{e}')
    else:
        try:
            sw_css_custom.write_text(default_custom_css_blue)
        except IOError as e:
            print(f'{TermColors.VIOLET2} SW_CSS:  {TermColors.RED}{e}')
        else:
            print(f'{TermColors.VIOLET2} SW_CSS:  {TermColors.GREEN}create sw_css_custom: done')


def check_bookmarks():
    """___create default bookmarks list___"""

    try:
        with open(sw_bookmarks, 'w', encoding='utf-8') as f:
            f.write(default_bookmarks)
            f.close()
    except IOError as e:
        print(f'{TermColors.VIOLET2}SW_BOOKMARKS: {TermColors.RED}{e}' + TermColors.END)
    else:
        print(f'{TermColors.VIOLET2}SW_BOOKMARKS: {TermColors.GREEN}create bookmarks: done' + TermColors.END)


def check_playlist():
    """___create default playlist___"""

    try:
        with open(sw_playlist, 'w', encoding='utf-8') as f:
            f.write(default_playlist)
            f.close()
    except IOError as e:
        print(f'{TermColors.VIOLET2}SW_PLAYLIST: {TermColors.RED}{e}' + TermColors.END)
    else:
        print(f'{TermColors.VIOLET2}SW_PLAYLIST: {TermColors.GREEN}create playlist: done' + TermColors.END)


def create_app_icons():
    """___create application icons directory___"""

    try:
        sw_app_hicons.mkdir(parents=True, exist_ok=True)
    except IOError as e:
        print(f'{TermColors.RED}{e}{TermColors.END}')
    try:
        sw_app_vicons.mkdir(parents=True, exist_ok=True)
    except IOError as e:
        print(f'{TermColors.RED}{e}{TermColors.END}')
    try:
        sw_app_heroes_icons.mkdir(parents=True, exist_ok=True)
    except IOError as e:
        print(f'{TermColors.RED}{e}{TermColors.END}')
    try:
        Path(f'{sw_app_icons}/default').mkdir(parents=True, exist_ok=True)
    except IOError as e:
        print(f'{TermColors.RED}{e}{TermColors.END}')


def clear_app_icons():
    """___clear application icons directory___"""

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


def create_json_data(data, dump):
    """___create new json file with data___"""

    with open(data, 'w', encoding='utf-8') as f:
        json.dump(dump, f)
    print(
        f'{TermColors.VIOLET2}SW_JSON_DATA: '
        + f'{TermColors.GREEN}create json data: done' + TermColors.END
    )


def read_json_data(data):
    """___return dictionary from json file___"""

    with open(data, mode='r', encoding='utf-8') as f:
        json_data = json.load(f)
        r_data = json_data
        f.close()

    return r_data


def write_json_data(data, dump):
    """___write new json file___"""

    with open(data, 'w') as f:
        f.write(json.dumps(dump))
        f.close()


def create_menu_json():
    """___create menu configuration file___"""

    with open(sw_menu_json, 'w', encoding='utf-8') as f:
        json.dump(default_ini, f)
        print(
            f'{TermColors.VIOLET2}SW_MENU_JSON: '
            + f'{TermColors.GREEN}create sw_menu.json: done' + TermColors.END
        )


def set_menu_json_default():
    """___reset menu configuration file to default___"""

    try:
        Path(sw_menu_json).unlink()
    except IOError as e:
        print(
            f'{TermColors.VIOLET2}SW_MENU_JSON: '
            + f'{TermColors.RED}{e}' + TermColors.END
        )
    else:
        with open(sw_menu_json, 'w', encoding='utf-8') as f:
            json.dump(default_ini, f)
            print(
                f'{TermColors.VIOLET2}SW_MENU_JSON: '
                + f'{TermColors.GREEN}create sw_menu.json: done' + TermColors.END
            )


def read_menu_conf():
    """___return dict from menu configuration file___"""

    with open(sw_menu_json, 'r', encoding='utf-8') as f:
        json_data = json.load(f)
        data_dict = json_data
        f.close()

    return data_dict


def write_menu_conf(data_dict):
    """___write menu configuration file___"""

    with open(sw_menu_json, 'w') as f:
        f.write(json.dumps(data_dict))
        f.close()


def diff_menu_conf():
    """___checking differences between current and default menu config___"""

    data_dict = read_menu_conf()

    for k, v in default_ini.items():
        if k not in data_dict.keys():
            data_dict[k] = default_ini[k]
    else:
        write_menu_conf(data_dict)


def get_roman(number):
    """___get roman number from arabic___"""

    roman = ''
    number = int(number)
    for letter, value in roman_numbers.items():
        while number >= value:
            roman += letter
            number -= value

    return roman


def str_to_roman(string):
    """___string arabic numbers to roman numbers___"""

    for e in string:
        if e.isdigit():
            try:
                arabic = int(e)
            except (Exception,):
                pass
            else:
                roman = romans[int(e)]
                string = string.replace(str(arabic), str(roman))

    return string


def get_print_mem_info(mapped):
    """___print used memory info___"""

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
            except (Exception,):
                pass


def get_wine_dicts():
    """___get Wine dictionary from JSON file and function list___"""

    winever_data = read_wine_ver_data()
    for wine, func in zip(wine_list, wine_func_list):
        if winever_data is not None:
            latest_wine_dict[wine] = Path(Path(winever_data[wine].split(' ')[0]).stem).stem

            for x in winever_data[wine].split(' '):
                x = Path(Path(x).stem).stem
                wine_download_dict[x] = func
        else:
            latest_wine_dict[wine] = None

    return winever_data, latest_wine_dict, wine_download_dict


def set_locale(sw_lang):
    """___set changed locale___"""

    _ = None
    for lang, label in zip(lang_list, lang_labels):
        if label == sw_lang:
            try:
                locale.setlocale(locale.LC_MESSAGES, (sw_lang, 'UTF-8'))
            except (Exception,) as e:
                print(e)
                try:
                    locale.setlocale(locale.LC_MESSAGES, ('en_US', 'UTF-8'))
                except (Exception,) as e:
                    print(e)
                else:
                    lang_en.install()
                    _ = lang_en.gettext
            else:
                lang.install()
                _ = lang.gettext
    return _


def check_exe_data(json_path, shortcut_dir, icon_dir):
    """___create json file data with executable items___"""

    exe_dict = {}
    if Path(json_path).exists():
        exe_dict = read_json_data(json_path)

    if shortcut_dir and Path(shortcut_dir).exists():
        for swd in Path(shortcut_dir).iterdir():
            if swd.is_file():
                text = swd.read_text().splitlines()
                if text:
                    path = None
                    for line in text:
                        if 'Exec=' in line:
                            path = line.split('=')[-1].strip('"')
                            break
                    if path:
                        exe = ''.join([e for e in Path(path).stem if e.isalnum()])
                        exe_dict[exe] = {
                            'name': None, 'id': None, 'default': None, 'vertical': None,
                            'horizontal': None, 'heroes': None, 'path': str(path)
                        }

    for r, d, f in walk(icon_dir):
        for icon in f:
            exe = str(icon).split('_')[0]
            id_ = str(Path(icon).stem).split('_')[-1]
            name = str(icon).split('_')[-2]
            if exe_dict.get(exe):
                exe_dict[exe]['name'] = str(name)
                exe_dict[exe]['id'] = str(id_)
                if '_vertical_' in str(icon):
                    exe_dict[exe]['vertical'] = str(icon)
                elif '_horizontal_' in str(icon):
                    exe_dict[exe]['horizontal'] = str(icon)
                elif '_heroes_' in str(icon):
                    exe_dict[exe]['heroes'] = str(icon)
                else:
                    exe_dict[exe]['default'] = str(icon)
            else:
                exe_dict[exe] = {
                    'name': None, 'id': None, 'default': None, 'vertical': None,
                    'horizontal': None, 'heroes': None, 'path': None
                }
                exe_dict[exe]['name'] = str(name)
                exe_dict[exe]['id'] = str(id_)
                if '_vertical_' in str(icon):
                    exe_dict[exe]['vertical'] = str(icon)
                elif '_horizontal_' in str(icon):
                    exe_dict[exe]['horizontal'] = str(icon)
                elif '_heroes_' in str(icon):
                    exe_dict[exe]['heroes'] = str(icon)
                else:
                    exe_dict[exe]['default'] = str(icon)

    if Path(json_path).exists():
        write_json_data(json_path, exe_dict)
    else:
        with open(f'{json_path}', 'w', encoding='utf-8') as f:
            json.dump(exe_dict, f)


class ExeData(dict):
    """___Data of executable items___"""

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)
        self.default_value = {
            'name': None, 'id': None, 'default': None, 'vertical': None,
            'horizontal': None, 'heroes': None, 'path': None
        }

    def __setitem__(self, key, value):

        key = ''.join(e for e in key if e.isalnum())
        if isinstance(value, dict):
            super().__setitem__(key, value)
        else:
            try:
                raise ValueError(f'Value must be a {dict}, not {type(value)}')
            except ValueError as e:
                print(e)

    def __getitem__(self, key):

        key = ''.join(e for e in key if e.isalnum())
        return self.get(key)

    def get_(self, item):
        """___get item key and value___"""

        item = ''.join(e for e in item if e.isalnum())
        return self.get(item)

    def set_(self, item, key, value):
        """___set item key and value___"""

        item = ''.join(e for e in item if e.isalnum())
        if value:
            value = value.strip('"')

        if self.get(item):
            self[item][key] = f'{value}'
        else:
            self.default_value[key] = str(value)
            self[item] = self.default_value

        print('update item value:', value)

    def del_(self, item):
        """___remove item from data___"""

        item = ''.join(e for e in item if e.isalnum())
        if self.get(item):
            print('remove item:', item)
            del self[item]


################################___Checking_config_files___:

check_cache_dir()

if not sw_css_dark.exists():
    check_css_dark()
else:
    if getenv('SW_DIFF_CSS_DARK') == '1':
        environ['SW_DIFF_CSS_DARK'] = '0'
        diff_css(sw_css_dark, default_dark_css, 'SW_CSS_DARK')

if not sw_css_light.exists():
    check_css_light()
else:
    if getenv('SW_DIFF_CSS_LIGHT') == '1':
        environ['SW_DIFF_CSS_LIGHT'] = '0'
        diff_css(sw_css_light, default_light_css, 'SW_CSS_LIGHT')

if not sw_css_custom.exists():
    check_css_custom()
else:
    if getenv('SW_DIFF_CSS_CUSTOM') == '1':
        environ['SW_DIFF_CSS_CUSTOM'] = '0'
        diff_css(sw_css_custom, default_custom_css_brown, 'SW_CSS_CUSTOM')

if not Path(f'{sw_gui_icons}/{sw_logo_dark}').exists():
    create_svg_logo(default_dark_logo, 'light', f'{sw_gui_icons}/{sw_logo_dark}')

if not Path(f'{sw_gui_icons}/{sw_logo_light}').exists():
    create_svg_logo(default_light_logo, 'dark', f'{sw_gui_icons}/{sw_logo_light}')

if not Path(f'{sw_gui_icons}/{sw_logo_custom}').exists():
    create_svg_logo(default_custom_logo, 'dark', f'{sw_gui_icons}/{sw_logo_custom}')

if not sw_bookmarks.exists():
    check_bookmarks()

if not sw_playlist.exists():
    check_playlist()

if (not sw_app_vicons.exists() or not sw_app_hicons.exists()
        or not sw_app_heroes_icons.exists() or not sw_app_default_icons.exists()):
    create_app_icons()

if not sw_menu_json.exists():
    create_menu_json()
else:
    diff_menu_conf()

if not sw_external_json.exists():
    create_json_data(sw_external_json, dict())

if not sw_exe_data_json.exists():
    check_exe_data(sw_exe_data_json, sw_shortcuts, sw_app_icons)

if not sw_dxvk_vkd3d_json.exists():
    create_json_data(sw_dxvk_vkd3d_json, dict())

if not sw_input_json.exists():
    create_json_data(sw_input_json, default_app_bind_profile)

################################___Menu_settings___:

sw_cfg = read_menu_conf()
sw_lang = sw_cfg.get('language') if sw_cfg.get('language') else 'en_US'
sw_renderer = sw_cfg.get('renderer') if sw_cfg.get('renderer') else 'opengl'

dxvk_vkd3d_data = read_json_data(sw_dxvk_vkd3d_json)
_exe_data = read_json_data(sw_exe_data_json)
app_bind_profile = read_json_data(sw_input_json)
exe_data = ExeData(_exe_data)
#ext_data_dict = read_json_data(sw_external_json)

if sw_cfg.get('opengl_bg') == 'True':
    environ['SW_OPENGL'] = '1'
else:
    environ['SW_OPENGL'] = '0'

environ['FRAGMENT_NUM'] = str(sw_cfg.get('shader_src'))
environ['FRAGMENT_INDEX'] = str(sw_cfg.get('shader_src'))
environ['SW_LOCALE'] = str(sw_cfg.get('language'))
environ['SW_SCRIPTS_PATH'] = f'{sw_scripts}'
environ['GTK_THEME'] = "Adwaita-dark"

################################____Locale___:

import locale
import gettext

gtxt = gettext.gettext
domain = 'StartWine'
locale.textdomain(domain)
locale.bindtextdomain(domain, sw_localedir)

lang_en = gettext.translation(domain, localedir=sw_localedir, languages=['en:en'])
lang_ru = gettext.translation(domain, localedir=sw_localedir, languages=['ru:en'])
lang_zh = gettext.translation(domain, localedir=sw_localedir, languages=['zh:en'])
lang_list = [lang_ru, lang_en, lang_zh]
lang_labels = ['ru_RU', 'en_US', 'zh_CN']
_ = set_locale(sw_lang)

################################___Icon data___:


class IconPath:
    """___symbolic icon path data___"""

    icon_app = f'{sw_gui_icons}/sw_icon.png'
    icon_sw_svg = f'{sw_gui_icons}/sw.svg'
    icon_start = f'{sw_symbolic_icons}/media-playback-start.svg'                #actions/16
    icon_up = f'{sw_symbolic_icons}/go-up.svg'                                  #actions/16
    icon_clear = f'{sw_symbolic_icons}/edit-clear-list.svg'                     #actions/16
    icon_stop = f'{sw_symbolic_icons}/media-playback-stop.svg'                  #actions/16
    icon_terminal = f'{sw_symbolic_icons}/cm_runterm.svg'                       #actions/16
    icon_rotate = f'{sw_symbolic_icons}/transform-rotate.svg'                   #actions/16
    icon_bookmarks = f'{sw_symbolic_icons}/bookmarks.svg'                       #actions/16
    icon_rm_bookmark = f'{sw_symbolic_icons}/bookmark-remove.svg'               #actions/16
    icon_taxes = f'{sw_symbolic_icons}/taxes-finances.svg'                      #actions/16
    icon_window_next = f'{sw_symbolic_icons}/window-next.svg'                   #actions/16
    icon_window_prev = f'{sw_symbolic_icons}/window-previous.svg'               #actions/16
    icon_start_sym = f'{sw_symbolic_icons}/media-playback-start-symbolic.svg'   #actions/symbolic
    icon_next = f'{sw_symbolic_icons}/go-next-symbolic.svg'                     #actions/symbolic
    icon_prev = f'{sw_symbolic_icons}/go-previous-symbolic.svg'                 #actions/symbolic
    icon_up_sym = f'{sw_symbolic_icons}/go-up-symbolic.svg'                     #actions/symbolic
    icon_search = f'{sw_symbolic_icons}/edit-find-symbolic.svg'                 #actions/symbolic
    icon_back = f'{sw_symbolic_icons}/go-previous-symbolic.svg'                 #actions/symbolic
    icon_create = f'{sw_symbolic_icons}/document-new-symbolic.svg'              #actions/symbolic
    icon_remove = f'{sw_symbolic_icons}/edit-delete-symbolic.svg'               #actions/symbolic
    icon_clear_sym = f'{sw_symbolic_icons}/edit-clear-all-symbolic.svg'         #actions/symbolic
    icon_stop_sym = f'{sw_symbolic_icons}/media-playback-stop-symbolic.svg'     #actions/symbolic
    icon_scale = f'{sw_symbolic_icons}/view-fullscreen-symbolic.svg'            #actions/symbolic
    icon_view_more = f'{sw_symbolic_icons}/view-more-symbolic.svg'              #actions/symbolic
    icon_add = f'{sw_symbolic_icons}/appointment-new-symbolic.svg'              #actions/symbolic
    icon_hide = f'{sw_symbolic_icons}/application-exit-symbolic.svg'            #actions/symbolic
    icon_grid_view = f'{sw_symbolic_icons}/view-grid-symbolic.svg'              #actions/symbolic
    icon_eject = f'{sw_symbolic_icons}/media-eject-symbolic.svg'                #actions/symbolic
    icon_new_bookmark = f'{sw_symbolic_icons}/bookmark-new-symbolic.svg'        #actions/symbolic
    icon_download = f'{sw_symbolic_icons}/document-save-symbolic.svg'           #actions/symbolic
    icon_close = f'{sw_css}/assets/window-close.svg'
    icon_min = f'{sw_css}/assets/window-minimize.svg'
    icon_max = f'{sw_css}/assets/window-maximize.svg'
    icon_close_light = f'{sw_css}/assets/window-close-light.svg'
    icon_min_light = f'{sw_css}/assets/window-minimize-light.svg'
    icon_max_light = f'{sw_css}/assets/window-maximize-light.svg'
    icon_br_close = f'{sw_css}/assets/breeze-window-close.svg'
    icon_br_min = f'{sw_css}/assets/breeze-minimize.svg'
    icon_br_max = f'{sw_css}/assets/breeze-maximize.svg'
    icon_br_close_light = f'{sw_css}/assets/breeze-window-close.svg'
    icon_br_min_light = f'{sw_css}/assets/breeze-minimize-light.svg'
    icon_br_max_light = f'{sw_css}/assets/breeze-maximize-light.svg'
    icon_settings = f'{sw_symbolic_icons}/gear.svg'                             #apps/16
    icon_wine = f'{sw_symbolic_icons}/windows.svg'                              #apps/16
    icon_toolbox = f'{sw_symbolic_icons}/jetbrains-toolbox.svg'                 #apps/16
    icon_backup = f'{sw_symbolic_icons}/backup.svg'                             #apps/16
    icon_update = f'{sw_symbolic_icons}/update.svg'                             #apps/16
    icon_shortcuts = f'{sw_symbolic_icons}/applications-games.svg'              #apps/16
    icon_global = f'{sw_symbolic_icons}/browser.svg'                            #apps/16
    icon_github = f'{sw_symbolic_icons}/github.svg'                             #apps/16
    icon_discord = f'{sw_symbolic_icons}/discord.svg'                           #apps/16
    icon_telegram = f'{sw_symbolic_icons}/telegram.svg'                         #apps/16
    icon_file_manager = f'{sw_symbolic_icons}/file-manager.svg'                 #apps/16
    icon_regedit = f'{sw_symbolic_icons}/regedit.svg'                           #apps/16
    icon_harddisk = f'{sw_symbolic_icons}/harddisk.svg'                         #apps/16
    icon_menu = f'{sw_symbolic_icons}/menu.svg'                                 #apps/16
    icon_shutdown = f'{sw_symbolic_icons}/gshutdown.svg'                        #apps/16
    icon_shop = f'{sw_symbolic_icons}/shop.svg'                                 #apps/16
    icon_partition = f'{sw_symbolic_icons}/partitions.svg'                      #apps/16
    icon_monitor = f'{sw_symbolic_icons}/monitor.svg'                           #apps/16
    icon_settings_sym = f'{sw_symbolic_icons}/gear-symbolic.svg'                #apps/symbolic
    icon_wine_sym = f'{sw_symbolic_icons}/windows-symbolic.svg'                 #apps/symbolic
    icon_protondb = f'{sw_symbolic_icons}/steam-symbolic.svg'                   #apps/symbolic
    icon_toolbox_sym = f'{sw_symbolic_icons}/jetbrains-toolbox-symbolic.svg'    #apps/symbolic
    icon_backup_restore = f'{sw_symbolic_icons}/mintbackup-symbolic.svg'        #apps/symbolic
    icon_tool = f'{sw_symbolic_icons}/tool-symbolic.svg'                        #apps/symbolic
    icon_shortcuts_sym = f'{sw_symbolic_icons}/applications-games-symbolic.svg' #apps/symbolic
    icon_debug = f'{sw_symbolic_icons}/hammer-symbolic.svg'                     #apps/symbolic
    icon_resize = f'{sw_symbolic_icons}/resizer-symbolic.svg'                    #apps/symbolic
    icon_home = f'{sw_symbolic_icons}/homerun-symbolic.svg'                     #apps/symbolic
    icon_desktop = f'{sw_symbolic_icons}/desktop-symbolic.svg'                  #apps/symbolic
    icon_pictures = f'{sw_symbolic_icons}/image-symbolic.svg'                   #apps/symbolic
    icon_video = f'{sw_symbolic_icons}/mimetype-video.svg'                      #mimetypes/16
    icon_docs = f'{sw_symbolic_icons}/document-symbolic.svg'                    #apps/symbolic
    icon_audio = f'{sw_symbolic_icons}/mimetype-audio.svg'                      #mimetypes/16
    icon_playlist = f'{sw_symbolic_icons}/media-playlist-play.svg'
    icon_mediaplay = f'{sw_symbolic_icons}/video.svg'                           #apps/scalable
    icon_clock = f'{sw_symbolic_icons}/clock-symbolic.svg'                      #apps/symbolic
    icon_speed = f'{sw_symbolic_icons}/kronometer-symbolic.svg'                 #apps/symbolic
    icon_partition_sym = f'{sw_symbolic_icons}/partitions-symbolic.svg'         #apps/symbolic
    icon_monitor_sym = f'{sw_symbolic_icons}/monitor-symbolic.svg'              #apps/symbolic
    icon_colors = f'{sw_symbolic_icons}/mimetype-theme.svg'                     #mimetypes/16
    icon_save = f'{sw_symbolic_icons}/media-floppy-symbolic.svg'                #devices/symbolic
    icon_drive = f'{sw_symbolic_icons}/drive-harddisk.svg'                      #devices/scalable
    icon_ssd = f'{sw_symbolic_icons}/drive-harddisk-solidstate.svg'             #devices/scalable
    icon_usb = f'{sw_symbolic_icons}/drive-harddisk-usb.svg'                    #devices/scalable
    icon_info = f'{sw_symbolic_icons}/dialog-information-symbolic.svg'          #status/symbolic
    icon_symlink = f'{sw_symbolic_icons}/emblem-symbolic-link.svg'              #emblems/16
    icon_folder = f'{sw_symbolic_icons}/folder.svg'                             #places/16
    icon_folder_sym = f'{sw_symbolic_icons}/folder-symbolic.svg'                #places/symbolic
    icon_games_sym = f'{sw_symbolic_icons}/folder-games-symbolic.svg'           #places/symbolic
    icon_games = f'{sw_symbolic_icons}/folder-games.svg'
    icon_cdrom = f'{sw_symbolic_icons}/cdrom.svg'                               #apps/scalable
    icon_unchecked = f'{sw_css}/assets/radio-unchecked-symbolic.svg'
    icon_checked = f'{sw_css}/assets/check-menuitem@2.png'
    icon_wine_staging = f'{sw_gui_icons}/wine_staging.jpg'
    icon_wine_steam_proton = f'{sw_gui_icons}/wine_steam_proton.jpg'
    icon_wine_proton_ge = f'{sw_gui_icons}/wine_proton_ge.jpg'

    icon_dpad_lt = f'{sw_gui_icons}/controller/generic_dpad_left.50dpi.png'
    icon_dpad_rt = f'{sw_gui_icons}/controller/generic_dpad_right.50dpi.png'
    icon_dpad_up = f'{sw_gui_icons}/controller/generic_dpad_up.50dpi.png'
    icon_dpad_dn = f'{sw_gui_icons}/controller/generic_dpad_down.50dpi.png'
    icon_RS = f'{sw_gui_icons}/controller/generic_right_stick.50dpi.png'
    icon_RS_lt = f'{sw_gui_icons}/controller/generic_right_stick_left.50dpi.png'
    icon_RS_rt = f'{sw_gui_icons}/controller/generic_right_stick_right.50dpi.png'
    icon_RS_up = f'{sw_gui_icons}/controller/generic_right_stick_up.50dpi.png'
    icon_RS_dn = f'{sw_gui_icons}/controller/generic_right_stick_down.50dpi.png'
    icon_LS = f'{sw_gui_icons}/controller/generic_left_stick.50dpi.png'
    icon_LS_lt = f'{sw_gui_icons}/controller/generic_left_stick_left.50dpi.png'
    icon_LS_rt = f'{sw_gui_icons}/controller/generic_left_stick_right.50dpi.png'
    icon_LS_up = f'{sw_gui_icons}/controller/generic_left_stick_up.50dpi.png'
    icon_LS_dn = f'{sw_gui_icons}/controller/generic_left_stick_down.50dpi.png'

    icon_xb_A = f'{sw_gui_icons}/controller/xb_a.50dpi.png'
    icon_xb_B = f'{sw_gui_icons}/controller/xb_b.50dpi.png'
    icon_xb_X = f'{sw_gui_icons}/controller/xb_x.50dpi.png'
    icon_xb_Y = f'{sw_gui_icons}/controller/xb_y.50dpi.png'
    icon_xb_LB = f'{sw_gui_icons}/controller/xb_lb.50dpi.png'
    icon_xb_LT = f'{sw_gui_icons}/controller/xb_lt.50dpi.png'
    icon_xb_start = f'{sw_gui_icons}/controller/xb_start.50dpi.png'
    icon_xb_RB = f'{sw_gui_icons}/controller/xb_rb.50dpi.png'
    icon_xb_RT = f'{sw_gui_icons}/controller/xb_rt.50dpi.png'
    icon_xb_select = f'{sw_gui_icons}/controller/xb_select.50dpi.png'
    icon_xb_super = f'{sw_gui_icons}/controller/xb_super.50dpi.png'
    icon_unknown_button = f'{sw_gui_icons}/controller/button.50dpi.png'

################################___Themes___:

wc_style_dict = dict(
    [
        ('default', []),
        ('macos', []),
        ('adwaita', [IconPath.icon_close, IconPath.icon_max,IconPath.icon_min]),
        ('breeze', [IconPath.icon_br_close, IconPath.icon_br_max,IconPath.icon_br_min])
    ]
)

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
str_tray_stop = _('Stop Wine processes')
str_tray_shutdown = _('Shutdown')

################################___View_widgets___:

next_vw = [
    'global_settings',
    'install_wine',
    'install_launchers',
    'shortcuts',
]
prev_vw = [
    'install_launchers',
    'shortcuts',
    'global_settings',
    'install_wine',
]
view_widgets = [
    'shortcuts',
    'global_settings',
    'install_wine',
    'install_launchers',
    'startapp_page',
    'launch_settings',
    'mangohud_settings',
    'vkbasalt_settings',
    'winetricks',
    'files',
    'web_view',
    'gc_settings',
]
view_labels = [
    _('Games and apps'),
    _('Interface settings'),
    _('Wine builds'),
    _('Apps and stores'),
    _('Application start page'),
    _('Launch settings'),
    _('MangoHud settings'),
    _('vkBasalt settings'),
    _('Winetricks'),
    _('Files'),
    _('Web browser'),
    _('Controller settings'),
]

next_vw_dict = dict(zip(view_widgets, next_vw))
prev_vw_dict = dict(zip(view_widgets, prev_vw))

vw_dict = dict()
for w in view_widgets:
    vw_dict[w] = w

vl_dict = dict()
for n, w in zip(view_labels, view_widgets):
    vl_dict[w] = n

################################_Start_mode___:

str_prefix = _('Prefix: ')
str_current_prefix = _('Current prefix:\n')
str_current_wine = _('Current Wine:\n')
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

about_dict = dict()
for n, w in zip(about_labels, about_widgets):
    about_dict[w] = n

str_about = _(
    'Is a Windows application launcher '
    + 'for GNU/Linux operating systems. '
    + 'Includes many features, extensions, and fixes '
    + 'to improve performance, visuals, and usability.'
)
str_news = (
_('''The full list of changes and fixes for the current release is available at the link below.''')
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
    _('Card'): 'https://yoomoney.ru/to/4100118571137050',
    'BTC': 'bc1q3h8lfs3l3r8jmt8ev0pwl9nueqttlep6ktvd02',
}

news_source = 'https://github.com/RusNor/StartWine-Launcher/releases'
website_source = 'https://startwine-launcher.ru'
github_source = 'https://github.com/RusNor'
telegram_source = 'https://t.me/StartWine'
discord_source = 'https://discord.com/invite/37FrGUpDEj'
license_source = 'https://www.gnu.org/licenses/gpl-3.0.html'

str_btc = 'BTC: bc1q3h8lfs3l3r8jmt8ev0pwl9nueqttlep6ktvd02'
winehq_source = 'https://www.winehq.org/search?q='
protondb_source = 'https://www.protondb.com/search?q='
griddb_source = 'https://www.steamgriddb.com/search/'
griddb = 'https://www.steamgriddb.com'
home_page = github_source

url_source = {
   # 'google': ['https://google.com', f'{sw_symbolic_icons}/google.png'],
   # 'yandex': ['https://ya.ru', f'{sw_symbolic_icons}/yandex.png'],
   # 'duckduckgo': ['https://duckduckgo.com', f'{sw_symbolic_icons}/duckduckgo.png'],
   # 'startwine': ['https://startwine-project.ru', f'{sw_gui_icons}/sw_icon.png'],
   # 'github': ['https://github.com/RusNor', f'{sw_symbolic_icons}/github.png'],
   # 'vkontakte': [' https://vk.com/club213719866', f'{sw_symbolic_icons}/vk.png'],
   # 'telegram': ['https://t.me/StartWine', f'{sw_symbolic_icons}/telegram.png'],
   # 'discord': ['https://discord.com/invite/37FrGUpDEj', f'{sw_symbolic_icons}/discord.png'],
   # 'license': ['https://www.gnu.org/licenses/gpl-3.0.html', f'{sw_symbolic_icons}/gnu.png'],
   # 'donation': ['https://my.qiwi.com/form/Nykyta-MhrLvGVgb3', f'{sw_symbolic_icons}/qiwi.png'],
   # 'winehq': ['https://www.winehq.org', f'{sw_symbolic_icons}/winehq.png'],
   # 'protondb': ['https://www.protondb.com', f'{sw_symbolic_icons}/protondb.png'],
   # 'griddb': ['https://www.steamgriddb.com', f'{sw_symbolic_icons}/griddb.png'],
}

about_menu_dict = {
    'about_authors': str_authors,
    'about_details': str_about,
    'about_code': str_developers,
    'about_members': ', '.join(str_members.splitlines()),
    'about_projects': ', '.join(str_projects.splitlines()),
    'about_design': str_design,
    'about_license': str_license,
    'about_donation': str_donation,
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
    IconPath.icon_settings,
    IconPath.icon_terminal,
    IconPath.icon_regedit,
    IconPath.icon_folder,
    IconPath.icon_remove,
    IconPath.icon_start,
    IconPath.icon_update,
]

sidebar_widgets = [
    'shortcuts',
    'files',
    'install_launchers',
    'install_wine',
    'global_settings',
    'shutdown',
]

sidebar_icons = [
    IconPath.icon_shortcuts,
    IconPath.icon_folder,
    IconPath.icon_shop,
    IconPath.icon_wine,
    IconPath.icon_settings,
    IconPath.icon_shutdown,
]

btn_widgets = [
    'start',
    'shortcuts',
    'files',
    'create_shortcut',
    'prefix_tools',
    'wine_tools',
    'install_wine',
    'install_launchers',
    'settings',
    'global_settings',
    'debug',
    'stop',
    'about',
    'files_info',
    'bookmarks',
    'shutdown',
    'playlist'
]

btn_labels = [
    _('Start'),
    _('Games and apps'),
    _('Files'),
    _('Create shortcut'),
    _('Prefix tools'),
    _('Wine tools'),
    _('Wine builds'),
    _('Apps and stores'),
    _('Settings'),
    _('Interface settings'),
    _('Debug'),
    _('Terminate all processes'),
    _('About'),
    _('Properties'),
    _('Bookmarks'),
    _('Shutdown'),
    _('Playlist'),
]

btn_widget_dict = dict()
for w in btn_widgets:
    btn_widget_dict[w] = w

btn_dict = dict()
for n, w in zip(btn_labels, btn_widgets):
    btn_dict[w] = n

prefix_labels = [
    _('Default prefix'),
    _('Application prefix'),
]
prefix_list = [
    'pfx_default',
    'pfx_app_name'
]

prefix_dict = dict()
for p, l in zip(prefix_list, prefix_labels):
    prefix_dict[p] = l

str_sw_use_pfx = 'SW_USE_PFX'

prefix_tools_labels = [
    _('Remove current prefix'),
    _('Clear current prefix'),
    _('Reinstall current prefix'),
    _('Prefix backup'),
    _('Prefix recovery'),
    _('Backup of saves'),
    _('Restoring saves')
]
prefix_tools_widgets = [
    'pfx_remove',
    'pfx_clear',
    'pfx_reinstall',
    'pfx_backup',
    'pfx_restore',
    'saves_backup',
    'saves_restore'
]

prefix_tools_dict = dict()
for w, l in zip(prefix_tools_widgets, prefix_tools_labels):
    prefix_tools_dict[w] = l

wine_tools_labels = [
    _('Wine settings'),
    _('Wine console'),
    _('Regedit'),
    _('File explorer'),
    _('Uninstaller'),
    _('Winetricks'),
    _('Clear shader cache'),
]
wine_tools_widgets = [
    'wine_settings',
    'wine_console',
    'regedit',
    'file_explorer',
    'uninstaller',
    'winetricks',
    'clear_shader_cache',
]

wine_tools_dict = dict()
for n, w in zip(wine_tools_labels, wine_tools_widgets):
    wine_tools_dict[w] = n

################################___Files_info___:

access_dict = {
    7: 'rwx', 6: 'rw-', 5: 'r-x', 4: 'r--', 3: '-wx', 2: '-w-', 1:'--x', 0:'---'
}

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

bookmarks_list = []
str_create_new_bookmark = _('Adding a new bookmark completed successfully')
str_remove_bookmark = _('Remove bookmark completed successfully')
str_bookmark_exists = _('Bookmark is already exists!')

bookmarks_dict = {
    dir_home: [IconPath.icon_home, None],
    dir_desktop: [IconPath.icon_desktop, None],
    dir_videos: [IconPath.icon_video, None],
    dir_docs: [IconPath.icon_docs, None],
    dir_downloads: [IconPath.icon_download, None],
    dir_pics: [IconPath.icon_pictures, None],
    dir_music: [IconPath.icon_audio, None],
    str(sw_wine): [IconPath.icon_wine, None],
    str(sw_games): [IconPath.icon_games, _('Games')],
    str(sw_shortcuts): [IconPath.icon_shortcuts, _('Shortcuts')],
    str(sw_pfx): [IconPath.icon_toolbox, _('Prefixes')],
    str(sw_pfx_backup): [IconPath.icon_backup_restore, _('Backups')],
    str(sw_app_config): [IconPath.icon_settings, _('Prefix configurations')],
    str(sw_logs): [IconPath.icon_regedit, _('Logs')],
}

################################___Playlist___:

playlist = []
str_create_new_media = _('Adding a new media file to playlist completed successfully')
str_remove_media = _('Remove media file from playlist completed successfully')
str_media_exists = _('Media file is already added to playlist!')

################################___Install_wine___:

str_iw_title_desc = _('Wine (originally an acronym for "Wine Is Not an Emulator") \
is a compatibility layer capable of running Windows applications on several \
POSIX-compliant operating systems, such as Linux, macOS, & BSD. Instead of \
simulating internal Windows logic like a virtual machine or emulator, Wine \
translates Windows API calls into POSIX calls on-the-fly, eliminating the \
performance and memory penalties of other methods and allowing you to cleanly \
integrate Windows applications into your desktop.')

str_iw_subtitle = _('List of Wines to download and install')
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
Experimental Wine. Things it contains that Valve's Proton does not: Additional \
media foundation patches for better video playback support, AMD FSR patches, \
Nvidia CUDA support for PhysX and NVAPI, raw input mouse support and various \
wine-staging patches applied as they become needed."),
}

wine_list = [
    'wine_staging',
    'wine_steam_proton',
    'wine_proton_ge',
    'wine_staging_tkg',
]
wine_labels = [
    f'Wine Staging',
    f'Wine Steam Proton',
    f'Wine Proton GE',
    f'Wine Staging TKG',
]
str_sw_use_wine = 'SW_USE_WINE'

wine_func_list = [
    'WINE_1',
    'WINE_2',
    'WINE_3',
    'WINE_4',
]
wine_source = [
    'https://github.com/Kron4ek/Wine-Builds',
    'https://github.com/RusNor/Wine-Steam-Proton/releases',
    'https://github.com/GloriousEggroll/proton-ge-custom',
    'https://github.com/Kron4ek/Wine-Builds',
]

wine_image_list = [
    IconPath.icon_wine_staging,
    IconPath.icon_wine_steam_proton,
    IconPath.icon_wine_proton_ge,
    IconPath.icon_wine_staging,
]

wine_list_dict = dict()
for w, l in zip(wine_list, wine_labels):
    wine_list_dict[l] = w

wine_source_dict = dict()
for w, s in zip(wine_list, wine_source):
    wine_source_dict[w] = s

wine_dict = dict()
for w in wine_list:
    wine_dict[w] = w

wine_func_dict = dict()
for w, f in zip(wine_list, wine_func_list):
    wine_func_dict[w] = f

winever_data, latest_wine_dict, wine_download_dict = get_wine_dicts()

################################___Install_launchers___:

str_il_subtitle = _('List of applications and stores available for installation')

launchers_descriptions = {
    'Anomaly_Zone': _('Anomaly Zone - MMORPG, open world game, successor to "stalker online". \
You can remain alone or conquer the Zone in the company of other daredevils, \
playing online with friends. Play in a clan, take part in PvP and PvE battles, \
use crafting, modifications, follow a large, interesting, global plot.'),
    'Battle_Net': _('Battle.net is an online gaming service, including digital \
distribution and social platform functions, developed by Blizzard Entertainment.'),
    'Caliber': _('Caliber is a third-person and first-person multiplayer online \
game about modern special forces. The project belongs to the genre of tactical \
team action, offering battles in PvP, PvE and PvPvE modes. "Caliber" is distributed \
according to the free-to-play business model.'),
    'Crossout': _('Crossout is a computer multiplayer online game in the genre \
of post-apocalyptic action with a third-person view. The core of the game is \
session PvP battles in armored vehicles assembled by the players themselves.'),
    'EA': _('EA app is Electronic Arts latest and most advanced PC platform where \
you can play your favorite games without any hassle. The app features an improved \
and optimized user interface, making it easy to find and play games in seconds.'),
    'Epic_Games': _('Epic Games Store is an online digital distribution service \
for computer games developed and managed by the American company Epic Games.'),
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
    'Genshin_Impact': _('Genshin Impact is an action-adventure computer game with \
an open world and RPG elements, developed by the Chinese company miHoYo Limited. \
The game is distributed through digital distribution using a free-to-play model, \
but has an in-game store that uses real currency.'),
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
live television channels, news, live sports, and games.'),
    'RetroBat': _('RetroBat is a software designed for emulation \
and to be the easiest way to enjoy your game collection. The EmulationStation \
interface is functional and highly customizable. You can run all your \
games and search online for visuals to enhance the presentation of your collection.'),
}

try:
    launchers_list = [str(x) for x in sw_launchers.iterdir()]
except (Exception,):
    launchers_list = [str(x) for x in launchers_descriptions.keys()]

################################___Settings___:

str_move_settings = _('Move settings')
str_reset_menu_settings = _('Reset interface settings')

settings_labels = [
    _('Launch settings'),
    _('MangoHud settings'),
    _('vkBasalt settings'),
    _('Reset app settings'),
    _('Clear shader cache'),
]
settings_widgets = [
    'launch_settings',
    'mangohud_settings',
    'vkbasalt_settings',
    'set_app_default',
    'clear_shader_cache',
]

settings_dict = dict()
for w, l in zip(settings_widgets, settings_labels):
    settings_dict[w] = l

settings_icons = [
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
    'LAUNCH_PARAMETERS',
    'WINEDLLOVERRIDES',
    "WINEARCH",
    'WINDOWS_VER',
    'REGEDIT_PATCH',
    'DXVK_VER',
    'VKD3D_VER',
    'FSR_MODE',
    'LANG_MODE',
    'FPS_LIMIT',
    'CPU_TOPOLOGY',
]

lp_title_dict = dict()
for n, t in zip(lp_list, lp_title):
    lp_title_dict[n] = t

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

lp_desc_dict = dict()
for t, d in zip(lp_list, lp_desc):
    lp_desc_dict[t] = d

winarch = [
    '64 bit architecture', '32 bit architecture'
]
arch_index = [
    'win64', 'win32'
]

winarch_dict = dict()
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
ver_index = ['11', '10', '81', '8', '7', 'xp']

winver_dict = dict()
for v,i in zip(winver, ver_index):
    winver_dict[v] = i

reg_patches = [''] + [
    str(reg.name) for reg in sorted(Path(sw_app_patches).iterdir())
]

dxvk_ver = dxvk_vkd3d_data['dxvk'].split()
vkd3d_ver = dxvk_vkd3d_data['vkd3d'].split()

combo_list = winarch + winver + reg_patches + dxvk_ver + vkd3d_ver
fsr_mode = {_('Ultra'): 'ultra', _('Quality'): 'quality', _('Balanced'): 'balanced', _('Performance'): 'performance'}

lang_mode = ['', 'en_US', 'ru_RU.UTF-8']

################################___Switch_check___:

switch_labels = [
    'DXVK_GE',
    'VKD3D_GE',
    'GALLIUM_HUD',
    'OPENGL',
    'MANGOHUD',
    'MESA_OVERLAY_HUD',
    'VIRTUAL_DESKTOP',
    'CONTROLLER',
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
    'ENABLE_VKBASALT',
    'FSR',
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
    _('Enable windows desktop emulation'),
    _('Enable game controller redirection to other input devices such as mouse and keyboard'),
    _('Improving frame rates and responsiveness with scheduling policies'),
    _('Increase performance for some games, especially ones that rely heavily on the CPU'),
    _('For old games that crash on very long extension strings'),
    _('Disabling the nvapi library required by PhysX to enable GPU acceleration via CUDA'),
    _('Disable debugging mode for Wine to improve performance'),
    _('Allocate to a 32-bit application more than 2 GB of RAM'),
    _('To simulate the memory management system of Windows'),
    _('Simulated Write Copy - Emulates how Windows loads DLLs into memory more accurately'),
    _('Сan optimize some Wineserver calls by using shared memory'),
    _('System monitoring in dxvk'),
    _('vkBasalt is a Vulkan post processing layer to enhance the visual graphics in games'),
    _('AMD FidelityFX Super Resolution - advanced upscaling technologies for higher fps'),
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
    _('Shows current MangoHud version'),
    _('Show if the application is 32 or 64 bit'),
    _('Change fps graph to histogram'),
    _('Displays used vulkan driver'),
    _("OpenGL or vulkan-based render engine's version"),
    _('Shows current Wine or Proton version in use'),
    _('Frametime next to fps text'),
    _('Frame count'),
    _('Current resolution'),
    _('Current fps limit'),
    _('Shows if vkBasalt is on'),
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
    'AdaptiveSharpen': _(
        'Contrast Adaptive Sharpening. An image sharpening method that observes the contrast of the local environment.'
    ),
    'AmbientLight': _('Ambient light. Bloom mixed with the EyeAdaption shader effect and lens dirt.'),
    'ASCII': _('For those who miss text games and Matrix fans.'),
    'Aspect Ratio': _('Сorrects aspect ratio in stretched images.'),
    'Bloom': _('A shader for simulating image blur depending on the brightness of the scene.'),
    'Border': _(
        'If you want to add borders in image but want the subject to hover over said border then try this shader.'
    ),
    'Cartoon': _('Creates an outline effect that makes the image look more cartoonish.'),
    'ChromaKey': _('Setting a blue or green screen away from the camera.'),
    'Chromatic Aberration': _(
        'It operates in HDR, simulating the physical effect of light passing through a prism inside a camera.'
    ),
    'CinematicDOF': _('Based on the most realistic and most used Depth of Field shader.'),
    'Clarity': _('Shader for image enhancement, makes things look sharper. Can rid the picture of haze.'),
    'ColorMatrix': _(
        'Editing colors using the color matrix. Essentially changes the brightness of the color channels: red, green '
        'and blue.'
    ),
    'Colourfulness': _('Saturates faded colors without touching the bright ones.'),
    'CRT': _(
        'To simulate a cathode ray tube monitor. The combination with the PerfectPerspective shader will shed a tear '
        'of nostalgia.'
    ),
    'Curves': _(
        'Increases the contrast of the image, while not touching the bright and dark areas, so that the detail in the '
        'shadows and the sky is not lost.'
    ),
    'Daltonize': _('Removes some colors.'),
    'Deband': _(
        'Remove banding - gradients that dont blend smoothly into each other when there arent enough tones available '
        'to recreate a smooth gradation.'
    ),
    'Denoise': _(
        'Remove dot noise. If possible, turn off the noise in the game itself, because the noise reduction shader '
        'reduces the frame rate.'
    ),
    'Depth3D': _('Split screen for owners of virtual reality glasses.'),
    'DepthHaze': _(
        'Simple depth-blur that makes far-away objects look slightly blurred, with fog based on depth and screen '
        'position.'
    ),
    'DisplayDepth': _('This is a shader mostly useful for checking if the depth buffer is working as intended.'),
    'DOF': _('Loss of sharpness in distant objects with the effect of chromatic aberration.'),
    'DPX': _('Makes the image look like it was converted from film to Cineon DPX. Can be used to create a sunny look.'),
    'Emphasize': _(
        'Make a part of the scene pop out more while other parts are de-emphasized. By default, it desaturates the '
        'areas which are not in focus.'
    ),
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
    'Glitch': _(
        'To simulate a failing video card and cause nausea. People with epilepsy should not turn on this filter!'
    ),
    'HighPassSharpen': _('Sharpering for more cinema-like look.'),
    'HQ4X': _(
        'Smoothing nearby pixels with filling in the missing parts. Is useful for smoothing objects in pixel games.'
    ),
    'HSLShift': _('Lightweight focus and sharpering effect.'),
    'Layer': _('Make own layer.png and overwrite on of the textures. It support alpha transparency.'),
    'Levels': _(
        'Shifts white and black points. will help in the absence of real black (everything is whitish, as if in a fog) '
        'or white is too gray.'
    ),
    'LevelsPlus': _('Shifts white and black points. will help in the absence of real black.'),
    'LiftGammaGain': _(
        'Gamma correction in color channels: red, green and blue. Can stylization of some games under a certain '
        'color shade.'
    ),
    'LightDOF': _(
        'The most lightweight defocus shader in terms of function, which does not greatly reduce performance.'
    ),
    'LumaSharpen': _('Sharpering for more cinema-like look.'),
    'LUT': _('In the context of game shaders, loot allows you to give the picture a cinema-like look.'),
    'MagicBloom': _(
        'Shader based on scene luminosity. It uses a Gaussian blur applied on the fly. It blends the bloom with the '
        'rest using the Screen blending method.'
    ),
    'Monochrome': _('The effect of simulating a black and white image.'),
    'MultiLUT': _('Hollywood preset LUT included.'),
    'MXAO': _('The effect of self-shadowing of objects, visually adding volume to them.'),
    'NightVision': _('For those who are nostalgic for a night vision device?'),
    'Nostalgia': _('Shader to create a 4-bit frame. Tries to mimic the look of very old computers or console systems.'),
    'PerfectPerspective': _(
        'The shader tilts the image and changes the point of view of the image. Can be useful for owners of virtual '
        'reality glasses.'
    ),
    'PPFX_Bloom': _('Filter that adds a glow around bright screen areas, adapting to the current scene brightness.'),
    'PPFX_Godrays': _('If you want to add godrays to a scene then this shader can help you with that.'),
    'Prism': _(
        'Yet Another Chromatic Aberration: It operates in HDR, is the only shader with a correct spectral gradient.'
    ),
    'ReflectiveBumpMapping': _(
        'Adds reflections to objects in the frame. Can improve the picture in older games without reflection support, '
        'but is useless in modern ones.'
    ),
    'Sepia': _('Applying a shade of brown. Color inherent in old black and white photographs.'),
    'SMAA': _(
        'Advanced implementation of anti-aliasing. Highlight the objects in the frame and blur their boundaries '
        'without erasing the small details of the frame.'
    ),
    'StageDepth': _('Resize image, positioning it, rotating it and use different blending modes.'),
    'SurfaceBlur': _('Reduction in object detail without blurring contrasting contours.'),
    'Technicolor': _('Makes the image look like it was processed using a three-strip Technicolor process.'),
    'Technicolor2': _('Like Technicolor, but gives a different picture, more aggressively changing colors.'),
    'TiltShift': _('For simulating tilt-shift photography, but recommended to use CinematicDOF.'),
    'Tonemap': _('Tone map for brightness, color and gamma correction.'),
    'UIDetect': _(
        'Detects the presence of a UI on the screen and switches the visibility of effects depending on its presence.'
    ),
    'UIMask': _(
        'Shader-mask that makes holes in the effects in the places of the menu items, provided that they do not '
        'move anywhere.'
    ),
    'Vibrance': _(
        'Saturates faded colors without touching the bright ones. The default settings are almost invisible.'
    ),
    'Vignette': _('Adds vignetting, reducing the brightness of the frame at the edges.'),
}

str_vk_subtitle = _('Vulkan layer postprocessing visual effects')
str_vk_intensity = _('Effect intensity')

################################___Mangohud_colors___:

str_mh_colors_title = _('MangoHud colors')
str_mh_colors_subtitle = _('MangoHud indicator color scheme settings')

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

################################___Gamepad_controller___:

str_gc_title = _('Controller redirection settings')
str_gc_subtitle = _('Map for binding controller buttons to keys of other input devices such as a keyboard or mouse.')
str_not_set = _('Not set')
str_press_any_key = _('Press any key for binding')

hotpad_dict = dict([
    (('BTN_A',), _('enter or accept')),
    (('BTN_B',), _('go back or cancel')),
    (('BTN_X',), 'backspace'),
    (('BTN_Y',), 'space'),
    (('BTN_TL',), _('control')),
    (('BTN_TR',), _('alt')),
    (('BTN_SELECT',), _('tabulation')),
    (('BTN_THUMBL',), _('middle mouse button')),
    (('BTN_THUMBR',), _('right shift')),
    (('BTN_MODE',), _('show or hide sidebar menu')),
    (('BTN_START',), _('show context menu')),
    (('ABS_Xrt',), _('scroll page right or left')),
    (('ABS_Yup',), _('scroll page up or down')),
    (('ABS_RXrt',), _('mouse movement on the x-axis')),
    (('ABS_RYup',), _('mouse movement on the y-axis')),
    (('ABS_Z',), _('right mouse button')),
    (('ABS_RZ',), _('left mouse button')),
    (('ABS_HAT0Xrt',), _('left, right')),
    (('ABS_HAT0Yup',), _('up, down')),
    (('BTN_TL', 'BTN_TR', 'BTN_B'), _('shutdown StartWine')),
    (('BTN_TL', 'BTN_TR', 'BTN_A'), _('show or hide StartWine window')),
    (('BTN_TL', 'BTN_TR', 'ABS_HAT0Yup'), _('show or hide list of mounted volumes')),
    (('BTN_TL', 'BTN_TR', 'BTN_X'), _('reduce the size of the icons and shortcuts')),
    (('BTN_TL', 'BTN_TR', 'BTN_Y'), _('increase the size of the icons and shortcuts')),
    (('BTN_TR', 'ABS_Yup'), _('go to the directory up in the file manager')),
    (('BTN_TL', 'BTN_START'), _('open main context menu')),
    (('BTN_TR', 'BTN_START'), _('show or hide media playlist')),
    (('BTN_TL', 'BTN_MODE'), _('show or hide bookmarks list')),
    (('BTN_TR', 'ABS_Xrt'), _('go to the next menu page')),
    (('BTN_TR', 'ABS_Xlt'), _('go to the previous menu page')),
    (('BTN_TR', 'BTN_A'), _('show file properties')),
])

controller_icons = {
    'BTN_JOYSTICK': IconPath.icon_xb_LT,
    'BTN_TRIGGER': IconPath.icon_xb_LT,
    'BTN_THUMB': IconPath.icon_xb_LB,
    'BTN_THUMB2': IconPath.icon_xb_A,
    'BTN_TOP': IconPath.icon_xb_B,
    'BTN_TOP2': IconPath.icon_xb_X,
    'BTN_PINKIE': IconPath.icon_xb_Y,
    'BTN_BASE': IconPath.icon_unknown_button,
    'BTN_BASE2': IconPath.icon_unknown_button,
    'BTN_BASE3': IconPath.icon_unknown_button,
    'BTN_BASE4': IconPath.icon_unknown_button,
    'BTN_BASE5': IconPath.icon_unknown_button,
    'BTN_BASE6': IconPath.icon_unknown_button,
    'BTN_DEAD': IconPath.icon_unknown_button,
    'BTN_GAMEPAD': IconPath.icon_xb_A,
    'BTN_SOUTH': IconPath.icon_xb_A,
    'BTN_A': IconPath.icon_xb_A,
    'BTN_EAST': IconPath.icon_xb_B,
    'BTN_B': IconPath.icon_xb_B,
    'BTN_C': IconPath.icon_unknown_button,
    'BTN_NORTH': IconPath.icon_xb_X,
    'BTN_X': IconPath.icon_xb_X,
    'BTN_WEST': IconPath.icon_xb_Y,
    'BTN_Y': IconPath.icon_xb_Y,
    'BTN_Z': IconPath.icon_unknown_button,
    'BTN_TL': IconPath.icon_xb_LB,
    'BTN_TR': IconPath.icon_xb_RB,
    'BTN_TL2': IconPath.icon_xb_LB,
    'BTN_TR2': IconPath.icon_xb_RB,
    'BTN_SELECT': IconPath.icon_xb_select,
    'BTN_START': IconPath.icon_xb_start,
    'BTN_MODE': IconPath.icon_xb_super,
    'BTN_THUMBL': IconPath.icon_LS,
    'BTN_THUMBR': IconPath.icon_RS,
    'ABS_Xrt': IconPath.icon_LS_rt,
    'ABS_Xlt': IconPath.icon_LS_lt,
    'ABS_Yup': IconPath.icon_LS_up,
    'ABS_Ydn': IconPath.icon_LS_dn,
    'ABS_Z': IconPath.icon_xb_LT,
    'ABS_RXrt': IconPath.icon_RS_rt,
    'ABS_RXlt': IconPath.icon_RS_lt,
    'ABS_RYup': IconPath.icon_RS_up,
    'ABS_RYdn': IconPath.icon_RS_dn,
    'ABS_RZ': IconPath.icon_xb_RT,
    'ABS_THROTTLE': IconPath.icon_unknown_button,
    'ABS_RUDDER': IconPath.icon_unknown_button,
    'ABS_WHEEL': IconPath.icon_unknown_button,
    'ABS_GAS': IconPath.icon_unknown_button,
    'ABS_BRAKE': IconPath.icon_unknown_button,
    'ABS_HAT0Xrt': IconPath.icon_dpad_rt,
    'ABS_HAT0Xlt': IconPath.icon_dpad_lt,
    'ABS_HAT0Yup': IconPath.icon_dpad_up,
    'ABS_HAT0Ydn': IconPath.icon_dpad_dn,
    'ABS_HAT1Xrt': IconPath.icon_dpad_rt,
    'ABS_HAT1Xlt': IconPath.icon_dpad_lt,
    'ABS_HAT1Yup': IconPath.icon_dpad_up,
    'ABS_HAT1Ydn': IconPath.icon_dpad_dn,
    'ABS_HAT2Xrt': IconPath.icon_dpad_rt,
    'ABS_HAT2Xlt': IconPath.icon_dpad_lt,
    'ABS_HAT2Yup': IconPath.icon_dpad_up,
    'ABS_HAT2Ydn': IconPath.icon_dpad_dn,
    'ABS_HAT3Xrt': IconPath.icon_dpad_rt,
    'ABS_HAT3Xlt': IconPath.icon_dpad_lt,
    'ABS_HAT3Yup': IconPath.icon_dpad_up,
    'ABS_HAT3Ydn': IconPath.icon_dpad_dn,
    'ABS_PRESSURE': IconPath.icon_unknown_button,
    'ABS_DISTANCE': IconPath.icon_unknown_button,
    'ABS_TILT_X': IconPath.icon_unknown_button,
    'ABS_TILT_Y': IconPath.icon_unknown_button,
    'ABS_TOOL_WIDTH': IconPath.icon_unknown_button,
}

################################___Custom_theme_colors___:

confirm_label = _('Confirm changes')
preview_label = _('MangoHud preview')

str_theme_colors_title = _('Custom theme')
str_theme_colors_subtitle = _('Custom interface color scheme settings')

str_wc_style_title = _('Window control buttons')
str_wc_style_subtitle = _('Select a style for the window control buttons')

str_icon_colors_title = _('Built-in icon theme')
str_icon_colors_subtitle = _('Choose a color for the built-in icon theme')

str_define_color = '@define-color'
css_change_list = list()

dcolor_names = [
    '@define-color sw_bg_color',
    '@define-color sw_accent_fg_color',
    '@define-color sw_accent_bg_color',
    '@define-color sw_header_bg_color',
    '@define-color sw_pop_bg_color',
]

invert_dcolors = [
    '@define-color sw_invert_bg_color',
    '@define-color sw_invert_accent_fg_color',
    '@define-color sw_invert_accent_bg_color',
    '@define-color sw_invert_header_bg_color',
    '@define-color sw_invert_pop_bg_color',
]

dcolor_labels = [
    _('Primary background'),
    _('Accent color'),
    _('Accent background'),
    _('Headerbars'),
    _('Popover context menu'),
]

################################___Global_settings___:

str_global_subtitle = _('Additional general parameters and interface settings')

str_title_startup = _('Startup options')
str_subtitle_startup = _('Some settings will take effect the next time you start')

str_title_lang = _('Language')
str_subtitle_lang = _('Change the interface language')

str_title_autostart = _('Autostart')
str_subtitle_autostart = _('Run StartWine in the tray at system startup')

str_title_restore_menu = _('Restore menu')
str_subtitle_restore_menu = _('Restore the menu after exiting a game or application')

str_title_auto_stop = _('Auto Stop')
str_subtitle_auto_stop = _('Auto terminate all Wine processes after exiting a game or application')

str_title_auto_hide_top = _('Auto-hide top header')
str_subtitle_auto_hide_top = _('Auto-hide the top panel of the window and show it on mouseover')

str_title_auto_hide_bottom = _('Auto-hide bottom header')
str_subtitle_auto_hide_bottom = _('Auto-hide the bottom panel of the window and show it on mouseover')

str_title_icons = _('Icons')
str_subtitle_icons = _('Use system icon theme')

str_title_menu_size = _('Compact mode')
str_subtitle_menu_size = _('Always run the menu in compact size mode')

str_title_def_dir = _('Default directory')
str_subtitle_def_dir = _('The default directory in which files will be opened in the StartWine file manager')

str_title_render = _('Rendering')
str_subtitle_render = _('Graphical interface rendering options')

str_title_vulkan = _('Vulkan')
str_subtitle_vulkan = _('Use Vulkan to render the graphical interface')

str_title_opengl = _('Live background')
str_subtitle_opengl = _(
    'Animation based on selected shaders. '
    'Warning!!! This function can lead to slowdowns and additional load on the graphics card.'
)

str_title_shaders = _('Shaders')
str_subtitle_shaders = _('Select shaders for the live background from the list')

str_title_hotkeys = _('Hotkeys')
str_subtitle_hotkeys = _('List of default hotkeys settings')

str_wrong_path = _('Wrong path, path does not exist, specify the correct path to the directory')

hotkey_list = [
    ['Escape', '', ''],
    ['Ctrl', 'K', ''],
    ['F1', '', ''],
    ['F4', '', ''],
    ['R_Shift', 'F12', ''],
    ['R_Shift','F11',''],
    ['HOME', '', ''],
    ['Ctrl', 'Q', ''],
    ['Ctrl', 'W', ''],
    ['Ctrl', '+', ''],
    ['Ctrl', '-', ''],
    ['F5', '', ''],
    ['F3', '', ''],
    ['Ctrl', '1', ''],
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
    ['Alt', 'I', ''],
    ['Alt', 'Return', ''],
]

hotkey_desc = [
    _('go back or cancel'),
    _('show hotkey settings window'),
    _('show help'),
    _('about StartWine'),
    _('enable / disable MangoHud overlay in the game'),
    _('toggle MangoHud overlay postion in the game'),
    _('enable / disable vkBasalt effects in the game'),
    _('shutdown StartWine'),
    _('close StartWine window'),
    _('increase the size of the icons and shortcuts'),
    _('reduce the size of the icons and shortcuts'),
    _('update files or shortcuts list view'),
    _('split view for viewing files'),
    _('show files in a grid or table view'),
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
    _('show the page of installed games and applications'),
    _('open file manager'),
    _('show or hide list of mounted volumes'),
    _('show or hide bookmarks list'),
    _('show the wine builds page'),
    _('show the application page to launch'),
    _('open interface settings menu'),
    _('show file properties'),
]

################################___Winetricks___:

btn_dll_list = list()
install_dll_list = list()
description_label = _('Description')
confirm_install_label = _('Confirm install')
libs_tab_label = _('Libraries')
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
    'mfc120 mfc42 msvcirt openal physx vb6run vcrun2005 vcrun2008 vcrun2010 \
    vcrun2012 vcrun2013 vcrun2019 vcrun2022 vcrun6 vcrun6sp6 lucida nocrashdialog',
    'dotnet20sp2 dotnet48 dotnet6 dotnet7',
    'd3dcompiler_42 d3dcompiler_43 d3dcompiler_46 d3dcompiler_47 d3dx10 \
    d3dx10_43 d3dx11_42 d3dx11_43 d3dx9',
    'vcrun2005 vcrun2008 vcrun2010 vcrun2012 vcrun2013 vcrun2019 vcrun2022 \
    vcrun6 vcrun6sp6',
]

dll_templates_dict = dict()
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
d2gl
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
dotnet8
dotnet_verifier
dotnetcore2
dotnetcore3
dotnetcoredesktop3
dotnetdesktop6
dotnetdesktop7
dotnetdesktop8
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
otvdm
otvdm090
pdh
pdh_nt4
peverify
physx
pngfilt
powershell
powershell_core
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
xaudio29
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
Diablo 2 LoD Glide to OpenGL Wrapper (Bayaraa, 2023)
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
MS .NET Runtime 8.0 LTS (Microsoft, 2024)
MS .NET Verifier (Microsoft, 2016)
MS .NET Core Runtime 2.1 LTS (Microsoft, 2020)
MS .NET Core Runtime 3.1 LTS (Microsoft, 2020)
MS .NET Core Desktop Runtime 3.1 LTS (Microsoft, 2020)
MS .NET Desktop Runtime 6.0 LTS (Microsoft, 2023)
MS .NET Desktop Runtime 7.0 LTS (Microsoft, 2023)
MS .NET Desktop Runtime 8.0 LTS (Microsoft, 2024)
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
MS Visual C++ Runtime Library Version 4.0 (Microsoft, 2011)
MS XML Core Services 3.0 (Microsoft, 2005)
MS XML Core Services 4.0 (Microsoft, 2009)
MS XML Core Services 6.0 sp2 (Microsoft, 2014)
NuGet Package manager (Outercurve Foundation, 2013)
OpenCodecs 0.85: FLAC, Speex, Theora, Vorbis, WebM (Xiph.Org Foundation, 2011)
MS ole32 Module (ole32.dll) (Microsoft, 2004)
MS oleaut32.dll (Microsoft, 2011)
OpenAL Runtime (Creative, 2023)
Otvdm - A modified version of winevdm as Win16 emulator (otya128, 2024)
Otvdm - A modified version of winevdm as Win16 emulator (otya128, 2024)
MS pdh.dll (Performance Data Helper) (Microsoft, 2011)
MS pdh.dll (Performance Data Helper); WinNT 4.0 Version (Microsoft, 1997)
MS peverify (from .NET 2.0 SDK) (Microsoft, 2006)
PhysX (Nvidia, 2021)
pngfilt.dll (from winxp) (Microsoft, 2004)
PowerShell Wrapper For Wine (ProjectSynchro, 2024)
PowerShell Core (Microsoft, 2024)
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
MS XAudio Redistributable 2.9 (Microsoft, 2023)
Microsoft XInput (Xbox controller support) (Microsoft, 2010)
MS xmllite dll (Microsoft, 2011)
MS XNA Framework Redistributable 3.1 (Microsoft, 2009)
MS XNA Framework Redistributable 4.0 (Microsoft, 2010)
Xvid Video Codec (xvid.org, 2019)
'''

dll_dict = dict()
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

fonts_dict = dict()
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
    'application/vnd.microsoft.portable-executable',
    'application/x-wine-extension-msp',
    'application/x-msdos-program',
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
    'text/x-python',
    'text/win-bat',
    'text/x-ms-regedit',
    'text/x-log',
    'application/x-zerosize',
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
    'image/apng',
]

video_mime_types = [
    'video/mp4',
    'video/vnd.radgamettools.bink',
    'video/x-matroska',
    'video/mp2t',
    'video/mpeg',
    'video/x-msvideo',
    'video/quicktime',
    'video/webm',
    'video/ogg',
    'video/x-ms-wmv',
    'video/x-flv',
    'video/3gpp',
    'video/3gpp2',
    'video/x-f4v',
    'video/x-m4v',
    'video/h264',
    'video/h265',
    'video/avi',
    'video/vnd.avi',
    'video/divx',
    'video/x-vob',
    'video/x-anim',
    'video/x-sgi-movie',
    'video/x-ms-asf',
    'video/x-ogm',
    'video/x-mjpeg',
    'video/x-pn-realvideo',
]

audio_mime_types = [
    'audio/mpeg',
    'audio/vnd.wave',
    'audio/wav',
    'audio/x-wav',
    'audio/ogg',
    'audio/x-ogg',
    'audio/flac',
    'audio/x-flac',
    'audio/mpeg',
    'audio/aac',
    'application/x-cdf',
    'audio/midi',
    'audio/x-midi',
    'audio/webm',
    'audio/3gpp',
    'audio/3gpp2',
    'audio/vorbis',
    'audio/vnd.rn-realaudio',
    'audio/x-mpegurl',
    'audio/x-aiff',
    'audio/mp4',
    'audio/mid',
    'auido/L24',
    'audio/basic',
    'audio/x-ms-wma',
    'audio/x-ms-wax',
    'audio/amr',
    'audio/x-matroska',
    'audio/x-ape',
    'audio/x-m4a',
    'audio/x-scpls',
    'audio/opus',
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
    'zip', 'gz', 'bz2', 'xz', 'zst', 'zst ultra'
]

################################___Messages___:


class Msg:
    """___messages and tooltips dictionaries___"""

    msg_dict = dict([
        ('about', _('About')),
        ('good_day_is', _('A good day is like a good Wine...')),
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
        ('cw', _('Change Wine')),
        ('shortcuts', _('Games and apps')),
        ('files_tree', _('Files')),
        ('launchers', _('Apps and stores')),
        ('install_wine', _('Wine builds')),
        ('settings', _('Settings')),
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
        ('permanently_delete', _('Do you really want to permanently delete')),
        ('oops_path', _('Oops! Wrong path...')),
        ('replace_override', _('Another file with the same name already exists. Replacing will overwrite content')),
        ('no_dll', _('You have not selected any libraries to install')),
        ('exist_desktop', _('Path not exist, try to create new shortcut')),
        ('same_name', _('You already have an executable and a prefix with the same name. \
To create a shortcut for this executable, rename it or delete the existing shortcut and prefix')),
        ('termination', _('Termination of active processes...')),
        ('equal_paths', _("You can't copy a directory to itself")),
        ('wine_not_exists', _('is not installed, download it now?')),
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
        ('install_desc', _('Applications and game stores')),
        ('device_name', _('Volume name')),
        ('device_id', _('Device ID')),
        ('device_uuid', _('Device UUID')),
        ('device_drive', _('Drive name')),
        ('device_size', _('Device size')),
        ('mount_options', _('Mount options')),
        ('app_conf_incorrect', _('Incorrect launch parameters')),
        ('app_conf_reset', _('Reset the application settings?')),
        ('lnk_error', _('The path to the executable file was not found, launch is impossible')),
        ('new_path', _('Do you want to specify a new path to the executable file?')),
        ('copied_to_clipboard', _('Сopied to clipboard')),
        ('total', _('Total')),
        ('free', _('Free')),
        ('used', _('Used')),
        ('action_not_supported', _('Action not supported')),
        ('launch_settings', _('Launch settings')),
        ('does_not_exist', _('The file you are trying to access does not exist')),
        ('file_name', _('Name')),
        ('file_size', _('Size')),
        ('file_type', _('Type')),
        ('file_modified', _('Modified date')),
        ('file_created', _('Creation date')),
        ('file_date', _('Modified/Created')),
        ('file_readable', _('Can-readable')),
        ('file_writable', _('Can-writable')),
        ('file_non_readable', _('Non-readable')),
        ('file_non_writable', _('Non-writable')),
        ('file_executable', _('Executable')),
        ('file_link', _('Symbolic link to')),
        ('directory_size', _('Directory size')),
        ('app', _('Application')),
        ('path', _('Path')),
        ('startup_mode', _('Startup mode')),
        ('access', _('Access')),
        ('user_group', _('Owner/Group')),
        ('permission', _('Permission')),
        ('total_time', _('Total time')),
        ('avg_fps', _('Average fps')),
        ('seconds', _('seconds')),
        ('minutes', _('minutes')),
        ('hours', _('hours')),
        ('days', _('days')),
        ('unknown', _('Unknown')),
        ('wine_not_found', _('Error, Wine not found...')),
        ('check_wine_updates', _('Check Wine updates')),
        ('specify_executable', _('Specify executable file')),
        ('specify_new_loacation', _('Specify the new location...')),
        ('is_nothing_to_rename', _('It is impossible to rename the file, the image is missing')),
        ('album', _('Album')),
        ('title', _('Title')),
        ('artist', _('Artist')),
        ('year', _('Year')),
        ('remove_pfx', _('Do you really want to remove the prefix?')),
        ('download_failed', _('Download failed...')),
    ])

    ################################___Tooltips___:

    tt_dict = dict([
        ('go_home', _('Go to the home directory')),
        ('back_up', _('Move up directory')),
        ('view_more', _('Current directory menu')),
        ('back_main', _('Сome back')),
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
        ('playlist', _('Show or hide media playlist')),
        ('apply', _('Apply')),
        ('registry', _('registry patch')),
        ('download_wine', _('Download Wine')),
        ('install_launchers', _('Install apps and game stores')),
        ('settings', _('Settings')),
        ('prefix_tools', _('Prefix tools')),
        ('wine_tools', _('Wine tools')),
        ('tools', _('Tools')),
        ('controller', _('Controller settings')),
        ('keyboard', _('Keyboard settings')),
        ('stats', _('Statistics and data')),
        ('debug', _('Debug')),
        ('stop', _('Terminate all processes')),
        ('about', _('About')),
        ('choose_app', _('Choose the application to transfer settings')),
        ('web', _('Show web entry')),
        ('view_menu', _('Menu')),
        ('check_wine_updates', _('Check and update the Wine list')),
        ('scroll_up', _('Scroll up the page')),
    ])

    ################################___Contexts___:

    ctx_dict = dict([
        ('run', _('Run')),
        ('open', _('Open')),
        ('open_with', _('Open with...')),
        ('open_location', _('Open file location')),
        ('app_settings', _('App settings')),
        ('remove', _('Remove')),
        ('app_to_menu', _('App to menu')),
        ('app_to_desktop', _('App to desktop')),
        ('app_to_steam', _('App to Steam Deck menu')),
        ('change_wine', _('Change Wine')),
        ('specify_executable', _('Specify executable file')),
        ('specify_new_loacation', _('Specify the new location...')),
        ('winehq', _('Winehq')),
        ('protondb', _('Protondb')),
        ('griddb', _('Search for an image')),
        ('staging', 'wine staging'),
        ('steam_proton', 'wine steam proton'),
        ('proton_ge', 'wine proton ge'),
        ('lutris_ge', 'wine lutris ge'),
        ('staging_tkg', 'wine staging tkg'),
        ('create', _('Create file')),
        ('create_dir', (_('Create directory'), '<Ctrl>N')),
        ('link', (_('Create link'), '<Shift>L')),
        ('rename', (_('Rename'), 'F2')),
        ('cut', (_('Cut'), '<Ctrl>X')),
        ('copy', (_('Copy'), '<Ctrl>C')),
        ('paste', (_('Paste'), '<Ctrl>V')),
        ('select_all', (_('Select all'), '<Ctrl>A')),
        ('trash', (_('Move to trash'), 'Delete')),
        ('delete', (_('Delete permanently'), '<Shift>Delete')),
        ('properties', (_('Properties'), '')),
        ('txt', _('Text')),
        ('sh', _('Bourne shell')),
        ('py', _('Python')),
        ('desktop', _('Desktop')),
        ('copy_path', _('Copy current path')),
        ('add_bookmark', _('Add to bookmark')),
        ('compress', _('Compress...')),
        ('extract', _('Extract...')),
        ('show_hidden_files', (_('Hidden files'), '<primary>H')),
        ('sort', _('Sort...')),
        ('sorting_by_type', (_('By type'), '')),
        ('sorting_by_size', (_('By size'), '')),
        ('sorting_by_date', (_('By date'), '')),
        ('sorting_by_name', (_('By name'), '')),
        ('sorting_reverse', (_('Reverse'), '')),
        ('global_settings', (_('Interface settings'), '<Alt>I')),
        ('show_hotkeys', (_('Hotkeys'), '<Ctrl>K')),
        ('about', (_('About'), 'F4')),
        ('help', (_('Help'), 'F1')),
        ('shutdown', (_('Shutdown'), '<Ctrl>Q')),
        ('add_media', _('Add to playlist...')),
        ('sample', _('sample')),
    ])


################################___Progress_and_file_ops___:

progress_dict = dict([
    ('search', _('Search...')),
    ('app_loaded', _('Loaded successfully')),
    ('app_loading', _('The app is loading...')),
    ('squashfs', _('Squashfs...')),
    ('installation', _('installation in progress please wait...'))
])

str_deletion = _('Deletion')
str_copying = _('Сopying')
str_removal = _('Removal')
str_copy = _('copy')

################################___Shaders___:

fragments_list = [s.value for s in list(Shaders)]
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
    _('blue parabolic waves'),
    _('red parabolic waves'),
    _('teal parabolic waves'),
    _('mint parabolic waves'),
    _('golden parabolic waves'),
    _('purple parabolic waves'),
    _('brown parabolic waves'),
    _('gray parabolic waves'),
    _('macos monterey'),
    _('neon road'),
    _('alien planet'),
    _('wallpaper'),
    _('ice and fire'),
    _('voronoi gradient'),
    _('pixelated rgb'),
    _('blue ps3 home background'),
    _('red ps3 home background'),
    _('teal ps3 home background'),
    _('mint ps3 home background'),
    _('golden ps3 home background'),
    _('purple ps3 home background'),
    _('brown ps3 home background'),
    _('gray ps3 home background'),
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
    _('sin cos 3d'),
    _('static abstraction'),
    _('galaxy/nebula and stars'),
    _('nebula 112'),
    _('magic ball'),
    _('zippy zaps'),
#    _('Charset mandelbrot'),
#    _('_')
]

################################___Apps_ID___:

#f'https://api.steampowered.com/IStoreService/GetAppList/v1/?key={api_key}&include_games=true&include_dlc=false&include_software=false&include_videos=false&include_hardware=false'

url_app_id = 'https://api.steampowered.com/ISteamApps/GetAppList/v2/'
url_api_list = 'http://api.steampowered.com/ISteamWebAPIUtil/GetSupportedAPIList/v1/'
url_app_dtls = 'https://store.steampowered.com/api/appdetails?appids=1091500'

request_headers = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101 Safari/537.36"
    ),
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
    '/', 'MNT', 'GAMES', 'DATA', 'HOME', '_X64', 'ENGINE', 'PH', 'WORK', 'BIN',
    'RUNTIME', 'MEDIA', 'SOURCE', 'GAME_INFO', 'RUN', 'STARTWINE', 'DRIVE_C',
    'PROGRAM FILES', 'PROGRAM FILES (X86)', 'PROGRAMDATA', 'APPDATA', 'USERS',
    'LOCAL', 'BINARIES', 'PUBLIC', 'STEAMUSER', 'ROAMING', 'PORTAL', 'WIN32',
    'WIN64', 'PROGRAMS', 'JAVA', 'SYSTEM', 'EN_US', 'CLIENT', 'PC',
    'WIN64_SHIPPING_CLIENT', 'WIN64_SHIPPING', 'RETAIL', user_name,
]
exclude_names = (mount_dirs + exclude_dirs + special_dirs)

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
    ('Ultimate', ''),
    ('Special', ''),
    ('Legendary', ''),
    ('Anniversary', ''),
    ("Collector's", ''),
    ('Voidfarer', ''),
    ('HDRemaster', ''),
    ('Remastered', ''),
    ('Edition', ''),
    ('Launcher', ''),
    ('Linux', ''),
    ('&', 'and'),
    ('InsaneRamZes', ''),
    ('Update', ''),
    ('CODEX', ''),
    ('SKIDROW', ''),
    ('Revision', ''),
    ('UnrealEngine', ''),
    ('UnrealGame', ''),
    ('RockstarGames', ''),
    ('Unity', ''),
    ('GOGRip', ''),
    ('EGSRip', ''),
    ('UplayRip', ''),
    ('SteamRip', ''),
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
    ('Voidfarer Edition', ''),
    ('Gold Classic', ''),
    ('Next Gen', ''),
    ('Game of the Year', ''),
    ('Unreal Engine', ''),
    ('Unreal Game', ''),
    ('Config App', ''),
    ('Single Player', ''),
    ('Rockstar Games', ''),
    ('GOG Rip', ''),
    ('EGS Rip', ''),
    ('Uplay Rip', ''),
    ('Steam Rip', ''),
    ('HD Remaster', ''),
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
