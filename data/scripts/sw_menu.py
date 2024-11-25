#!/usr/bin/env python3
"""
StartWine graphical shell module.
"""
import time
from time import time, process_time, sleep, perf_counter
import io
from platform import python_version
import os
from os import environ, getenv, walk, scandir
from os.path import join
from sys import argv, exit
from subprocess import Popen, run, PIPE, DEVNULL
from pathlib import Path
from threading import Thread, Timer
import multiprocessing as mp
import asyncio
from warnings import filterwarnings
import mimetypes
import shutil
import tarfile
import zipfile
import itertools

from sw_data import *
from sw_data import sw_renderer

start_counter = perf_counter()
start_process = process_time()
start_time = time()

filterwarnings("ignore")
ls_gpu_in_use = "lspci -nnk | grep -i vga -A3 | grep 'in use' | cut -d ' ' -f5-100"
environ['WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS'] = '1'
environ['SW_DIFF_CSS_DARK'] = '1'
environ['SW_DIFF_CSS_LIGHT'] = '1'
environ['SW_DIFF_CSS_CUSTOM'] = '1'
#environ['GDK_DEBUG'] = 'fatal-criticals'

gpu_in_use = None
try:
    gpu_in_use = run(ls_gpu_in_use, shell=True, stdout=PIPE, encoding='UTF-8').stdout.splitlines()[0]
except IndexError as e:
    print(f'GPU_IN_USE:', gpu_in_use)
else:
    print(f'GPU_IN_USE:', gpu_in_use)

if getenv('XDG_SESSION_TYPE') == 'wayland' or getenv('WAYLAND_DISPLAY'):
    if gpu_in_use == 'nvidia':
        cat_ver = "cat /sys/module/nvidia/version"
        smi_ver = "nvidia-smi --query-gpu driver_version --format=csv,noheader"
        try:
            nv_drv_ver = run(cat_ver, shell=True, stdout=PIPE, encoding='UTF-8').stdout.splitlines()[0]
        except (Exception,):
            try:
                nv_drv_ver = run(smi_ver, shell=True, stdout=PIPE, encoding='UTF-8').stdout.splitlines()[0]
            except (Exception,):
                nv_drv_ver = None
            else:
                print(f'NVIDIA_DRIVER_VERSION: {nv_drv_ver}')
        else:
            print(f'NVIDIA_DRIVER_VERSION: {nv_drv_ver}')

        if nv_drv_ver and int(nv_drv_ver.split('.')[0]) >= 545:
            environ['PYOPENGL_PLATFORM'] = 'egl'
            environ['GDK_DEBUG'] = 'gl-prefer-gl'
            environ['GDK_BACKEND'] = 'wayland'
            environ['GSK_RENDERER'] = 'opengl'
        else:
            environ['PYOPENGL_PLATFORM'] = 'posix'
            environ['GDK_DEBUG'] = 'gl-glx'
            environ['GDK_BACKEND'] = 'x11'
            environ['GSK_RENDERER'] = 'opengl'
    else:
        environ['PYOPENGL_PLATFORM'] = 'egl'
        environ['GDK_DEBUG'] = 'gl-prefer-gl'
        environ['GDK_BACKEND'] = 'wayland'
        environ['GSK_RENDERER'] = str(sw_renderer)
        if getenv('SW_RENDERER'):
            environ['GSK_RENDERER'] = str(getenv('SW_RENDERER'))
        #environ['GDK_VULKAN_DEVICE'] = 'list'
else:
    if str(sw_renderer) == 'vulkan':
        environ['PYOPENGL_PLATFORM'] = 'egl'
        environ['GDK_DEBUG'] = 'gl-prefer-gl'
        environ['GDK_BACKEND'] = 'x11'
        environ['GSK_RENDERER'] = 'vulkan'
    else:
        environ['PYOPENGL_PLATFORM'] = 'posix'
        environ['GDK_DEBUG'] = 'gl-prefer-gl'
        environ['GDK_DISABLE'] = 'egl'
        environ['GDK_BACKEND'] = 'x11'
        environ['GSK_RENDERER'] = 'opengl'

#environ["LD_LIBRARY_PATH"] = os.path.sep + f'/usr/local/lib'
#environ['GI_TYPELIB_PATH'] = os.path.sep + f'/usr/local/lib/girepository-1.0'
#from ctypes import CDLL
#CDLL('/usr/local/lib/libgtk4-layer-shell.so.1.0.1')
#gi.require_version('Gtk4LayerShell', '1.0')
#from gi.repository import Gtk4LayerShell as LayerShell

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Gdk', '4.0')
gi.require_version('WebKit', '6.0')
gi.require_version('Vte', '3.91')
from gi.repository import Gtk, Gdk, Gio, GLib, Pango, GObject
from gi.repository import WebKit
from gi.repository import GdkPixbuf
from gi.repository import Vte

from PIL import Image, ImageColor
import psutil
from psutil import Process

from sw_data import Msg as msg
from sw_data import TermColors as tc
from sw_crier import SwDialogQuestion
from sw_crier import SwDialogEntry
from sw_crier import SwDialogDirectory
from sw_crier import SwCrier
from sw_crier import SwProgressBar
from sw_crier import SwExtractIcon
from sw_opengl import SwRenderArea
from sw_func import *
from sw_input import (
    SwKeyController, SwDeviceRedirectionSettings, run_zero_device_redirection)


try:
    mimetypes.add_type(exe_mime_types[0], '.exe', strict=True)
except (Exception,):
    print(f'{tc.VIOLET2}ADD_MIME_TYPES: {tc.RED}failed')

try:
    mimetypes.add_type(exe_mime_types[1], '.msi', strict=True)
except (Exception,):
    print(f'{tc.VIOLET2}ADD_MIME_TYPES: {tc.RED}failed')


def check_arg(arg_path: str | None):
    """___check system commandline arg and set to environment___"""

    if arg_path is None or arg_path == 'None':
        try:
            arg_path = argv[2]
        except (Exception,):
            arg_path = None

    if arg_path is not None and arg_path != '%F':
        if Path(arg_path).exists():
            g_file = Gio.File.new_for_commandline_arg(arg_path)
            g_info = g_file.query_info('*', Gio.FileQueryInfoFlags.NONE)
            arg_type = g_info.get_content_type()

            if Path(arg_path).suffix == '.desktop' or Path(arg_path).suffix == '.swd':
                arg = [x.split('=')[1].strip('"') for x in Path(arg_path).read_text().splitlines() if 'Exec=' in x]

                if len(arg) > 0:
                    exe = [x for x in str(arg[0]).split('"') if '.exe' in x.lower()]
                    msi = [x for x in str(arg[0]).split('"') if '.msi' in x.lower()]
                    bat = [x for x in str(arg[0]).split('"') if '.bat' in x.lower()]
                    lnk = [x for x in str(arg[0]).split('"') if '.lnk' in x.lower()]
                    steam = str(arg[0]) if 'steam://rungameid' in str(arg[0]) else None

                    if len(exe) > 0:
                        x_path = exe[0]

                    elif len(msi) > 0:
                        x_path = msi[0]

                    elif len(bat) > 0:
                        x_path = bat[0]

                    elif len(lnk) > 0:
                        x_path = lnk[0]
                    elif steam is not None:
                        x_path = steam
                    else:
                        x_path = None

                    if x_path is not None and Path(x_path).exists():
                        environ['SW_COMMANDLINE'] = f'"{x_path}"'
                        environ['SW_EXEC'] = f'"{x_path}"'
                    elif x_path == steam:
                        environ['SW_COMMANDLINE'] = f'"{x_path}"'
                        environ['SW_EXEC'] = f'"{x_path}"'
                    else:
                        print(f'{tc.RED} SW_START: {tc.GREEN}Executable is {arg[0]}{tc.END}')
                        environ['SW_COMMANDLINE'] = f'"{arg[0]}"'
                        environ['SW_EXEC'] = 'StartWine'
                else:
                    print('{tc.RED} SW_START: Executable not exists...{tc.END}')
                    environ['SW_COMMANDLINE'] = 'None'
                    environ['SW_EXEC'] = 'StartWine'

            elif (Path(arg_path).suffix.lower() == '.exe'
                    or Path(arg_path).suffix.lower() == '.msi'
                    or Path(arg_path).suffix.lower() == '.bat'
                    or Path(arg_path).suffix.lower() == '.lnk'):

                print(f'{tc.RED} SW_START: {tc.GREEN}Executable is {arg_type} mimetype{tc.END}')
                environ['SW_COMMANDLINE'] = f'"{arg_path}"'
                environ['SW_EXEC'] = f'"{arg_path}"'

            elif arg_type in exe_mime_types:
                print(f'{tc.RED} SW_START: {tc.GREEN}Executable is {arg_type} mimetype{tc.END}')
                environ['SW_COMMANDLINE'] = f'"{arg_path}"'
                environ['SW_EXEC'] = f'"{arg_path}"'
            else:
                print(f'{tc.RED} SW_START: {tc.GREEN}Executable is {arg_type} mimetype{tc.END}')
                environ['SW_COMMANDLINE'] = f'"{arg_path}"'
                environ['SW_EXEC'] = 'StartWine'
        else:
            print(f'{tc.RED} SW_START: Executable not exists...{tc.END}')
            environ['SW_COMMANDLINE'] = 'None'
            environ['SW_EXEC'] = 'StartWine'
    else:
        print(f'{tc.RED} SW_START: {tc.GREEN}Running without args...{tc.END}')
        environ['SW_COMMANDLINE'] = 'None'
        environ['SW_EXEC'] = 'StartWine'

    print(f'{tc.RED} SW_EXEC: {tc.GREEN}{getenv("SW_EXEC")}{tc.END}')


def set_print_run_time(show):
    """___print program run time info___"""

    if show:
        print(
            tc.VIOLET2,
            'RUN_TIME_PROC:      '
            + tc.GREEN
            + str(round(process_time() - start_process, 2)),
            f'\n{tc.VIOLET2} RUN_TIME:           '
            + tc.GREEN
            + str(round(time() - start_time, 2)),
            f'\n{tc.VIOLET2} PERF_TIME:          '
            + tc.GREEN
            + str(round(perf_counter() - start_counter, 2))
            + tc.END)
    else:
        return None


def set_print_id_info(swgs, show, default_display):
    """___print default display and application id info___"""

    if show:
        display = 'Unknown'
        py_ver = str(python_version())
        exc_type = get_arg_mimetype()

        if default_display is not None:
            display = default_display

        print(
            f'\n{tc.SELECTED + tc.BEIGE}'
            + f'--------------< STARTWINE {str_sw_version} >-------------{tc.END}\n'
        )
        print(
            f'{tc.VIOLET2} APPLICATION_ID: {tc.GREEN}{swgs.get_application_id()}\n'
            f"{tc.VIOLET2} DISPLAY:        {tc.GREEN}{str(display).split(' ')[0].strip('<')}\n"
            f'{tc.VIOLET2} PYTHON_VERSION: {tc.GREEN}{py_ver}{tc.END}\n'
            f'{tc.VIOLET2} ADD_MIME_TYPES: {tc.GREEN}{", ".join(exe_mime_types)}\n'
            f'{tc.VIOLET2} EXE_MIME_TYPE:  {tc.GREEN}{exc_type}{tc.END}'
            + tc.END
        )
    else:
        return None


def get_reverse_texture(file: str):
    """___get flip Gdk.Texture from image bytes array___"""

    if Path(file).exists():
        image = Image.open(file)
        image = image.transpose(Image.Transpose.FLIP_LEFT_RIGHT)
        byte_arr = io.BytesIO()
        image.save(byte_arr, format='PNG')
        byte_arr = byte_arr.getvalue()
        texture = Gdk.Texture.new_from_bytes(GLib.Bytes.new(byte_arr))
    else:
        print(f'{file} not found')
        texture = None

    return texture


def update_exe_data(item, data=None):
    """___update executable items data___"""

    check_exe_data(sw_exe_data_json, sw_shortcuts, sw_app_icons)
    global exe_data
    exe_data = ExeData(read_json_data(sw_exe_data_json))
    print(f'{tc.GREEN}Update exe data {item}... Done{tc.END}')


def try_get_exe_logo(event=None):
    """___try to get image for current application.___"""

    app_path = get_app_path()
    app_name = get_out()

    if app_name != 'StartWine' and not check_exe_logo(app_name):
        p = mp.Process(target=get_exe_metadata, args=(app_name, app_path, event))
        process_workers.append(p)
        p.start()
        data = {'func': update_exe_data, 'args': (app_name,)}
        Thread(target=process_event_wait, args=(event, data)).start()


class AppConfReplace:
    """___Application selection window for transferring settings___"""

    def __init__(self, app=None, data=None):
        self.app = app
        self.data = data

    def run(self):
        self.activate()

    def factory_apps_setup(self, factory, items):
        """___setup application config list___"""

        image = Gtk.Picture(
            css_name='sw_picture', hexpand=True, halign=Gtk.Align.FILL,
            content_fit=Gtk.ContentFit.COVER,
        )
        image.add_css_class('gridview')
        image.set_size_request(196, 96)

        pic = Gtk.Picture(
            css_name='sw_uncheck', hexpand=True, halign=Gtk.Align.START,
            content_fit=Gtk.ContentFit.SCALE_DOWN, vexpand=True,
            valign=Gtk.Align.END,
        )
        pic.set_size_request(32, 32)

        label = Gtk.Label(
            css_name='sw_label_view', xalign=0, ellipsize=Pango.EllipsizeMode.END,
            lines=2, wrap=True, natural_wrap_mode=True, hexpand=True,
            halign=Gtk.Align.FILL, vexpand=True, valign=Gtk.Align.CENTER,
        )
        check = Gtk.CheckButton(
            css_name='sw_checkbutton', halign=Gtk.Align.START, vexpand=True,
            valign=Gtk.Align.CENTER,
        )
        check.get_first_child().set_visible(False)
        check.set_child(pic)

        box = Gtk.Box(
            css_name='sw_box_overlay', orientation=Gtk.Orientation.HORIZONTAL,
            spacing=8, hexpand=True, vexpand=True, valign=Gtk.Align.END,
        )
        box.append(check)
        box.append(label)

        child_overlay = Gtk.Overlay(
            css_name='sw_box_view', margin_start=8, margin_end=8, margin_top=8,
            margin_bottom=8,
        )
        child_overlay.set_child(image)
        child_overlay.add_overlay(box)

        items.set_child(child_overlay)

    def factory_apps_bind(self, factory, items):
        """___bind application config list___"""

        item = items.get_item()
        child_overlay = items.get_child()
        image = child_overlay.get_first_child()
        box = child_overlay.get_last_child()
        check = box.get_first_child()
        label = check.get_next_sibling()
        pic = check.get_child()
        path = item.get_path()

        n = ''.join([x for x in Path(path).stem if x.isalnum()])
        p = f'{sw_app_hicons}/{n}'

        try:
            image.set_filename(f'{sw_app_default_icons}/' + Path(path).stem + '_x256.png')
        except (Exception,):
            pass
        else:
            label.set_label(Path(path).stem)

        for x in sw_app_hicons.iterdir():
            if p in str(x):
                image.set_filename(str(x))
                label.set_label(str(x.stem.split('_')[-2]))
                break

        check.set_name(item.get_path())
        check.connect('toggled', self.cb_check, pic)

        if self.check_header.get_active():
            pic.set_filename(IconPath.icon_checked)
            check.set_active(True)
        else:
            pic.set_filename(None)
            self.data.clear()

    def update_apps_view(self):
        """___update application config list store___"""

        self.list_apps_store.remove_all()
        for s in sw_shortcuts.iterdir():
            for c in sw_app_config.iterdir():
                if c.stem == s.stem:
                    f = Gio.File.new_for_path(f'{c}')
                    self.list_apps_store.append(f)

    def cb_check(self, btn, pic):
        """___toggle choosed item in view___"""

        if btn.get_active():
            pic.set_filename(IconPath.icon_checked)
            self.data.append(btn.get_name())
        else:
            pic.set_filename(None)
            self.data.remove(btn.get_name())

    def cb_check_all(self, btn, pic):
        """___toggle all item in view___"""

        if btn.get_active():
            pic.set_filename(IconPath.icon_checked)
        else:
            pic.set_filename(None)

        return self.update_apps_view()

    def cb_btn_ok_choose(self, btn):
        """___moving settings after confirmation from the user___"""

        if self.data is not None:
            if len(self.data) > 0:
                self.data = list(set(self.data))
                for x in self.data:
                    self.on_move_settings(x)
                else:
                    self.win.close()
            else:
                self.win.close()
        else:
            self.win.close()

    def on_move_settings(self, x_conf):
        """___moving current settings to other prefix___"""

        app_name = get_out()
        src_conf = Path(f'{sw_app_config}/{app_name}')
        dst_conf = Path(x_conf)
        src_lst = src_conf.read_text().splitlines()
        dst_lst = dst_conf.read_text().splitlines()
        print(dst_conf)
        for s, d in zip(src_lst, dst_lst):
            if not f'{str_sw_use_pfx}=' in s:
                dst = dst_conf.read_text()
                dst_conf.write_text(dst.replace(d, s))

    def key_pressed(self, _ctrl_key, keyval, _keycode, _state, _widget):
        """___key event handler___"""

        if keyval == Gdk.KEY_Escape:
            return self.win.close()

    def cb_close(self, _btn):
        """___close window___"""

        self.win.close()

    def activate(self):
        """___building and present window___"""

        self.list_apps_store = Gio.ListStore()
        apps_model = Gtk.SingleSelection.new(self.list_apps_store)

        apps_factory = Gtk.SignalListItemFactory()
        apps_factory.connect('setup', self.factory_apps_setup)
        apps_factory.connect('bind', self.factory_apps_bind)

        apps_view = Gtk.GridView(
                        css_name='sw_gridview',
                        hexpand=True,
                        halign=Gtk.Align.CENTER,
        )
        apps_view.set_model(apps_model)
        apps_view.set_factory(apps_factory)

        label_header = Gtk.Label(
                        css_name='sw_label',
                        label=msg.ctx_dict['select_all'][0],
        )
        pic_header = Gtk.Picture(
                        css_name='sw_uncheck',
                        hexpand=True,
                        halign=Gtk.Align.FILL,
                        content_fit=Gtk.ContentFit.COVER,
        )
        pic_header.set_size_request(32, 32)

        self.check_header = Gtk.CheckButton(
                        css_name='sw_checkbutton',
                        child=pic_header,
        )
        self.check_header.get_first_child().set_visible(False)
        self.check_header.connect('toggled', self.cb_check_all, pic_header)

        apps_header = Gtk.Box(
                        css_name='sw_box_view',
                        orientation=Gtk.Orientation.HORIZONTAL,
                        hexpand=True,
        )
        apps_header.append(self.check_header)
        apps_header.append(label_header)

        scrolled = Gtk.ScrolledWindow(
                        css_name='sw_scrolledwindow',
                        child=apps_view,
                        propagate_natural_height=True,
                        vexpand=True,
        )
        apps_grid = Gtk.Grid(
                        css_name='sw_pref_box',
                        vexpand=True,
        )
        apps_grid.attach(apps_header, 0, 0, 1, 1)
        apps_grid.attach(scrolled, 0, 1, 1, 1)

        ok = Gtk.Button(
                        css_name='sw_button_accept',
                        valign=Gtk.Align.CENTER,
                        label=msg.msg_dict['ok'],
        )
        ok.set_size_request(160, -1)
        ok.connect('clicked', self.cb_btn_ok_choose)

        cancel = Gtk.Button(
                        css_name='sw_button_cancel',
                        valign=Gtk.Align.CENTER,
                        label=msg.msg_dict['cancel'],
        )
        cancel.set_size_request(160, -1)
        cancel.connect('clicked', self.cb_close)

        headerbar = Gtk.HeaderBar(
                        css_name='sw_header_top',
                        show_title_buttons=False
        )
        title = Gtk.Label(
                        css_name='sw_label',
                        label=msg.msg_dict['choose_app'],
                        margin_start=8,
                        margin_end=8,
                        ellipsize=Pango.EllipsizeMode.END,
        )
        headerbar.set_title_widget(title)
        headerbar.pack_start(cancel)
        headerbar.pack_end(ok)

        self.win = Gtk.Window(
            css_name='sw_window', application=self.app, titlebar=headerbar,
            modal=True, child=apps_grid, transient_for=self.app.get_active_window(),
        )
        self.ctrl_key = Gtk.EventControllerKey()
        self.ctrl_key.connect('key_pressed', self.key_pressed, self.win)
        self.win.remove_css_class('background')
        self.win.add_css_class('sw_background')
        self.win.set_default_size(1248, 688)
        self.win.add_controller(self.ctrl_key)
        self.update_apps_view()
        self.win.present()


class StartWineGraphicalShell(Gtk.Application):
    """___Building graphical user interface for StartWine___"""

    def __init__(self):
        super().__init__(
                        application_id="ru.launcher.StartWine",
                        flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        GLib.set_prgname(sw_program_name)
        GLib.set_application_name(sw_program_name)
        self.default_display = Gdk.DisplayManager.get().get_default_display()
        self.get_default().register()
        self.cfg = sw_cfg
        self.mp_event = mp.Event()
        self.width = int(self.cfg.get('width')) if self.cfg.get('width') else 1280
        self.height = int(self.cfg.get('height')) if self.cfg.get('height') else 720
        self.default_dir = self.cfg.get('default_dir') if self.cfg.get('default_dir') else f'{Path.home()}'
        self.current_dir = self.cfg.get('current_dir') if self.cfg.get('current_dir') else f'{Path.home()}'
        self.flap_locked = True
        self.f_mon_event = list()
        self.colorscheme = ''
        self.connection = self.get_dbus_connection()
        self.gdbus_node = Gio.DBusNodeInfo.new_for_xml(gdbus_node_sample)
        set_print_id_info(self, True, self.default_display)
        self.connect('activate', sw_activate)


def sw_activate(swgs):
    """___activate application___"""

    def gdbus_method_call(
                        _connection, sender, _object_path, _interface_name,
                        method_name, params, invocation):

        if method_name == "Message":
            parm = params.unpack()[0]

            if parm == 'lnk_error':
                text_message = msg.msg_dict['lnk_error']
            else:
                text_message = None

            if text_message is not None:
                print(f'{sender}: {text_message}')
                SwCrier(text_message=text_message, message_type='ERROR').run()
                invocation.return_value(None)

        elif method_name == "Active":
            name = params.unpack()[0]
            print(f'{sender}: {name}')
            answer = GLib.Variant(
                "(s)", ("True",)
            )
            invocation.return_value(answer)

        elif method_name == "Run":
            if len(params.unpack()) > 0:
                arg = params.unpack()[0].strip('"').replace('**', "'")
                check_arg(arg)

            on_start()
            invocation.return_value(None)

        elif method_name == "Terminal":
            open_window(None)
            on_terminal()
            terminal.feed_child(f'neofetch\n'.encode("UTF-8"))
            invocation.return_value(None)

        elif method_name == "Show":
            if len(params.unpack()) > 0:
                arg = params.unpack()[0].strip('"').replace('**', "'")
                check_arg(arg)

            startup_question()
            invocation.return_value(None)

        elif method_name == "ShowHide":
            window = swgs.get_active_window()

            if window.get_visible():
                hide_window()
            else:
                open_window(None)

            invocation.return_value(None)

        elif method_name == "Shutdown":
            run(f"{sw_scripts}/sw_stop", shell=True)
            swgs.connection.flush(callback=flush_connection, user_data=None)
            invocation.return_value(None)

    def flush_connection(self, res, _data):
        """___Async close dbus connection___"""

        result = self.flush_finish(res)
        print(result)

        winedevices = (
            [
                p.info['pid'] for p in psutil.process_iter(['pid', 'name'])
                if 'winedevice' in p.info['name']
            ]
        )
        for proc in winedevices:
            psutil.Process(proc).kill()

        webkits = (
            [
                p.info['pid'] for p in psutil.process_iter(['pid', 'name'])
                if 'WebKitNetworkProcess' in p.info['name']
            ]
        )
        for proc in webkits:
            psutil.Process(proc).kill()

        timeout_list_clear(None)

        for p in process_workers:
            p.terminate()

        window = swgs.get_active_window()
        window.close()
        swgs.quit()

        #swgs_proc = psutil.Process()
        #print(swgs_proc)
        #swgs_proc.terminate()

    def startup_question():
        """___Startup dialog question___"""

        app_name = get_out()
        app_path = get_app_path()
        write_app_conf(Path(app_path))

        if app_name != 'StartWine':
            if not Path(f'{sw_shortcuts}/{app_name}.swd').exists():
                open_path = Path(Path(app_path.strip('"')).parent)
                on_shortcuts()
                response = [
                            msg.msg_dict['run'].title(),
                            msg.msg_dict['open'].title(),
                            msg.msg_dict['cs'].title(),
                            msg.msg_dict['launch_settings'].title(),
                            msg.msg_dict['cancel'].title(),
                ]
                title = msg.msg_dict['choose']
                message = [Path(app_path.strip('"')).name, '']
                func = [on_start, {open_window: (open_path,)}, on_message_cs, on_startapp_page, None]
                SwDialogQuestion(swgs, title, message, response, func)
            else:
                if not Path(app_path.strip('"')).exists():
                    text_message = msg.msg_dict['lnk_error']
                    SwCrier(text_message=text_message, message_type='ERROR').run()
                else:
                    open_path = Path(Path(app_path.strip('"')).parent)
                    on_shortcuts()
                    response = [
                                msg.msg_dict['run'].title(),
                                msg.msg_dict['open'].title(),
                                msg.msg_dict['launch_settings'].title(),
                                msg.msg_dict['cancel'].title(),
                    ]
                    title = msg.msg_dict['choose']
                    message = [Path(app_path.strip('"')).name, '']
                    func = [on_start, {open_window: (open_path,)}, on_startapp_page, None]
                    SwDialogQuestion(swgs, title, message, response, func)
        else:
            commandline = str(getenv('SW_COMMANDLINE'))
            if commandline != 'None':
                if Path(commandline.strip('"')).exists():
                    open_path = Path(Path(commandline.strip('"')).parent)
                    open_window(open_path)
                else:
                    SwCrier(text_message=f"{msg.msg_dict['lnk_error']}", message_type='ERROR').run()
            else:
                open_window(None)

    def open_window(open_path):

        if open_path is not None:
            on_files(open_path)

        window = swgs.get_active_window()
        window.set_hide_on_close(False)
        window.set_visible(True)
        window.unminimize()

    def hide_window():

        window = swgs.get_active_window()
        window.set_hide_on_close(True)
        window.close()

    def g_file_monitor(_m, f, _o, event_type):
        """___emitted when file has been changed.___"""

        swgs.f_mon_event.clear()

        if (event_type == Gio.FileMonitorEvent.MOVED_OUT
                or event_type == Gio.FileMonitorEvent.MOVED_IN
                or event_type == Gio.FileMonitorEvent.RENAMED
                or event_type == Gio.FileMonitorEvent.MOVED
                or event_type == Gio.FileMonitorEvent.CREATED
                or event_type == Gio.FileMonitorEvent.DELETED
                or event_type == Gio.FileMonitorEvent.CHANGED
                or event_type == Gio.FileMonitorEvent.ATTRIBUTE_CHANGED
                or event_type == Gio.FileMonitorEvent.CHANGES_DONE_HINT):

            swgs.f_mon_event = [f, event_type]

    def cb_ctrl_key_pressed(_ctrl_key_press, keyval, keycode, state, parent):
        """___key pressed events handler___"""

        all_mask = (
                    Gdk.ModifierType.CONTROL_MASK
                    | Gdk.ModifierType.SHIFT_MASK
                    | Gdk.ModifierType.ALT_MASK
                    | Gdk.ModifierType.SUPER_MASK
        )
        letters_list = [
            chr(x) for x in list(range(ord('A'), ord('z') + 1))
            ]
        numbers_list = [
            chr(x) for x in list(range(ord('0'), ord('9') + 1))
            ]

        key_name = Gdk.keyval_name(keyval)
        k_val = display.translate_key(keycode, state, 0)
        f_keys = (
            Gdk.KEY_F1, Gdk.KEY_F2, Gdk.KEY_F3, Gdk.KEY_F4,
            Gdk.KEY_F5, Gdk.KEY_F6, Gdk.KEY_F7, Gdk.KEY_F8,
            Gdk.KEY_F9, Gdk.KEY_F10, Gdk.KEY_F11, Gdk.KEY_F12
        )
        if (not (state & Gdk.ModifierType.ALT_MASK)
                and not (state & Gdk.ModifierType.CONTROL_MASK)
                and not (state & Gdk.ModifierType.SHIFT_MASK)):

            if keyval not in f_keys:
                if key_name == 'period' or key_name == 'KP_Decimal':
                    stack_search_path.set_visible_child(box_search)
                    entry_search.grab_focus()
                    entry_search.set_text('.')
                    entry_search.set_position(-1)

                for letter in letters_list:
                    if key_name in letter:
                        stack_search_path.set_visible_child(box_search)
                        entry_search.grab_focus()
                        entry_search.set_text(key_name)
                        entry_search.set_position(-1)

                for number in numbers_list:
                    if number in key_name:
                        stack_search_path.set_visible_child(box_search)
                        entry_search.grab_focus()
                        entry_search.set_text(number)
                        entry_search.set_position(-1)

        if keyval == Gdk.KEY_F1:
            return on_webview(home_page + '/StartWine-Launcher')

        if keyval == Gdk.KEY_F2:
            if main_stack.get_visible_child() == files_view_grid:
                selected = get_selected_item_gfile()
                parent_file = get_parent_file()
                if len(selected) > 1:
                    if str(get_parent_path()) == str(sw_shortcuts):
                        print(selected)
                    else:
                        return on_files_rename(selected)
                elif len(selected) == 1:
                    if str(get_parent_path()) == str(sw_shortcuts):
                        print(selected)
                    else:
                        return on_file_rename(selected[0])

        if keyval == Gdk.KEY_F3:
            return on_paned_files_view()

        if keyval == Gdk.KEY_F4:
            return on_about()

        if keyval == Gdk.KEY_F5:
            if main_stack.get_visible_child() == files_view_grid:
                parent_file = get_parent_file()
                if parent_file.get_path() is None:
                    parent_uri = parent_file.get_uri()
                    update_grid_view_uri(parent_uri)
                else:
                    on_files(parent_file.get_path())

        if ((state & all_mask) == Gdk.ModifierType.SHIFT_MASK
                and keyval == Gdk.KEY_Delete):

            if main_stack.get_visible_child() == files_view_grid:
                selected = get_selected_item_gfile()
                return on_file_remove(selected)

        if keyval == Gdk.KEY_Delete:
            if main_stack.get_visible_child() == files_view_grid:
                selected = get_selected_item_gfile()
                return on_file_to_trash(selected)

        if ((state & all_mask) == Gdk.ModifierType.SHIFT_MASK
                and k_val[1] in (Gdk.KEY_l, Gdk.KEY_L)):

            if main_stack.get_visible_child() == files_view_grid:
                data = get_selected_item_gfile()
                return on_file_link(data)

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and k_val[1] in (Gdk.KEY_t, Gdk.KEY_T)):

            if main_stack.get_visible_child() == files_view_grid:
                return on_terminal()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and k_val[1] in (Gdk.KEY_v, Gdk.KEY_V)):

            if main_stack.get_visible_child() == files_view_grid:
                return on_video()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and k_val[1] in (Gdk.KEY_m, Gdk.KEY_M)):

            if stack_progress_main.get_visible_child() != media_main_grid:
                stack_progress_main.set_visible_child(media_main_grid)

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and k_val[1] in (Gdk.KEY_d, Gdk.KEY_D)):

            if main_stack.get_visible_child() == files_view_grid:
                return on_drive()

        if ((state & all_mask) == (Gdk.ModifierType.ALT_MASK | Gdk.ModifierType.CONTROL_MASK)
                and keyval == Gdk.KEY_Up):

            if main_stack.get_visible_child() == files_view_grid:
                return on_drive()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and k_val[1] in (Gdk.KEY_b, Gdk.KEY_B)):

            return on_bookmarks()

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and keyval == Gdk.KEY_grave):

            return on_bookmarks()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and k_val[1] in (Gdk.KEY_p, Gdk.KEY_P)):

            return on_playlist()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and k_val[1] in (Gdk.KEY_f, Gdk.KEY_F)):

            swgs.default_dir = swgs.cfg['default_dir']
            return on_files(Path(swgs.default_dir))

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and keyval == Gdk.KEY_1):

            set_view_parent_path(left_grid_view)

            if scrolled_left_files.get_child().get_name() != 'left_column_view':
                add_column_view()
            else:
                scrolled_left_files.set_child(left_grid_view)

            return on_files(Path(get_parent_file().get_path()))

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and k_val[1] in (Gdk.KEY_w, Gdk.KEY_W)):

            return on_download_wine()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and k_val[1] in (Gdk.KEY_a, Gdk.KEY_A)):

            return on_shortcuts()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and k_val[1] in (Gdk.KEY_l, Gdk.KEY_L)):

            return on_install_launchers()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and k_val[1] in (Gdk.KEY_i, Gdk.KEY_I)):

            return on_global_settings()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and k_val[1] in (Gdk.KEY_j, Gdk.KEY_J)):

            return on_controller_settings()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and k_val[1] in (Gdk.KEY_u, Gdk.KEY_U)):

            return on_webview(home_page)

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and k_val[1] in (Gdk.KEY_n, Gdk.KEY_N)):

            if main_stack.get_visible_child() == grid_web:
                add_webview(home_page)

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and keyval == Gdk.KEY_Up):

            return back_up()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and k_val[1] in (Gdk.KEY_s, Gdk.KEY_S)):

            return on_sidebar()

        if keyval == Gdk.KEY_grave:
            return on_sidebar()

        if keyval == Gdk.KEY_Escape:
            if stack_search_path.get_visible_child() != box_path:
                entry_search.set_text('')
                stack_search_path.set_visible_child(box_path)

            if btn_back_main.get_visible():
                return on_back_main()

            elif sidebar_revealer.get_reveal_child():
                return on_sidebar()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and k_val[1] == Gdk.KEY_Return):

            if main_stack.get_visible_child() == files_view_grid:
                data = get_selected_item_gfile()
                on_file_properties()
                if len(data) == 0:
                    get_file_props(get_parent_file())
                elif len(data) == 1:
                    get_file_props(data[0])
                else:
                    get_file_props_list(data)

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and k_val[1] in (Gdk.KEY_w, Gdk.KEY_W)):

            swgs.get_active_window().close()

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and k_val[1] in (Gdk.KEY_q, Gdk.KEY_Q)):

            return on_shutdown()

        if ((state & all_mask) == (Gdk.ModifierType.ALT_MASK | Gdk.ModifierType.CONTROL_MASK)
                and keyval == Gdk.KEY_Escape):

            return on_shutdown()

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and keyval == Gdk.KEY_Menu):

             return cb_btn_view_header_menu(btn_header_menu)

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and keyval == Gdk.KEY_Menu):

            return on_playlist()

        if keyval == Gdk.KEY_Menu:
            if (main_stack.get_visible_child_name() == 'files'
                    or main_stack.get_visible_child_name() == 'shortcuts'):
                return show_item_context()
            else:
                return cb_btn_view_more(btn_more)

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and k_val[1] in (Gdk.KEY_a, Gdk.KEY_A)):

            if main_stack.get_visible_child() == files_view_grid:
                grid_view = get_list_view()
                grid_view.get_model().select_all()

        if ((state & all_mask) == (Gdk.ModifierType.ALT_MASK | Gdk.ModifierType.CONTROL_MASK)
                and keyval == Gdk.KEY_space):

            if main_stack.get_visible_child() == files_view_grid:
                if Path(entry_path.get_name()) == sw_shortcuts:
                    btn_scale_shortcuts.set_value(btn_scale_shortcuts.get_value() + scale_step)
                else:
                    btn_scale_icons.set_value(btn_scale_icons.get_value() + scale_step)

        if ((state & all_mask) == (Gdk.ModifierType.ALT_MASK | Gdk.ModifierType.CONTROL_MASK)
                and keyval == Gdk.KEY_BackSpace):

            if main_stack.get_visible_child() == files_view_grid:
                if Path(entry_path.get_name()) == sw_shortcuts:
                    btn_scale_shortcuts.set_value(btn_scale_shortcuts.get_value() - scale_step)
                else:
                    btn_scale_icons.set_value(btn_scale_icons.get_value() - scale_step)

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and keyval == Gdk.KEY_KP_Add):

            if main_stack.get_visible_child() == files_view_grid:
                if Path(entry_path.get_name()) == sw_shortcuts:
                    btn_scale_shortcuts.set_value(btn_scale_shortcuts.get_value() + scale_step)
                else:
                    btn_scale_icons.set_value(btn_scale_icons.get_value() + scale_step)

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and keyval == Gdk.KEY_KP_Subtract):

            if main_stack.get_visible_child() == files_view_grid:
                if Path(entry_path.get_name()) == sw_shortcuts:
                    btn_scale_shortcuts.set_value(btn_scale_shortcuts.get_value() - scale_step)
                else:
                    btn_scale_icons.set_value(btn_scale_icons.get_value() - scale_step)

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and keyval == Gdk.KEY_equal):

            if main_stack.get_visible_child() == files_view_grid:
                if Path(entry_path.get_name()) == sw_shortcuts:
                    btn_scale_shortcuts.set_value(btn_scale_shortcuts.get_value() + scale_step)
                else:
                    btn_scale_icons.set_value(btn_scale_icons.get_value() + scale_step)

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and keyval == Gdk.KEY_minus):

            if main_stack.get_visible_child() == files_view_grid:
                if Path(entry_path.get_name()) == sw_shortcuts:
                    btn_scale_shortcuts.set_value(btn_scale_shortcuts.get_value() - scale_step)
                else:
                    btn_scale_icons.set_value(btn_scale_icons.get_value() - scale_step)

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and k_val[1] in (Gdk.KEY_d, Gdk.KEY_D)):

            parent.set_interactive_debugging(True)

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and k_val[1] in (Gdk.KEY_t, Gdk.KEY_T)):

            return on_switch_tray()

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and k_val[1] in (Gdk.KEY_h, Gdk.KEY_H)):

            if main_stack.get_visible_child() == files_view_grid:
                return on_hidden_files()

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and k_val[1] in (Gdk.KEY_l, Gdk.KEY_L)):

            stack_search_path.set_visible_child(box_side)
            entry_path.grab_focus()

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and k_val[1] in (Gdk.KEY_n, Gdk.KEY_N)):

            if main_stack.get_visible_child() == files_view_grid:
                parent_file = get_parent_file()
                if parent_file.get_path() is not None:
                    return on_create_dir()

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and k_val[1] in (Gdk.KEY_c, Gdk.KEY_C)):

            if main_stack.get_visible_child() == files_view_grid:
                data = get_selected_item_gfile()
                if data is not None:
                    return on_file_copy(data)

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and k_val[1] in (Gdk.KEY_v, Gdk.KEY_V)):

            if main_stack.get_visible_child() == files_view_grid:
                return on_file_paste()

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and k_val[1] in (Gdk.KEY_x, Gdk.KEY_X)):

            if main_stack.get_visible_child() == files_view_grid:
                data = get_selected_item_gfile()
                return on_file_cut(data)

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and k_val[1] in (Gdk.KEY_k, Gdk.KEY_K)):

            return on_show_hotkeys()

        if ((state & all_mask) == (
                Gdk.ModifierType.SHIFT_MASK | Gdk.ModifierType.CONTROL_MASK)
                and k_val[1] in (Gdk.KEY_k, Gdk.KEY_K)):

            return on_stop()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and keyval == Gdk.KEY_Left):

            if main_stack.get_visible_child_name() == 'startapp_page':
                return cb_btn_prev_shortcut(None)
            else:
                return on_prev()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
                and keyval == Gdk.KEY_Right):

            if main_stack.get_visible_child_name() == 'startapp_page':
                return cb_btn_next_shortcut(None)
            else:
                return on_next()

        if ((state & all_mask) == (
                Gdk.ModifierType.SHIFT_MASK | Gdk.ModifierType.CONTROL_MASK)
                and k_val[1] in (Gdk.KEY_f, Gdk.KEY_F)):

            return on_parent_fullscreen()

    def key_event_handler():
        """___callback of key event handler___"""

        count = 0
        if len(kc_dict) > 0:
            mod = kc_dict.get(1)
            key0 = kc_dict.get(2)
            key1 = kc_dict.get(3)

            if 'BTN_TL' in str(mod) and 'BTN_TR' in str(key0) and 'BTN_A' in str(key1):
                count += 1
                if count == 1:
                    print(f'Event: {mod} {key0} {key1}')
                    if parent.get_visible():
                        parent.close()
                    else:
                        open_window(None)

                    kc_dict.clear()

            if 'KEY_LEFTCTRL' in str(mod) and 'KEY_LEFTSHIFT' in str(key0) and 'KEY_SYSRQ' in str(key1):
                count += 1
                if count == 1:
                    print(f'Event: {mod} {key0} {key1}')
                    run_screencast()
                    kc_dict.clear()

            if 'KEY_LEFTALT' in str(mod) and 'KEY_KPMINUS' in str(key0):
                count += 1
                if count == 1:
                    print(f'Event: {mod} {key0} {key1}')
                    volume_control(vol_dict, '-0.05')
                    kc_dict.clear()

            if 'KEY_LEFTALT' in str(mod) and 'KEY_KPPLUS' in str(key0):
                count += 1
                if count == 1:
                    print(f'Event: {mod} {key0} {key1}')
                    volume_control(vol_dict, '+0.05')
                    kc_dict.clear()

        return True

    def cb_ctrl_lclick_parent(_self, _n_press, x, y):
        """___left click on parent window___"""

        if (terminal_revealer.get_reveal_child()
                and terminal_stack.get_visible_child() == terminal):

            terminal.set_visible(False)
            terminal_revealer.set_reveal_child(False)
            files_view_grid.set_position(-1)

#    def cb_ctrl_swipe_panel(self, x, y, data):
#        """___swipe gesture on the bottom panel of the window___"""

#        swap_x = x*1000
#        swap_y = y*1000
#        print(swap_x, swap_y)
#        if swap_x != 0.0:
#            if swap_x > swap_y:
#                return on_next()
#            elif swap_x < swap_y:
#                return on_prev()

    def cb_ctrl_motion_headerbar(_self, x, y, data):
        """______"""

        swgs.x = x
        swgs.y = y

        if getenv('SW_AUTO_HIDE_TOP_HEADER') == '1':
            if (y <= 32
                    or stack_search_path.get_visible_child() == box_search
                    or stack_search_path.get_visible_child() == box_web):

                top_headerbar_revealer.set_reveal_child(True)

            elif y > 32:
                top_headerbar_revealer.set_reveal_child(False)

        if getenv('SW_AUTO_HIDE_BOTTOM_HEADER') == '1':
            if (y >= (data.get_height() - 32)
                    or progress_main.get_visible()):

                bottom_headerbar_revealer.set_reveal_child(True)

            else:
                bottom_headerbar_revealer.set_reveal_child(False)

    def cb_ctrl_key_term(_ctrl_key_press, keyval, keycode, state, terminal):
        """___key press events in terminal___"""

        k_val = display.translate_key(keycode, state, 0)
        all_mask = (
                    Gdk.ModifierType.CONTROL_MASK
                    | Gdk.ModifierType.SHIFT_MASK
                    | Gdk.ModifierType.ALT_MASK
                    | Gdk.ModifierType.SUPER_MASK
        )
        if ((state & all_mask) == (
                Gdk.ModifierType.CONTROL_MASK | Gdk.ModifierType.SHIFT_MASK)
                and k_val[1] in (Gdk.KEY_v, Gdk.KEY_V)):

            terminal.paste_clipboard()

        if ((state & all_mask) == (
                Gdk.ModifierType.SHIFT_MASK | Gdk.ModifierType.CONTROL_MASK)
                and k_val[1] in (Gdk.KEY_c, Gdk.KEY_C)):

            terminal.copy_clipboard()

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and keyval == Gdk.KEY_KP_Add):

            s = terminal.get_font_scale()
            terminal.set_font_scale(s+0.1)

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and keyval == Gdk.KEY_equal):

            s = terminal.get_font_scale()
            terminal.set_font_scale(s+0.1)

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and keyval == Gdk.KEY_minus):

            s = terminal.get_font_scale()
            terminal.set_font_scale(s-0.1)

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
                and keyval == Gdk.KEY_KP_Subtract):

            s = terminal.get_font_scale()
            terminal.set_font_scale(s-0.1)

    def cb_ctrl_rclick_term(_self, _n_press, _x, _y):
        """___vte terminal right click event___"""

        terminal.paste_clipboard()

    def cb_terminal_selection_changed(_self):
        """___emitted when vte terminal selection changed___"""
        terminal.copy_clipboard()

    def cb_terminal_changed(_self, _pid, _error, _data):
        """___vte terminal pid___"""
        pass

    def overlay_info(_overlay, title, message, icon, response, timer):
        """___dialog info widget for text message in overlay widget___"""

        def timer_finish(q):
            q.append('close')

        def close(grid_info):
            """___remove overlay info message___"""

            grid_info.set_visible(False)

        def cb_btn_exit(_self):
            """___remove overlay info message___"""
            return close(grid_info)

        if title is None:
            title = f'{sw_program_name} INFO'

        title_info.set_label(title)

        if message is None:
            label_info.set_visible(False)
        else:
            label_info.set_visible(True)
            label_info.set_label(str(message))

        if icon is not None:
            image_info.set_from_file(icon)
        else:
            image_info.set_from_file(None)

        if response is not None:
            btn_info_response.set_visible(True)
            btn_info_response.connect('clicked', response)
        else:
            btn_info_response.set_visible(False)

        if timer is not None:
            q = []
            t = Timer(timer, timer_finish, args=[q])
            t.start()
            GLib.timeout_add(1000, check_alive, t, close, grid_info, None)

        btn_info_exit.connect('clicked', cb_btn_exit)
        grid_info.set_visible(True)

    def progress_on_thread(bar, thread, info):

        if thread.is_alive():
            stack_progress_main.set_visible_child(progress_main_grid)
            bar.set_visible(True)
            bar.pulse()
            environ['FRAGMENT_NUM'] = f'{len(fragments_list) - 1}'
            return True
        else:
            bar.set_fraction(0.0)
            bar.set_show_text(False)
            bar.set_visible(False)
            stack_progress_main.set_visible_child(stack_panel)

            if getenv('FRAGMENT_INDEX') is not None:
                environ['FRAGMENT_NUM'] = str(getenv('FRAGMENT_INDEX'))

            if bar.get_name() == 'create_shortcut':
                print('create_shortcut: done')

            if bar.get_name() == 'install_launchers':
                on_install_launchers()

            if bar.get_name() == 'install_wine':
                on_download_wine()

            if bar.get_name() == 'pfx_remove':
                environ['SW_EXEC'] = ''

            if info is not None:
                overlay_info(main_overlay, None, info, None, None, 3)

            return False

    def progress_percent_on_thread(bar, thread, fraction):

        if thread.is_alive():
            stack_progress_main.set_visible_child(progress_main_grid)
            bar.set_visible(True)
            bar.set_fraction(fraction)
            environ['FRAGMENT_NUM'] = f'{len(fragments_list) - 1}'
            return True
        else:
            stack_progress_main.set_visible_child(stack_panel)
            bar.set_show_text(False)
            bar.set_visible(False)
            bar.set_fraction(0.0)
            if getenv('FRAGMENT_INDEX') is not None:
                environ['FRAGMENT_NUM'] = str(getenv('FRAGMENT_INDEX'))
            return False

    def cb_btn_search(_self):
        """___show search entry widget___"""

        stack_search_path.set_visible_child(box_search)

    def cb_entry_search_changed(_self):
        """___filter list items when search___"""

        wv_main = main_stack.get_visible_child().get_name()
        parent_file = get_parent_file()

        if parent_file is not None:

            if wv_main == vw_dict['shortcuts']:
                if main_stack.get_visible_child() == files_view_grid:
                    if parent_file.get_path() is not None:
                        on_view_search()
                    else:
                        overlay_info(main_overlay, None, msg.msg_dict['action_not_supported'], None, None, 3)

            elif wv_main == vw_dict['files']:
                if main_stack.get_visible_child() == files_view_grid:
                    if parent_file.get_path() is not None:
                        on_view_search()
                    else:
                        overlay_info(main_overlay, None, msg.msg_dict['action_not_supported'], None, None, 3)

            elif wv_main == vw_dict['install_launchers']:
                if main_stack.get_visible_child() == scrolled_install_launchers:
                    swgs.launchers_flow.set_filter_func(on_flowbox_search_filter, launchers_list)

            elif wv_main == vw_dict['startapp_page']:
                if stack_settings.get_visible_child() == scrolled_launch_settings:
                    ls_names = lp_title + switch_labels
                    swgs.launch_flow.set_filter_func(on_flowbox_search_filter, ls_names)

                elif stack_settings.get_visible_child() == scrolled_mangohud_settings:
                    swgs.mangohud_flow.set_filter_func(on_flowbox_search_filter, check_mh_labels)
                    swgs.colors_flow_mh.set_filter_func(on_flowbox_search_filter, mh_colors_description)

                elif stack_settings.get_visible_child() == scrolled_vkbasalt_settings:
                    swgs.vkbasalt_flow.set_filter_func(on_flowbox_search_filter, vkbasalt_dict)

            elif wv_main == vw_dict['winetricks']:
                if main_stack.get_visible_child() == scrolled_winetricks:
                    if swgs.stack_tabs.get_visible_child() == swgs.scrolled_dll:
                        on_winetricks_search(swgs.list_store_dll_0, dll_dict)
                    elif swgs.stack_tabs.get_visible_child() == swgs.scrolled_fonts:
                        on_winetricks_search(swgs.list_store_fonts, fonts_dict)

    def cb_entry_search_stop(self):
        """___stop and hide search when press Escape___"""

        if stack_search_path.get_visible_child() == box_search:
            self.set_text('')
            stack_search_path.set_visible_child(box_path)

    def on_view_search():
        """___recursive search for files in the current directory___"""

        find = entry_search.get_text().lower()
        start_path = Path(entry_path.get_name())
        parent_path_list.append(start_path)

        paned_store = get_list_store()
        dir_list = get_dir_list()

        def get_found():
            """___append found files to list store___"""

            paned_store.remove_all()
            timeout_list_clear(None)
            count = 24
            for r, d, f in walk(start_path):
                if len(search_is_empty) == 0:
                    paned_store.remove_all()
                    timeout_list_clear(None)
                    break

                for x in d:
                    if find in x.lower():
                        count += 2
                        p = Path(join(r, x))
                        x_file = Gio.File.new_for_path(bytes(p))
                        x_info = x_file.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
                        timeout_info = GLib.timeout_add(
                            count, get_file_info, paned_store, dir_list, x_file, x_info, None
                        )
                        timeout_list.append(timeout_info)

                for x in f:
                    if find in x.lower():
                        count += 2
                        p = Path(join(r, x))
                        x_file = Gio.File.new_for_path(bytes(p))
                        x_info = x_file.query_info('*', Gio.FileQueryInfoFlags.NONE, None)

                        timeout_info = GLib.timeout_add(
                            count, get_file_info, paned_store, dir_list, x_file, x_info, None
                        )
                        timeout_list.append(timeout_info)

        def clear():
            """___terminate all when thread is dead and search is done___"""

            find = entry_search.get_text().lower()

            if len(find) <= 1:
                x_hidden_files = getenv('SW_HIDDEN_FILES')
                paned_store.remove_all()
                timeout_list_clear(None)
                count = 24
                g_file = Gio.File.new_for_path(bytes(start_path))
                g_enum = g_file.enumerate_children('*', Gio.FileQueryInfoFlags.NONE)
                sorted_list = sort_func(g_enum)

                for x in sorted_list:
                    count += 2
                    x_file = g_enum.get_child(x)
                    timeout_info = GLib.timeout_add(
                        count, get_file_info, paned_store, dir_list, x_file, x, x_hidden_files
                    )
                    timeout_list.append(timeout_info)

        if stack_search_path.get_visible_child() == box_search:
            if start_path is not None:

                if len(find) <= 1:
                    search_is_empty.clear()
                    clear()

                if len(find) > 1:
                    search_is_empty.append(find)
                    paned_store.remove_all()
                    timeout_list_clear(None)

                    if str(start_path) == str(sw_shortcuts):
                        count = 24
                        with scandir(path=start_path) as sp:
                            for x in sp:
                                if find in str(x.name).lower():
                                    count += 2
                                    p = Path(join(start_path, str(x.name)))
                                    x_file = Gio.File.new_for_path(bytes(p))
                                    x_info = x_file.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
                                    timeout_info = GLib.timeout_add(
                                        count, get_file_info, paned_store, dir_list, x_file, x_info, None
                                    )
                                    timeout_list.append(timeout_info)
                    else:
                        thread_get_found = Thread(target=get_found)
                        thread_get_found.start()
                        progress_main.set_show_text(True)
                        progress_main.set_text(progress_dict['search'])
                        GLib.timeout_add(100, progress_on_thread, progress_main, thread_get_found, None)

    def on_flowbox_search_filter(fb_child, data_labels):
        """___filter item in flowbox___"""

        fb_name = []
        for line in data_labels:
            if fb_child.get_name() in str(line):
                fb_name = [line]

        find = entry_search.get_text()

        for line in fb_name:
            if find.lower() in line.lower():
                return True

    def on_winetricks_search(x_tab_store, x_dict):
        """___search item in winetricks list___"""

        w_log = get_dll_info(get_pfx_path())
        find = entry_search.get_text()
        found = [line for line in list(x_dict) if find.lower() in line.lower()]

        if len(find) <= 1:
            update_dll_store()

        if len(find) > 1:
            x_tab_store.remove_all()

            for x in found:
                x_store = Gtk.Label(label=x)
                x_store.set_name(x)

                for w in w_log:
                    if str(x) == str(w):
                        x_store.set_name(f'installed_{x}')
                        break

                x_tab_store.append(x_store)

    def append_dll(x_dll, y_dll, f_dll):
        """___append dll items to list store___"""

        if x_dll is not None:
            swgs.list_store_dll_0.append(x_dll)

        if y_dll is not None:
            swgs.list_store_dll_1.append(y_dll)

        if f_dll is not None:
            swgs.list_store_fonts.append(f_dll)

        return False

    def update_dll_store():
        """___update dlls and fonts list___"""

        w_log = get_dll_info(get_pfx_path())
        swgs.list_store_dll_0.remove_all()
        swgs.list_store_dll_1.remove_all()
        swgs.list_store_fonts.remove_all()

        def update_dll():

            d_count = 0
            for i, d in enumerate(list(dll_dict), start=0):
                dll = Gtk.Label(label=d)
                if i <= len(list(dll_dict)) / 2:
                    for w in w_log:
                        if str(d) == str(w):
                            dll.set_name(f'installed_{d}')
                            print(f'{tc.BLUE}UPDATE_DLL_INFO: {tc.GREEN}{dll.get_name()}{tc.END}')
                            break

                    d_count += 10
                    GLib.timeout_add(d_count, append_dll, dll, None, None)

                if i > len(list(dll_dict)) / 2:
                    for w in w_log:
                        if str(d) == str(w):
                            dll.set_name(f'installed_{d}')
                            print(f'{tc.BLUE}UPDATE_DLL_INFO: {tc.GREEN}{dll.get_name()}{tc.END}')
                            break

                    d_count += 10
                    GLib.timeout_add(d_count, append_dll, None, dll, None)

        def update_fonts():

            f_count = 0
            for f in list(fonts_dict):
                font = Gtk.Label(label=f)
                for w in w_log:
                    if str(f) == str(w):
                        font.set_name(f'installed_{f}')
                        print(f'{tc.BLUE}UPDATE_DLL_INFO: {tc.GREEN}{font.get_name()}{tc.END}')
                        break

                f_count += 10
                GLib.timeout_add(f_count, append_dll, None, None, font)

        update_dll()
        update_fonts()

    def cb_btn_path(_self):
        """___show path bar widget___"""

        stack_search_path.set_visible_child(box_path)

    def cb_btn_back_path(_self):
        """___show path bar widget___"""

        stack_search_path.set_visible_child(box_path)

    def cb_entry_path_activate(self):
        """___activate found list items___"""

        path = Path(self.get_name())
        return on_files(path)

    def cb_ctrl_scroll_path(self, _x, y):
        """___mouse scroll event to scroll path bar___"""

        if self.get_unit() == Gdk.ScrollUnit.WHEEL:
            if y == -1.0:
                hadjustment_path.set_value(0)
            elif y == 1.0:
                hadjustment_path.set_value(1000)

    def create_web_view():
        """___Create new web page in web view___"""

        swgs.hit_test_uri = None

        webview_network_session = WebKit.NetworkSession.new(
                                    cache_directory=f'{sw_fm_cache_database}',
                                    data_directory=f'{sw_fm_cache_database}'
        )
        webview_network_session.connect('download-started', cb_network_session_download_started)

        web_data_manager = webview_network_session.get_website_data_manager()
        web_data_manager.set_favicons_enabled(True)

        favicon_database = web_data_manager.get_favicon_database()
        favicon_database.connect('favicon-changed', cb_favicon_changed)

        webview = WebKit.WebView(
            network_session=webview_network_session,
            automation_presentation_type=WebKit.AutomationBrowsingContextPresentation.TAB,
        )
        webview.connect('load-changed', cb_webview_load_changed)
        webview.connect('decide-policy', cb_webview_decide_policy)
        webview.connect('mouse-target-changed', cb_webview_mouse_target_changed)
        webview.connect('resource-load-started', cb_web_resource_load_started)
        webview.connect('permission-request', cb_web_permission_request)
        webview.connect('create', cb_web_create)
        webview.connect('context-menu', cb_webview_context_menu)
        #webview.connect('authenticate', cb_web_authenticate)
        webview_settings = webview.get_settings()
        webview_settings.set_enable_write_console_messages_to_stdout(True)
        webview_settings.set_javascript_can_open_windows_automatically(True)
        webview_settings.set_javascript_can_access_clipboard(True)
        webview_settings.set_allow_modal_dialogs(True)
        webview_settings.set_allow_file_access_from_file_urls(True)
        webview_settings.set_allow_top_navigation_to_data_urls(True)
        webview_settings.set_allow_universal_access_from_file_urls(True)
        #webview_settings.set_enable_caret_browsing(True)
        webview_settings.set_enable_spatial_navigation(True)
        webview_settings.set_enable_media_capabilities(True)
        webview_settings.set_enable_dns_prefetching(True)
        webview_settings.set_enable_encrypted_media(False)
        webview_settings.set_enable_webgl(False)
        webview_settings.set_enable_webrtc(True)
        webview_settings.set_enable_mock_capture_devices(True)

        scrolled_webview = Gtk.ScrolledWindow(
                                            css_name='sw_scrolledwindow',
                                            name=vw_dict['web_view'],
                                            vexpand=True,
                                            hexpand=True,
                                            valign=Gtk.Align.FILL,
                                            halign=Gtk.Align.FILL,
                                            child=webview,
        )
        title_box = Gtk.Box(css_name='sw_row', spacing=32, orientation=Gtk.Orientation.HORIZONTAL)
        image = Gtk.Picture(css_name='sw_picture')
        image.set_size_request(16, 16)
        label = Gtk.Label(
                        css_name='sw_label_info',
                        label=str(home_page.split('/')[-1]),
                        ellipsize=Pango.EllipsizeMode.END,
                        width_request=160
        )
        button = Gtk.Button(css_name='sw_wc_close', valign=Gtk.Align.CENTER)
        button.connect('clicked', cb_web_page_close, webview)
        title_box.append(image)
        title_box.append(label)
        title_box.append(button)
        stack_web.append_page(scrolled_webview, title_box)

    def update_web_page_tab(url, load, favicon):

        if stack_web.get_nth_page(0) is None:
            create_web_view()

        page_num = stack_web.get_current_page()
        page = stack_web.get_nth_page(page_num)
        webview = page.get_child().get_child()

        title_box = Gtk.Box(
                            css_name='sw_row',
                            spacing=32,
                            orientation=Gtk.Orientation.HORIZONTAL
        )
        if favicon is not None:
            image = Gtk.Picture(css_name='sw_picture')
            image.new_for_paintable(favicon)
            image.set_content_fit(Gtk.ContentFit.SCALE_DOWN)
            image.set_size_request(16, 16)
            title_box.append(image)

        label = Gtk.Label(
                        css_name='sw_label_info',
                        label=str(url.split('/')[-1]),
                        ellipsize=Pango.EllipsizeMode.END,
                        width_request=160
        )
        button = Gtk.Button(css_name='sw_wc_close', valign=Gtk.Align.CENTER)
        button.connect('clicked', cb_web_page_close, webview)
        title_box.append(label)
        title_box.append(button)

        stack_web.set_tab_label(page, title_box)

        if load is not None:
            webview.load_uri(url)

    def on_webview(url):

        environ['LAST_VIEW_PAGE'] = str(main_stack.get_visible_child_name())
        btn_back_main.set_visible(True)

        if stack_web.get_nth_page(0) is None:
            create_web_view()

        webview = stack_web.get_nth_page(0).get_child().get_child()
        webview.load_uri(url)

        stack_search_path.set_visible_child(box_web)
        entry_web.grab_focus()

        return set_settings_widget(
                                main_stack,
                                vw_dict['web_view'],
                                None
        )

    def add_webview(url):

        create_web_view()
        num_pages = stack_web.get_n_pages()
        stack_web.set_current_page(num_pages-1)
        webview = stack_web.get_nth_page(num_pages-1).get_child().get_child()
        webview.load_uri(url)

    def cb_btn_add_webview(self):

        url = self.get_name()
        add_webview(url)

    def cb_web_resource_load_started(_self, _resource, request):
        """___signal emitted when a new resource is going to be loaded___"""

        print('Request uri:', request.get_uri())

    def cb_web_permission_request(_self, request):
        """___signal is emitted when WebKit is requesting the client to decide 
        about a permission request___"""

        request.allow()

#    def cb_authenticated(self, credential):
#        """___signal is emitted when the user authentication request succeeded___"""

#        print('Authenticated succeeded:', credential)

#    def cb_cancelled(self):
#        """___signal is emitted when the user authentication request cancelled___"""

#        print('Authenticate cancelled')

#    def cb_web_authenticate(self, request):
#        """___emitted when the user is challenged with HTTP authentication___"""

#        credential = WebKit.Credential.new(
#                                        username, password,
#                                        WebKit.CredentialPersistence.SESSION
#        )
#        request.connect('authenticated', cb_authenticated)
#        request.connect('authenticated', cb_cancelled)
#        request.authenticate(credential)

    def cb_web_create(_self, _navigation_action):
        """___emitted when the creation of a new WebKitWebView is requested___"""

        if swgs.hit_test_uri is not None:
            return add_webview(swgs.hit_test_uri)

    def cb_webview_context_menu(_self, _context_menu, hit_test_result):
        """___emitted when a context menu is about to be displayed ___"""

        swgs.hit_test_uri = hit_test_result.get_link_uri()
        print(tc.YELLOW, hit_test_result.get_link_uri(), tc.END)

    def cb_entry_web_activate(self):

        buffer = self.get_buffer()
        url = buffer.get_text()
        if '://' not in url:
            url = 'https://www.google.com/search?q=' + url

            if url.endswith('/'):
                url = url.rstrip('/')

        update_web_page_tab(url, True, None)

    def cb_webview_load_changed(self, _load_event):
        """___handler for changing the loading state of a web page___"""

        url = self.get_uri()
        if url.endswith('/'):
            url = url.rstrip('/')

        format_url = WebKit.uri_for_display(url)
        entry_web.set_text(url)
        favicon = self.get_favicon()

        if favicon is not None:
            update_web_page_tab(format_url, None, favicon)
        else:
            update_web_page_tab(format_url, None, None)

    def cb_favicon_get(self, res, _data):
        """___returns changed favicon from the database___"""

        try:
            result = self.get_favicon_finish(res)
        except Exception as e:
            print(e)
        else:
            print(result)

    def cb_favicon_changed(self, page_uri, favicon_uri):
        """___signal emitted when the favicon URI of page_uri has been changed
         to favicon_uri in the database___"""

        self.get_favicon(
                        page_uri=page_uri,
                        cancellable=Gio.Cancellable(),
                        callback=cb_favicon_get,
                        user_data=favicon_uri,
        )

    def cb_network_session_download_started(_self, download):
        """___signal emitted when download started___"""

        if download is not None:
            uri = download.get_web_view().get_uri()
            name = download.get_web_view().get_uri().split('/')[-1]

            if 'steamgriddb' in uri:
                download.set_destination(f'{sw_fm_cache_donloads}/{name}')

            download.set_allow_overwrite(True)
            #download.connect('decide-destination', cb_download_decide_destination)
            download.connect('created-destination', cb_download_create_destination)
            download.connect('received-data', cb_download_received_data)
            download.connect('failed', cb_download_failed)
            download.connect('finished', cb_download_finished)

    def cb_download_finished(self):
        """___signal emitted when download finished___"""

        current_image_path = Path(str(getenv(f'{get_out()}')))
        cache = self.get_destination()

        if Path(cache).exists():
            gfile = Gio.File.new_for_path(cache)
            ginfo = gfile.query_info('*', Gio.FileQueryInfoFlags.NONE)
            gtype = ginfo.get_content_type()

            if gtype in image_mime_types:
                app_name = get_out().replace('_', ' ')
                app_name_isalnum = ''.join(e for e in app_name if e.isalnum())
                app_id = Path(cache).stem
                length = len(app_name)
                is_lower_around = (
                                    lambda: app_name[i-1].islower() or 
                                    length > (i + 1) and app_name[i + 1].islower()
                )
                count = 0
                parts = []
                for i in range(1, length):
                    if app_name[i].isupper() and is_lower_around():
                        parts.append(app_name[count: i])
                        count = i

                parts.append(app_name[count:])
                edited_name = ' '.join(parts)
                name = current_image_path.name

                if '/hero/' in self.get_web_view().get_uri():
                    name = name.replace('_horizontal_', '_heroes_').replace('_vertical_', '_heroes_')
                    destination = f'{sw_app_heroes_icons}/{name}'
                    try:
                        convert_image(cache, destination, 3840, 1240)
                    except (Exception,):
                        shutil.move(cache, destination)
                        exe_data.set_(app_name, 'heroes', name)
                        print(f'{tc.GREEN} Copy heroes icon: {tc.YELLOW}{destination} {tc.END}')
                    else:
                        exe_data.set_(app_name, 'heroes', name)
                        print(f'{tc.GREEN} Convert heroes icon: {tc.YELLOW}{destination} {tc.END}')

                elif getenv('ICON_POSITION') == 'vertical':
                    name = name.replace('_horizontal_', '_vertical_')
                    if not Path(f'{sw_app_vicons}/{name}').exists():
                        name = f'{app_name_isalnum}_vertical_{edited_name}_{app_id}.jpg'

                    destination = f'{sw_app_vicons}/{name}'
                    try:
                        convert_image(cache, destination, 400, 600)
                    except (Exception,):
                        shutil.move(cache, destination)
                        exe_data.set_(app_name, 'vertical', name)
                        print(f'{tc.GREEN} Copy vertical icon: {tc.YELLOW}{destination} {tc.END}')
                    else:
                        exe_data.set_(app_name, 'vertical', name)
                        print(f'{tc.GREEN} Convert vertical icon: {tc.YELLOW}{destination} {tc.END}')

                elif getenv('ICON_POSITION') == 'horizontal':
                    name = name.replace('_vertical_', '_horizontal_')
                    if not Path(f'{sw_app_hicons}/{name}').exists():
                        name = f'{app_name_isalnum}_horizontal_{edited_name}_{app_id}.jpg'

                    destination = f'{sw_app_hicons}/{name}'
                    try:
                        convert_image(cache, destination, 644, 301)
                    except (Exception,):
                        shutil.move(cache, destination)
                        exe_data.set_(app_name, 'horizontal', name)
                        print(f'{tc.GREEN} Copy horizontal icon: {tc.YELLOW}{destination} {tc.END}')
                    else:
                        exe_data.set_(app_name, 'horizontal', name)
                        print(f'{tc.GREEN} Convert horizontal icon: {tc.YELLOW} {destination} {tc.END}')
                else:
                    message = msg.msg_dict['download_failed']
                    return overlay_info(main_overlay, None, message, None, None, 5)

            message = f'Download to {self.get_destination()} completed'
            return overlay_info(main_overlay, None, message, None, None, 5)
        else:
            message = f'Downloaded file not exists, try again...'
            return overlay_info(main_overlay, None, message, None, None, 5)

    def cb_download_failed(_self, error):
        """___signal is emitted when an error occurs during the download operation___"""

        if error:
            return overlay_info(main_overlay, None, error, None, None, 5)

    def cb_download_create_destination(_self, destination):
        """___Notify that destination file has been created successfully at destination___"""

        print(f'{tc.VIOLET}CREATE_DOWNLAOD_DESTINATION: {tc.GREEN}{destination}{tc.END}')

    def cb_download_received_data(self, _data_length):
        """___ signal is emitted after response is received, 
        every time new data has been written to the destination___"""

        fraction = self.get_estimated_progress()
        stack_progress_main.set_visible_child(progress_main_grid)
        progress_main.set_visible(True)
        progress_main.set_show_text(True)
        progress_main.set_fraction(fraction)
        if fraction >= 1:
            progress_main.set_fraction(0)
            progress_main.set_show_text(False)
            progress_main.set_visible(False)
            stack_progress_main.set_visible_child(stack_panel)

    def cb_decide_destination(self, res, webkit_download):
        """___response callback to the selected destination___

        try:
            result = self.select_folder_finish(res)
        except GLib.GError as e:
            SwCrier(text_message=str(e.message), message_type='ERROR').run()
        else:
            url_name = str(entry_web.get_text()).split('/')[-1]
            path = str(result.get_path()) + '/' + url_name
            webkit_download.set_destination(path)
            print(f'{tc.VIOLET}SET_DOWNLAOD_DESTINATION: {tc.GREEN}{path}{tc.END}')
        """

    def cb_download_decide_destination(self, suggested_filename):
        """___a response has been received to decide a destination for the download___

        title = 'Change Directory'
        dialog = SwDialogDirectory(title)
        dialog.select_folder(
                    parent=parent,
                    cancellable=Gio.Cancellable(),
                    callback=cb_decide_destination,
                    user_data=self,
        )
        """

    def cb_webview_decide_policy(_self, decision, decision_type):
        """___requesting the client to decide a policy decision___"""

        if decision_type == WebKit.PolicyDecisionType.RESPONSE:
            if not decision.is_mime_type_supported():
                decision.download()

    def cb_webview_mouse_target_changed(_self, hit_test_result, _modifiers):
        """___when the mouse cursor moves over an web page element___"""

        if hit_test_result.get_link_uri() is not None:
            label_overlay.set_visible(True)
            label_overlay.set_label(hit_test_result.get_link_uri())
            swgs.hit_test_uri = hit_test_result.get_link_uri()
        else:
            swgs.hit_test_uri = None
            label_overlay.set_visible(False)

    def cb_web_page_close(_self, webview):
        """___closing a web page tab___"""

        webview.terminate_web_process()
        webview.try_close()
        page_num = stack_web.get_current_page()
        stack_web.remove_page(page_num)

    def cb_paned_cycle_child_focus(self, _reversed):
        """___Emitted to cycle the focus between the children of the paned.___"""

        print(self.get_focus_child().get_name())

    def cb_paned_cycle_handle_focus(self):
        """___Emitted to accept the current position of the handle.___"""

        print(self.get_position())

    def on_paned_files_view():
        """___paned files grid view___"""

        if paned_grid_view.get_end_child() is not None:
            paned_grid_view.set_end_child(None)
        else:
            right_grid_factory = Gtk.SignalListItemFactory()
            right_list_model = Gtk.MultiSelection.new(right_list_store)

            right_grid_view = Gtk.GridView(name='right_grid_view', css_name='sw_gridview')
            right_grid_view.set_enable_rubberband(True)
            right_grid_view.set_min_columns(1)
            right_grid_view.set_max_columns(16)
            right_grid_view.set_tab_behavior(Gtk.ListTabBehavior.ITEM)

            right_grid_view.set_factory(right_grid_factory)
            right_grid_view.set_model(right_list_model)
            right_grid_view.connect('activate', cb_item_activate)

            right_grid_factory.connect('setup', cb_factory_setup, right_grid_view)
            right_grid_factory.connect('bind', cb_factory_bind, right_grid_view)
            right_grid_factory.connect('teardown', cb_grid_factory_teardown)
            right_grid_factory.connect('unbind', cb_grid_factory_unbind)

            ctrl_lclick_view_ = Gtk.GestureClick()
            ctrl_lclick_view_.connect('pressed', cb_ctrl_lclick_view)
            ctrl_lclick_view_.set_button(1)

            ctrl_rclick_view_ = Gtk.GestureClick()
            ctrl_rclick_view_.connect('pressed', cb_ctrl_rclick_view)
            ctrl_rclick_view_.set_button(3)

            ctrl_drag_source_ = Gtk.DragSource()
            ctrl_drag_source_.set_actions(Gdk.DragAction.MOVE)
            ctrl_drag_source_.connect('prepare', cb_ctrl_drag_prepare)
            ctrl_drag_source_.connect('drag-end', cb_ctrl_drag_end)
            ctrl_drag_source_.connect('drag-cancel', cb_ctrl_drag_cancel)

            ctrl_drop_target = Gtk.DropTarget()
            types = (Gdk.FileList, Gio.File)
#            action_copy = Gdk.DragAction.COPY
            action_move = Gdk.DragAction.MOVE
#            action_ask = Gdk.DragAction.ASK

            ctrl_drop_target.set_gtypes(types)
            ctrl_drop_target.set_actions(action_move)
            ctrl_drop_target.set_preload(True)
            ctrl_drop_target.connect('drop', cb_ctrl_drop_target)

            ctrl_right_view_motion = Gtk.EventControllerMotion()
            ctrl_right_view_motion.connect('enter', cb_ctrl_right_view_motion)

            ctrl_right_view_focus = Gtk.EventControllerFocus()
#            ctrl_right_view_focus.connect('enter', cb_ctrl_right_view_focus)
#            ctrl_left_view_focus.connect('leave', cb_ctrl_right_view_focus)

            right_grid_view.add_controller(ctrl_drag_source_)
            right_grid_view.add_controller(ctrl_lclick_view_)
            right_grid_view.add_controller(ctrl_rclick_view_)
            right_grid_view.add_controller(ctrl_right_view_motion)
            right_grid_view.add_controller(ctrl_right_view_focus)

            scrolled_right_files = Gtk.ScrolledWindow(
                                            css_name='sw_scrolled_view',
                                            name='right_files',
                                            vexpand=True,
                                            hexpand=True,
                                            valign=Gtk.Align.FILL,
                                            halign=Gtk.Align.FILL,
                                            child=right_grid_view,
            )
            paned_grid_view.set_end_child(scrolled_right_files)

            right_dir_list.set_file(Gio.File.new_for_path(swgs.default_dir))
            set_view_parent_path(right_grid_view)
            swgs.default_dir = swgs.cfg.get('default_dir')
            return on_files(swgs.default_dir)

    def on_files(path):
        """___show files list view___"""

        timeout_list_clear(None)
        on_show_hidden_widgets(vw_dict['files'])
        if stack_sidebar.get_visible_child() == frame_main:
            btn_back_main.set_visible(False)

        if Path(path).is_dir():
            try:
                update_grid_view(path)
            except PermissionError as e:
                return overlay_info(main_overlay, None, e, None, None, 3)
            else:
                terminal.feed_child(f'cd "{str(path)}" && clear\n'.encode("UTF-8"))

        main_stack.set_visible_child(files_view_grid)
        scrolled_left_files.set_min_content_width(mon_width*0.2)
        scrolled_left_files.set_min_content_height(240)
        scrolled_right_files = paned_grid_view.get_end_child()

        if scrolled_right_files is not None:
            scrolled_right_files.set_min_content_width(mon_width*0.2)
            scrolled_right_files.set_min_content_height(240)

        update_color_scheme()

    def on_hidden_files():
        """___show or hide hidden files___"""

        timeout_list_clear(None)

        if swgs.cfg['hidden_files'] == 'True':
            environ['SW_HIDDEN_FILES'] = 'False'
            swgs.cfg['hidden_files'] = 'False'
        else:
            environ['SW_HIDDEN_FILES'] = 'True'
            swgs.cfg['hidden_files'] = 'True'

        parent_file = get_parent_file()

        if parent_file.get_path() is not None:
            try:
                update_grid_view(parent_file.get_path())
            except PermissionError as e:
                overlay_info(main_overlay, None, e, None, None, 3)
        else:
            try:
                update_grid_view_uri(parent_file.get_uri())
            except PermissionError as e:
                overlay_info(main_overlay, None, e, None, None, 3)

    def on_terminal():
        """___show or hide terminal___"""

        if terminal_revealer.get_reveal_child():
            scrolled_gvol.set_visible(False)
            terminal.set_visible(False)
            video_player.set_visible(False)
            terminal_revealer.set_reveal_child(False)
            files_view_grid.set_position(-1)
        else:
            terminal.set_visible(True)
            terminal_stack.set_visible_child(terminal)
            terminal_revealer.set_reveal_child(True)
            files_view_grid.set_position(0)

    def on_video():
        """___show or hide video player___"""

        if terminal_revealer.get_reveal_child():
            video_player.set_file(None)
            scrolled_gvol.set_visible(False)
            terminal.set_visible(False)
            video_player.set_visible(False)
            terminal_revealer.set_reveal_child(False)
            files_view_grid.set_position(-1)
        else:
            video_player.set_visible(True)
            terminal_stack.set_visible_child(video_player)
            terminal_revealer.set_reveal_child(True)
            files_view_grid.set_position(0)

    def media_play(media_file, samples, media_controls, volume, show):
        """___playing system event sounds___"""

        timeout_list_clear(None)
        stream = media_controls.get_media_stream()

        if show is True:
            stack_progress_main.set_visible_child(media_main_grid)

        if isinstance(samples, str):
            stream.stream_unprepared()
            media_file.clear()
            media_file.set_filename(f'{samples}')
            media_file.set_volume(volume)
            media_file.play()

        if isinstance(samples, itertools.cycle):
            if stream.has_audio() or stream.has_video():
                stream.stream_unprepared()
                media_file.clear()

            next_sample = next(samples)
            media_file.set_filename(f'{next_sample}')
            media_file.set_volume(volume)
            media_file.play()

            timeout = GLib.timeout_add(1000, cycle_playback, stream, samples, volume)
            timeout_list.append(timeout)

        if scrolled_playlist.get_child() is None:
            add_playlist_menu()

        update_playlist()

    def cb_playlist_activate(self, position):
        """___playback media playlist item___"""

        string_path = self.get_model().get_item(position).get_string()
        if Path(string_path).exists():
            p_list = get_format_playlist(string_path)
            media_play(media_file, p_list, media_controls, 1.0, True)
        else:
            e = msg.msg_dict['does_not_exist']
            overlay_info(main_overlay, None, e, None, None, 3)

    def get_format_playlist(current_media_file):
        """___get reorder media playlist___"""

        fmt_list = list()
        p_list = None
        playlist = get_playlist()
        pos_p = [n for n, s in enumerate(playlist) if s == current_media_file]

        if len(pos_p) > 0:
            for e in range(pos_p[0], len(playlist)):
                fmt_list.append(playlist[e])

            for e in range(pos_p[0]):
                fmt_list.append(playlist[e])

            p_list = itertools.cycle(fmt_list)
        return p_list

    def cycle_playback(media_stream, samples, volume):
        """___cycle playback media playlist___"""

        if media_file.get_file() is not None:
            current_file = media_file.get_file().get_path()
            samples = get_format_playlist(current_file)

            if samples is not None:
                next_sample = next(samples)
            else:
                update_playlist()
                return False

        if media_stream.get_ended():
            volume = media_file.get_volume()
            media_stream.stream_unprepared()
            media_file.clear()
            next_sample = next(samples)
            media_file.set_filename(f'{next_sample}')
            media_file.set_volume(volume)
            media_file.play()
            update_playlist()

        if not media_stream.get_playing():
            print('stoped')
            update_playlist()
            return False
        return True

    def cb_media_info(_self):
        """___show or hide media playlist___"""

        media_gfile = media_file.get_file()
        media_info = get_media_info(media_gfile)
        media_path = media_gfile.get_path()
        media_title = Path(media_path).name if media_path is not None else None
        return overlay_info(main_overlay, media_title, media_info, None, None, None)

    def gvolume_focus(gvolume_view):
        """___grab focus of mounted drive list view___"""
        gvolume_view.grab_focus()

    def on_drive():
        """___show or hide mounted volumes___"""

        if scrolled_gvol.get_child() is None:
            add_gvol_view()

        gvolume_view = scrolled_gvol.get_child()
        update_gvolume()

        if terminal_revealer.get_reveal_child():
            scrolled_gvol.set_visible(False)
            terminal.set_visible(False)
            video_player.set_visible(False)
            terminal_revealer.set_reveal_child(False)
            files_view_grid.set_position(-1)
            grid_view = get_list_view()
            grid_view.grab_focus()
        else:
            scrolled_gvol.set_visible(True)
            terminal_stack.set_visible_child(scrolled_gvol)
            scrolled_gvol.set_min_content_width(swgs.width*0.2)
            scrolled_gvol.set_min_content_height(240)
            terminal_revealer.set_reveal_child(True)
            gvolume_view.grab_focus()

            if getenv('TERMINAL_HANDLE_POSITION'):
                files_view_grid.set_position(int(getenv('TERMINAL_HANDLE_POSITION')))
            else:
                files_view_grid.set_position(swgs.height*0.5)

            update_color_scheme()

    def update_gvolume():
        """___update mounted volumes list___"""

        swgs.list_gvol_store.remove_all()
        gvolume_list = swgs.gvolume_monitor.get_volumes()

        if gvolume_list is None or gvolume_list == []:
            partitions = psutil.disk_partitions()
            for x in sorted(partitions):
                for m in ['/mnt/', '/run/media/', '/home']:
                    if m in x.mountpoint:
                        mountpoint = x.mountpoint
                        if '.Xauthority' not in mountpoint:
                            string = Gtk.StringObject.new(f'{mountpoint}:{x.device}:{x.fstype}:{x.opts}')
                            swgs.list_gvol_store.append(string)
        else:
            for gvolume in gvolume_list:
                swgs.list_gvol_store.append(gvolume)

    def on_message_cs():
        """___run create shortcut function___"""

        def on_thread_wine():
            t = Thread(target=echo_wine, args=[func_wine, name_ver, wine_ver])
            t.start()
            GLib.timeout_add(100, progress_on_thread, progress_main, t, None)
            f = on_cs_wine
            q = (app_name, app_path, wine)
            GLib.timeout_add(100, check_alive, t, f, q, None)

        app_path = get_app_path()
        app_name = get_out()
        winever_data, latest_wine_dict, wine_download_dict = get_wine_dicts()
        wine = latest_wine_dict['wine_proton_ge']

        if wine is None:
            message = msg.msg_dict['wine_not_found']
            SwCrier(text_message=message, message_type='ERROR').run()

        elif Path(f'{sw_wine}/{wine}/bin/wine').exists():
            on_cs_wine(app_name, app_path, wine)
        else:
            wine, exist = check_wine()
            if not exist:
                wine_ver = wine.replace('-amd64', '').replace('-x86_64', '')
                wine_ver = ''.join([e for e in wine_ver if not e.isalpha()]).strip('-')
                name_ver = 'GE_VER'
                func_wine = 'WINE_3'
                text_message = [f"{wine} {msg.msg_dict['wine_not_exists']}", '']
                func = [on_thread_wine, None]
                SwDialogQuestion(swgs, None, text_message, None, func)
            else:
                on_cs_wine(app_name, app_path, wine)

    def cb_item_activate(self, position):
        """___activate view item by user___"""

        item = self.get_model().get_item(position)
        item_path = self.get_model().get_item(position).get_path()

        file_info = item.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
        f_type = file_info.get_content_type()

        if item_path is None:
            item_uri = item.get_uri()
            if item_uri is not None:
                update_grid_view_uri(item_uri)

        elif f_type in dir_mime_types:

            if file_info.get_is_symlink():
                symlink_target = file_info.get_symlink_target()

                if not symlink_target.startswith('/'):
                    symlink_target = Path(symlink_target).absolute()
                try:
                    update_grid_view(symlink_target)
                except PermissionError as e:
                    return overlay_info(main_overlay, None, e, None, None, 3)
                else:
                    terminal.feed_child(f'cd "{symlink_target}" && clear\n'.encode("UTF-8"))
            else:
                try:
                    update_grid_view(item_path)
                except PermissionError as e:
                    return overlay_info(main_overlay, None, e, None, None, 3)
                else:
                    terminal.feed_child(f'cd "{item_path}" && clear\n'.encode("UTF-8"))

        elif f_type in exe_mime_types:
            check_arg(str(item_path))
            app_path = get_app_path().strip('"')
            app_name = get_out()
            write_app_conf(Path(app_path))

            if app_path != 'StartWine':
                if Path(f'{sw_shortcuts}/{app_name}.swd').exists():
                    app_dict = app_info(Path(f'{sw_shortcuts}/{app_name}.swd'))
                    app_exec = app_dict['Exec'].replace(f'env "{sw_start}" ', '').strip('"')

                    if str(app_path) == str(app_exec):
                        response = [
                                    msg.msg_dict['run'].title(),
                                    msg.msg_dict['launch_settings'].title(),
                                    msg.msg_dict['cancel'].title(),
                        ]
                        title = msg.msg_dict['choose']
                        func = [on_start, on_startapp_page, None]
                        SwDialogQuestion(swgs, title, [Path(app_path).name, ''], response, func)
                    else:
                        overlay_info(main_overlay, None, msg.msg_dict['same_name'], None, None, None)
                else:
                    response = [
                                msg.msg_dict['run'].title(),
                                msg.msg_dict['cs'].title(),
                                msg.msg_dict['launch_settings'].title(),
                                msg.msg_dict['cancel'].title(),
                    ]
                    title = msg.msg_dict['choose']
                    func = [on_start, on_message_cs, on_startapp_page, None]
                    SwDialogQuestion(swgs, title, [Path(app_path).name, ''], response, func)
            else:
                overlay_info(main_overlay, None, msg.msg_dict['lnk_error'], None, None, None)

        elif f_type in app_mime_types:

            check_arg(str(item_path))
            if getenv('SW_EXEC') != 'StartWine':
                #return on_start()
                print(f'{item_path}')

            elif getenv('SW_COMMANDLINE') != 'None':
                cmd = str(getenv('SW_COMMANDLINE')).strip('"').replace('env ', '')
                gio_app_info = Gio.AppInfo.create_from_commandline(
                    cmd, None, Gio.AppInfoCreateFlags.SUPPORTS_URIS)
                try:
                    gio_app_info.launch_uris()
                except GLib.GError as e:
                    print(tc.RED, e.message, tc.END)
                    fl = Gtk.FileLauncher()
                    fl.set_file(item)
                    try:
                        fl.launch()
                    except Exception as e:
                        print(tc.RED, e, tc.END)
                        message = msg.msg_dict['launch_error'] + f': {e}'
                        return overlay_info(main_overlay, None, message, None, None, 3)
            else:
                fl = Gtk.FileLauncher()
                fl.set_file(item)
                try:
                    fl.launch()
                except Exception as e:
                    print(tc.RED, e, tc.END)
                    message = msg.msg_dict['launch_error'] + f': {e}'
                    return overlay_info(main_overlay, None, message, None, None, 3)

        elif Path(item_path).suffix in swd_mime_types:
            check_arg(str(item_path))

            if getenv('SW_EXEC') != 'StartWine':
                on_startapp_page()

            elif getenv('SW_COMMANDLINE') != 'None':
                cmd = str(getenv('SW_COMMANDLINE')).strip('"').replace('env ', '')
                if Path(cmd).exists():
                    run(cmd, shell=True)
                else:
                    return overlay_info(main_overlay, None, msg.msg_dict['lnk_error'], None, None, 3)
            else:
                return overlay_info(main_overlay, None, msg.msg_dict['lnk_error'], None, None, 3)

        elif f_type in bin_mime_types:
            gio_app_info = Gio.AppInfo.create_from_commandline(
                                            bytes(Path(f'\"{item_path}\"')),
                                            f'\"{item_path}\"',
                                            Gio.AppInfoCreateFlags.SUPPORTS_URIS
            )
            try:
                gio_app_info.launch_uris()
            except GLib.GError as e:
                print(tc.RED, e.message, tc.END)
                return SwCrier(text_message=e.message, message_type='ERROR').run()

        elif f_type in video_mime_types and getenv('GSK_RENDERER') == 'vulkan':
            video_player.set_file(item)
            video_player.set_autoplay(True)
            on_video()

        elif f_type in audio_mime_types:
            media_play(media_file, f'{item.get_path()}', media_controls, 1.0, True)

        else:
            fl = Gtk.FileLauncher()
            fl.set_file(item)
            try:
                fl.launch()
            except GLib.GError as e:
                print(tc.RED, e.message, tc.END)
                return SwCrier(text_message=e.message, message_type='ERROR').run()

    def get_dll_info(x_path):
        """___get installed dll list from winetricks log___"""

        w_log = Path(f'{x_path}/winetricks.log')

        if w_log.exists():
            read_w_log = w_log.read_text().splitlines()
            return read_w_log
        else:
            read_w_log = []
            return read_w_log

    def get_list_store():

        view = getenv('SW_FILES_VIEW_NAME')
        store = list_store

        if view == 'left_grid_view':
            store = list_store
        elif view == 'right_grid_view':
            store = right_list_store

        return store

    def get_list_view():

        view_name = getenv('SW_FILES_VIEW_NAME')
        view = paned_grid_view.get_start_child().get_child()

        if view_name == 'left_grid_view':
            view = paned_grid_view.get_start_child().get_child()
        elif view_name == 'right_grid_view':
            if paned_grid_view.get_end_child() is not None:
                view = paned_grid_view.get_end_child().get_child()
            else:
                view = paned_grid_view.get_start_child().get_child()

        return view

    def get_dir_list():

        view = getenv('SW_FILES_VIEW_NAME')
        dir_list = left_dir_list

        if view == 'left_grid_view':
            dir_list = left_dir_list
        elif view == 'right_grid_view':
            dir_list = right_dir_list

        return dir_list

    def get_parent_path():
        """___get current path in file manger list view___"""

        parent_path = getenv('SW_FILES_PARENT_PATH')
        return parent_path

    def get_parent_file():
        """___get current path in file manger list view___"""

        parent_file = None
        grid_view = get_list_view()
        dir_list = get_dir_list()

        if grid_view.get_model().get_item(0) is None:
            parent_file = dir_list.get_file()
            if Path(parent_file.get_path()).is_file():
                parent_file = dir_list.get_file().get_parent()
        else:
            parent_file = dir_list.get_file().get_parent()

        return parent_file

    def get_parent_uri():
        """___get current uri in file manger list view___"""

        grid_view = get_list_view()
        dir_list = get_dir_list()

        if grid_view.get_model().get_item(0) is None:
            parent_uri = dir_list.get_file().get_uri()
        else:
            parent_uri = dir_list.get_file().get_parent().get_uri()

        return parent_uri

    def get_selected_item_gfile():
        """___get gio files list from selected item in list view___"""

        grid_view = get_list_view()
        model = grid_view.get_model()
        nums = model.get_n_items()
        files = list()

        for n in range(nums):
            if model.is_selected(n):
                f = model.get_item(n)
                files.append(f)

        return files

    def try_get_theme_icon(icon_name):
        """___try get icon paintable from system icon theme by name___"""

        try:
            icon = icon_theme.lookup_icon(
                                        icon_name=icon_name,
                                        fallbacks=None,
                                        size=256,
                                        scale=1,
                                        direction=Gtk.TextDirection.NONE,
                                        flags=Gtk.IconLookupFlags.FORCE_REGULAR
            )
        except (Exception,):
            icon = None
            return icon
        else:
            return icon

    def sort_func(x_list):
        """___file sorting function in the list___"""

        sorted_list = list()
        sorting_files = swgs.cfg.get('sorting_files') if swgs.cfg.get('sorting_files') else 'name'
        sorting_reverse = swgs.cfg.get('sorting_reverse') if swgs.cfg.get('sorting_reverse') else 'False'

        if sorting_files == 'type':
            sorted_list_by_type = sorted(
                [x for x in x_list if x.has_attribute(attrs['type'])],
                key=lambda x: str(x.get_content_type()),
                reverse=eval(sorting_reverse)
            )
            sorted_list = sorted_list_by_type

        elif sorting_files == 'size':
            sorted_list_by_size = sorted(
                [x for x in x_list if x.has_attribute(attrs['size'])],
                key=lambda x: str(round(x.get_size()/1024/1024, 4)),
                reverse=eval(sorting_reverse)
            )
            sorted_list = sorted_list_by_size

        elif sorting_files == 'date':
            sorted_list_by_date = sorted(
                [x for x in x_list if x.has_attribute(attrs['created'])],
                key=lambda x: str(x.get_creation_date_time().format('%c')),
                reverse=eval(sorting_reverse)
            )
            sorted_list = sorted_list_by_date

        elif sorting_files == 'name':
            sorted_list_by_name = sorted(
                [x for x in x_list],
                key=lambda x: str(x.get_display_name()),
                reverse=eval(sorting_reverse)
            )
            sorted_list = sorted_list_by_name

        else:
            pass

        sorted_list = sorted(
            sorted_list,
            key=lambda x: (
                        str(Path(x_list.get_child(x).get_path()).is_file()),
                        str(Path(x_list.get_child(x).get_path()).is_symlink())
            ),
            reverse=False
        )
        return sorted_list

    def get_file_info(paned_store, dir_list, x_file, x_info, x_hidden_files):
        """___getting file attributes to set name and images in list___"""

        x_path = Path(x_file.get_path())
        if x_path.parent == Path(sw_shortcuts):
            if x_info is not None:
                if (x_info.get_content_type() in app_mime_types
                        and x_info.has_attribute(attrs['rename'])):
                    try:
                        x_file.set_display_name(x_path.stem + swd_mime_types[0])
                    except GLib.GError as e:
                        print(e.message)
                else:
                    if x_path.suffix not in swd_mime_types:
                        pass

        if x_hidden_files is None:
            x_hidden = False

        elif x_hidden_files == 'True':
            x_hidden = x_path.name.startswith('.')
        else:
            x_hidden = False

        if not x_hidden:
            dir_list.set_file(x_file)
            paned_store.append(x_file)

        return False

    def update_grid_view(new_path):
        """___update list view when path is changed___"""

        if Path(new_path).is_dir():
            update_path(new_path)
            entry_path.set_text(str(new_path))
            entry_path.set_name(str(new_path))

            swgs.cur_dir = Gio.File.new_for_path(bytes(Path(new_path)))
            swgs.f_mon = swgs.cur_dir.monitor(Gio.FileMonitorFlags.WATCH_MOVES, None)
            swgs.f_mon.connect('changed', g_file_monitor)

            paned_store = get_list_store()
            grid_view = get_list_view()

            os.chdir(new_path)
            paned_store.remove_all()

            g_file = Gio.File.new_for_path(bytes(Path(new_path)))
            t = Thread(target=update_view, args=[paned_store, g_file])
            t.start()
            timeout = GLib.timeout_add(200, check_alive, t, update_selection, grid_view, None)
            timeout_list.append(timeout)

    async def exe_thumbnail():
        """___generate image thumbnail for exe files___"""

        async def run_thumbnail(in_file, out_file, width, height):
            """___generate thumbnail for image mime type files___"""

            start = perf_counter()
            in_type = 'image'
            file = Gio.File.new_for_commandline_arg(in_file)
            file_info = file.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
            size = width, height

            if file_info.get_content_type() == 'image/svg+xml':
                in_type = 'svg'

            if in_type == 'svg':
                shutil.copy(in_file, out_file)
            else:
                try:
                    image = Image.open(in_file)
                except (Exception,):
                    print(
                        f'{tc.RED}get_image_thumbnail'
                        + f'{tc.GREEN}{in_file}{tc.RED}failed{tc.END}'
                    )
                else:
                    try:
                        image.thumbnail(size, Image.Resampling.LANCZOS)
                    except (Exception,):
                        print(
                            f'{tc.RED}get_image_thumbnail'
                            + f'{tc.GREEN}{in_file}{tc.RED}failed{tc.END}'
                        )
                    else:
                        try:
                            image.save(out_file, 'png')
                        except (Exception,):
                            print(
                                f'{tc.RED}save_image_thumbnail'
                                + f'{tc.GREEN}{in_file}{tc.RED}failed{tc.END}'
                            )
                        else:
                            end = perf_counter() - start
                            print(f'-->Thumbnail {in_file} => {out_file} (took {end:0.2f} seconds)')

        start = perf_counter()
        items = thumbnail_exe_dict.items()

        for k, v in items:
            if not Path(k).exists():
                ico = SwExtractIcon(str(v.get_path()))
                ico.extract_icon(str(k).replace('.png', '.ico'), _num=0)
                ico.save_to_png(str(k).replace('.png', '.ico'))

        await asyncio.gather(*(run_thumbnail(k, k, 128, 128) for k, v in items))

        end = perf_counter() - start
        print(f"Thumbnailer finished in {end:0.2f} seconds.")

        thumbnail_exe_dict.clear()
        print(f"Thumbnail list clear...")

    async def image_thumbnail():
        """___generate image thumbnail___"""

        async def run_thumbnail(in_file, out_file, width, height):
            """___generate thumbnail for image mime type files___"""

            start = perf_counter()
            in_type = 'image'
            file = Gio.File.new_for_commandline_arg(in_file)
            file_info = file.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
            size = width, height

            if file_info.get_content_type() == 'image/svg+xml':
                in_type = 'svg'

            if in_type == 'svg':
                shutil.copy(in_file, out_file)
            else:
                try:
                    image = Image.open(in_file)
                except (Exception,):
                    print(
                        f'{tc.RED}get_image_thumbnail'
                        + f'{tc.GREEN}{in_file}{tc.RED}failed{tc.END}'
                    )
                else:
                    try:
                        image.thumbnail(size, Image.Resampling.LANCZOS)
                    except (Exception,):
                        print(
                            f'{tc.RED}get_image_thumbnail'
                            + f'{tc.GREEN}{in_file}{tc.RED}failed{tc.END}'
                        )
                    else:
                        try:
                            image.save(out_file, 'png')
                        except (Exception,):
                            print(
                                f'{tc.RED}save_image_thumbnail'
                                + f'{tc.GREEN}{in_file}{tc.RED}failed{tc.END}'
                            )
                        else:
                            end = perf_counter() - start
                            print(f'-->Thumbnail {in_file} => {out_file} (took {end:0.2f} seconds)')

        start = perf_counter()
        items = thumbnail_image_dict.items()
        await asyncio.gather(*(run_thumbnail(v.get_path(), k, 128, 128) for k, v in items if not Path(k).exists()))

        end = perf_counter() - start
        print(f"Thumbnailer finished in {end:0.2f} seconds.")

        thumbnail_image_dict.clear()
        print(f"Thumbnail list clear...")

    async def video_thumbnail():
        """___generate video thumbnail___"""

        async def run_thumbnail(in_file, out_file, width):
            """___generate thumbnail for video mime type files___"""

            start = perf_counter()
            cmd = (
                f'ffmpeg -loglevel quiet -ss 00:00:01.00 -i "{in_file}" -vf '
                + f'"scale={width}:{width}:force_original_aspect_ratio=decrease" -vframes 1 -y "{out_file}"'
            )
            try:
                run(cmd, shell=True)
            except (Exception,):
                print(f'{tc.RED}Thumbnail {tc.GREEN}{in_file}{tc.RED}failed{tc.END}')
            else:
                end = perf_counter() - start
                print(f'-->Thumbnail {in_file} => {out_file} (took {end: 0.2f} seconds)')
                print(f'{tc.GREEN}done{tc.END}')

        start = perf_counter()
        items = thumbnail_video_dict.items()
        args = (run_thumbnail(v.get_path(), k, 128) for k, v in items if not Path(k).exists())
        await asyncio.gather(*args)

        end = perf_counter() - start
        print(f"Thumbnailer finished in {end: 0.2f} seconds.")

        thumbnail_video_dict.clear()
        print(f"Thumbnail list clear...")

    def update_selection(grid_view):
        """___update list model item selection when list view is updated___"""

        if len(list(thumbnail_exe_dict)) > 0:
            Thread(target=asyncio.run, args=[exe_thumbnail()]).start()

        if len(list(thumbnail_video_dict)) > 0:
            Thread(target=asyncio.run, args=[video_thumbnail()]).start()

        if len(list(thumbnail_image_dict)) > 0:
            Thread(target=asyncio.run, args=[image_thumbnail()]).start()

        grid_view.grab_focus()
        set_view_parent_path(grid_view)

        if stack_search_path.get_visible_child() == box_search:
            entry_search.set_text('')
            stack_search_path.set_visible_child(box_path)

    def update_view(paned_store, g_file):
        """___update list view when path is changed___"""

        x_hidden_files = getenv('SW_HIDDEN_FILES')
        dir_list = get_dir_list()
        g_enum = None
        count = 0
        if Path(g_file.get_path()).is_dir():
            g_enum = g_file.enumerate_children('*', Gio.FileQueryInfoFlags.NONE)
            sorted_list = sort_func(g_enum)
        else:
            sorted_list = [g_file.query_info('*', Gio.FileQueryInfoFlags.NONE, None)]

        if len(sorted_list) == 0:
            dir_list.set_file(g_file)
        else:
            if g_enum is not None:
                for x_info in sorted_list:
                    count += 1
                    x_file = g_enum.get_child(x_info)
                    timeout_info = GLib.timeout_add(
                        count, get_file_info, paned_store, dir_list, x_file, x_info, x_hidden_files
                    )
                    timeout_list.append(timeout_info)

                    if str(Path(x_file.get_path()).suffix).lower() == '.exe':
                        out_file = f'{sw_fm_cache_thumbnail}/{x_file.get_path().replace("/", "")}.png'
                        thumbnail_exe_dict[f'{out_file}'] = x_file

                    if x_info.get_content_type() in video_mime_types:
                        out_file = f'{sw_fm_cache_thumbnail}/{x_file.get_path().replace("/", "")}.png'
                        thumbnail_video_dict[f'{out_file}'] = x_file

                    if x_info.get_content_type() in image_mime_types:
                        out_file = f'{sw_fm_cache_thumbnail}/{x_file.get_path().replace("/", "")}'
                        thumbnail_image_dict[out_file] = x_file

    def cb_btn_back_up(_self):
        """___return to the parent directory when user activated___"""

        return back_up()

    def timeout_list_clear(args):
        """___terminate all glib timeout process___"""

        if args is None:
            for t in timeout_list:
                GLib.Source.remove(t)
            timeout_list.clear()

        elif len(args) == 1:
            GLib.Source.remove(args)
            timeout_list.remove(args)

        elif len(args) > 1:
            for t in args:
                GLib.Source.remove(t)
                timeout_list.remove(t)
        else:
            pass

    def on_walk_path(_self, x_path, x_type):

        g_file = Gio.File.new_for_commandline_arg(x_path)
        timeout_list_clear(None)

        if not main_stack.get_visible_child() == files_view_grid:
            on_files(x_path)

        elif x_type == 'uri':
            update_grid_view_uri(x_path)
        else:
            update_grid_view(g_file.get_path())

    def update_path(x_path):
        """___update entry path button when path is chaged___"""

        len_cur_path = len(Path(entry_path.get_name()).parts)
        for p in range(len_cur_path*2):
            child = box_scrolled.get_last_child()
            try:
                box_scrolled.remove(child)
            except (Exception,):
                pass

        split_path = list(str(x_path).split('://'))
        if len(split_path) == 1:
            path_type = 'file'
            parts = list(Path(split_path[0]).parts)
        else:
            prefix = split_path[0] + ':/'
            path_type = 'uri'
            parts = list(Path(split_path[1]).parts)
            parts.insert(0, prefix)

        if parts[0] == '/':
            parts.remove('/')
            parts.insert(0, '')

        list_paths = list()
        for i in range(len(parts)):
            x = '/'.join(parts[0:i+1])
            list_paths.append(x)

        if list_paths[0] == '':
            list_paths.remove('')
            list_paths.insert(0, '/')
            parts.remove('')
            parts.insert(0, '/')

        for name, path in zip(parts, list_paths):
            if name == '/':
                child = Gtk.Label(css_name='sw_label_desc', label='rootfs')
            else:
                child = Gtk.Label(
                                css_name='sw_label_desc', label=name,
                                ellipsize=Pango.EllipsizeMode.END,
                                max_width_chars=32
                )
            btn = Gtk.Button(
                            name=name, css_name='sw_button_path',
                            valign=Gtk.Align.CENTER
            )
            btn.set_size_request(80, -1)
            btn.set_child(child)
            btn.connect('clicked', on_walk_path, path, path_type)
            box_scrolled.append(btn)

    def cb_btn_home(_self):
        """___return to the home directory when user activated___"""

        return on_home()

    def on_home():
        """___go to the home directory___"""

        path = Path.home()
        on_files(path)
        terminal.feed_child(f'cd "{str(path)}" && clear\n'.encode("UTF-8"))

    def cb_btn_view_more(self):
        """___activate headerbar context menu for current path___"""
        x = 0
        y = 32
        parent_path = get_parent_path()
        show_context(x, y, self, parent_path)

    def cb_btn_view_header_menu(self):
        """___activate headerbar context header menu___"""
        x = 0
        y = 32
        parent_path = get_parent_path()
        on_header_context(x, y, self, parent_path)

    def on_btn_header_menu(action_name, _parameter, _data):
        """___activate header menu button___"""

        if action_name.get_name() == (
                            msg.ctx_dict['global_settings'][0].replace(' ', '')):
            return on_global_settings()

        if action_name.get_name() == (
                                msg.ctx_dict['show_hotkeys'][0].replace(' ', '')):
            return on_show_hotkeys()

        if action_name.get_name() == (
                                msg.ctx_dict['about'][0].replace(' ', '')):
            return on_about()

        if action_name.get_name() == (
                                msg.ctx_dict['help'][0].replace(' ', '')):
            return on_webview(home_page + '/StartWine-Launcher')

        if action_name.get_name() == (
                                msg.ctx_dict['shutdown'][0].replace(' ', '')
                                + f'{sw_program_name}'):
            return on_shutdown()

    def on_files_view_props(prop_name, prop_value):
        """___set files view properties___"""

        if prop_value is None:
            if swgs.cfg[prop_name] == 'True':
                environ[f'SW_{prop_name.upper()}'] = 'False'
                swgs.cfg[prop_name] = 'False'
            else:
                environ[f'SW_{prop_name.upper()}'] = 'True'
                swgs.cfg[prop_name] = 'True'
        else:
            swgs.cfg[prop_name] = prop_value

        parent_file = get_parent_file()

        if parent_file.get_path() is not None:
            try:
                update_grid_view(parent_file.get_path())
            except PermissionError as e:
                overlay_info(main_overlay, None, e, None, None, 3)
        else:
            try:
                update_grid_view_uri(parent_file.get_uri())
            except PermissionError as e:
                overlay_info(main_overlay, None, e, None, None, 3)

    def back_up():
        """___return to the parent directory when user activated___"""

        parent_file = get_parent_file()
        if parent_file.get_path() is None:
            if parent_file.get_parent() is not None:
                uri = parent_file.get_parent().get_uri()
                update_grid_view_uri(uri)
            else:
                swgs.default_dir = swgs.cfg.get('default_dir')
                on_files(swgs.default_dir)
        else:
            if parent_file.get_parent() is not None:
                on_files(Path(parent_file.get_parent().get_path()))

    def cb_btn_back_main(_self):
        """___sidebar back to main menu___"""

        return on_back_main()

    def on_back_main():
        """___sidebar back to main menu___"""

        if stack_search_path.get_visible_child() != box_path:
            stack_search_path.set_visible_child(box_path)

        btn_back_main.set_visible(False)
        stack_sidebar.set_visible_child(frame_main)

        if main_stack.get_visible_child_name() == 'winetricks':
            return on_startapp_page()

        elif main_stack.get_visible_child_name() == 'web_view':

            if str(getenv('LAST_VIEW_PAGE')) == 'startapp_page':
                return on_startapp_page()

            elif str(getenv('LAST_VIEW_PAGE')) == 'files':
                current_path = get_parent_file().get_path()
                return on_files(current_path)
            else:
                return on_shortcuts()

        elif main_stack.get_visible_child_name() != 'files':
            current_path = get_parent_file().get_path()
            return on_files(current_path)

    def cb_btn_main(self):
        """___main buttons signal handler___"""

        if self.get_name() == btn_widget_dict['stop']:
            return on_stop()

        if self.get_name() == vw_dict['shortcuts']:
            return on_shortcuts()

        if self.get_name() == vw_dict['files']:
            swgs.default_dir = swgs.cfg.get('default_dir')
            return on_files(swgs.default_dir)

        if self.get_name() == vw_dict['global_settings']:
            return on_global_settings()

        if self.get_name() == vw_dict['install_wine']:
            return on_download_wine()

        if self.get_name() == vw_dict['install_launchers']:
            return on_install_launchers()

        if self.get_name() == btn_widget_dict['shutdown']:
            return on_shutdown()

    def on_show_hidden_widgets(widget_name):
        """___show hidden widgets when expand menu___"""

        if widget_name is not None:
            try:
                next_name = next_vw_dict[widget_name]
            except (Exception,):
                next_name = 'global_settings'
            try:
                prev_name = prev_vw_dict[widget_name]
            except (Exception,):
                prev_name = 'install_launchers'

            stack_panel.set_visible_child_name(vw_dict[widget_name])
            child = stack_panel.get_child_by_name(vw_dict[widget_name])

            one = child.get_first_child()
            one.get_first_child().get_first_child().set_label(vl_dict[prev_name])

            two = one.get_next_sibling()
            two.set_label(vl_dict[widget_name])

            three = two.get_next_sibling()
            three.get_first_child().get_last_child().set_label(vl_dict[next_name])

        if (widget_name == vw_dict['shortcuts']
                or widget_name == vw_dict['files']):

            btn_gmount.set_visible(True)
            btn_bookmarks.set_visible(True)
            btn_playlist.set_visible(True)
            btn_popover_scale.set_visible(True)
            btn_icon_position.set_visible(True)

        stack_search_path.set_visible(True)
        btn_sidebar.set_visible(True)
        btn_back_up.set_visible(True)
        btn_home.set_visible(True)
        btn_more.set_visible(True)
        stack_progress_main.set_visible_child(stack_panel)
        stack_panel.set_visible(True)
        scrolled_winetricks.set_visible(True)

    def on_set_px_size(self):
        """___updating list when user resize icons___"""

        timeout_list_clear(None)
        t = GLib.timeout_add(100, on_spin_update, self)
        timeout_list.append(t)

    def on_spin_update(_self):

        parent_file = get_parent_file()
        if parent_file.get_path() is not None:
            update_grid_view(parent_file.get_path())
        else:
            update_grid_view_uri(parent_file.get_uri())

    def update_color_scheme():
        """___update new widgets color scheme___"""

        css_path = None
        if swgs.colorscheme == 'dark':
            css_path = sw_css_dark
        elif swgs.colorscheme == 'light':
            css_path = sw_css_light
        else:
            css_path = sw_css_custom

        if css_path is not None:
            css_provider.load_from_file(Gio.File.new_for_path(bytes(css_path)))
            Gtk.StyleContext.add_provider_for_display(
                                        display,
                                        css_provider,
                                        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        set_define_colors()

    def update_bookmarks():
        """___update bookmarks list view___"""

        swgs.bookmarks_store.remove_all()
        bookmarks_list = get_bookmark_list()

        for b in bookmarks_list:
            gtk_str = Gtk.StringObject.new(b)
            swgs.bookmarks_store.append(gtk_str)

    def update_playlist():
        """___update playlist view___"""

        swgs.playlist_store.remove_all()
        playlist = get_playlist()

        for m in playlist:
            gtk_str = Gtk.StringObject.new(m)
            swgs.playlist_store.append(gtk_str)

    def on_shortcuts():
        """___show shortcuts list view___"""

        timeout_list_clear(None)
        on_show_hidden_widgets(vw_dict['shortcuts'])
        if stack_sidebar.get_visible_child() == frame_main:
            btn_back_main.set_visible(False)

        try:
            update_grid_view(sw_shortcuts)
        except PermissionError as e:
            return overlay_info(main_overlay, None, e, None, None, 3)
        else:
            terminal.feed_child(f'cd "{str(sw_shortcuts)}" && clear\n'.encode("UTF-8"))

        main_stack.set_visible_child(files_view_grid)
        scrolled_left_files.set_min_content_width(mon_width*0.2)
        scrolled_left_files.set_min_content_height(240)
        scrolled_right_files = paned_grid_view.get_end_child()

        if scrolled_right_files is not None:
            scrolled_right_files.set_min_content_width(mon_width*0.2)
            scrolled_right_files.set_min_content_height(240)

        update_color_scheme()

    def get_iter_exec(current_exec):
        """___get a list of exe files with the current shortcut position___"""

        next_exec = None
        prev_exec = None
        exec_dict = dict()
        fmt_list = list()

        store = get_list_store()
        if str(get_parent_file().get_path()) != str(sw_shortcuts):
            gfile = Gio.File.new_for_path(f'{sw_shortcuts}')
            gfile_enum = gfile.enumerate_children('*', Gio.FileQueryInfoFlags.NONE)
            store = [gfile_enum.get_child(x) for x in gfile_enum]

        for x in store:
            p = x.get_path()
            if Path(p).is_file():
                if Path(app_info(p)['Exec'].strip('"')).exists():
                    exec_dict[Path(p).stem] = app_info(p)['Exec'].strip('"')
        else:
            pos_exec = [n for n, e in enumerate(exec_dict.values()) if e == current_exec]
            if len(pos_exec) > 0:
                for e in range(pos_exec[0], len(exec_dict.values())):
                    fmt_list.append(list(exec_dict.values())[e])

                for e in range(pos_exec[0]):
                    fmt_list.append(list(exec_dict.values())[e])

                next_exec = itertools.cycle(fmt_list)
                prev_exec = itertools.cycle(reversed(fmt_list))

        return next_exec, prev_exec


    def on_startapp_page():
        """___show start app page___"""

        vscroll = scrolled_startapp_page.get_vadjustment()
        vscroll.set_value(0.0)

        if scrolled_startapp_page.get_child() is None:
            add_startapp_page()

        swgs.btn_start.grab_focus()
        btn_back_main.set_visible(True)
        main_stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        main_stack.set_visible_child_name('startapp_page')

        app_path = get_app_path().strip('"')
        stat_name = app_path.replace(' ', '_').replace('/', '_').replace('.', '_')
        stat_path = f'{sw_fm_cache_stats}/{stat_name}'

        total_time = read_app_stat(stat_path, 'Time')
        str_time = f'{msg.msg_dict["total_time"]}: {total_time}'
        swgs.label_time.set_label(str_time)

        total_fps = read_app_stat(stat_path, 'Fps')
        str_fps = f'{msg.msg_dict["avg_fps"]}: {total_fps}'
        swgs.label_fps.set_label(str_fps)

        size = 0
        data = Path(app_path).parent
        Thread(target=get_allocated_size, args=[size, data, swgs.label_size]).start()

        swgs.label_size.set_tooltip_markup(str(data))
        swgs.btn_folder.set_tooltip_markup(str(data))

        img_path = getenv(f'{get_out()}')
        app_original_name = ''

        if img_path:
            app_original_name = str(Path(img_path).stem).split('_')[-2]

        desktop_dir = Path(f'{dir_desktop}/{app_original_name}.desktop')
        local_dir = Path(f'{sw_local}/{app_original_name}.desktop')

        if desktop_dir.exists():
            swgs.switch_app_to_desktop.set_active(True)
        else:
            swgs.switch_app_to_desktop.set_active(False)

        if local_dir.exists():
            swgs.switch_app_to_menu.set_active(True)
        else:
            swgs.switch_app_to_menu.set_active(False)

        swgs.next_exec, swgs.prev_exec = get_iter_exec(app_path)

        if swgs.next_exec and swgs.prev_exec:
            swgs.btn_next_shortcut.set_sensitive(True)
            swgs.btn_prev_shortcut.set_sensitive(True)
        else:
            swgs.btn_next_shortcut.set_sensitive(False)
            swgs.btn_prev_shortcut.set_sensitive(False)

        set_heroes_icon(get_out(), swgs.image_title, swgs.label_startapp)
        swgs.image_title.queue_draw()
        on_launch_settings()
        update_wine_store()
        set_selected_prefix()

    def add_startapp_page():
        """___create start application page___"""

        image_play = Gtk.Picture(css_name='sw_picture')
        paintable_icon_play = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(IconPath.icon_start_sym), 64, 1,
        )
        image_play.set_paintable(paintable_icon_play)

        image_stop = Gtk.Picture(
                                css_name='sw_picture', width_request=24,
                                height_request=24
        )
        paintable_icon_stop = Gtk.IconPaintable.new_for_file(
                            Gio.File.new_for_path(IconPath.icon_stop), 32, 1,
        )
        image_stop.set_paintable(paintable_icon_stop)

        label_btn_start = Gtk.Label(
                            css_name='sw_label_title', label=btn_dict['start']
        )
        swgs.box_btn_start = Gtk.Box(
                                    orientation=Gtk.Orientation.HORIZONTAL,
                                    spacing=8,
                                    halign=Gtk.Align.CENTER
        )
        swgs.box_btn_start.append(label_btn_start)
        swgs.box_btn_start.append(image_play)

        swgs.btn_stop = Gtk.Button(
                                    css_name='sw_button',
                                    name=btn_widget_dict['stop'],
                                    tooltip_markup=msg.tt_dict['stop'],
                                    child=image_stop,
        )
        swgs.btn_stop.connect('clicked', cb_btn_main)

        swgs.btn_start = Gtk.Button(css_name='sw_button', width_request=220)
        swgs.btn_start.add_css_class('accent_color')
        swgs.btn_start.set_child(swgs.box_btn_start)
        swgs.btn_start.connect('clicked', cb_btn_start)

        swgs.label_startapp = Gtk.Label(css_name='sw_label_title', xalign=0.0)
        swgs.label_startapp.add_css_class('font_size_18')

        swgs.wine_store = Gio.ListStore()
        swgs.change_wine_model = Gtk.SingleSelection.new(swgs.wine_store)

        swgs.change_wine_factory = Gtk.SignalListItemFactory()
        swgs.change_wine_factory.connect('setup', on_change_wine_setup)
        swgs.change_wine_factory.connect('bind', on_change_wine_bind)

        swgs.dropdown_change_wine = Gtk.DropDown(css_name='sw_dropdown')
        swgs.dropdown_change_wine.set_size_request(200, -1)
        swgs.dropdown_change_wine.set_model(swgs.change_wine_model)
        swgs.dropdown_change_wine.set_factory(swgs.change_wine_factory)
        swgs.dropdown_change_wine.set_name(str_sw_use_wine)
        swgs.drop_list_view = (
                                swgs.dropdown_change_wine
                                .get_last_child()
                                .get_first_child()
                                .get_first_child()
                                .get_first_child()
                                .get_next_sibling()
                                .get_first_child()
        )
        swgs.drop_list_view.connect('activate', cb_change_wine_activate)

        change_pfx_list_model = Gtk.StringList()
        for prefix_label in prefix_labels:
            change_pfx_list_model.append(prefix_label)

        change_pfx_factory = Gtk.SignalListItemFactory()
        change_pfx_factory.connect('setup', on_change_pfx_setup)
        change_pfx_factory.connect('bind', on_change_pfx_bind)

        swgs.dropdown_change_pfx = Gtk.DropDown(
                                                css_name='sw_dropdown',
                                                halign=Gtk.Align.START
        )
        swgs.dropdown_change_pfx.set_size_request(200, -1)
        swgs.dropdown_change_pfx.set_model(change_pfx_list_model)
        swgs.dropdown_change_pfx.set_name(str_sw_use_pfx)
        swgs.dropdown_change_pfx.connect('notify::selected-item', on_change_pfx_activate)

        swgs.image_title = Gtk.Picture(css_name='sw_picture')
        swgs.image_title.set_hexpand(True)
        swgs.image_title.set_vexpand(True)
        swgs.image_title.add_css_class('stub')
        swgs.image_title.set_size_request(-1, 540)
        swgs.image_title.add_css_class('corner_0')

        image_stats = Gtk.Picture(
                                css_name='sw_picture', width_request=24,
                                height_request=24
        )
        paintable_icon_stats = Gtk.IconPaintable.new_for_file(
                            Gio.File.new_for_path(IconPath.icon_info), 32, 1,
        )
        image_stats.set_paintable(paintable_icon_stats)

        image_settings = Gtk.Picture(
                                    css_name='sw_picture', width_request=24,
                                    height_request=24
        )
        paintable_icon_settings = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(IconPath.icon_settings), 32, 1,
        )
        image_settings.set_paintable(paintable_icon_settings)

        image_controller = Gtk.Picture(
                                    css_name='sw_picture', width_request=24,
                                    height_request=24
        )
        paintable_icon_controller = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(IconPath.icon_games), 32, 1,
        )
        image_controller.set_paintable(paintable_icon_controller)

        image_scroll_up = Gtk.Picture(
                                css_name='sw_picture', width_request=24,
                                height_request=24
        )
        paintable_icon_up = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(IconPath.icon_up), 32, 1,
        )
        image_scroll_up.set_paintable(paintable_icon_up)

        image_wine_tools = Gtk.Picture(
                                    css_name='sw_picture', width_request=24,
                                    height_request=24
        )
        paintable_icon_wine_tools = Gtk.IconPaintable.new_for_file(
                            Gio.File.new_for_path(IconPath.icon_wine), 32, 1,
        )
        image_wine_tools.set_paintable(paintable_icon_wine_tools)

        image_prefix_tools = Gtk.Picture(
                                        css_name='sw_picture', width_request=24,
                                        height_request=24
        )
        paintable_icon_prefix_tools = Gtk.IconPaintable.new_for_file(
                            Gio.File.new_for_path(IconPath.icon_toolbox), 32, 1,
        )
        image_prefix_tools.set_paintable(paintable_icon_prefix_tools)

        image_time = Gtk.Picture(css_name='sw_picture')
        paintable_icon_time = Gtk.IconPaintable.new_for_file(
                            Gio.File.new_for_path(IconPath.icon_clock), 32, 1,
        )
        image_time.set_paintable(paintable_icon_time)

        image_fps = Gtk.Picture(css_name='sw_picture')
        paintable_icon_fps = Gtk.IconPaintable.new_for_file(
                            Gio.File.new_for_path(IconPath.icon_speed), 32, 1,
        )
        image_fps.set_paintable(paintable_icon_fps)

        image_size = Gtk.Picture(css_name='sw_picture')
        paintable_icon_size = Gtk.IconPaintable.new_for_file(
                    Gio.File.new_for_path(IconPath.icon_partition_sym), 32, 1,
        )
        image_size.set_paintable(paintable_icon_size)

        image_folder = Gtk.Picture(css_name='sw_picture')
        paintable_icon_folder = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(IconPath.icon_folder_sym), 32, 1,
        )
        image_folder.set_paintable(paintable_icon_folder)

        swgs.label_time = Gtk.Label(css_name='sw_label_sub', xalign=0.0)
        swgs.label_time.add_css_class('font_size_12')

        swgs.label_fps = Gtk.Label(css_name='sw_label_sub', xalign=0.0)
        swgs.label_fps.add_css_class('font_size_12')

        label_size_name = Gtk.Label(
                                    css_name='sw_label_sub', xalign=0.0,
                                    label=msg.msg_dict['directory_size'] + ': '
        )
        label_size_name.add_css_class('font_size_12')

        swgs.label_size = Gtk.Label(css_name='sw_label_sub', xalign=0.0)
        swgs.label_size.add_css_class('font_size_12')

        label_folder = Gtk.Label(
                                css_name='sw_label', xalign=0.0,
                                label=msg.ctx_dict['open_location'],
        )
        swgs.btn_folder = Gtk.Button(css_name='sw_button', child=label_folder)

        label_griddb_heroes = Gtk.Label(
                                        css_name='sw_label', xalign=0.0,
                                        label=msg.ctx_dict['griddb'],
        )
        swgs.btn_griddb_heroes = Gtk.Button(
                                            css_name='sw_button',
                                            child=label_griddb_heroes
        )
        label_switch_app_to_desktop = Gtk.Label(
                                css_name='sw_label_sub',
                                label=msg.ctx_dict['app_to_desktop'],
                                xalign=0
        )
        label_switch_app_to_menu = Gtk.Label(
                                css_name='sw_label_sub',
                                label=msg.ctx_dict['app_to_menu'],
                                xalign=0
        )
        swgs.switch_app_to_desktop = Gtk.Switch(
                            css_name='sw_switch', valign=Gtk.Align.CENTER,
                            hexpand=True, halign=Gtk.Align.END
        )
        swgs.switch_app_to_menu = Gtk.Switch(
                            css_name='sw_switch', valign=Gtk.Align.CENTER,
                            hexpand=True, halign=Gtk.Align.END
        )
        swgs.switch_app_to_desktop.connect('state-set', cb_btn_switch_app_to_desktop, None)
        swgs.switch_app_to_menu.connect('state-set', cb_btn_switch_app_to_menu, None)

        swgs.box_switch_to_desktop = Gtk.Box(css_name='sw_box', spacing=8)
        swgs.box_switch_to_desktop.append(label_switch_app_to_desktop)
        swgs.box_switch_to_desktop.append(swgs.switch_app_to_desktop)

        swgs.box_switch_to_menu = Gtk.Box(css_name='sw_box', spacing=8)
        swgs.box_switch_to_menu.append(label_switch_app_to_menu)
        swgs.box_switch_to_menu.append(swgs.switch_app_to_menu)

        swgs.box_label_time = Gtk.Box(css_name='sw_box', spacing=8)
        swgs.box_label_time.append(image_time)
        swgs.box_label_time.append(swgs.label_time)

        swgs.box_label_fps = Gtk.Box(css_name='sw_box', spacing=8)
        swgs.box_label_fps.append(image_fps)
        swgs.box_label_fps.append(swgs.label_fps)

        swgs.box_label_size = Gtk.Box(css_name='sw_box', spacing=8)
        swgs.box_label_size.append(image_size)
        swgs.box_label_size.append(label_size_name)
        swgs.box_label_size.append(swgs.label_size)

        btn_stats = Gtk.Button(css_name='sw_button', child=image_stats)
        btn_stats.add_css_class('darkened')
        btn_stats.set_tooltip_markup(msg.tt_dict['stats'])

        swgs.btn_tools = Gtk.Button(css_name='sw_button', child=image_settings)
        swgs.btn_tools.set_tooltip_markup(msg.tt_dict['tools'])

        swgs.btn_controller = Gtk.Button(css_name='sw_button', child=image_controller)
        swgs.btn_controller.set_tooltip_markup(msg.tt_dict['controller'])

        swgs.btn_scroll_up = Gtk.Button(
                                css_name='sw_button', child=image_scroll_up,
        )
        swgs.btn_scroll_up.set_tooltip_markup(msg.tt_dict['scroll_up'])
        swgs.btn_scroll_up.set_visible(False)
        swgs.btn_scroll_up.connect('clicked', cb_btn_scroll_up)

        swgs.box_bottom_panel = Gtk.Box(
                            css_name='sw_box', spacing=8, hexpand=True,
                            orientation=Gtk.Orientation.HORIZONTAL, height_request=32,
                            baseline_position=Gtk.BaselinePosition.CENTER
        )
        swgs.box_bottom_panel.add_css_class('padding_8')

        swgs.box_bottom_panel.append(swgs.btn_stop)
        swgs.box_bottom_panel.append(swgs.btn_start)
        swgs.box_bottom_panel.append(swgs.dropdown_change_wine)
        swgs.box_bottom_panel.append(swgs.dropdown_change_pfx)
        swgs.box_bottom_panel.append(swgs.btn_tools)
        swgs.box_bottom_panel.append(swgs.btn_controller)
        swgs.box_bottom_panel.append(swgs.btn_scroll_up)

        swgs.overlay_stats = Gtk.Box(
                                    css_name='sw_box',
                                    orientation=Gtk.Orientation.VERTICAL,
                                    spacing=10,
                                    valign=Gtk.Align.START,
        )
        swgs.overlay_stats.add_css_class('padding_10')

        swgs.overlay_stats.append(swgs.box_label_time)
        swgs.overlay_stats.append(swgs.box_label_fps)
        swgs.overlay_stats.append(swgs.box_label_size)
        swgs.overlay_stats.append(swgs.box_switch_to_desktop)
        swgs.overlay_stats.append(swgs.box_switch_to_menu)
        swgs.overlay_stats.append(swgs.btn_folder)
        swgs.overlay_stats.append(swgs.btn_griddb_heroes)

        swgs.reveal_stats = Gtk.Revealer(
                        css_name='sw_revealer',
                        transition_duration=250,
                        transition_type=Gtk.RevealerTransitionType.SLIDE_RIGHT,
                        vexpand=True, hexpand=True,
                        valign=Gtk.Align.START,
                        halign=Gtk.Align.START,
                        child=swgs.overlay_stats,
        )
        swgs.reveal_stats.add_css_class('darkened')
        swgs.reveal_stats.add_css_class('corner')

        swgs.column_wine_tools = add_overlay_wine_tools()
        swgs.column_wine_tools.add_css_class('padding_10')

        swgs.column_prefix_tools = add_overlay_prefix_tools()
        swgs.column_prefix_tools.add_css_class('padding_10')

        swgs.grid_settings = Gtk.Grid(css_name='sw_grid')
        swgs.grid_settings.set_column_homogeneous(True)
        swgs.grid_settings.add_css_class('darkened')
        swgs.grid_settings.add_css_class('corner')
        swgs.grid_settings.attach(swgs.column_prefix_tools, 0, 0, 1, 1)
        swgs.grid_settings.attach(swgs.column_wine_tools, 1, 0, 1, 1)

        swgs.reveal_settings = Gtk.Revealer(
                        css_name='sw_revealer',
                        transition_duration=250,
                        transition_type=Gtk.RevealerTransitionType.SLIDE_RIGHT,
                        vexpand=True, hexpand=True,
                        valign=Gtk.Align.START,
                        halign=Gtk.Align.START,
                        child=swgs.grid_settings,
        )
        btn_stats.connect('clicked', cb_btn_revealer, swgs.reveal_stats)
        swgs.btn_tools.connect('clicked', cb_btn_revealer, swgs.reveal_settings)
        swgs.btn_controller.connect('clicked', cb_btn_controller)
        swgs.btn_folder.connect('clicked', open_app_folder)
        swgs.btn_griddb_heroes.connect('clicked', cb_btn_web_view_griddb, None, 'heroes?term=')

        swgs.box_title = Gtk.Box(css_name='sw_box', spacing=8)
        swgs.box_title.add_css_class('left_padding_8')
        swgs.box_title.append(btn_stats)
        swgs.box_title.append(swgs.label_startapp)

        swgs.grid_title = Gtk.Grid(
            name='grid_title', css_name='sw_grid', vexpand=True, hexpand=True,
        )
        swgs.grid_title.set_row_spacing(4)
        swgs.grid_title.set_column_spacing(4)

        swgs.grid_title.add_css_class('shadow')

        swgs.grid_title.attach(swgs.box_title, 0, 0, 1, 1)
        swgs.grid_title.attach(swgs.reveal_stats, 0, 1, 1, 1)
        swgs.grid_title.attach(swgs.reveal_settings, 0, 1, 1, 1)
        swgs.grid_title.attach(swgs.box_bottom_panel, 0, 2, 1, 1)

        image_next = Gtk.Picture(css_name='sw_picture')
        paintable_icon_next = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(IconPath.icon_window_next), 96, 1,
        )
        image_next.set_paintable(paintable_icon_next)

        image_prev = Gtk.Picture(css_name='sw_picture')
        paintable_icon_prev = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(IconPath.icon_window_prev), 96, 1,
        )
        image_prev.set_paintable(paintable_icon_prev)

        swgs.btn_prev_shortcut = Gtk.Button(
            css_name='sw_button', height_request=96, child=image_prev,
        )
        swgs.btn_prev_shortcut.add_css_class('darkened')
        swgs.btn_prev_shortcut.connect('clicked', cb_btn_prev_shortcut)

        swgs.btn_next_shortcut = Gtk.Button(
            css_name='sw_button', height_request=96, child=image_next,
        )
        swgs.btn_next_shortcut.add_css_class('darkened')
        swgs.btn_next_shortcut.connect('clicked', cb_btn_next_shortcut)

        swgs.box_cycle_shortcut = Gtk.Box(
            css_name='sw_box', orientation=Gtk.Orientation.HORIZONTAL,
            margin_end=32, spacing=8, hexpand=True, vexpand=True,
            halign=Gtk.Align.END, valign=Gtk.Align.CENTER,
        )
        swgs.box_cycle_shortcut.append(swgs.btn_prev_shortcut)
        swgs.box_cycle_shortcut.append(swgs.btn_next_shortcut)

        swgs.overlay_title = Gtk.Overlay()
        swgs.overlay_title.set_child(swgs.image_title)
        swgs.overlay_title.add_overlay(swgs.grid_title)
        swgs.overlay_title.add_overlay(swgs.box_cycle_shortcut)

        title_stack_switcher = Gtk.Label(
                                        css_name='sw_label_title',
                                        label=msg.msg_dict['settings'],
                                        xalign=0.0,
        )
        image_reset = Gtk.Image(css_name='sw_image')
        image_reset.set_from_file(IconPath.icon_update)
        label_reset = Gtk.Label(
                                css_name='sw_label',
                                label=settings_dict['set_app_default'],
                                ellipsize=Pango.EllipsizeMode.END
        )
        box_btn_reset = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        box_btn_reset.append(image_reset)
        box_btn_reset.append(label_reset)

        btn_reset = Gtk.Button(css_name='sw_button', hexpand=True, halign=Gtk.Align.END)
        btn_reset.set_name(settings_dict['set_app_default'])
        btn_reset.set_child(box_btn_reset)
        btn_reset.connect('clicked', cb_btn_settings)

        box_title_stack_switcher = Gtk.Grid(css_name='sw_box_view')
        box_title_stack_switcher.attach(title_stack_switcher, 0, 0, 1, 1)
        box_title_stack_switcher.attach(btn_reset, 1, 0, 1, 1)

        swgs.box_stack_switcher = Gtk.Box(
                                    css_name='sw_box',
                                    orientation=Gtk.Orientation.HORIZONTAL,
                                    spacing=8,
                                    halign=Gtk.Align.START,
                                    valign=Gtk.Align.CENTER,
                                    homogeneous=True,
        )
        swgs.box_stack_switcher.add_css_class('padding_8')

        page_list = [
                    vw_dict['launch_settings'], vw_dict['mangohud_settings'],
                    vw_dict['vkbasalt_settings']
        ]
        count = 0
        for name in page_list:
            count += 1
            btn = Gtk.Button(
                            css_name='sw_button', label=vl_dict[name],
                            name=vl_dict[name]
            )
            btn.connect('clicked', cb_btn_settings)
            swgs.box_stack_switcher.append(btn)

        swgs.grid_settings_stack = Gtk.Grid(css_name='sw_pref_box')
        swgs.grid_settings_stack.attach(box_title_stack_switcher, 0, 0, 1, 1)
        swgs.grid_settings_stack.attach(swgs.box_stack_switcher, 0, 1, 1, 1)
        swgs.grid_settings_stack.attach(stack_settings, 0, 2, 1, 1)
        #swgs.grid_settings_stack.set_margin_top(32)

        swgs.reveal_top_panel = Gtk.Revealer(hexpand=True, valign=Gtk.Align.START)
        swgs.reveal_top_panel.add_css_class('darkened')
        swgs.reveal_top_panel.set_transition_type(Gtk.RevealerTransitionType.SLIDE_DOWN)
        swgs.reveal_top_panel.set_transition_duration(250)

        swgs.grid_content = Gtk.Grid(name='grid_content', css_name='sw_grid')
        swgs.grid_content.add_css_class('darkened')
        swgs.grid_content.attach(swgs.overlay_title, 0, 0, 1, 1)
        swgs.grid_content.attach(swgs.grid_settings_stack, 0, 1, 1, 1)

        scrolled_startapp_page.set_child(swgs.grid_content)
        vadjustment = scrolled_startapp_page.get_vadjustment()
        vadjustment.connect('value-changed', on_scroll_startapp_page)

        overlay_startapp_page.set_child(scrolled_startapp_page)
        overlay_startapp_page.add_overlay(swgs.reveal_top_panel)

        swgs.overlay_title.add_tick_callback(on_overlay_title_resize)

    def cb_btn_scroll_up(_self):
        """___scrolling the startapp page up___"""

        scrolled_startapp_page.get_child().scroll_to(swgs.box_title)

    def cb_btn_next_shortcut(_self):
        """___cycling through the next startapp page___"""

        if swgs.next_exec:
            next_shortcut = next(swgs.next_exec)
            if str(next_shortcut) == str(get_app_path().strip('"')):
                next_shortcut = next(swgs.next_exec)

            check_arg(str(next_shortcut))
            on_startapp_page()

    def cb_btn_prev_shortcut(_self):
        """___cycling through the next startapp page___"""

        if swgs.prev_exec:
            prev_shortcut = next(swgs.prev_exec)
            if str(prev_shortcut) == str(get_app_path().strip('"')):
                prev_shortcut = next(swgs.prev_exec)

            check_arg(str(prev_shortcut))
            on_startapp_page()

    def on_scroll_startapp_page(self):
        """___show or hide top panel when scrolling the page___"""

        if self.get_value() > swgs.image_title.get_height():
            if swgs.reveal_top_panel.get_child() is None:
                swgs.box_bottom_panel.unparent()
                swgs.box_bottom_panel.add_css_class('darkened')
                swgs.reveal_top_panel.set_child(swgs.box_bottom_panel)
                swgs.btn_tools.set_visible(False)
                swgs.btn_scroll_up.set_visible(True)
            swgs.reveal_top_panel.set_reveal_child(True)
        else:
            swgs.box_bottom_panel.unparent()
            swgs.box_bottom_panel.remove_css_class('darkened')
            swgs.reveal_top_panel.set_child(None)
            swgs.btn_tools.set_visible(True)
            swgs.btn_scroll_up.set_visible(False)
            swgs.grid_title.attach(swgs.box_bottom_panel, 0, 2, 1, 1)

            swgs.reveal_top_panel.set_reveal_child(False)

    def cb_btn_revealer(_self, revealer):
        """___button handler for revealer overlay___"""

        if revealer == swgs.reveal_stats:
            if revealer.get_reveal_child():
                revealer.set_reveal_child(False)
            else:
                revealer.set_reveal_child(True)
                swgs.reveal_settings.set_reveal_child(False)

        elif revealer == swgs.reveal_settings:
            if revealer.get_reveal_child():
                revealer.set_reveal_child(False)
            else:
                revealer.set_reveal_child(True)
                swgs.reveal_stats.set_reveal_child(False)

    def cb_btn_controller(_self):
        """___open device redirection settings___"""

        rc_dict['controller_active'] = False
        profile = read_json_data(sw_input_json)
        SwDeviceRedirectionSettings(swgs, profile, rc_dict)

    def open_app_folder(_self):
        """___open application directory___"""

        app_path = str(Path(get_app_path().strip('"')).parent)
        if app_path is not None and app_path != 'StartWine':
            return on_files(app_path)

    def on_overlay_title_resize(self, frame_clock):
        """___resize box when window size is changed___"""

        if float(frame_clock.get_frame_counter() / 250).is_integer():
            image_path = self.get_child().get_file().get_path()
            if not Path(image_path).exists() or image_path == f'{sw_gui_icons}/{sw_logo_light}':
                set_heroes_icon(get_out(), swgs.image_title, swgs.label_startapp)

        if self.get_width() < 1060 and swgs.reveal_settings.get_reveal_child():
            swgs.box_cycle_shortcut.set_visible(False)
        else:
            swgs.box_cycle_shortcut.set_visible(True)

        self.set_size_request(-1, swgs.width * 28/96)
        return True

    def context_connect(menu_x, context_x, data_x, count):
        """___connect context menu items to a callback function___"""

        for a in context_x:
            count += 1
            action_name: str = a['name']
            action_type = ''.join(e for e in action_name if e.isalnum())
            action_func = a['func']
            item = Gio.MenuItem.new(f'{action_name}\t', f'app.{action_type}')
            menu_x.insert_item(count, item)
            action = Gio.SimpleAction.new(action_type, None)
            action.connect('activate', action_func, data_x)
            swgs.add_action(action)

            try:
                accel_for_action = a['accel']
            except (Exception,):
                accel_for_action = None

            swgs.set_accels_for_action(
                f'app.{action_type}',
                [accel_for_action],
            )
            action_list.append(f'app.{action_type}')

        context_x.clear()

    def cb_context_activate(self, position, data):

        item = self.get_model().get_item(position)
        action_name = item.get_label()
        action_type = item.get_name()
        context_popover = self.get_parent().get_parent().get_parent().get_parent()

        if 'backward' in action_type:
            self.get_parent().get_parent().set_visible_child_name('menu')

        if 'submenu' in action_type:
            self.get_parent().get_parent().set_visible_child_name(action_type)

        if data.get(action_type):
            if action_type == 'sort_submenu':
                if action_name == (
                                    msg.ctx_dict['show_hidden_files'][0]):
                    context_popover.popdown()
                    return on_files_view_props('hidden_files', None)

                if action_name == (
                                    msg.ctx_dict['sorting_by_type'][0]):
                    context_popover.popdown()
                    return on_files_view_props('sorting_files', 'type')

                if action_name == (
                                    msg.ctx_dict['sorting_by_size'][0]):
                    context_popover.popdown()
                    return on_files_view_props('sorting_files', 'size')

                if action_name == (
                                    msg.ctx_dict['sorting_by_date'][0]):
                    context_popover.popdown()
                    return on_files_view_props('sorting_files', 'date')

                if action_name == (
                                    msg.ctx_dict['sorting_by_name'][0]):
                    context_popover.popdown()
                    return on_files_view_props('sorting_files', 'name')

                if action_name == (
                                    msg.ctx_dict['sorting_reverse'][0]):
                    context_popover.popdown()
                    return on_files_view_props('sorting_reverse', None)
            else:
                for d in data[action_type]:
                    if d.get('name') == action_name:
                        func = d['func']
                        args = d['data']
                        context_popover.popdown()
                        return func(action_name, action_type, args)

    def cb_context_factory_setup(self, item_list):

        label = Gtk.Label(css_name='sw_label', xalign=0)
        label.add_css_class('padding_8')
        item_list.set_child(label)

    def cb_context_factory_bind(self, item_list):

        item = item_list.get_item()
        label = item_list.get_child()
        name = item.get_label()
        func = item.get_name()
        label.set_label(name)
        label.set_name(str(func))

    def show_context(x, y, widget, data):

        f_data = {
            'exe_section': [
                {
                    'name': msg.ctx_dict['run'],
                    'func': on_cb_file_exe,
                    'data': data
                },
            ],
            'open_location_section': [
                {
                    'name': msg.ctx_dict['open_location'],
                    'func': on_cb_file_open_location,
                    'data': data
                },
            ],
            'open_with_section': [
                {
                    'name': msg.ctx_dict['open_with'],
                    'func': on_cb_file_open_with,
                    'data': data
                },
            ],
            'run_section': [
                {
                    'name': msg.ctx_dict['run'],
                    'func': on_cb_file_run,
                    'data': data
                },
                {
                    'name': msg.ctx_dict['open'],
                    'func': on_cb_file_open,
                    'data': data
                },
            ],
            'open_section': [
                {
                    'name': msg.ctx_dict['open'],
                    'func': on_cb_file_open,
                    'data': data
                },
            ],
            'media_section': [
                {
                    'name': msg.ctx_dict['add_media'],
                    'func': on_cb_add_media,
                    'data': data
                },
            ],
            'edit_section': [
                {
                    'name': msg.ctx_dict['cut'][0],
                    'func': on_cb_file_cut,
                    'accel': msg.ctx_dict['cut'][1],
                    'data': data
                },
                {
                    'name': msg.ctx_dict['copy'][0],
                    'func': on_cb_file_copy,
                    'accel': msg.ctx_dict['copy'][1],
                    'data': data
                },
                {
                    'name': msg.ctx_dict['rename'][0],
                    'func': on_cb_file_rename,
                    'accel': msg.ctx_dict['rename'][1],
                    'data': data
                },
                {
                    'name': msg.ctx_dict['link'][0],
                    'func': on_cb_file_link,
                    'accel': msg.ctx_dict['link'][1],
                    'data': data
                },
                {
                    'name': msg.ctx_dict['compress'],
                    'func': on_cb_file_compress,
                    'data': data
                },
            ],
            'remove_section': [
                {
                    'name': msg.ctx_dict['trash'][0],
                    'func': on_cb_file_remove,
                    'accel': msg.ctx_dict['trash'][1],
                    'data': data
                },
                {
                    'name': msg.ctx_dict['delete'][0],
                    'func': on_cb_file_remove,
                    'accel': msg.ctx_dict['delete'][1],
                    'data': data
                },
            ],
            'property_section': [
                {
                    'name': msg.ctx_dict['properties'][0],
                    'func': on_cb_file_properties,
                    'data': data
                },
            ],
            'dir_section': [
                {
                    'name': msg.ctx_dict['open'],
                    'func': on_cb_dir_open,
                    'data': data
                },
            ],
        }
        e_data = {
            'more_section': [
                {
                    'name': msg.ctx_dict['copy_path'],
                    'func': on_cb_empty_copy_path,
                    'data': data
                },
                {
                    'name': msg.ctx_dict['add_bookmark'],
                    'func': on_cb_empty_add_bookmark,
                    'data': data
                },
            ],
            'sort_submenu': [
                {
                    'name': msg.ctx_dict['show_hidden_files'][0],
                    'accel': msg.ctx_dict['show_hidden_files'][1],
                    'func': on_files_view_props,
                    'data': data
                },
                {
                    'name': msg.ctx_dict['sorting_by_type'][0],
                    'accel': msg.ctx_dict['sorting_by_type'][1],
                    'func': on_files_view_props,
                    'data': data
                },
                {
                    'name': msg.ctx_dict['sorting_by_size'][0],
                    'accel': msg.ctx_dict['sorting_by_size'][1],
                    'func': on_files_view_props,
                    'data': data
                },
                {
                    'name': msg.ctx_dict['sorting_by_date'][0],
                    'accel': msg.ctx_dict['sorting_by_date'][1],
                    'func': on_files_view_props,
                    'data': data
                },
                {
                    'name': msg.ctx_dict['sorting_by_name'][0],
                    'accel': msg.ctx_dict['sorting_by_name'][1],
                    'func': on_files_view_props,
                    'data': data
                },
                {
                    'name': msg.ctx_dict['sorting_reverse'][0],
                    'accel': msg.ctx_dict['sorting_reverse'][1],
                    'func': on_files_view_props,
                    'data': data
                },
            ],
            'dir_section': [
                {
                    'name': msg.ctx_dict['create_dir'][0],
                    'func': on_cb_empty_create_dir,
                    'accel': msg.ctx_dict['create_dir'][1],
                    'data': data
                },
            ],
            'create_submenu': [
                {
                    'name': msg.ctx_dict['txt'],
                    'func': on_cb_empty_create_file,
                    'data': data
                },
                {
                    'name': msg.ctx_dict['sh'],
                    'func': on_cb_empty_create_file,
                    'data': data
                },
                {
                    'name': msg.ctx_dict['py'],
                    'func': on_cb_empty_create_file,
                    'data': data
                },
                {
                    'name': msg.ctx_dict['desktop'],
                    'func': on_cb_empty_create_file,
                    'data': data
                },
            ],
            'edit_section': [
                {
                    'name': msg.ctx_dict['paste'][0],
                    'func': on_cb_empty_paste,
                    'accel': msg.ctx_dict['paste'][1],
                    'data': data
                },
                {
                    'name': msg.ctx_dict['select_all'][0],
                    'func': on_cb_empty_select_all,
                    'accel': msg.ctx_dict['select_all'][1],
                    'data': data
                },
            ],
            'props_section': [
                {
                    'name': msg.ctx_dict['properties'][0],
                    'func': on_cb_empty_properties,
                    'data': data
                },
            ],
        }
        ctx = widget.get_last_child()
        if ctx and ctx.get_name() == 'context_menu':
            ctx.unparent()
            ctx.unmap()
            ctx.unrealize()
            print(f'{tc.VIOLET2}{ctx} {tc.GREEN}unrealize{tc.END}')

        context_data = {}
        if isinstance(data, str):
            context_data = e_data

        elif data and isinstance(data, list):

            f_info = data[0].query_info('*', Gio.FileQueryInfoFlags.NONE, None)
            f_type = f_info.get_content_type()

            if len(entry_search.get_text()) > 1:
                context_data['open_location_section'] = f_data['open_location_section']

            if f_type == dir_mime_types[0]:
                context_data['dir_section'] = f_data['dir_section']

            elif f_type in exe_mime_types:
                context_data['exe_section'] = f_data['exe_section']

            elif (f_type in script_mime_types or f_type in bin_mime_types):
                context_data['run_section'] = f_data['run_section']

            elif f_type in audio_mime_types:
                context_data['media_section'] = f_data['media_section']
            else:
                context_data['open_section'] = f_data['open_section']

            if data[0].get_path():
                if Path(data[0].get_path()).is_file():
                    context_data['open_with_section'] = f_data['open_with_section']

                context_data['edit_section'] = f_data['edit_section']
                context_data['remove_section'] = f_data['remove_section']
                context_data['property_section'] = f_data['property_section']
            else:
                context_data['edit_section'] = f_data['edit_section']
                context_data['remove_section'] = f_data['remove_section']

        rect = Gdk.Rectangle()
        rect.x = x
        rect.y = y
        rect.width = 10
        rect.height = 10

        context_menu = Gtk.Popover(css_name='sw_popovermenu')
        context_menu.set_has_arrow(False)
        context_menu.set_position(Gtk.PositionType.BOTTOM)
        context_menu.set_pointing_to(rect)
        context_menu.set_name('context_menu')

        context_stack = Gtk.Stack(
            transition_duration=200,
            transition_type=Gtk.StackTransitionType.SLIDE_LEFT_RIGHT,
        )
        menu_store = Gio.ListStore()
        for k, v in context_data.items():
            if 'section' in k:
                for m in v:
                    section = k
                    name = m['name']
                    item = Gtk.Label(label=name, name=section)
                    menu_store.append(item)
            if 'submenu' in k:
                subtitle = k.replace('_submenu', '')
                submenu = Gtk.Label(label=msg.ctx_dict[subtitle], name=k)
                menu_store.append(submenu)
                submenu_store = Gio.ListStore()
                submenu_model = Gtk.SingleSelection.new(submenu_store)
                submenu_factory = Gtk.SignalListItemFactory()
                submenu_factory.connect('setup', cb_context_factory_setup)
                submenu_factory.connect('bind', cb_context_factory_bind)
                submenu_listview = Gtk.ListView(
                    name='submenu', css_name='sw_listview', single_click_activate=True,
                    show_separators=True,
                )
                submenu_listview.remove_css_class('view')
                submenu_listview.add_css_class('padding_4')
                submenu_listview.set_model(submenu_model)
                submenu_listview.set_factory(submenu_factory)
                submenu_listview.connect('activate', cb_context_activate, context_data)

                context_subbox = Gtk.Box(css_name='sw_box', orientation=Gtk.Orientation.VERTICAL)
                context_subbox.append(submenu_listview)

                context_stack.add_named(context_subbox, k)
                backward = Gtk.Label(label=f'<-- {msg.tt_dict["back_main"]}', name='backward')
                submenu_store.append(backward)
                for s in v:
                    subname = s['name']
                    subitem = Gtk.Label(label=subname, name=k)
                    submenu_store.append(subitem)

        menu_model = Gtk.SingleSelection.new(menu_store)
        menu_factory = Gtk.SignalListItemFactory()
        menu_factory.connect('setup', cb_context_factory_setup)
        menu_factory.connect('bind', cb_context_factory_bind)

        menu_listview = Gtk.ListView(
            name='menu', css_name='sw_listview', single_click_activate=True,
            show_separators=True,
        )
        menu_listview.remove_css_class('view')
        menu_listview.add_css_class('padding_4')
        menu_listview.set_model(menu_model)
        menu_listview.set_factory(menu_factory)
        menu_listview.connect('activate', cb_context_activate, context_data)

        context_box = Gtk.Box(css_name='sw_box', orientation=Gtk.Orientation.VERTICAL)
        context_box.append(menu_listview)

        context_stack.add_named(context_box, 'menu')
        context_stack.set_visible_child_name('menu')

        context_menu.set_child(context_stack)
        context_menu.set_parent(widget)
        context_menu.popup()

    def on_header_context(x, y, widget, parent_path):
        """___right click on empty place in view___"""

        if stack_sidebar.get_visible_child() == frame_files_info:
            on_back_main()

        context_header_menu = [
            {
                'name': msg.ctx_dict['global_settings'][0],
                'accel': msg.ctx_dict['global_settings'][1],
                'func': on_btn_header_menu
            },
            {
                'name': msg.ctx_dict['show_hotkeys'][0],
                'accel': msg.ctx_dict['show_hotkeys'][1],
                'func': on_btn_header_menu
            },
            {
                'name': msg.ctx_dict['about'][0],
                'accel': msg.ctx_dict['about'][1],
                'func': on_btn_header_menu
            },
            {
                'name': msg.ctx_dict['help'][0],
                'accel': msg.ctx_dict['help'][1],
                'func': on_btn_header_menu
            },
        ]
        context_shutdown = [
            {
                'name': msg.ctx_dict['shutdown'][0] + f' {sw_program_name}',
                'accel': msg.ctx_dict['shutdown'][1],
                'func': on_btn_header_menu
            },
        ]
        rect = Gdk.Rectangle()
        rect.x = x
        rect.y = y
        rect.width = 1
        rect.height = 1

        section_header_menu = Gio.Menu()
        section_shutdown = Gio.Menu()

        context_menu = Gtk.PopoverMenu(css_name='sw_popovermenu')
        context_menu.set_has_arrow(False)
        context_menu.set_position(Gtk.PositionType.BOTTOM)
        context_menu.set_pointing_to(rect)
        context_menu.set_name('header_context_menu')

        if widget.get_name() == 'header_menu':
            gmenu = Gio.Menu()
            gmenu.insert_section(1, None, section_header_menu)
            gmenu.append_section(None, section_shutdown)
            context_connect(section_header_menu, context_header_menu, parent_path, 0)
            context_connect(section_shutdown, context_shutdown, parent_path, 0)
            context_menu.set_menu_model(gmenu)
            context_menu.set_parent(widget)
            scrolled = context_menu.get_first_child().get_first_child()
            scrolled.set_propagate_natural_height(True)
            scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.NEVER)
            context_menu.popup()

        context_header_menu.clear()
        context_shutdown.clear()
        return context_menu

    def on_cb_empty_copy_path(_action_name, _parameter, data):
        """___callback context button copy current path___"""

        x_file = Gio.File.new_for_commandline_arg(bytes(Path(data)))
        on_file_copy([x_file])

    def on_cb_empty_add_bookmark(_action_name, _parameter, data):
        """___callback context button add current path to bookmark___"""

        return on_add_bookmark(data)

    def on_add_bookmark(data):
        """___add new bookmark button in bookmarks menu___"""

        d = data
        try:
            r = sw_bookmarks.read_text()
        except IOError as e:
            return overlay_info(main_overlay, None, e, None, None, 3)
        else:
            s = r.splitlines()
            for x in s:
                if x == d:
                    d = None
            else:
                if d is not None:
                    try:
                        s.append(d)
                        sw_bookmarks.write_text('\n'.join(s))
                    except IOError as e:
                        return overlay_info(main_overlay, None, e, None, None, 3)
                    else:
                        if scrolled_bookmarks.get_child() is None:
                            add_bookmarks_menu()
                        update_bookmarks()
                        text_message = str_create_new_bookmark
                        print(f'{tc.VIOLET2}SW_BOOKMARKS: {tc.GREEN}write new bookmark: done' + tc.END)
                        return overlay_info(main_overlay, None, text_message, None, None, 3)
                else:
                    text_message = str_bookmark_exists
                    return overlay_info(main_overlay, None, text_message, None, None, 3)

    def cb_btn_remove_bookmark(self):
        """___remove bookmark button from bookmarks menu___"""

        try:
            r = sw_bookmarks.read_text()
        except IOError as e:
            return overlay_info(main_overlay, None, e, None, None, 3)
        else:
            s = r.splitlines()
            s.remove(self.get_name())
            try:
                sw_bookmarks.write_text('\n'.join(s))
            except IOError as e:
                return overlay_info(main_overlay, None, e, None, None, 3)
            else:
                if scrolled_bookmarks.get_child() is None:
                    add_bookmarks_menu()
                update_bookmarks()
                text_message = str_remove_bookmark
                print(f'{tc.VIOLET2}SW_BOOKMARKS: {tc.GREEN}remove bookmark: done' + tc.END)
                return overlay_info(main_overlay, None, text_message, None, None, 3)

    def on_cb_add_media(_action_name, _parameter, data):
        """___callback context button add current file path to playlist___"""

        format_data = []
        for f in data:
            f_info = f.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
            f_type = f_info.get_content_type()
            if f_type in audio_mime_types:
                format_data.append(f)

        if len(format_data) > 0:
            return on_add_media(format_data)
        else:
            e = msg.msg_dict['does_not_exist']
            return overlay_info(main_overlay, None, e, None, None, 3)

    def on_add_media(data):
        """___add new media source button in playlist___"""

        try:
            r = sw_playlist.read_text()
        except IOError as e:
            return overlay_info(main_overlay, None, e, None, None, 3)
        else:
            s = r.splitlines()
            d = [p.get_path() for p in data if p.get_path() is not None]
            set_ = set(s + d)

            try:
                sw_playlist.write_text('\n'.join(set_))
            except IOError as e:
                return overlay_info(main_overlay, None, e, None, None, 3)
            else:
                if scrolled_playlist.get_child() is None:
                    add_playlist_menu()
                update_playlist()
                text_message = str_create_new_media
                return overlay_info(main_overlay, None, text_message, None, None, 3)

    def cb_btn_clear_media_playlist():
        """___clear media playlist and remove buttons___"""

        try:
            sw_playlist.write_text('')
        except IOError as e:
            return overlay_info(main_overlay, None, e, None, None, 3)
        else:
            if scrolled_playlist.get_child() is None:
                add_playlist_menu()
            update_playlist()

    def cb_btn_remove_media(self):
        """___remove media and button from playlist___"""

        try:
            r = sw_playlist.read_text()
        except IOError as e:
            return overlay_info(main_overlay, None, e, None, None, 3)
        else:
            s = r.splitlines()
            s.remove(self.get_name())
            try:
                sw_playlist.write_text('\n'.join(s))
            except IOError as e:
                return overlay_info(main_overlay, None, e, None, None, 3)
            else:
                if scrolled_playlist.get_child() is None:
                    add_playlist_menu()
                update_playlist()
                text_message = str_remove_media
                return overlay_info(main_overlay, None, text_message, None, None, 3)

    def on_cb_empty_create_file(action_name, _parameter, data):
        """___callback context button create file___"""

        if Path(data) == Path(sw_shortcuts):
            text_message = msg.msg_dict['impossible_create']
            return overlay_info(main_overlay, None, text_message, None, None, 3)

        elif Path(data) == Path(sw_launchers):
            text_message = msg.msg_dict['impossible_create']
            return overlay_info(main_overlay, None, text_message, None, None, 3)

        else:
            if action_name == str(msg.ctx_dict['txt']):
                on_create_file(f'{msg.ctx_dict["sample"]}', f'.txt', None)

            if action_name == str(msg.ctx_dict['sh']):
                on_create_file(f'{msg.ctx_dict["sample"]}', f'.sh', sample_bash)

            if action_name == str(msg.ctx_dict['py']):
                on_create_file(f'{msg.ctx_dict["sample"]}', f'.py', sample_python)

            if action_name == str(msg.ctx_dict['desktop']):
                on_create_file(f'{msg.ctx_dict["sample"]}', f'.desktop', sample_desktop)

    def on_create_file(name, ext, sample):
        """___create new file___"""

        parent_file = get_parent_file()

        if parent_file.get_path() is not None:
            parent_path = parent_file.get_path()
        else:
            parent_path = parent_file.get_uri()

        count = int()
        x_path = f'{parent_path}/{name}{ext}'
        x_file = Gio.File.new_for_commandline_arg(x_path)

        while x_file.query_exists():
            count += 1
            x_path = f'{parent_path}/{name} {count}{ext}'
            x_file = Gio.File.new_for_commandline_arg(x_path)

        try:
            x_file.create(Gio.FileCreateFlags.NONE)
        except GLib.GError as e:
            print(e.message)
            SwCrier(text_message=str(e.message), message_type='ERROR').run()
        else:
            if sample is not None:
                try:
                    with open(x_path, 'w') as x:
                        x.write(sample)
                        x.close()
                except IOError as e:
                    print(e)
                    strerr = msg.msg_dict['does_not_exist']
                    SwCrier(text_message=strerr, message_type='ERROR').run()

    def on_cb_empty_create_dir(_action_name, _parameter, parent_path):
        """___callback on context button for create directory___"""

        if Path(parent_path) == Path(sw_shortcuts):
            text_message = msg.msg_dict['impossible_create']
            return overlay_info(main_overlay, None, text_message, None, None, 3)

        elif Path(parent_path) == Path(sw_launchers):
            text_message = msg.msg_dict['impossible_create']
            return overlay_info(main_overlay, None, text_message, None, None, 3)

        else:
            return on_create_dir()

    def on_create_dir():
        """___create new directory___"""

        def create_dir(src):
            """___create new directory___"""

            dir_name = entry_name.get_text()
            count = int()
            x_path = f'{src}/{dir_name}'
            x_file = Gio.File.new_for_commandline_arg(x_path)

            while x_file.query_exists():
                count += 1
                x_path = f'{src}/{dir_name} {count}'
                x_file = Gio.File.new_for_commandline_arg(x_path)

            try:
                x_file.make_directory_with_parents()
            except GLib.GError as e:
                print(e.message)
                SwCrier(text_message=str(e.message), message_type='ERROR').run()

        parent_file = get_parent_file()
        if parent_file.get_path() is None:
            src = parent_file.get_uri()
        else:
            src = parent_file.get_path()

        title = msg.msg_dict['create_dir'].capitalize()
        text_message = [msg.msg_dict['new_dir'].capitalize()]
        button_name = msg.msg_dict['create'].capitalize()
        func = [(create_dir, (src,)), None]
        dialog = SwDialogEntry(swgs, title, text_message, button_name, func, 1, None)
        dialog_child = dialog.get_child()
        if dialog_child is not None:
            entry_name = dialog_child.get_first_child()

    def on_cb_empty_paste(_action_name, _parameter, _data):
        """___activate context menu button paste___"""

        return on_file_paste()

    def on_cb_empty_select_all(_action_name, _parameter, _data):
        """___callback context button select all___"""

        grid_view = get_list_view()
        grid_view.get_model().select_all()

    def on_cb_empty_properties(_action_name, _parameter, data):
        """___get current directory properties___"""

        on_file_properties()

        if data is None:
            x_file = get_parent_uri()
        else:
            x_file = Gio.File.new_for_commandline_arg(bytes(Path(data)))

        get_file_props(x_file)

    def on_file_context(x, y, grid_view, x_files):
        """___build and connect file context menu___"""

        if stack_sidebar.get_visible_child() == frame_files_info:
            on_back_main()

        custom_context = '''
             <?xml version="1.0" encoding="UTF-8"?>
             <interface>
               <menu id="custom_context">
                 <item>
                   <attribute name="custom">widget</attribute>
                 </item>
               </menu>
             </interface>
        '''

        builder_context = Gtk.Builder()
        builder_context.add_from_string(custom_context)
        menu = builder_context.get_object('custom_context')

        context_exe = [
            {'name': msg.ctx_dict['run'], 'func': on_cb_file_exe},
        ]
        context_open_location = [
            {'name': msg.ctx_dict['open_location'], 'func': on_cb_file_open_location},
        ]
        context_open_with = [
            {'name': msg.ctx_dict['open_with'], 'func': on_cb_file_open_with},
        ]
        context_run = [
            {'name': msg.ctx_dict['run'], 'func': on_cb_file_run},
            {'name': msg.ctx_dict['open'], 'func': on_cb_file_open},
        ]
        context_open = [
            {'name': msg.ctx_dict['open'], 'func': on_cb_file_open},
        ]
        context_media = [
            {'name': msg.ctx_dict['add_media'], 'func': on_cb_add_media},
        ]
        context_edit = [
            {'name': msg.ctx_dict['cut'][0], 'func': on_cb_file_cut, 'accel': msg.ctx_dict['cut'][1]},
            {'name': msg.ctx_dict['copy'][0], 'func': on_cb_file_copy, 'accel': msg.ctx_dict['copy'][1]},
            {'name': msg.ctx_dict['rename'][0], 'func': on_cb_file_rename, 'accel': msg.ctx_dict['rename'][1]},
            {'name': msg.ctx_dict['link'][0], 'func': on_cb_file_link, 'accel': msg.ctx_dict['link'][1]},
            {'name': msg.ctx_dict['compress'], 'func': on_cb_file_compress},
        ]
        context_remove = [
            {'name': msg.ctx_dict['trash'][0], 'func': on_cb_file_remove, 'accel': msg.ctx_dict['trash'][1]},
            {'name': msg.ctx_dict['delete'][0], 'func': on_cb_file_remove, 'accel': msg.ctx_dict['delete'][1]},
        ]
        context_property = [
            {'name': msg.ctx_dict['properties'][0], 'func': on_cb_file_properties},
        ]
        context_dir = [
            {'name': msg.ctx_dict['open'], 'func': on_cb_dir_open},
        ]
        rect = Gdk.Rectangle()
        rect.x = x
        rect.y = y
        rect.width = 1
        rect.height = 1

        section_edit = Gio.Menu()
        section_remove = Gio.Menu()
        section_property = Gio.Menu()

        menu.append_section(None, section_edit)
        menu.append_section(None, section_remove)
        menu.append_section(None, section_property)

        context_menu = Gtk.PopoverMenu(css_name='sw_popovermenu')
        context_menu.set_has_arrow(False)
        context_menu.set_hexpand(True)
        context_menu.set_vexpand(True)
        context_menu.set_position(Gtk.PositionType.BOTTOM)
        context_menu.set_pointing_to(rect)
        context_menu.set_offset(128, 16)
        context_menu.set_name('file_context_menu')
        context_menu.set_parent(main_overlay)

        file_info = x_files[0].query_info(
                                    '*', Gio.FileQueryInfoFlags.NONE, None,
        )
        file_type = file_info.get_content_type()

        if x_files[0].get_path() is not None:
            if Path(x_files[0].get_path()).is_file():
                context_connect(menu, context_open_with, x_files, 0)

            context_connect(section_edit, context_edit, x_files, 0)
            context_connect(section_remove, context_remove, x_files, 0)
            context_connect(section_property, context_property, x_files, 0)
        else:
            context_connect(section_edit, context_edit[0:2], x_files, 0)
            context_connect(section_remove, context_remove, x_files, 0)

        if len(entry_search.get_text()) > 1:
            context_connect(menu, context_open_location, x_files, 0)

        if file_type == dir_mime_types[0]:
            context_connect(menu, context_dir, x_files, 0)

        elif file_type in exe_mime_types:
            context_connect(menu, context_exe, x_files, 0)

        elif (file_type in script_mime_types
                or file_type in bin_mime_types):
            context_connect(menu, context_run, x_files, 0)

        elif file_type in audio_mime_types:
            context_connect(menu, context_media, x_files, 0)
        else:
            context_connect(menu, context_open, x_files, 0)

        context_menu.set_menu_model(menu)

        scrolled = context_menu.get_first_child().get_first_child()
        scrolled.set_propagate_natural_height(True)
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.NEVER)

        context_menu.popup()

        context_dir.clear()
        context_open.clear()
        context_edit.clear()
        context_remove.clear()
        context_property.clear()

    def on_content_changed(_self, data):
        """___paste content from clipboard___"""

        replace_source = list()
        copy_source = list()
        copy_target = list()
        cut_source = list()
        cut_target = list()
        parent_file = get_parent_file()

        if (parent_file.get_path() is not None
                and data[1].get_files()[0].get_path() is not None):
            parent_path = parent_file.get_path()

            if data[0] == 'is_cut':
                for f in data[1].get_files():
                    source = Path(f.get_path())
                    target = Path(f'{parent_path}/{source.name}')
                    if (source != target
                            and source != Path(parent_path)):
                        if (target.exists()
                                and source.name == target.name):
                            replace_source.append(str(source))
                        else:
                            cut_source.append(source)
                            cut_target.append(target)
                    else:
                        text_message = msg.msg_dict['equal_paths']
                        SwCrier(text_message=text_message, message_type='INFO').run()
                else:
                    if len(replace_source) > 0:
                        str_source = str('\n'.join(sorted(replace_source)))
                        title = msg.msg_dict['replace_file']
                        message = [msg.msg_dict['replace_override'], f'{str_source}']
                        func = [{move_replace: (parent_path, replace_source)}, None]
                        SwDialogQuestion(swgs, title, message, None, func)

                    if len(cut_source) > 0:
                        for s, t in zip(cut_source, cut_target):
                            move_thread = Thread(target=run_move, args=(s, t,))
                            move_thread.start()
                            Thread(target=on_copy_move_progress, args=[s, t, move_thread]).start()

            elif data[0] == 'is_copy':
                for f in data[1].get_files():
                    source = Path(f.get_path())
                    target = Path(f'{parent_path}/{source.name}')

                    if source != target and source != Path(parent_path):
                        if target.exists() and source.name == target.name:
                            replace_source.append(str(source))
                        else:
                            copy_source.append(source)
                            copy_target.append(target)

                    elif source == target and source != Path(parent_path):
                        target = Path(f'{parent_path}/{str_copy}_{source.name}')
                        count = int()
                        while target.exists():
                            count += 1
                            target = Path(f'{parent_path}/{str_copy}{count}_{source.name}')

                        copy_source.append(source)
                        copy_target.append(target)
                    else:
                        text_message = msg.msg_dict['equal_paths']
                        SwCrier(text_message=text_message, message_type='INFO').run()
                else:
                    if len(replace_source) > 0:
                        str_source = str('\n'.join(sorted(replace_source)))
                        title = msg.msg_dict['replace_file']
                        message = [msg.msg_dict['replace_override'], f'{str_source}']
                        func = [{copy_replace: (parent_path, replace_source)}, None]
                        SwDialogQuestion(swgs, title, message, None, func)

                    if len(copy_source) > 0:
                        for s, t in zip(copy_source, copy_target):
                            copy_thread = Thread(target=run_copy, args=[s, t])
                            copy_thread.start()
                            Thread(target=on_copy_move_progress, args=[s, t, copy_thread]).start()
            else:
                pass
        else:
            on_uri_changed(data)

    def get_dir_size(size, data):
        """___get size of files in current directory___"""

        s_list = list()
        for root, dirs, files in walk(data):
            for f in files:
                try:
                    size += os.stat(join(root, f)).st_size
                except (Exception,) as e:
                    pass
                else:
                    s_list.append(size)
        return s_list

    def run_copy(source, target):
        """___run copy file in thread___"""

        if Path(source).is_file() or Path(source).is_symlink():
            if target.exists() and source.name == target.name:
                Path(target).unlink()
                shutil.copy2(source, target, follow_symlinks=False)
                print(f'{tc.GREEN}File: {source} copy done.{tc.END}')
            else:
                shutil.copy2(source, target, follow_symlinks=False)
                print(f'{tc.GREEN}File: {source} copy done.{tc.END}')

        elif Path(source).is_dir():
            shutil.copytree(source, target, symlinks=True, dirs_exist_ok=True)
            print(f'{tc.GREEN}Directory: {source} copy done.{tc.END}')
        else:
            print(f'{tc.RED}File: {source} is not a file or directory{tc.END}')

    def run_move(source, target):
        """___run copy file in thread___"""

        if Path(source).is_symlink():
            shutil.move(source, target)
            print(f'{tc.GREEN}File: {source} move done.{tc.END}')

        elif Path(source).is_file():
            shutil.move(source, target)
            print(f'{tc.GREEN}File: {source} move done.{tc.END}')

        elif Path(source).is_dir():
            shutil.copytree(source, target, symlinks=True, dirs_exist_ok=True)
            shutil.rmtree(source)
            print(f'{tc.GREEN}Directory: {source} move done.{tc.END}')
        else:
            print(f'{tc.RED}File: {source} is not a file or directory{tc.END}')

    def move_replace(parent_path, replace_source):
        """___replace files on dialog response___"""

        for r in replace_source:
            s = Path(r)
            t = Path(f'{parent_path}/{s.name}')
            move_thread = Thread(target=run_move, args=(s, t,))
            move_thread.start()
            Thread(target=on_copy_move_progress, args=[s, t, move_thread]).start()

    def copy_replace(parent_path, replace_source):
        """___replace files on dialog response___"""

        for r in replace_source:
            s = Path(r)
            t = Path(f'{parent_path}/{s.name}')
            copy_thread = Thread(target=run_copy, args=[s, t])
            copy_thread.start()
            Thread(target=on_copy_move_progress, args=[s, t, copy_thread]).start()

    def on_copy_move_progress(source, target, working_thread):
        """___progress copy file in thread___"""

        fraction = 0.0
        s_size = 0
        t_size = 0
        stack_progress_main.set_visible_child(progress_main_grid)
        progress_main.set_visible(True)
        progress_main.set_show_text(True)

        while working_thread.is_alive():
            if Path(source).is_symlink():
                s_size = os.stat(source).st_size
                try:
                    t_size = os.stat(target).st_size
                except (Exception,) as e:
                    print(e)
                    t_size = 0

            elif Path(source).is_file():
                s_size = os.stat(source).st_size
                try:
                    t_size = os.stat(target).st_size
                except (Exception,) as e:
                    print(e)
                    t_size = 0

            elif Path(source).is_dir() and len(list(Path(source).iterdir())) >= 1:
                s_size = get_dir_size(0, source)[-1]
                try:
                    t_size = get_dir_size(0, target)[-1]
                except (Exception,) as e:
                    print(e)

            else:
                print(f'{tc.RED}file {source} is not a file or directory{tc.END}')

            if s_size > 0:
                fraction = round(t_size / s_size, 2)

            sleep(0.1)
            progress_main.set_fraction(fraction)
            progress_main.set_text(f'{str_copying} {Path(source).name} {fraction*100}%')

        progress_main.set_fraction(0)
        progress_main.set_show_text(False)
        progress_main.set_visible(False)
        stack_progress_main.set_visible_child(stack_panel)
        overlay_info(main_overlay, str_copying, msg.msg_dict['copy_completed'], None, None, 3)
        #return True

    def on_delete_progress(start_size, source, working_thread):
        """___progress of deleting a files in a thread___"""

        fraction = 0
        current_size = 0
        stack_progress_main.set_visible_child(progress_main_grid)
        progress_main.set_visible(True)
        progress_main.set_show_text(True)

        while working_thread.is_alive():
            if Path(source).exists():
                if Path(source).is_symlink():
                    current_size = os.stat(source).st_size

                elif Path(source).is_file():
                    current_size = os.stat(source).st_size

                elif Path(source).is_dir() and len(list(Path(source).iterdir())) >= 1:
                    try:
                        current_size = get_dir_size(0, source)[-1]
                    except IndexError:
                        pass
                else:
                    print(f'{tc.RED}file {source} is not a file or directory{tc.END}')

                if start_size > 0:
                    fraction = round(1 - (current_size / start_size), 2)

                progress_main.set_text(f'{str_deletion} {Path(source).name} {fraction*100}%')
                progress_main.set_fraction(fraction)

            sleep(0.1)

        progress_main.set_fraction(0)
        progress_main.set_show_text(False)
        progress_main.set_visible(False)
        stack_progress_main.set_visible_child(stack_panel)
        overlay_info(main_overlay, str_deletion, msg.msg_dict['delete_completed'], None, None, 3)
        return True

    def on_file_run(g_file):
        """___run a file from the context menu___"""

        x_path = g_file.get_path()
        gio_app_info = Gio.AppInfo.create_from_commandline(
                                        bytes(Path(f'\"{x_path}\"')),
                                        f'\"{x_path}\"',
                                        Gio.AppInfoCreateFlags.SUPPORTS_URIS
        )
        try:
            gio_app_info.launch_uris()
        except Exception as e:
            print(tc.RED, e, tc.END)

    def on_file_open(g_file):
        """___open a file from the context menu___"""

        fl = Gtk.FileLauncher()
        fl.set_file(g_file)
        try:
            fl.launch()
        except Exception as e:
            print(tc.RED, e, tc.END)

    def on_file_open_location(g_file):
        """___open a file location from the context menu___"""

        path = g_file.get_path()
        if path is not None:
            entry_search.set_text('')
            stack_search_path.set_visible_child(box_path)

            if Path(path).is_file() or Path(path).is_symlink():
                on_files(Path(path).parent)
            else:
                on_files(Path(path))

    def on_cb_file_exe(_action_name, _parameter, data):
        """___run a x-ms-dos-executable file from the context menu___"""

        if data[0].get_path() is not None:
            environ['SW_EXEC'] = f'"{data[0].get_path()}"'
            write_app_conf(Path(data[0].get_path()))
            return on_start()
        else:
            return overlay_info(main_overlay, None, msg.msg_dict['action_not_supported'], None, None, 3)

    def on_cb_file_run(_action_name, _parameter, data):
        """___run a x-executable file from the context menu___"""

        g_file = data[0]
        return on_file_run(g_file)

    def on_cb_file_open_location(_action_name, _parameter, data):
        """___open a file from the context menu___"""

        g_file = data[0]
        on_file_open_location(g_file)

    def on_cb_file_open_with(_action_name, _parameter, data):
        """___open a file with program from context menu___"""

        g_file = data[0]
        if g_file.get_path() is None:
            uri = g_file.get_uri()
            on_uri_open_with(uri)
        else:
            on_file_open_with(g_file)

    def on_file_open_with(g_file):
        """___open a file with program___"""

        fl = Gtk.FileLauncher()
        fl.set_always_ask(True)
        fl.set_file(g_file)
        try:
            fl.launch()
        except Exception as e:
            print(tc.RED, e, tc.END)

    def on_uri_open_with(uri):
        """___open a file with program___"""

        ul = Gtk.UriLauncher()
        ul.set_uri(uri)
        try:
            ul.launch()
        except Exception as e:
            print(tc.RED, e, tc.END)

    def on_cb_file_open(_action_name, _parameter, data):
        """___open a file from the context menu___"""

        g_file = data[0]
        if g_file.get_path() is None:
            uri = g_file.get_uri()
            return on_uri_open_with(uri)
        else:
            return on_file_open(g_file)

    def on_cb_dir_open(_action_name, _parameter, data):
        """___open a directory from the context menu___"""

        if data[0].get_path() is not None:
            file = Path(data[0].get_path()).name
            parent_file = get_parent_file()
            if parent_file.get_path() is not None:
                path = parent_file.get_path()
                on_files(Path(f'{path}/{file}'))
        else:
            item_uri = data[0].get_uri()
            update_grid_view_uri(item_uri)

    def on_cb_file_cut(_action_name, _parameter, data):
        """___cut the selected file from the curent directory___"""

        if main_stack.get_visible_child() == files_view_grid:
            return on_file_cut(data)

    def on_file_cut(data):
        """___cut the selected file from the curent directory___"""

        grid_view = get_list_view()
        model = grid_view.get_model()
        nums = model.get_n_items()
        child = grid_view.get_first_child()
        child_list = [child]

        for i in range(1, nums):
            child = child.get_next_sibling()
            child_list.append(child)

        for i, c in enumerate(child_list, start=0):
            n = c.get_first_child().get_name()
            s = model.is_selected(i)

            if s and n == str(i):
                c.set_opacity(0.5)

        f_list = Gdk.FileList.new_from_list(data)
        clipboard.set(f_list)
        content = clipboard.get_content()
        content.connect('content-changed', on_content_changed, ['is_cut', f_list])

    def on_cb_file_copy(_action_name, _parameter, data):
        """___copy the selected file to the clipboard___"""

        if main_stack.get_visible_child() == files_view_grid:
            return on_file_copy(data)

    def on_file_copy(data):
        """___copy the selected file to the clipboard___"""

        if len(data) > 0:
            f_list = Gdk.FileList.new_from_list(data)
            clipboard.set(f_list)
            content = clipboard.get_content()
            content.connect('content-changed', on_content_changed, ['is_copy', f_list])

    def on_uri_changed(data):

        replace_source = list()
        replace_target = list()
        copy_source = list()
        copy_target = list()

        parent_file = get_parent_file()
        parent_uri = get_parent_uri()

        for f in data[1].get_files():
            source = f
            if parent_file.get_path() is None:
                target = Gio.File.new_for_uri(parent_uri + '/' + f.get_basename())
            else:
                target = Gio.File.new_for_path(parent_file.get_path() + '/' + f.get_basename())

            if source != target:
                if (target.query_exists()
                        and f.get_basename() == target.get_basename()):
                    replace_source.append(source)
                    replace_target.append(target)
                else:
                    copy_source.append(source)
                    copy_target.append(target)
        else:
            if len(replace_source) > 0:

                def paste_replace(replace_source, replace_target):
                    """___replace files on dialog response___"""

                    for s, t in zip(replace_source, replace_target):
                        try:
                            s.copy(
                                    t, Gio.FileCopyFlags.OVERWRITE,
                                    progress_callback=on_copy_uri_progress
                            )
                        except GLib.GError as e:
                            print(e.message)
                            SwCrier(text_message=str(e.message), message_type='ERROR').run()

                str_source = str(
                    '\n'.join(sorted([str(s.get_basename()) for s in replace_source])))
                title = msg.msg_dict['replace_file']
                message = [msg.msg_dict['replace_override'], f'\n{str_source}']
                func = [(paste_replace, [replace_source, replace_target]), None]
                SwDialogQuestion(swgs, title, message, None, func)

            if len(copy_source) > 0:
                for s, t in zip(copy_source, copy_target):
                    try:
                        s.copy(
                                t, Gio.FileCopyFlags.NONE,
                                progress_callback=on_copy_uri_progress
                        )
                    except GLib.GError as e:
                        print(e.message)
                        SwCrier(text_message=str(e.message), message_type='ERROR').run()

    def on_copy_uri_progress(cur_bytes, total_bytes):
        print(cur_bytes/total_bytes)

    def on_file_paste():
        """___get files for paste from clipboard___"""

        def read_text(self, res, _data):
            """___async reading non-local content from the clipboard___"""

            replace_source = list()
            copy_source = list()
            copy_target = list()
            parent_file = get_parent_file()
            result = None

            try:
                result = self.read_text_finish(res)
            except GError as e:
                print(f'on_file_paste: {e}')

            if parent_file.get_path() is not None and result is not None:
                parent_path = parent_file.get_path()
                for r in result.splitlines():
                    source = Path(r)
                    target = Path(f'{parent_path}/{source.name}')
                    if source != target:
                        if target.exists() and source.name == target.name:
                            replace_source.append(str(source))
                        else:
                            copy_source.append(source)
                            copy_target.append(target)
                else:
                    if len(replace_source) > 0:
                        str_source = str('\n'.join(sorted(replace_source)))
                        title = msg.msg_dict['replace_file']
                        message = [msg.msg_dict['replace_override'], f'{str_source}']
                        func = [{copy_replace: (parent_path, replace_source)}, None]
                        SwDialogQuestion(swgs, title, message, None, func)

                    if len(copy_source) > 0:
                        for s, t in zip(copy_source, copy_target):
                            copy_thread = Thread(target=run_copy, args=[s, t])
                            copy_thread.start()
                            Thread(target=on_copy_move_progress, args=[s, t, copy_thread]).start()
            else:
                print(f'{tc.RED}paste result is {result}{tc.END}')

        print(f'{tc.VIOLET2}CLIPBOARD: {tc.GREEN}is local {clipboard.is_local()}{tc.END}')

        if not clipboard.is_local():
            clipboard.read_text_async(None, read_text, None)
        else:
            content = clipboard.get_content()
            content.content_changed()

    def on_cb_file_rename(_action_name, _parameter, data):
        """___activate file rename button___"""

        if main_stack.get_visible_child() == files_view_grid:
            if len(data) > 1:
                return on_files_rename(data)
            elif len(data) == 1:
                return on_file_rename(data[0])
            else:
                return None
        else:
            return None

    def on_file_rename(x_file):
        """___rename the selected file___"""

        def rename():
            """___set new file name attribute___"""

            new_name = entry_rename.get_text()
            try:
                x_file.set_display_name(new_name)
            except GLib.GError as e:
                print(e.message)
                SwCrier(text_message=str(e.message), message_type='ERROR').run()

        x_info = x_file.query_info('*', Gio.FileQueryInfoFlags.NONE, None)

        if x_info.has_attribute(attrs['rename']):
            edit_name = x_info.get_attribute_as_string("standard::edit-name")

            if not Path(x_file.get_path()).is_file():
                title = msg.msg_dict['rename_dir'].capitalize()
            else:
                title = msg.msg_dict['rename_file'].capitalize()

            text_message = [edit_name]
            button_name = msg.msg_dict['rename'].capitalize()
            func = [rename, None]
            dialog = SwDialogEntry(swgs, title, text_message, button_name, func, 1, None)
            dialog_child = dialog.get_child()
            if dialog_child is not None:
                entry_rename = dialog_child.get_first_child()

    def on_files_rename(x_files):
        """___rename multiple files___"""

        def rename():
            """___set a new name attribute for multiple files___"""

            new_name = entry_rename.get_text()
            count = 0

            for x in x_files:
                count += 1
                x_info = x.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
                if x_info.has_attribute(attrs['rename']):
                    edit_name = Path(x.get_path()).stem
                    suffix = Path(x.get_path()).suffix
                    if new_name == msg.msg_dict['original_name'].title() + '1, 2, 3...':
                        x.set_display_name(edit_name + str(count) + suffix)
                    elif new_name == '':
                        x.set_display_name(str(count) + suffix)
                    else:
                        x.set_display_name(new_name + str(count) + suffix)
            else:
                dialog.destroy()

        title = (
                msg.msg_dict['rename'].capitalize()
                + f' {len(x_files)} '
                + msg.msg_dict['files'].lower()
        )
        text_message = [msg.msg_dict['original_name'].title() + '1, 2, 3...']
        button_name = msg.msg_dict['rename'].capitalize()
        func = [rename, None]
        dialog = SwDialogEntry(swgs, title, text_message, button_name, func, 1, None)
        dialog_child = dialog.get_child()
        if dialog_child is not None:
            entry_rename = dialog_child.get_first_child()

    def on_cb_file_link(_action_name, _parameter, data):
        """___activate create link button___"""

        if main_stack.get_visible_child() == files_view_grid:
            return on_file_link(data)

    def on_file_link(x_path):
        """___create file symbolic link___"""

        for x in x_path:
            if x.get_path() is not None:
                parent_path = Path(x.get_path()).parent
                link_path = Path(f'{parent_path}/{msg.msg_dict["file_link"]} {Path(x.get_path()).name}')
                x_file = Gio.File.new_for_path(bytes(link_path))
                x_file.make_symbolic_link(bytes(Path(x.get_path())))

    def on_cb_file_compress(_action_name, _parameter, data):
        """___create a compressed archive from file or files___"""

        if main_stack.get_visible_child() == files_view_grid:
            return on_file_compress(data)

    def on_file_compress(data):
        """___create a compressed archive___"""

        def create_archive():
            """___create new file compressed archive___"""

            archive_name = entry_name.get_text()
            selected_type = dropdown.get_selected_item()

            if selected_type is not None:
                archive_type = selected_type.get_string()
            else:
                archive_type = 'xz'

            count = int()
            x_path = Path(f'{parent_path}/{archive_name}')

            if archive_type == 'zip':
                while Path(f'{x_path}.zip').exists():
                    count += 1
                    x_path = Path(f'{parent_path}/{archive_name}{count}')

                info = msg.msg_dict['compression_completed']
                progress_main.set_show_text(True)
                progress_main.set_text(msg.msg_dict['compression'] + f'{archive_name}')
                zip_thread = Thread(target=zip_compress, args=[x_path, data])
                zip_thread.start()
                GLib.timeout_add(100, progress_on_thread, progress_main, zip_thread, info)

            elif archive_type == 'zst' or archive_type == 'zst ultra':
                while Path(f'{x_path}.tar.zst').exists():
                    count += 1
                    x_path = Path(f'{parent_path}/{archive_name}{count}')

                tar_thread = Thread(target=zst_compress, args=[x_path, data, archive_type])
                tar_thread.start()
                info = msg.msg_dict['compression_completed']
                progress_main.set_show_text(True)
                progress_main.set_text(msg.msg_dict['compression'] + f'{archive_name}')
                GLib.timeout_add(100, progress_on_thread, progress_main, tar_thread, info)
            else:
                while Path(f'{x_path}.tar.{archive_type}').exists():
                    count += 1
                    x_path = Path(f'{parent_path}/{archive_name}{count}')

                tar_thread = Thread(target=tar_compress, args=[x_path, data, archive_type])
                tar_thread.start()
                info = msg.msg_dict['compression_completed']
                progress_main.set_show_text(True)
                progress_main.set_text(msg.msg_dict['compression'] + f'{archive_name}')
                GLib.timeout_add(100, progress_on_thread, progress_main, tar_thread, info)

        if len(data) > 1:
            filename = msg.msg_dict['new_archive']
        else:
            filename = data[0].get_basename()

        parent_path = get_parent_path()
        title = msg.msg_dict['create_archive'].capitalize()
        text_message = [filename]
        button_name = msg.msg_dict['create'].capitalize()
        func = [create_archive, None]
        dialog = SwDialogEntry(swgs, title, text_message, button_name, func, 1, archive_formats)
        dialog_child = dialog.get_child()
        if dialog_child is not None:
            entry_name = dialog_child.get_first_child()
            dropdown = dialog_child.get_last_child()

    def zst_compress(x_path, data, archive_type):
        """___create a zstd compressed archive___"""

        target = ' '.join([f'"{x.get_basename()}"' for x in data])

        if archive_type == 'zst':
            run(f"tar -I 'zstd -T0 -11 --progress' -cf '{x_path}.tar.zst' {target}", shell=True)
        else:
            run(f"tar -I 'zstd -T0 --ultra -22 --progress' -cf '{x_path}.tar.zst' {target}", shell=True)

    def tar_compress(x_path, data, archive_type):
        """___create a gz, xz, bz2 compressed archive___"""

        with tarfile.open(f'{x_path}.tar.{archive_type}', f'w:{archive_type}') as tar:
            for file in data:
                tar.add(file.get_basename())
            else:
                tar.close()

    def zip_compress(x_path, data):
        """___create a zip compressed archive___"""

        parent_path = x_path.parent
        with zipfile.ZipFile(f'{x_path}.zip', 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as fzip:
            for file in data:
                if Path(file.get_path()).is_dir():
                    for r, d, f in walk(file.get_path()):
                        for x in f:
                            fzip.write(f'{r}/{x}'.replace(f'{parent_path}/', ''))
                fzip.write(file.get_basename())
            else:
                fzip.close()

    def on_cb_file_remove(action_name, _parameter, x_path):
        """___activate context button and remove changed file___"""

        if action_name == msg.ctx_dict['trash'][0]:
            if main_stack.get_visible_child() == files_view_grid:
                on_file_to_trash(x_path)

        elif action_name == msg.ctx_dict['delete'][0]:
            if main_stack.get_visible_child() == files_view_grid:
                if x_path[0].get_path() is None:
                    on_uri_remove(x_path)
                else:
                    on_file_remove(x_path)

    def on_file_to_trash(x_path):
        """___move selected file to trash___"""

        for x in x_path:
            try:
                x.trash()
            except GLib.GError as e:
                print(e.message)
                SwCrier(text_message=str(e.message), message_type='ERROR').run()
                break
        else:
            return overlay_info(main_overlay, str_removal, msg.msg_dict['trash_completed'], None, None, 3)

    def on_file_remove(x_path):
        """___delete selected files___"""

        def remove(x_path):
            """___delete selected files on dialog response___"""

            for x in x_path:
                if Path(x.get_path()).is_file() or Path(x.get_path()).is_symlink():
                    source = x.get_path()
                    try:
                        start_size = os.stat(source).st_size
                    except (Exception,):
                        start_size = 0

                    del_thread = Thread(target=x.delete)
                    del_thread.start()
                    Thread(target=on_delete_progress, args=(start_size, source, del_thread)).start()

                elif Path(x.get_path()).is_dir():
                    source = Path(x.get_path())
                    if len(list(source.iterdir())) >= 1:
                        try:
                            start_size = get_dir_size(0, source)[-1]
                        except IndexError:
                            start_size = 0

                        rm_thread = Thread(target=shutil.rmtree, args=[source])
                        rm_thread.start()
                        Thread(target=on_delete_progress, args=(start_size, source, rm_thread)).start()
                    else:
                        start_size = 0
                        rm_thread = Thread(target=shutil.rmtree, args=[source])
                        rm_thread.start()
                        Thread(target=on_delete_progress, args=(start_size, source, rm_thread)).start()

            return overlay_info(main_overlay, str_removal, msg.msg_dict['trash_completed'], None, None, 3)

        title = msg.msg_dict['remove']
        text_message = [
            msg.msg_dict['permanently_delete'],
            ' '.join([Path(x.get_path()).name for x in x_path]) + '?'
        ]
        func = [(remove, (x_path,)), None]
        SwDialogQuestion(swgs, title, text_message, None, func)

    def on_uri_remove(x_files):
        """___delete selected files___"""

        for g_file in x_files:
            try:
                g_info = g_file.query_info('*', Gio.FileQueryInfoFlags.NONE)
            except GLib.GError as e:
                print(e.message)
                return SwCrier(text_message=str(e.message), message_type='ERROR').run()
            else:
                content_type = g_info.get_content_type()

            if content_type == dir_mime_types[0]:
                g_file_enum = g_file.enumerate_children('*', Gio.FileQueryInfoFlags.NONE)
                for x in g_file_enum:
                    f = g_file_enum.get_child(x)
                    try:
                        f.delete()
                    except GLib.GError as e:
                        print(e.message)
                        return SwCrier(text_message=str(e.message), message_type='ERROR').run()
                else:
                    try:
                        g_file.delete()
                    except GLib.GError as e:
                        print(e.message)
                        return SwCrier(text_message=str(e.message), message_type='ERROR').run()
            else:
                try:
                    g_file.delete()
                except GLib.GError as e:
                    print(e.message)
                    return SwCrier(text_message=str(e.message), message_type='ERROR').run()

    def on_cb_file_properties(_action_name, _parameter, data):
        """___activate file properties button___"""

        on_file_properties()

        if len(data) > 1:
            get_file_props_list(data)
        else:
            get_file_props(data[0])

    def on_switch_file_exec(self, _state):
        """___switch file execute property___"""

        p = Path(swgs.switch_file_execute.get_name())
        f = Gio.File.new_for_commandline_arg(bytes(p))
        i = f.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
        e = i.get_attribute_as_string('access::can-execute')

        if self.get_active():

            if e == 'FALSE':
                # p.stat().st_mode
                p.chmod(0o755)
        else:
            if e == 'TRUE':
                # p.stat().st_mode
                p.chmod(0o644)

    def get_allocated_size(size, data, label):
        """___get size of files in current directory___"""

        size_list = list()
        GLib.timeout_add(100, set_allocated_size, size_list, label)

        for root, dirs, files in walk(data):
            for f in files:
                try:
                    size += os.stat(join(root, f)).st_size
                except (Exception,):
                    pass
                else:
                    size_list.append(size)

    def set_allocated_size(size_list, label):
        """___set file size info to label___"""

        str_size = None

        if len(size_list) >= 1:
            size = int(size_list[-1])

            if len(str(round(size, 2))) <= 6:
                str_size = f'{str(round(size/1024, 2))} Kib / {str(round(size/1000, 2))} Kb'

            elif 6 < len(str(round(size, 2))) <= 9:
                str_size = f'{str(round(size/1024**2, 2))} Mib / {str(round(size/1000**2, 2))} Mb'

            elif len(str(round(size, 2))) > 9:
                str_size = f'{str(round(size/1024**3, 2))} Gib / {str(round(size/1000**3, 2))} Gb'

            if str_size is not None:
                label.set_label(str_size)

            size_list.clear()
            return True

        return False

    def get_disk_usage(data):
        """___get size of the current partition___"""

        partitions = psutil.disk_partitions()
        mountpoint = ''

        if data is not None:
            data_path = data.get_path()

            for x in sorted(partitions):
                if x.mountpoint in data_path:
                    mountpoint = x.mountpoint

            try:
                mnt_point = psutil.disk_usage(mountpoint)
            except (Exception,):
                fmt_size = msg.msg_dict['unknown']
            else:
                if mnt_point is not None:
                    fs_size = mnt_point.total
                    fmt_size = GLib.format_size(int(fs_size))
                else:
                    fmt_size = msg.msg_dict['unknown']

            try:
                mnt_point = psutil.disk_usage(mountpoint)
            except (Exception,):
                fmt_free = msg.msg_dict['unknown']
            else:
                if mnt_point is not None:
                    fs_free = mnt_point.free
                    fmt_free = GLib.format_size(int(fs_free))
                else:
                    fmt_free = msg.msg_dict['unknown']

            fmt_all = (
                        f"{msg.msg_dict['free']} {fmt_free} / "
                        + f"{msg.msg_dict['total']} {fmt_size}"
            )
            swgs.label_disk_size.set_label(fmt_all)

    def get_file_props_list(x_path):
        """___get file list attributes___"""

        if isinstance(x_path, list):
            if len(x_path) > 1:
                swgs.box_file_info.set_visible(False)
                swgs.box_file_execute.set_visible(False)

                swgs.label_file_path.set_label('\n'.join([x.get_path() for x in x_path]))
                swgs.label_file_name.set_label(vl_dict['files'])
                swgs.label_file_mime.set_label('')
                swgs.label_file_mime.set_visible(False)
                swgs.label_file_size.set_visible(False)

                parent_file = x_path[0].get_parent()
                parent_info = parent_file.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
                get_disk_usage(parent_file)

                if parent_info.has_attribute(attrs['icon']):
                    f_icon = parent_info.get_attribute_object("standard::icon")
                    swgs.image_file_info.set_from_gicon(f_icon)
                    swgs.image_file_info.set_pixel_size(128)

    def get_file_props(x_file):
        """___get file attributes___"""

        f_type = None
        f_uid = None
        f_gid = None
        read = None
        write = None

        if x_file.get_path() is not None:
            x_path = x_file.get_path()
            parent_file = x_file.get_parent()
        else:
            x_path = x_file.get_uri()
            parent_file = None

        swgs.box_file_info.set_visible(True)
        swgs.label_file_mime.set_visible(True)
        swgs.label_file_size.set_visible(True)
        swgs.label_file_size.set_label('0.0 Kib / 0.0 Kb')
        swgs.label_file_path.set_label(str(x_path))
        get_disk_usage(parent_file)

        try:
            file_info = x_file.query_info(
                                        '*', Gio.FileQueryInfoFlags.NONE, None)
        except GLib.GError as e:
            print(e.message)
        else:
            if file_info.has_attribute(attrs['type']):
                f_type = file_info.get_content_type()
                swgs.label_file_mime.set_label(f_type)

            if file_info.has_attribute(attrs['name']):
                f_name = file_info.get_attribute_as_string("standard::display-name")
                swgs.label_file_name.set_label(f_name)

            if file_info.has_attribute(attrs['icon']):
                f_icon = file_info.get_attribute_object("standard::icon")
                swgs.image_file_info.set_from_gicon(f_icon)
                swgs.image_file_info.set_pixel_size(128)

            if file_info.has_attribute(attrs['size']):
                f_size = [file_info.get_size()]

                if f_type == dir_mime_types[0]:
                    swgs.box_file_execute.set_visible(False)
                    size = 0
                    data = Path(x_path)
                    Thread(target=get_allocated_size, args=[size, data, swgs.label_file_size]).start()
                else:
                    swgs.box_file_execute.set_visible(True)
                    set_allocated_size(f_size, swgs.label_file_size)

            if file_info.has_attribute(attrs['user']):
                f_uid = file_info.get_attribute_as_string("owner::user")

            if file_info.has_attribute(attrs['group']):
                f_gid = file_info.get_attribute_as_string("owner::group")

            if file_info.has_attribute(attrs['modified']):
                f_modified = file_info.get_modification_date_time().format('%c')
                swgs.label_file_modified.set_label(f_modified)

            if file_info.has_attribute(attrs['created']):
                f_created = file_info.get_creation_date_time().format('%c')
                swgs.label_file_created.set_label(f_created)

            if (x_file.get_path() is not None
                    and file_info.has_attribute(attrs['exec'])):

                f_execute = file_info.get_attribute_as_string("access::can-execute")
                swgs.switch_file_execute.set_name(x_path)

                if not swgs.switch_file_execute.get_active():
                    if f_execute == 'TRUE':
                        swgs.switch_file_execute.set_active(True)
                else:
                    if f_execute == 'FALSE':
                        swgs.switch_file_execute.set_active(False)

            if file_info.has_attribute(attrs['read']):
                f_read = file_info.get_attribute_as_string("access::can-read")

                if f_read == 'TRUE':
                    read = msg.msg_dict['file_readable']
                else:
                    read = msg.msg_dict['file_non_readable']

            if file_info.has_attribute(attrs['write']):
                f_write = file_info.get_attribute_as_string("access::can-write")

                if f_write == 'TRUE':
                    write = msg.msg_dict['file_writable']
                else:
                    write = msg.msg_dict['file_non_writable']

            try:
                swgs.label_file_uid.set_label(f'{f_uid} / {f_gid}')
            except (Exception,):
                pass

            try:
                swgs.label_file_rw.set_label(f'{read} / {write}')
            except (Exception,):
                pass

    def on_file_properties():
        """___set visible file properties page___"""

        if scrolled_files_info.get_child() is None:
            add_files_info()

        if not sidebar_revealer.get_reveal_child():
            on_sidebar()

        btn_back_main.set_visible(True)
        stack_sidebar.set_visible_child(frame_files_info)
        update_color_scheme()

    def show_shortcut_context(x, y, widget, data):
        """___popup context menu callback on right click___"""

        path = data.get_path()
        shortcut = str(Path(path).name)
        parent_path = get_parent_path()
        shortcut_path = f'{parent_path}/{shortcut}'
        check_arg(shortcut_path)
        if getenv('SW_EXEC') == 'StartWine':
            question = [msg.msg_dict['lnk_error'], msg.msg_dict['new_path']]
            func = [{on_select_file: (shortcut_path,)}, None]
            return SwDialogQuestion(
                _app=swgs, title=sw_program_name, text_message=question, func=func)

        context_data = {
            'app_run_section': [
                {
                    'name': msg.ctx_dict['run'],
                    'func': on_cb_app_run,
                    'data': shortcut
                },
                {
                    'name': msg.ctx_dict['open'],
                    'func': on_cb_app_open,
                    'data': shortcut
                },
                {
                    'name': msg.ctx_dict['app_settings'],
                    'func': on_cb_app_settings,
                    'data': shortcut
                },
                {
                    'name': msg.ctx_dict['rename'][0],
                    'func': on_cb_app_rename,
                    'data': shortcut
                },
            ],
            'new_path_section': [
                {
                    'name': msg.ctx_dict['specify_new_loacation'],
                    'func': on_cb_app_spec_exe_path,
                    'data': shortcut
                },
            ],
            'remove_section': [
                {
                    'name': msg.ctx_dict['remove'],
                    'func': on_cb_app_remove,
                    'data': shortcut
                },
            ]
        }

        rect = Gdk.Rectangle()
        rect.x = x
        rect.y = y
        rect.width = 1
        rect.height = 1

        context_menu = Gtk.Popover(css_name='sw_popovermenu')
        context_menu.set_has_arrow(False)
        context_menu.set_position(Gtk.PositionType.BOTTOM)
        context_menu.set_pointing_to(rect)
        context_menu.set_name(str(shortcut))

        context_stack = Gtk.Stack(
            transition_duration=200,
            transition_type=Gtk.StackTransitionType.SLIDE_LEFT_RIGHT,
        )
        menu_store = Gio.ListStore()
        for k, v in context_data.items():
            if 'section' in k:
                for m in v:
                    section = k
                    name = m['name']
                    item = Gtk.Label(label=name, name=section)
                    menu_store.append(item)

        menu_model = Gtk.SingleSelection.new(menu_store)
        menu_factory = Gtk.SignalListItemFactory()
        menu_factory.connect('setup', cb_context_factory_setup)
        menu_factory.connect('bind', cb_context_factory_bind)

        menu_listview = Gtk.ListView(
            name='menu', css_name='sw_listview', single_click_activate=True,
            show_separators=True,
        )
        menu_listview.remove_css_class('view')
        menu_listview.add_css_class('padding_4')
        menu_listview.set_model(menu_model)
        menu_listview.set_factory(menu_factory)
        menu_listview.connect('activate', cb_context_activate, context_data)

        image_winehq = Gtk.Image(css_name='sw_image')
        image_winehq.set_halign(Gtk.Align.START)
        image_winehq.set_from_file(IconPath.icon_wine)

        image_protondb = Gtk.Image(css_name='sw_image')
        image_protondb.set_halign(Gtk.Align.START)
        image_protondb.set_from_file(IconPath.icon_protondb)

        image_griddb = Gtk.Image(css_name='sw_image')
        image_griddb.set_halign(Gtk.Align.START)
        image_griddb.set_from_file(IconPath.icon_search)

        label_winehq = Gtk.Label(css_name='sw_label_popover', label=msg.ctx_dict['winehq'])
        label_winehq.set_xalign(0)

        label_protondb = Gtk.Label(css_name='sw_label_popover', label=msg.ctx_dict['protondb'])
        label_protondb.set_xalign(0)

        label_griddb = Gtk.Label(css_name='sw_label_popover', label=msg.ctx_dict['griddb'])
        label_griddb.set_xalign(0)

        btn_winehq = Gtk.LinkButton(css_name='sw_link')
        btn_winehq.set_child(label_winehq)
        btn_winehq.connect("activate-link", cb_btn_winehq, shortcut, context_menu)

        btn_protondb = Gtk.LinkButton(css_name='sw_link')
        btn_protondb.set_child(label_protondb)
        btn_protondb.connect("activate-link", cb_btn_protondb, shortcut, context_menu)

        btn_griddb = Gtk.LinkButton(css_name='sw_link')
        btn_griddb.set_child(label_griddb)
        source_type = 'grids?term='
        btn_griddb.connect("clicked", cb_btn_web_view_griddb, context_menu, source_type)

        box_winehq = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        box_winehq.set_spacing(4)
        box_winehq.append(image_winehq)
        box_winehq.append(btn_winehq)

        box_protondb = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        box_protondb.set_spacing(4)
        box_protondb.append(image_protondb)
        box_protondb.append(btn_protondb)

        box_griddb = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        box_griddb.set_spacing(4)
        box_griddb.append(image_griddb)
        box_griddb.append(btn_griddb)

        switch_0 = Gtk.Switch(
                            css_name='sw_switch', valign=Gtk.Align.CENTER,
                            hexpand=True, halign=Gtk.Align.END
        )
        switch_1 = Gtk.Switch(
                            css_name='sw_switch', valign=Gtk.Align.CENTER,
                            hexpand=True, halign=Gtk.Align.END
        )
        switch_0.connect('state-set', cb_btn_switch_app_to_menu, context_menu)
        switch_1.connect('state-set', cb_btn_switch_app_to_desktop, context_menu)

        img_path = getenv(f'{get_out()}')
        app_original_name = ''
        if img_path is not None:
            app_original_name = str(Path(img_path).stem).split('_')[-2]

        local_dir = Path(f'{sw_local}/{app_original_name}.desktop')
        desktop_dir = Path(f'{dir_desktop}/{app_original_name}.desktop')

        if local_dir.exists():
            switch_0.set_active(True)

        if desktop_dir.exists():
            switch_1.set_active(True)

        label_switch_0 = Gtk.Label(
                                css_name='sw_label_popover',
                                label=msg.ctx_dict['app_to_menu'],
                                xalign=0
        )
        label_switch_1 = Gtk.Label(
                                css_name='sw_label_popover',
                                label=msg.ctx_dict['app_to_desktop'],
                                xalign=0
        )
        box_switch_0 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        box_switch_0.append(label_switch_0)

        box_switch_1 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        box_switch_1.append(label_switch_1)

        grid_context = Gtk.Grid(css_name='sw_grid')
        grid_context.set_row_spacing(8)
        grid_context.set_column_spacing(8)
        grid_context.attach(box_winehq, 0, 0, 1, 1)
        grid_context.attach(box_protondb, 0, 1, 1, 1)
        grid_context.attach(box_griddb, 0, 2, 1, 1)
        grid_context.attach(box_switch_0, 0, 3, 1, 1)
        grid_context.attach(box_switch_1, 0, 4, 1, 1)
        grid_context.attach(switch_0, 1, 3, 1, 1)
        grid_context.attach(switch_1, 1, 4, 1, 1)

        context_box = Gtk.Box(css_name='sw_box', orientation=Gtk.Orientation.VERTICAL)
        context_box.append(menu_listview)
        context_box.append(grid_context)

        context_stack.add_named(context_box, 'menu')
        context_stack.set_visible_child_name('menu')

        context_menu.set_child(context_stack)

        context_menu.set_parent(widget)
        context_menu.popup()

    def on_cb_app_run(_action_name, _parameter, data):
        """___run application from context menu___"""

        parent_path = get_parent_path()
        app_dict = app_info(f'{parent_path}/{data}')
        app_exec = app_dict['Exec'].replace(f'env "{sw_start}" ', '').strip('"')

        if Path(app_exec).exists():
            return on_start()
        else:
            return overlay_info(main_overlay, None, msg.msg_dict['lnk_error'], None, None, 3)

    def on_cb_app_open(_action_name, _parameter, data):
        """___open application directory from context menu___"""

        parent_path = get_parent_path()
        app_dict = app_info(f'{parent_path}/{data}')
        app_exec = app_dict['Exec'].replace(f'env "{sw_start}" ', '').strip('"')

        if Path(app_exec).exists():
            on_files(Path(app_exec).parent)
        else:
            return overlay_info(main_overlay, None, msg.msg_dict['lnk_error'], None, None, 3)

    def on_cb_app_settings(_action_name, _parameter, _widget):
        """___open application settings menu from context menu___"""

        on_startapp_page()

    def on_cb_app_rename(_action_name, _parameter, data):
        """___rename application display name___"""

        shortcut_name = data.replace('.swd', '')
        get_app_image_path(shortcut_name)

    def get_app_image_path(x_name):
        """___get application image source path___"""

        src_dict = dict()
        current_image_path = getenv(f'{x_name}')

        if current_image_path is not None:
            vicon_path = (
                current_image_path.replace('horizontal', 'vertical')
                .replace('/heroes/', '/vertical/').replace('_heroes_', '_vertical_')
            )
            if Path(vicon_path).exists():
                vicon_name = str(Path(vicon_path).stem).split('_')[-2]
                src_dict[vicon_path] = vicon_name

            hicon_path = (
                current_image_path.replace('vertical', 'horizontal')
                .replace('/heroes/', '/horizontal/').replace('_heroes_', '_horizontal_')
            )
            if Path(hicon_path).exists():
                hicon_name = str(Path(vicon_path).stem).split('_')[-2]
                src_dict[hicon_path] = hicon_name

            heroes_path = (
                current_image_path.replace('vertical', 'heroes').replace('horizontal', 'heroes')
            )
            if Path(heroes_path).exists():
                heroes_name = str(Path(vicon_path).stem).split('_')[-2]
                src_dict[heroes_path] = heroes_name

            print(src_dict)
            if len(list(src_dict)) > 0:
                on_app_rename(src_dict)
            else:
                overlay_info(main_overlay, None, msg.msg_dict['is_nothing_to_rename'], None, None, 3)
        else:
            overlay_info(main_overlay, None, msg.msg_dict['is_nothing_to_rename'], None, None, 3)

    def on_app_rename(src_dict):
        """___rename application display name___"""

        def rename():
            """___set new file name attribute___"""

            new_name = entry_rename.get_text().replace('_', ' ')
            for src_path, src_name in src_dict.items():
                if str(Path(src_path).parent) == str(sw_app_default_icons):
                    split_name = str(Path(src_path).stem).split('_')
                    target = Path(f'{sw_app_default_icons}/{split_name[0]}_{new_name}_x256.png')
                    exe_data.set_(split_name[0], 'name', new_name)
                    exe_data.set_(split_name[0], 'default', target.name)
                else:
                    split_name = str(Path(src_path).stem).split('_')
                    target = Path(src_path.replace(f'_{src_name}_', f'_{new_name}_'))
                    exe_data.set_(split_name[0], 'name', new_name)

                    if '_vertical_' in target.name:
                        exe_data.set_(split_name[0], 'vertical', target.name)

                    if '_horizontal_' in target.name:
                        exe_data.set_(split_name[0], 'horizontal', target.name)

                    if '_heroes_' in target.name:
                        exe_data.set_(split_name[0], 'heroes', target.name)

                Path(src_path).rename(target)

                print(f'{tc.VIOLET}Rename: {tc.YELLOW}{src_path} {tc.GREEN}to {target}{tc.END}')

            on_shortcuts()

        title = msg.msg_dict['rename'].capitalize()
        text_message = [src_dict[list(src_dict)[0]]]
        button_name = msg.msg_dict['rename'].capitalize()
        func = [rename, None]
        dialog = SwDialogEntry(swgs, title, text_message, button_name, func, 1, None)
        dialog_child = dialog.get_child()
        if dialog_child is not None:
            entry_rename = dialog_child.get_first_child()

    def on_cb_app_spec_exe_path(_action_name, _parameter, data):
        """___change application path to executable file___"""

        shortcut_path = f'{sw_shortcuts}/{data}'
        if Path(shortcut_path).exists():
            on_select_file(shortcut_path)

    def on_cb_app_remove(_action_name, _parameter, _data):
        """___remove application prefix from context menu___"""

        cb_btn_pfx_remove()

    def cb_btn_winehq(self, file, widget):

        name = get_out()
        if getenv(name):
            img_path = str(getenv(name))
            name = str(Path(img_path).stem).split('_')[-2]

        on_webview(f"{winehq_source}{name}")
        if widget:
            widget.popdown()

    def cb_btn_protondb(self, file, widget):
        """___search info on protondb web page by app name___"""

        name = get_out()
        if getenv(name):
            img_path = str(getenv(name))
            name = str(Path(img_path).stem).split('_')[-2]

        on_webview(f"{protondb_source}{name}")

        if widget:
            widget.popdown()

    def cb_btn_web_view_griddb(_self, widget, source_type):
        """___search info on griddb web page by app name___"""

        name = get_out()
        if getenv(name):
            img_path = str(getenv(name))
            name = str(Path(img_path).stem).split('_')[-2]

        on_webview(f"{griddb_source}{source_type}{name}")

        if widget:
            widget.popdown()

    def cb_btn_switch_app_to_menu(self, _state, widget):
        """___add application shortcut to system menu___"""

        img_path = getenv(f'{get_out()}')

        if img_path is not None:
            app_original_name = str(Path(img_path).stem).split('_')[-2]

            if self.get_active():
                if not Path(f'{sw_local}/{app_original_name}.desktop').exists():
                    add_shortcut_to_menu(app_original_name)
            else:
                if Path(f'{sw_local}/{app_original_name}.desktop').exists():
                    Path(f'{sw_local}/{app_original_name}.desktop').unlink()

        if widget is not None:
            widget.popdown()

    def add_shortcut_to_menu(shortcut_name):
        """___add application shortcut to system menu___"""

        if not Path(f'{sw_local}/{shortcut_name}').exists():
            environ['CUSTOM_GAME_NAME'] = f'"{shortcut_name}"'
            func_name = f"ADD_SHORTCUT_TO_MENU"
            echo_func_name(func_name)

    def cb_btn_switch_app_to_desktop(self, _state, widget):
        """___add application shortcut to desktop___"""

        img_path = getenv(f'{get_out()}')
        if img_path is not None:
            app_original_name = str(Path(img_path).stem).split('_')[-2]

            if self.get_active():
                if not Path(f'{dir_desktop}/{app_original_name}.desktop').exists():
                    add_shortcut_to_desktop(app_original_name, None)
            else:
                if Path(f'{dir_desktop}/{app_original_name}.desktop').exists():
                    Path(f'{dir_desktop}/{app_original_name}.desktop').unlink()

        if widget is not None:
            widget.popdown()

    def add_shortcut_to_desktop(custom_name, custom_path):
        """___add application shortcut to desktop___"""

        if not Path(f'{dir_desktop}/{custom_name}').exists():
            environ['CUSTOM_GAME_NAME'] = f'"{custom_name}"'

            if custom_path is None:
                environ['CUSTOM_GAME_PATH'] = f'"{dir_desktop}"'
            else:
                environ['CUSTOM_GAME_PATH'] = f'"{custom_path}"'

            func_name = f"ADD_SHORTCUT_TO_DESKTOP"
            echo_func_name(func_name)

    def set_view_parent_path(grid_view):
        """___set environment variable to current file path___"""

        parent_path = None

        if (grid_view.get_name() == 'left_grid_view'
                or grid_view.get_name() == 'left_column_view'):

            if grid_view.get_model().get_item(0) is None:
                parent_path = left_dir_list.get_file().get_path()
                if Path(parent_path).is_file():
                    parent_path = left_dir_list.get_file().get_parent().get_path()
                if parent_path is None:
                    parent_path = left_dir_list.get_file().get_uri()
            else:
                parent_path = left_dir_list.get_file().get_parent().get_path()
                if parent_path is None:
                    parent_path = left_dir_list.get_file().get_parent().get_uri()

        elif grid_view.get_name() == 'right_grid_view':
            if grid_view.get_model().get_item(0) is None:
                parent_path = right_dir_list.get_file().get_path()
                if Path(parent_path).is_file():
                    parent_path = right_dir_list.get_file().get_parent().get_path()
                if parent_path is None:
                    parent_path = right_dir_list.get_file().get_uri()
            else:
                parent_path = right_dir_list.get_file().get_parent().get_path()
                if parent_path is None:
                    parent_path = right_dir_list.get_file().get_parent().get_uri()

        if parent_path is not None and parent_path != entry_path.get_name():
            update_path(parent_path)
            entry_path.set_text(str(parent_path))
            entry_path.set_name(str(parent_path))

        environ['SW_FILES_PARENT_PATH'] = str(parent_path)
        environ['SW_FILES_VIEW_NAME'] = str(grid_view.get_name())

    def cb_ctrl_lclick_view(self, _n_press, x, y):
        """___left click on empty place in list view___"""

        grid_view = self.get_widget()
        grid_view.grab_focus()

        if stack_search_path.get_visible_child() == box_web:
            stack_search_path.set_visible_child(box_path)

        if stack_search_path.get_visible_child() != box_search:
            set_view_parent_path(grid_view)

        if stack_progress_main.get_visible_child() == media_main_grid:
            stack_progress_main.set_visible_child(stack_panel)

        pick = grid_view.pick(x, y, Gtk.PickFlags.DEFAULT)

        if stack_sidebar.get_visible_child() == frame_files_info:
            on_back_main()

        if parent.get_width() < 960:
            if sidebar_revealer.get_reveal_child():
                on_sidebar()

        if pick is not None:
            pos = pick.get_name()

            if str(pos).isdigit():
                model = grid_view.get_model()
                parent_path = get_parent_path()
                if parent_path is not None:
                    if Path(parent_path) == Path(sw_shortcuts):
                        model.select_item(int(pos), True)
                    else:
                        pass
                else:
                    pass
            elif str(pos) == grid_view.get_name() or str(pos) == 'GtkColumnListView':
                grid_view.get_model().unselect_all()
            else:
                pass

    def show_item_context():
        """___show context menu for selected item___"""

        grid_view = get_list_view()
        model = grid_view.get_model()
        nums = model.get_n_items()
        selected = [i for i in range(nums) if model.is_selected(i)]

        if selected:
            gio_files = get_selected_item_gfile()
            gfile = gio_files[0]
            path = gfile.get_path()

            if Path(path).parent == sw_shortcuts:

                shortcut = str(Path(path).name)
                parent_path = get_parent_path()
                shortcut_path = f'{parent_path}/{shortcut}'
                check_arg(shortcut_path)
                if getenv('SW_EXEC') == 'StartWine':
                    question = [msg.msg_dict['lnk_error'], msg.msg_dict['new_path']]
                    func = [{on_select_file: (shortcut_path,)}, None]
                    return SwDialogQuestion(
                        _app=swgs, title=sw_program_name, text_message=question, func=func)

                response = [
                    msg.ctx_dict['run'].capitalize(),
                    msg.ctx_dict['open'].capitalize(),
                    msg.ctx_dict['app_settings'].capitalize(),
                    msg.ctx_dict['rename'][0].capitalize(),
                    msg.ctx_dict['specify_new_loacation'].capitalize(),
                    msg.ctx_dict['remove'].capitalize(),
                    msg.ctx_dict['winehq'].capitalize(),
                    msg.ctx_dict['protondb'].capitalize(),
                    msg.ctx_dict['griddb'].capitalize(),
                    msg.msg_dict['cancel'].capitalize()
                ]
                func = [
                    {on_cb_app_run: (None, None, shortcut)},
                    {on_cb_app_open: (None, None, shortcut)},
                    {on_cb_app_settings: (None, None, shortcut)},
                    {on_cb_app_rename: (None, None, shortcut)},
                    {on_cb_app_spec_exe_path: (None, None, shortcut)},
                    {on_cb_app_remove: (None, None, shortcut)},
                    {cb_btn_winehq: (None, shortcut, None)},
                    {cb_btn_protondb: (None, shortcut, None)},
                    {cb_btn_web_view_griddb: (None, None, 'grids?term=')},
                    None
                ]
                name = getenv(str(Path(path).stem))
                if name:
                    name = name.split('_')[-2]
                else:
                    name = Path(path).stem

                title = msg.msg_dict['choose']
                SwDialogQuestion(swgs, title, [name, ''], response, func)

            else:
                gfile_info = gfile.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
                gfile_type = gfile_info.get_content_type()

                if gfile_type in exe_mime_types:
                    open_ = on_cb_file_exe

                elif Path(path).is_dir():
                    open_ = on_cb_dir_open
                else:
                    open_ = on_cb_file_open

                func = [
                    {open_: (None, None, gio_files)},
                    {on_cb_file_open_with: (None, None, gio_files)},
                    {on_cb_file_cut: (None, None, gio_files)},
                    {on_cb_file_copy: (None, None, gio_files)},
                    {on_cb_file_rename: (None, None, gio_files)},
                    {on_cb_file_link: (None, None, gio_files)},
                    {on_cb_file_compress: (None, None, gio_files)},
                    {on_cb_file_remove: (msg.ctx_dict['trash'][0], None, gio_files)},
                    {on_cb_file_remove: (msg.ctx_dict['delete'][0], None, gio_files)},
                    {on_cb_file_properties: (None, None, gio_files)},
                    None,
                ]
                response = [
                    msg.ctx_dict['open'].capitalize(),
                    msg.ctx_dict['open_with'].capitalize(),
                    msg.ctx_dict['cut'][0].capitalize(),
                    msg.ctx_dict['copy'][0].capitalize(),
                    msg.ctx_dict['rename'][0].capitalize(),
                    msg.ctx_dict['link'][0].capitalize(),
                    msg.ctx_dict['compress'].capitalize(),
                    msg.ctx_dict['trash'][0].capitalize(),
                    msg.ctx_dict['delete'][0].capitalize(),
                    msg.ctx_dict['properties'][0].capitalize(),
                    msg.msg_dict['cancel'].title()
                ]
                if gfile_type in audio_mime_types:
                    func.insert(0, {on_cb_add_media: (None, None, gio_files)})
                    response.insert(0, msg.ctx_dict['add_media'].capitalize())

                title = msg.msg_dict['choose']
                SwDialogQuestion(swgs, title, [Path(path).name, ''], response, func)

    def cb_ctrl_rclick_view(self, _n_press, x, y):
        """___right click in list view___"""

        grid_view = get_list_view()
        grid_view.grab_focus()

        if stack_search_path.get_visible_child() != box_search:
            set_view_parent_path(grid_view)

        pick = grid_view.pick(x, y, Gtk.PickFlags.DEFAULT)

        if pick is not None:
            pos = pick.get_name()
            parent_path = get_parent_path()

            if str(pos).isdigit():
                model = grid_view.get_model()
                if parent_path:
                    if Path(parent_path) == Path(sw_shortcuts):
                        model.select_item(int(pos), True)
                        gfile = model.get_item(int(pos))
                        if Path(f'{gfile.get_path()}').is_file():
                            show_shortcut_context(x, y, grid_view, gfile)
                    else:
                        nums = model.get_n_items()
                        selected = [i for i in range(nums) if model.is_selected(i)]
                        if len(selected) > 1:
                            model.select_item(int(pos), False)
                        else:
                            model.select_item(int(pos), True)

                        gio_files = get_selected_item_gfile()
                        show_context(x, y, grid_view, gio_files)
                else:
                    nums = model.get_n_items()
                    selected = [i for i in range(nums) if model.is_selected(i)]
                    if len(selected) > 1:
                        model.select_item(int(pos), False)
                    else:
                        model.select_item(int(pos), True)

                    gio_files = get_selected_item_gfile()
                    show_context(x, y, grid_view, gio_files)

            elif str(pos) == grid_view.get_name() or str(pos) == 'GtkColumnListView':
                grid_view.get_model().unselect_all()
                parent_path = get_parent_path()

                if parent_path is not None:
                    if Path(parent_path) == Path(sw_shortcuts):
                        pass
                    else:
                        show_context(x, y, grid_view, parent_path)

    def cb_model_selection_changed(_self, _position, _n_items):
        """___Get selected item path___

        if str(get_parent_path()) == str(sw_shortcuts):
            item = self.get_item(position)
            print(item.get_path())
        """

    def cb_ctrl_left_view_focus(self):
        """___Emitted whenever the focus enters into the widget or child___"""

    def cb_ctrl_right_view_focus(self):
        """___Emitted whenever the focus enters into the widget or child___"""

    def cb_ctrl_left_view_motion(self, _x, _y):
        """___Emitted when the pointer has entered the widget___

        grid_view = self.get_widget()
        grid_view.grab_focus()
        set_view_parent_path(grid_view)
        """

    def cb_ctrl_right_view_motion(self, _x, _y):
        """___Emitted when the pointer has entered the widget___

        grid_view = self.get_widget()
        grid_view.grab_focus()
        set_view_parent_path(grid_view)
        """

    def cb_ctrl_drag_prepare(self, x, y):
        """___return content for the drag file start___"""

        grid_view = self.get_widget()
        pick = grid_view.pick(x, y, Gtk.PickFlags.DEFAULT)

        if pick is not None:
            pos = pick.get_name()

            if str(pos).isdigit():
                parent_path = get_parent_path()
                model = grid_view.get_model()

                if str(parent_path) == str(sw_shortcuts):
                    model.select_item(int(pos), True)
                    paintable = Gtk.WidgetPaintable()
                    paintable.set_widget(pick.get_parent())
                    self.set_icon(paintable, 0, 0)
                    source = Path(model.get_item(int(pos)).get_path())
                    src_name = (
                                pick.get_parent().get_parent().get_last_child()
                                .get_first_child().get_label()
                    )
                    sc_path = Path(f'{sw_tmp}/{src_name}.desktop')

                    if source.is_file():
                        add_shortcut_to_desktop(src_name, sw_tmp)
                        file = Gio.File.new_for_commandline_arg(bytes(sc_path))
                        content = Gdk.ContentProvider.new_for_value(GObject.Value(Gio.File, file))
                        self.set_content(content)
                        return content
                else:
                    nums = model.get_n_items()
                    selected = [model.get_item(i) for i in range(nums) if model.is_selected(i)]

                    if len(selected) > 1:
                        model.select_item(int(pos), False)
                        for x in selected:
                            pic = Gtk.Picture.new_for_file(x)
                            paintable = pic.get_paintable()
                            self.set_icon(paintable, 0, 0)
                    else:
                        model.select_item(int(pos), True)
                        paintable = Gtk.WidgetPaintable()
                        paintable.set_widget(pick.get_parent())
                        self.set_icon(paintable, 0, 0)

                    if len(selected) != 0:
                        file_list = Gdk.FileList.new_from_list(selected)
                        content = Gdk.ContentProvider.new_for_value(GObject.Value(Gdk.FileList, file_list))
                        self.set_content(content)
                        selected.clear()
                        return content

    def cb_ctrl_drag_end(_self, _drag, _delete_data):
        """___signal on the drag source when a drag is finished___"""

    def cb_ctrl_drag_cancel(_self, _drag, reason):
        """___emitted on the drag source when a drag has failed.___"""

        print(reason)

    def cb_ctrl_drop_target(_self, value, x, y):
        """___file drop in choose directory___"""

        replace_source = list()
        copy_source = list()
        copy_target = list()
        grid_view = get_list_view()
        pick = parent.pick(x, y, Gtk.PickFlags.DEFAULT)

        if pick is not None:
            pos = pick.get_name()
            parent_path = get_parent_path()

            if parent_path is not None:
                if Path(parent_path) == sw_shortcuts:
                    pass
                else:
                    if pos == 'GtkGridView':
                        f_items = value.get_files()

                        for item in f_items:
                            source = Path(item.get_path())
                            target = Path(f'{parent_path}/{source.name}')

                            if source != target:
                                if (target.exists()
                                        and source.name == target.name):
                                    replace_source.append(str(source))
                                else:
                                    copy_source.append(source)
                                    copy_target.append(target)
                        else:
                            if len(replace_source) > 0:
                                str_source = str('\n'.join(sorted(replace_source)))
                                title = msg.msg_dict['replace_file']
                                message = [msg.msg_dict['replace_override'], f'{str_source}']
                                func = [{move_replace: (parent_path, replace_source)}, None]
                                SwDialogQuestion(swgs, title, message, None, func)

                            if len(copy_source) > 0:
                                for s, t in zip(copy_source, copy_target):
                                    move_thread = Thread(target=run_move, args=(s, t,))
                                    move_thread.start()
                                    Thread(target=on_copy_move_progress, args=[s, t, move_thread]).start()

                    elif pos.isdigit():
                        model = grid_view.get_model()
                        target = Path(model.get_item(int(pos)).get_path())

                        if target.is_dir():
                            on_files(target)
                            f_items = value.get_files()

                            for item in f_items:
                                source = Path(item.get_path())
                                new_target = Path(f'{target}/{source.name}')

                                if source != new_target:
                                    if (new_target.exists()
                                            and source.name == new_target.name):
                                        replace_source.append(str(source))
                                    else:
                                        copy_source.append(source)
                                        copy_target.append(new_target)
                            else:
                                if len(replace_source) > 0:
                                    str_source = str('\n'.join(sorted(replace_source)))
                                    title = msg.msg_dict['replace_file']
                                    message = [msg.msg_dict['replace_override'], f'{str_source}']
                                    func = [{move_replace: (parent_path, replace_source)}, None]
                                    SwDialogQuestion(swgs, title, message, None, func)

                                if len(copy_source) > 0:
                                    for s, t in zip(copy_source, copy_target):
                                        move_thread = Thread(target=run_move, args=(s, t,))
                                        move_thread.start()
                                        Thread(target=on_copy_move_progress, args=[s, t, move_thread]).start()

    def cb_factory_setup(_self, item_list, data):
        """___setup items in grid view___"""

        cb_paned_factory_setup(item_list, data)

    def cb_paned_factory_setup(item_list, view):

        ft_size = btn_scale_icons.get_value()
        sc_size = btn_scale_shortcuts.get_value()

        if sc_size < 156:
            sc_font = f'font_size_12'
        elif 156 <= sc_size < 204:
            sc_font = f'font_size_14'
        elif 204 <= sc_size < 252:
            sc_font = f'font_size_16'
        else:
            sc_font = f'font_size_18'

        if ft_size < 84:
            f_font = f'font_size_12'
        elif 84 <= ft_size < 132:
            f_font = f'font_size_14'
        elif 132 <= ft_size < 180:
            f_font = f'font_size_16'
        else:
            f_font = f'font_size_18'

        file_overlay = Gtk.Overlay()

        if (get_parent_file().get_path() is not None
                and Path(get_parent_file().get_path()) == Path(sw_shortcuts)):

            view.set_single_click_activate(True)

            file_image = Gtk.Picture(
                                css_name='sw_picture',
                                content_fit=Gtk.ContentFit.COVER,
            )
            file_image.add_css_class('gridview')

            label_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

            label_revealer = Gtk.Revealer(
                                css_name='sw_revealer',
                                transition_duration=350,
                                transition_type=Gtk.RevealerTransitionType.SLIDE_UP,
                                child=label_box,
            )
            label_revealer.set_reveal_child(False)

            overlay_box = Gtk.Box(
                                css_name='sw_box_overlay',
                                orientation=Gtk.Orientation.VERTICAL,
                                vexpand=True,
                                valign=Gtk.Align.END,
            )
            if view.get_name() == 'left_column_view':
                file_image.set_size_request(swgs.width/5, (swgs.width/105)*9)
                overlay_box.set_size_request(swgs.width/5, -1)
                swgs.column_view_file.set_fixed_width(swgs.width/5)
                if swgs.width == 0:
                    file_image.set_size_request(256, (256/21)*9)
                    overlay_box.set_size_request(256, -1)
                    swgs.column_view_file.set_fixed_width(256)

                swgs.column_view_file.set_expand(False)

                file_label = Gtk.Label(
                                    css_name='sw_label_view',
                                    width_chars=0,
                                    ellipsize=Pango.EllipsizeMode.END,
                                    wrap=True,
                                    natural_wrap_mode=True,
                                    xalign=0,
                )
                for i in range(9, 28):
                    file_label.remove_css_class(f'font_size_{i}')

                file_label.add_css_class(f'{sc_font}')

                file_box = Gtk.Box(
                                css_name='sw_box',
                                orientation=Gtk.Orientation.HORIZONTAL,
                                spacing=4,
                )
                overlay_box.append(file_label)

            else:
                file_label = Gtk.Label(
                                    css_name='sw_label_view',
                                    width_chars=0,
                                    ellipsize=Pango.EllipsizeMode.END,
                                    wrap=True,
                                    natural_wrap_mode=True,
                                    xalign=0,
                )
                for i in range(9, 28):
                    file_label.remove_css_class(f'font_size_{i}')

                file_label.add_css_class(f'{sc_font}')

                file_box = Gtk.Box(
                                css_name='sw_box',
                                orientation=Gtk.Orientation.VERTICAL,
                                spacing=4,
                )
                overlay_box.append(file_label)
                overlay_box.append(label_revealer)

                if getenv('ICON_POSITION') == 'horizontal':
                    file_image.set_size_request(sc_size * (92/43), sc_size)
                    overlay_box.set_size_request(sc_size * (92/43), -1)

                elif getenv('ICON_POSITION') == 'vertical':
                    file_image.set_size_request(sc_size, sc_size * (18/10))
                    overlay_box.set_size_request(sc_size, -1)

            file_box.append(file_image)
            file_overlay.set_child(file_box)
            file_overlay.add_overlay(overlay_box)
            item_list.set_child(file_overlay)

            if not view.has_css_class('shortcuts'):
                view.add_css_class('shortcuts')
        else:
            view.set_single_click_activate(False)
            if view.get_name() == 'left_column_view':
                swgs.column_view_file.set_expand(True)

                file_label = Gtk.Label(
                                    css_name='sw_label_desc',
                                    width_chars=0,
                                    ellipsize=Pango.EllipsizeMode.MIDDLE,
                                    wrap=True,
                                    natural_wrap_mode=True,
                                    xalign=0,
                )
                for i in range(9, 28):
                    file_label.remove_css_class(f'font_size_{i}')

                file_box = Gtk.Box(
                                css_name='sw_box',
                                orientation=Gtk.Orientation.HORIZONTAL,
                                spacing=4,
                )
            else:
                file_label = Gtk.Label(
                                    css_name='sw_label_desc',
                                    width_chars=12,
                                    ellipsize=Pango.EllipsizeMode.MIDDLE,
                                    lines=2,
                                    wrap=True,
                                    wrap_mode=Pango.WrapMode.CHAR,
                )
                for i in range(9, 28):
                    file_label.remove_css_class(f'font_size_{i}')

                file_box = Gtk.Box(
                                css_name='sw_box',
                                orientation=Gtk.Orientation.VERTICAL,
                                spacing=4,
                )

            file_label.add_css_class(f'{f_font}')
            file_image = Gtk.Image(css_name='sw_image')
            file_image.set_pixel_size(ft_size)
            symlink_image = Gtk.Image(
                                    css_name='sw_image',
                                    pixel_size=24,
                                    halign=Gtk.Align.END,
                                    valign=Gtk.Align.START,
                                    visible=False,
            )
            file_box.set_margin_top(4)
            file_box.set_margin_bottom(4)
            file_box.set_margin_start(4)
            file_box.set_margin_end(4)
            file_box.append(file_image)
            file_box.append(file_label)

            file_overlay.set_child(file_box)
            file_overlay.add_overlay(symlink_image)

            item_list.set_child(file_overlay)

            if view.has_css_class('shortcuts'):
                view.remove_css_class('shortcuts')

    def cb_factory_bind(_self, item_list, data):
        """___bind items in list view___"""

        cb_paned_factory_bind(item_list, data)

    def cb_paned_factory_bind(item_list, view):
        """___bind items in list view___"""

        child_overlay = item_list.get_child()
        box = child_overlay.get_first_child()
        image = box.get_first_child()
        symlink_image = child_overlay.get_last_child()
        item = item_list.get_item()
        position = item_list.get_position()

        try:
            info = item.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
        except (Exception,):
            info = None

        if info is not None:
            if not info.has_attribute(attrs['content_type']):
                pass
            else:
                content_type = info.get_content_type()
                if info.has_attribute('standard::is-symlink'):
                    symbolic_link = info.get_is_symlink()

                    if symbolic_link:
                        try:
                            symlink_image.set_from_file(IconPath.icon_symlink)
                        except (Exception,):
                            pass
                        else:
                            symlink_image.set_visible(True)

                if item.get_path() is None:
                    uri_factory_bind(child_overlay, item, box, image, position, info)
                else:
                    if Path(item.get_path()).parent == Path(sw_shortcuts):
                        if Path(item.get_path()).suffix in swd_mime_types:
                            shortcut_factory_bind(view, child_overlay, item, image, position)
                    else:
                        file_factory_bind(view, item, image, content_type, info)

                    if label is not None:
                        label.set_name(str(position))

                    if image is not None:
                        image.set_name(str(position))

                    if box is not None:
                        box.set_name(str(position))

                    if child_overlay is not None:
                        child_overlay.set_name(str(position))

    def uri_factory_bind(overlay, _item, box, image, position, info):

        label = image.get_next_sibling()
        label.set_label(info.get_name())
        label.set_name(info.get_name())
        image.set_from_gicon(info.get_icon())
        image.set_name(str(position))
        box.set_name(str(position))
        overlay.set_name(str(position))

    def shortcut_factory_bind(view, overlay, item, image, position):

        app_name = str(Path(item.get_path()).stem)
        write_app_conf(item.get_path())

        overlay_box = overlay.get_last_child()
        overlay_box.set_name(str(position))
        label = overlay_box.get_first_child()

        if view.get_name() == 'left_column_view':
            swgs.column_view_file.set_title(msg.msg_dict['file_name'])
            set_horizontal_icon(app_name, image, label)
        else:
            if getenv('ICON_POSITION') == 'horizontal':
                set_horizontal_icon(app_name, image, label)

            elif getenv('ICON_POSITION') == 'vertical':
                set_vertical_icon(app_name, image, label)

    def set_horizontal_icon(app_name, image, label):

        data = exe_data.get_(app_name)
        if data:
            name = data.get('name')
            h_icon = data.get('horizontal')
            d_icon = data.get('default')
            path = data.get('path')

            if name:
                label.set_label(name.replace('&', '&amp;'))
                label.set_tooltip_markup(name.replace('&', '&amp;'))

            elif path:
                label.set_label(app_name)
                label.set_tooltip_markup(app_name)

            if h_icon:
                icon_path = f'{sw_app_hicons}/{h_icon}'
                image.set_filename(icon_path)
                environ[f'{app_name}'] = f'{icon_path}'
            else:
                image.set_filename(f'{sw_gui_icons}/sw.svg')
                image.set_content_fit(Gtk.ContentFit.SCALE_DOWN)

                if d_icon and Path(f'{sw_app_default_icons}/{d_icon}').exists():
                    icon_path = f'{sw_app_default_icons}/{d_icon}'
                    environ[f'{app_name}'] = f'{icon_path}'

    def set_vertical_icon(app_name, image, label):
        """___set application vertical icon, label and tooltip markup___"""

        data = exe_data.get_(app_name)
        if data:
            name = data.get('name')
            v_icon = data.get('vertical')
            d_icon = data.get('default')
            path = data.get('path')

            if name:
                label.set_label(name.replace('&', '&amp;'))
                label.set_tooltip_markup(name.replace('&', '&amp;'))

            elif path:
                label.set_label(app_name)
                label.set_tooltip_markup(app_name)

            if v_icon:
                icon_path = f'{sw_app_vicons}/{v_icon}'
                image.set_filename(icon_path)
                environ[f'{app_name}'] = f'{icon_path}'
            else:
                image.set_filename(f'{sw_gui_icons}/sw.svg')
                image.set_content_fit(Gtk.ContentFit.SCALE_DOWN)

                if d_icon and Path(f'{sw_app_default_icons}/{d_icon}').exists():
                    icon_path = f'{sw_app_default_icons}/{d_icon}'
                    environ[f'{app_name}'] = f'{icon_path}'

    def set_heroes_icon(app_name, image, label):

        an_isalnum = ''.join(e for e in app_name if e.isalnum())
        for icon in sw_app_heroes_icons.iterdir():
            if an_isalnum == str(Path(icon).name).split('_')[0]:
                image.set_filename(f'{icon}')
                image.set_content_fit(Gtk.ContentFit.COVER)
                if label is not None:
                    label.set_label(str(Path(icon).name).split('_')[-2])
                    label.set_tooltip_markup(str(Path(icon).name).split('_')[-2].replace('&', '&amp;'))
                break
        else:
            try:
                image.set_filename(f'{sw_gui_icons}/{sw_logo_light}')
            except (Exception,):
                pass
            else:
                image.set_content_fit(Gtk.ContentFit.SCALE_DOWN)
                for icon in sw_app_default_icons.iterdir():
                    if an_isalnum == str(Path(icon).name).split('_')[0]:
                        if label is not None:
                            label.set_label(str(Path(icon).name).split('_')[-2])
                            label.set_tooltip_markup(str(Path(icon).name).split('_')[-2].replace('&', '&amp;'))
                        break
                else:
                    if label is not None:
                        label.set_label(app_name)
                        label.set_tooltip_markup(app_name)

    def file_factory_bind(view, item, image, content_type, info):

        label = image.get_next_sibling()

        if view.get_name() == 'left_column_view':
            swgs.column_view_file.set_title(msg.msg_dict['file_name'])
            label.set_size_request(140, -1)

        if content_type in app_mime_types:
            app_dict = app_info(item.get_path())
            try:
                app_dict["Icon"]
            except (Exception,):
                try:
                    image.set_from_gicon(
                        info.get_attribute_object("standard::icon"))
                except (Exception,):
                    print(
                        f'{tc.VIOLET2} app_mime_type icon not found for: {tc.GREEN}'
                        + item.get_path() + tc.END)
            else:
                try:
                    image.set_from_file(app_dict["Icon"])
                except (Exception,):
                    try:
                        image.set_from_gicon(
                            info.get_attribute_object("standard::icon"))
                    except (Exception,):
                        print(
                            f'{tc.VIOLET2} app_mime_type icon not found for: {tc.GREEN}'
                            + item.get_path() + tc.END)

        elif content_type in image_mime_types or str(Path(item.get_path()).suffix).lower() == '.exe':

            thumb_path = f'{sw_fm_cache_thumbnail}/{item.get_path().replace("/", "")}'
            thumb = thumb_path if Path(thumb_path).exists() else str(Path(f'{thumb_path}.png'))

            if Path(thumb).exists():
                file_icon = Gtk.IconPaintable.new_for_file(
                                Gio.File.new_for_path(thumb),
                                btn_scale_icons.get_value(), 1)
                try:
                    image.set_from_paintable(file_icon)
                except (Exception,):
                    try:
                        image.set_paintable(file_icon)
                    except (Exception,):
                        try:
                            image.set_from_gicon(
                                info.get_attribute_object("standard::icon"))
                        except (Exception,):
                            try:
                                icon = try_get_theme_icon('image')
                                image.set_from_paintable(icon)
                            except (Exception,):
                                print(
                                    f'{tc.VIOLET2} image_mime_type icon not found for: {tc.GREEN}'
                                    + item.get_path() + tc.END)
            else:
                try:
                    image.set_from_gicon(
                        info.get_attribute_object("standard::icon"))
                except (Exception,):
                    try:
                        icon = try_get_theme_icon('image')
                        image.set_from_paintable(icon)
                    except (Exception,):
                        print(
                            f'{tc.VIOLET2} image_mime_type icon not found for: {tc.GREEN}'
                            + item.get_path() + tc.END)

        elif content_type in video_mime_types:
            thumb = f'{sw_fm_cache_thumbnail}/{item.get_path().replace("/", "")}.png'
            if Path(thumb).exists():
                file_icon = Gtk.IconPaintable.new_for_file(
                                Gio.File.new_for_path(f'{thumb}'),
                                btn_scale_icons.get_value(), 1,)
                try:
                    image.set_from_paintable(file_icon)
                except (Exception,):
                    try:
                        image.set_paintable(file_icon)
                    except (Exception,):
                        try:
                            image.set_from_gicon(
                                info.get_attribute_object("standard::icon"))
                        except (Exception,):
                            print(
                                f'{tc.VIOLET2} video_mime_type icon not found for: {tc.GREEN}'
                                + item.get_path() + tc.END)
            else:
                try:
                    image.set_from_gicon(
                                    info.get_attribute_object("standard::icon")
                    )
                except (Exception,):
                    print(
                        f'{tc.VIOLET2} video_mime_type icon not found for: {tc.GREEN}'
                        + item.get_path() + tc.END)
        else:
            try:
                image.set_from_gicon(
                    info.get_attribute_object("standard::icon"))
            except (Exception,):
                try:
                    icon = try_get_theme_icon('text')
                    image.set_from_paintable(icon)
                except (Exception,):
                    print(
                        f'{tc.VIOLET2} other_mime_type gicon not found for: {tc.GREEN}'
                        + item.get_path() + tc.END)
        try:
            label.set_label(
                info.get_attribute_string("standard::display-name"))
        except (Exception,):
            print(
                f'{tc.VIOLET2} label not set for: {tc.GREEN}'
                + item.get_path() + tc.END)
        try:
            label.set_tooltip_markup(
                info.get_attribute_string("standard::display-name"))
        except (Exception,):
            print(
                f'{tc.VIOLET2} tooltip not set for: {tc.GREEN}'
                + item.get_path() + tc.END)

    def cb_grid_factory_teardown(_self, _item_list):
        """___prepare remove objects from list view___"""
        pass

    def cb_grid_factory_unbind(_self, _item_list):
        """___remove objects from list view___"""
        pass

    def cb_column_factory_type_setup(_self, item_list):
        """___setup items in column size view___"""

        file_label = None

        box = Gtk.Box(
                        css_name='sw_box',
                        orientation=Gtk.Orientation.VERTICAL,
                        spacing=4,
                        valign=Gtk.Align.CENTER,
        )
        if str(get_parent_file().get_path()) == str(sw_shortcuts):
            for i in range(4):
                file_label = Gtk.Label(
                                css_name='sw_label_desc',
                                wrap=True,
                                natural_wrap_mode=True,
                                ellipsize=Pango.EllipsizeMode.END,
                                xalign=0,
                                margin_start=4,
                                margin_end=4,
                )
                box.append(file_label)
        else:
            file_label = Gtk.Label(
                            css_name='sw_label_desc',
                            wrap=True,
                            natural_wrap_mode=True,
                            ellipsize=Pango.EllipsizeMode.END,
                            wrap_mode=Pango.WrapMode.WORD_CHAR,
                            lines=5,
                            xalign=0,
                            margin_start=4,
                            margin_end=4,
            )
            box.append(file_label)

        if file_label is not None:
            file_label.set_size_request(140, -1)

        item_list.set_child(box)

    def cb_column_factory_size_setup(_self, item_list):
        """___setup items in column size view___"""

        file_label = Gtk.Label(
                        css_name='sw_label_desc',
                        wrap=True,
                        natural_wrap_mode=True,
                        ellipsize=Pango.EllipsizeMode.END,
                        wrap_mode=Pango.WrapMode.WORD_CHAR,
                        lines=5,
                        xalign=0,
                        margin_start=4,
                        margin_end=4,
        )
        file_label.set_size_request(140, -1)
        item_list.set_child(file_label)

    def cb_column_factory_uid_setup(_self, item_list):
        """___setup items in column size view___"""

        file_label = Gtk.Label(
                        css_name='sw_label_desc',
                        wrap=True,
                        natural_wrap_mode=True,
                        ellipsize=Pango.EllipsizeMode.END,
                        wrap_mode=Pango.WrapMode.WORD_CHAR,
                        lines=5,
                        xalign=0,
                        margin_start=4,
                        margin_end=4,
        )
        file_label.set_size_request(140, -1)
        item_list.set_child(file_label)

    def cb_column_factory_created_setup(_self, item_list):
        """___setup items in column file created time view___"""

        file_label = Gtk.Label(
                        css_name='sw_label_desc',
                        wrap=True,
                        natural_wrap_mode=True,
                        ellipsize=Pango.EllipsizeMode.END,
                        wrap_mode=Pango.WrapMode.WORD_CHAR,
                        lines=5,
                        xalign=0,
                        margin_start=4,
                        margin_end=4,
        )
        file_label.set_size_request(140, -1)
        item_list.set_child(file_label)

    def cb_column_factory_type_bind(_self, item_list):
        """___bind items in list view___"""

        box = item_list.get_child()
        file_label = box.get_first_child()
        item = item_list.get_item()

        try:
            file_info = item.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
        except (Exception,):
            file_info = None

        if file_info is not None:
            if str(item.get_parent().get_path()) == str(sw_shortcuts):
                swgs.column_view_type.set_title(msg.msg_dict['startup_mode'])

                stat_dict = app_info(item.get_path())
                app_path = stat_dict['Exec'].replace(f'env "{sw_start}" ', '').strip('"').replace(' ', '_')
                stat_name = app_path.replace('/', '_').replace('.', '_')
                stat_path = f'{sw_fm_cache_stats}/{stat_name}'

                app_name = str(Path(item.get_path()).stem)
                app_strip = app_name.strip('"').replace(' ', '_')
                app_config_path = f"{sw_app_config}/{app_strip}"
                app_conf_dict = app_info(app_config_path)
                prefix = ''
                wine = ''
                if app_conf_dict.get('export SW_USE_PFX'):
                    prefix = app_conf_dict['export SW_USE_PFX'][1:-1].replace('pfx_', '')
                if app_conf_dict.get('export SW_USE_PFX'):
                    wine = app_conf_dict['export SW_USE_WINE'][1:-1].replace('wine_', '')

                prefix_str = (str_prefix + ' ' + prefix)
                wine_str = (str('Wine: ') + wine)

                file_label.set_label(prefix_str)
                file_label.set_tooltip_markup(prefix)

                wine_label = file_label.get_next_sibling()
                wine_label.set_label(wine_str)
                wine_label.set_tooltip_markup(wine)

                total_time = read_app_stat(stat_path, 'Time')
                time_str = f'{msg.msg_dict["total_time"]}: {total_time}'
                time_label = wine_label.get_next_sibling()
                time_label.set_label(time_str)
                time_label.set_tooltip_markup(str(total_time))

                total_fps = read_app_stat(stat_path, 'Fps')
                fps_str = f'{msg.msg_dict["avg_fps"]}: {total_fps}'
                fps_label = time_label.get_next_sibling()
                fps_label.set_label(fps_str)
                fps_label.set_tooltip_markup(str(total_fps))
            else:
                swgs.column_view_type.set_title(msg.msg_dict['file_type'])
                f_type = file_info.get_content_type()
                file_label.set_label(str(f_type))

    def cb_column_factory_size_bind(_self, item_list):
        """___bind items in list view___"""

        file_label = item_list.get_child()
        item = item_list.get_item()

        try:
            file_info = item.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
        except (Exception,):
            file_info = None

        if file_info is not None:
            if str(item.get_parent().get_path()) == str(sw_shortcuts):
                swgs.column_view_size.set_title(msg.msg_dict['path'])
                app_dict = app_info(f'{item.get_path()}')
                app_exec = app_dict['Exec'].replace(f'env "{sw_start}" ', '').strip('"')
                file_label.set_label(app_exec)
                file_label.set_tooltip_markup(app_exec)
            else:
                swgs.column_view_size.set_title(msg.msg_dict['file_size'])
                f_size = file_info.get_size()

                if len(str(f_size)) > 9:
                    file_label.set_label(
                        str(round(f_size/1024/1024/1024, 2))[0:5] + ' Gb')

                if 6 < len(str(f_size)) <= 9:
                    file_label.set_label(
                        str(round(f_size/1024/1024, 2))[0:5] + ' Mb')

                if len(str(f_size)) <= 6:
                    file_label.set_label(
                        str(round(f_size/1024, 2))[0:5] + ' Kb')

    def cb_column_factory_uid_bind(_self, item_list):
        """___bind items in list view___"""

        file_label = item_list.get_child()
        item = item_list.get_item()

        try:
            file_info = item.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
        except (Exception,):
            file_info = None

        if file_info is not None:
            swgs.column_view_uid.set_title(msg.msg_dict['user_group'])
            f_uid = file_info.get_attribute_as_string("owner::user")
            f_gid = file_info.get_attribute_as_string("owner::group")
            try:
                st = os.stat(item.get_path())
            except (Exception,):
                permission = ''
            else:
                permission = oct(st.st_mode)
                permission = list(permission[:-4:-1])
                permission.reverse()
                permission = ' '.join([access_dict[int(p)] for p in permission])

            file_label.set_label(f'{f_uid} {f_gid}\n{msg.msg_dict["access"]}: {permission}')

    def cb_column_factory_created_bind(_self, item_list):
        """___bind items in list view___"""

        file_label = item_list.get_child()
        item = item_list.get_item()
        try:
            file_info = item.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
        except (Exception,):
            file_info = None

        if file_info is not None:
            title = msg.msg_dict['file_date']
            swgs.column_view_created.set_title(title)

            if file_info.get_modification_date_time() is not None:
                f_modified = file_info.get_modification_date_time().format('%c')
            else:
                f_modified = 'Unknown'

            if file_info.get_creation_date_time() is not None:
                f_created = file_info.get_creation_date_time().format('%c')
            else:
                f_created = 'Unknown'

            file_label.set_label(f'{f_modified}\n{f_created}')

    def cb_volume_ops(_self, _volume):
        """___mount unmount volume changed___"""

        if scrolled_gvol.get_child() is None:
            add_gvol_view()

        return update_gvolume()

    def cb_gvol_activate(self, position):
        """___activate mount and unmount operation by the user___"""

        gvol = self.get_model().get_item(position)

        if isinstance(gvol, Gtk.StringObject):
            mount_path = Path(gvol.get_string().split(':')[0])
            gmount_path = Gio.File.new_for_path(bytes(mount_path))
            if gmount_path is not None and mount_path.exists():
                try:
                    update_grid_view(mount_path)
                except PermissionError as e:
                    overlay_info(main_overlay, None, e, None, None, 3)
        else:
            gmnt = gvol.get_mount()

            if gmnt is None and gvol.can_mount():
                gvol.mount(Gio.MountMountFlags.NONE, swgs.gmount_ops, callback=gvol_mount)

            elif gmnt is not None:
                mount_path = gvol.get_mount().get_default_location().get_path()

                if mount_path is not None and Path(mount_path).exists():
                    try:
                        update_grid_view(mount_path)
                    except PermissionError as e:
                        overlay_info(main_overlay, None, e, None, None, 3)

                elif mount_path is None:
                    uri = gmnt.get_default_location().get_uri()
                    if uri is not None:
                        update_grid_view_uri(uri)
            else:
                raise ValueError(f'{tc.RED}{gvol.get_name()} mount error{tc.END}')

    def update_grid_view_uri(new_uri):

        paned_store = get_list_store()
        dir_list = get_dir_list()

        if str(new_uri).endswith('/'):
            new_uri = new_uri
        else:
            new_uri = str(new_uri) + '/'

        update_path(new_uri)
        entry_path.set_text(str(new_uri))
        entry_path.set_name(str(new_uri))

        swgs.cur_dir = Gio.File.new_for_uri(new_uri)
        swgs.f_mon = swgs.cur_dir.monitor(Gio.FileMonitorFlags.WATCH_MOVES, None)
        swgs.f_mon.connect('changed', g_file_monitor)

        gfile = Gio.File.new_for_uri(new_uri)

        try:
            ginfo = gfile.query_info('*', Gio.FileQueryInfoFlags.NONE)
        except GLib.GError:
            content_type = None
        else:
            content_type = ginfo.get_content_type()

        if content_type is None:
            swgs.default_dir = swgs.cfg.get('default_dir')
            on_files(swgs.default_dir)

        elif content_type == dir_mime_types[0]:
            paned_store.remove_all()
            gfile_enum = gfile.enumerate_children('*', Gio.FileQueryInfoFlags.NONE)
            for g in gfile_enum:
                uri_file = Gio.File.new_for_uri(f'{new_uri}{g.get_name()}')
                paned_store.append(uri_file)
                dir_list.set_file(uri_file)

        elif content_type in bin_mime_types[0]:
            gio_app_info = Gio.AppInfo.create_from_commandline(
                                            new_uri, None,
                                            Gio.AppInfoCreateFlags.SUPPORTS_URIS
            )
            try:
                gio_app_info.launch_default_for_uri(new_uri)
            except GLib.GError as e:
                print(tc.RED, e, tc.END)
                return SwCrier(text_message=str(e.message), message_type='ERROR').run()
        else:
            gio_app_info = Gio.AppInfo.get_default_for_type(content_type, True)
            if gio_app_info is not None:
                try:
                    gio_app_info.launch_default_for_uri(new_uri)
                except GLib.GError as e:
                    print(e.message)
            else:
                ul = Gtk.UriLauncher()
                ul.set_uri(new_uri)
                try:
                    ul.launch()
                except GLib.GError as e:
                    print(tc.RED, e.message, tc.END)
                    return SwCrier(text_message=str(e.message), message_type='ERROR').run()

    def cb_eject_btn(_self, gmount):
        """___unmount selected volume___"""

        gmount.unmount_with_operation(
            Gio.MountUnmountFlags.NONE, swgs.gmount_ops, callback=gmount_unmount)

    def gvol_mount(self, res):
        """___mount operation finish___"""
        try:
            self.mount_finish(res)
        except GLib.GError as e:
            print(e)
            SwCrier(text_message=str(e.message), message_type='ERROR').run()
        else:
            mount_path = self.get_mount().get_default_location().get_path()

            if mount_path is not None and Path(mount_path).exists():
                try:
                    update_grid_view(mount_path)
                except PermissionError as e:
                    return overlay_info(main_overlay, None, e, None, None, 3)

            elif mount_path is None:
                uri = self.get_mount().get_default_location().get_uri()
                if uri is not None:
                    try:
                        update_grid_view_uri(uri)
                    except PermissionError as e:
                        return overlay_info(main_overlay, None, e, None, None, 3)
            else:
                raise ValueError(f'{tc.RED}{self.get_name()} mount error{tc.END}')

    def gmount_unmount(self, res):
        """___unmount operation finish___"""
        try:
            self.unmount_with_operation_finish(res)
        except GLib.GError as e:
            return SwCrier(text_message=str(e.message), message_type='ERROR').run()
        else:
            unmount_path = swgs.cfg['default_dir']
            if unmount_path is not None and Path(unmount_path).exists():
                try:
                    update_grid_view(unmount_path)
                except PermissionError as e:
                    return overlay_info(main_overlay, None, e, None, None, 3)

    def cb_gvol_factory_setup(_self, list_item):
        """___bind items in column view___"""

        label = Gtk.Label(
                        css_name='sw_label_desc', wrap=True,
                        natural_wrap_mode=True, xalign=0,
        )
        image = Gtk.Image(css_name='sw_image')
        image.set_icon_size(Gtk.IconSize.LARGE)

        eject_image = Gtk.Image(css_name='sw_image')
        eject_image.set_from_file(IconPath.icon_eject)

        eject_btn = Gtk.Button(
                            css_name='sw_button',
                            hexpand=True,
                            valign=Gtk.Align.CENTER,
                            halign=Gtk.Align.END,
        )
        eject_btn.set_child(eject_image)

        box = Gtk.Box(css_name='sw_box_view')
        box.set_orientation(Gtk.Orientation.HORIZONTAL)
        box.set_halign(Gtk.Align.FILL)
        box.set_hexpand(True)
        box.set_spacing(8)
        box.append(image)
        box.append(label)
        box.append(eject_btn)

        list_item.set_child(box)

    def cb_gvol_id_factory_setup(_self, list_item):
        """___bind items in column view___"""

        label = Gtk.Label(
                        css_name='sw_label_desc',
                        wrap=True,
                        natural_wrap_mode=True,
                        xalign=0,
                        margin_start=8,
                        margin_end=8,
        )
        list_item.set_child(label)

    def cb_gvol_uuid_factory_setup(_self, list_item):
        """___bind items in column view___"""

        label = Gtk.Label(
                        css_name='sw_label_desc',
                        wrap=True,
                        natural_wrap_mode=True,
                        ellipsize=Pango.EllipsizeMode.END,
                        wrap_mode=Pango.WrapMode.WORD_CHAR,
                        lines=3,
                        xalign=0,
                        margin_start=8,
                        margin_end=8,
        )
        list_item.set_child(label)

    def cb_gvol_drive_factory_setup(_self, list_item):
        """___bind items in column view___"""

        label = Gtk.Label(
                        css_name='sw_label_desc',
                        wrap=True,
                        natural_wrap_mode=True,
                        ellipsize=Pango.EllipsizeMode.END,
                        wrap_mode=Pango.WrapMode.WORD_CHAR,
                        lines=3,
                        xalign=0,
                        margin_start=8,
                        margin_end=8,
        )
        list_item.set_child(label)

    def cb_gvol_size_factory_setup(_self, list_item):
        """___bind items in column view___"""

        bar = Gtk.ProgressBar(
                            css_name='sw_progressbar',
                            valign=Gtk.Align.CENTER,
                            margin_start=16,
                            margin_end=16,
        )
        list_item.set_child(bar)

    def cb_gvol_factory_bind(_self, list_item):
        """___bind items in column view___"""

        box = list_item.get_child()
        data = list_item.get_item()
        image = box.get_first_child()
        label = image.get_next_sibling()
        eject_btn = label.get_next_sibling()

        if isinstance(data, Gtk.StringObject):
            mountpoint = data.get_string().split(':')[0]
            device = data.get_string().split(':')[1]
            name = f'{Path(mountpoint).stem}'
            icon = IconPath.icon_drive
            if mountpoint == '/':
                name = 'rootfs'
                icon = IconPath.icon_drive
            if '/run/media' in mountpoint:
                icon = IconPath.icon_usb
            if '/dev/loop' in mountpoint:
                icon = IconPath.icon_cdrom
            if 'nvme' in device:
                icon = IconPath.icon_ssd
            label.set_name(mountpoint)
            label.set_text(name)
            image.set_from_file(icon)
            eject_btn.set_visible(False)
            swgs.column_gvol_drive.set_title(msg.msg_dict['mount_options'])
        else:
            image.set_from_gicon(data.get_icon())
            label.set_text(data.get_name())

            if data.get_mount() is not None and data.get_mount().can_unmount():
                eject_btn.connect('clicked', cb_eject_btn, data.get_mount())
                eject_btn.set_name(data.get_name())
                eject_btn.set_visible(True)
            else:
                eject_btn.set_name(data.get_name())
                eject_btn.set_visible(False)

    def cb_gvol_id_factory_bind(_self, list_item):
        """___bind items in column view___"""

        label = list_item.get_child()
        data = list_item.get_item()

        if isinstance(data, Gtk.StringObject):
            devid = data.get_string().split(':')[1]
            label.set_label(devid)
        else:
            dev_id = data.get_identifier('unix-device')
            if dev_id is not None:
                label.set_label(dev_id)

    def cb_gvol_uuid_factory_bind(_self, list_item):
        """___bind items in column view___"""

        label = list_item.get_child()
        data = list_item.get_item()

        if isinstance(data, Gtk.StringObject):
            pass
        else:
            if data.get_uuid() is not None:
                label.set_label(data.get_uuid())

    def cb_gvol_drive_factory_bind(_self, list_item):
        """___bind items in column view___"""

        label = list_item.get_child()
        data = list_item.get_item()

        if isinstance(data, Gtk.StringObject):
            mount_options = data.get_string().split(':')[3]
            label.set_label(mount_options)
        else:
            if not data.get_drive() is None:
                label.set_label(data.get_drive().get_name())

    def cb_gvol_size_factory_bind(_self, list_item):
        """___bind items in column view___"""

        size_bar = list_item.get_child()
        data = list_item.get_item()

        if isinstance(data, Gtk.StringObject):
            mountpoint = data.get_string().split(':')[0]

            fs_size = psutil.disk_usage(mountpoint).total
            fs_used = psutil.disk_usage(mountpoint).used
            fs_free = psutil.disk_usage(mountpoint).free
            fs_type = data.get_string().split(':')[2]

            fmt_size = GLib.format_size(int(fs_size))
            fmt_free = GLib.format_size(int(fs_free))
            fmt_used = GLib.format_size(int(fs_used))
            size_bar.set_fraction(1 - (int(fs_free)/int(fs_size)))
            fmt_all = f'{fmt_free} / {fmt_used} / {fmt_size} ({fs_type})'
            fmt_free = f'{fmt_free} / {fmt_size} ({fs_type})'

            size_bar.set_show_text(True)
            size_bar.set_text(fmt_free)
            size_bar.set_tooltip_markup(fmt_all)
        else:
            if data.get_mount() is not None:
                try:
                    file_info = data.get_mount().get_root().query_filesystem_info("*", None)
                except (Exception,):
                    pass
                else:
                    fs_size = file_info.get_attribute_as_string('filesystem::size')
                    fs_free = file_info.get_attribute_as_string('filesystem::free')
                    fs_used = file_info.get_attribute_as_string('filesystem::used')
                    fs_type = file_info.get_attribute_as_string('filesystem::type')

                    if fs_size is not None:
                        fmt_size = GLib.format_size(int(fs_size))
                    else:
                        fs_size = None
                        fmt_size = ''

                    if fs_free is not None:
                        fmt_free = GLib.format_size(int(fs_free))
                    else:
                        fs_free = 0
                        fmt_free = ''

                    if fs_used is not None:
                        fmt_used = GLib.format_size(int(fs_used))
                    else:
                        fmt_used = ''

                    if fs_size is None:
                        pass
                    else:
                        size_bar.set_fraction(1 - (int(fs_free)/int(fs_size)))

                    fmt_all = f'{fmt_free} / {fmt_used} / {fmt_size} ({fs_type})'
                    fmt_free = f'{fmt_free} / {fmt_size} ({fs_type})'
                    size_bar.set_show_text(True)
                    size_bar.set_text(fmt_free)
                    size_bar.set_tooltip_markup(fmt_all)

    def cb_bookmarks_factory_setup(_self, item_list):
        """___setup items in bookmarks list view___"""

        label_bookmark = Gtk.Label(
                            css_name='sw_label_desc',
                            xalign=0,
                            ellipsize=Pango.EllipsizeMode.END,
                            margin_top=4,
                            margin_bottom=4,
                            margin_start=4,
                            margin_end=4,
                            hexpand=True,
                            halign=Gtk.Align.START,
        )
        image_bookmark = Gtk.Image(
                            css_name='sw_image',
        )
        image_btn = Gtk.Image(
                            css_name='sw_image',
        )
        btn_remove = Gtk.Button(
                            css_name='sw_button_close',
                            child=image_btn,
                            hexpand=True,
                            halign=Gtk.Align.END,
                            vexpand=True,
                            valign=Gtk.Align.CENTER,
                            visible=False,
        )
        box_bookmark = Gtk.Box(
                            css_name='sw_box_view',
                            orientation=Gtk.Orientation.HORIZONTAL,
                            hexpand=True,
                            spacing=8,
                            halign=Gtk.Align.FILL,
                            valign=Gtk.Align.CENTER,
        )
        box_bookmark.append(image_bookmark)
        box_bookmark.append(label_bookmark)
        box_bookmark.append(btn_remove)
        btn_remove.connect('clicked', cb_btn_remove_bookmark)
        ctrl_motion_bookmarks = Gtk.EventControllerMotion()
        ctrl_motion_bookmarks.connect('enter', cb_ctrl_enter_bookmarks, btn_remove)
        ctrl_motion_bookmarks.connect('leave', cb_ctrl_leave_bookmarks, btn_remove)
        box_bookmark.add_controller(ctrl_motion_bookmarks)

        item_list.set_child(box_bookmark)

    def cb_bookmarks_factory_bind(_self, item_list):
        """___bind items in bookmarks list view___"""

        item = item_list.get_item()
        box = item_list.get_child()
        image = box.get_first_child()
        label = image.get_next_sibling()
        btn = label.get_next_sibling()
        image_btn = btn.get_child()
        str_item = item.get_string()

        btn.set_name(str_item)
        image_btn.set_from_file(IconPath.icon_clear)
        btn.set_tooltip_markup(msg.tt_dict['remove'])
        box.set_tooltip_markup(str_item)

        try:
            image.set_from_file(bookmarks_dict[str_item][0])
        except (Exception,):
            image.set_from_file(IconPath.icon_folder)
            label.set_label(Path(str_item).name.capitalize())
        else:
            if bookmarks_dict[str_item][1] is not None:
                label.set_label(bookmarks_dict[str_item][1])
            else:
                label.set_label(Path(str_item).name.capitalize())

    def cb_playlist_factory_setup(_self, item_list):
        """___setup items in playlist view___"""

        label_media = Gtk.Label(
                            css_name='sw_label_desc',
                            xalign=0,
                            ellipsize=Pango.EllipsizeMode.END,
                            margin_top=4,
                            margin_bottom=4,
                            margin_start=4,
                            margin_end=4,
                            hexpand=True,
                            halign=Gtk.Align.START,
        )
        image_media = Gtk.Image(
                            css_name='sw_image',
        )
        image_btn = Gtk.Image(
                            css_name='sw_image',
        )
        btn_remove = Gtk.Button(
                            css_name='sw_button_close',
                            child=image_btn,
                            hexpand=True,
                            halign=Gtk.Align.END,
                            vexpand=True,
                            valign=Gtk.Align.CENTER,
                            visible=False,
        )
        box_media = Gtk.Box(
                            css_name='sw_box_view',
                            orientation=Gtk.Orientation.HORIZONTAL,
                            hexpand=True,
                            spacing=8,
                            halign=Gtk.Align.FILL,
                            valign=Gtk.Align.CENTER,
        )
        box_media.append(image_media)
        box_media.append(label_media)
        box_media.append(btn_remove)
        btn_remove.connect('clicked', cb_btn_remove_media)
        ctrl_motion_playlist = Gtk.EventControllerMotion()
        ctrl_motion_playlist.connect('enter', cb_ctrl_enter_media, btn_remove)
        ctrl_motion_playlist.connect('leave', cb_ctrl_leave_media, btn_remove)
        box_media.add_controller(ctrl_motion_playlist)

        item_list.set_child(box_media)

    def cb_playlist_factory_bind(_self, item_list):
        """___bind items in bookmarks list view___"""

        item = item_list.get_item()
        box = item_list.get_child()
        image = box.get_first_child()
        label = image.get_next_sibling()
        btn = label.get_next_sibling()
        image_btn = btn.get_child()
        str_item = item.get_string()

        btn.set_name(str_item)
        image_btn.set_from_file(IconPath.icon_clear)
        btn.set_tooltip_markup(msg.tt_dict['remove'])
        box.set_tooltip_markup(str_item)
        image.set_from_file(IconPath.icon_audio)
        label.set_label(Path(str_item).stem.capitalize())

        if media_file.get_file() is not None:
            if media_file.get_file().get_path() == str_item:
                box.add_css_class('accent_background')
                label.add_css_class('accent_label')

    def cb_factory_dll_0_setup(_self, item_list):
        """___setup items in dll column view___"""

        label_dll = Gtk.Label(
                            css_name='sw_label_desc',
                            xalign=0,
        )
        pic_dll = Gtk.Picture(
                            css_name='sw_uncheck',
                            content_fit=Gtk.ContentFit.COVER,
        )
        pic_dll.set_size_request(32, 32)

        btn_dll = Gtk.CheckButton(
                            css_name='sw_checkbutton',
                            valign=Gtk.Align.CENTER,
        )
        check = btn_dll.get_first_child()
        check.set_visible(False)
        btn_dll.set_child(pic_dll)
        box_dll = Gtk.Box(
                        orientation=Gtk.Orientation.HORIZONTAL,
                        spacing=8,
        )
        box_dll.append(btn_dll)
        box_dll.append(label_dll)
        item_list.set_child(box_dll)

    def cb_factory_dll_1_setup(_self, item_list):
        """___setup items in dll column view___"""

        label_dll = Gtk.Label(
                            css_name='sw_label_desc',
                            xalign=0,
        )
        pic_dll = Gtk.Picture(
                            css_name='sw_uncheck',
                            content_fit=Gtk.ContentFit.COVER,
        )
        pic_dll.set_size_request(32, 32)

        btn_dll = Gtk.CheckButton(
                            css_name='sw_checkbutton',
                            valign=Gtk.Align.CENTER,
        )
        check = btn_dll.get_first_child()
        check.set_visible(False)
        btn_dll.set_child(pic_dll)
        box_dll = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        box_dll.append(btn_dll)
        box_dll.append(label_dll)
        item_list.set_child(box_dll)

    def cb_factory_dll_0_bind(_self, item_list):
        """___bind items in dll column view___"""

        btn_check = item_list.get_child().get_first_child()
        label_dll = btn_check.get_next_sibling()
        item = item_list.get_item()
        label_dll.set_label(item.get_label())
        pic_dll = btn_check.get_child()

        if 'installed_' in str(item.get_name()):
            pic_dll.set_filename(IconPath.icon_checked)
            btn_check.set_active(True)
            btn_check.set_sensitive(False)

        btn_check.connect('toggled', on_dll_toggled, label_dll, pic_dll)

    def cb_factory_dll_1_bind(_self, item_list):
        """___bind items in dll column view___"""

        btn_check = item_list.get_child().get_first_child()
        label_dll = btn_check.get_next_sibling()
        item = item_list.get_item()
        label_dll.set_label(item.get_label())
        pic_dll = btn_check.get_child()

        if 'installed_' in str(item.get_name()):
            pic_dll.set_filename(IconPath.icon_checked)
            btn_check.set_active(True)
            btn_check.set_sensitive(False)

        btn_check.connect('toggled', on_dll_toggled, label_dll, pic_dll)

    def cb_factory_dll_0_desc_setup(_self, item_list):
        """___setup items in dll column view___"""

        label_desc = Gtk.Label(css_name='sw_label_desc')
        label_desc.set_xalign(0)
        label_desc.set_wrap(True)
        label_desc.set_wrap_mode(Pango.WrapMode.CHAR)
        item_list.set_child(label_desc)

    def cb_factory_dll_0_desc_bind(_self, item_list):
        """___bind items in dll column view___"""

        label_dll = item_list.get_child()
        item = item_list.get_item()
        label_dll.set_label(dll_dict[item.get_label()])

    def cb_factory_dll_1_desc_setup(_self, item_list):
        """___setup items in dll column view___"""

        label_desc = Gtk.Label(css_name='sw_label_desc')
        label_desc.set_xalign(0)
        label_desc.set_wrap(True)
        label_desc.set_wrap_mode(Pango.WrapMode.CHAR)
        item_list.set_child(label_desc)

    def cb_factory_dll_1_desc_bind(_self, item_list):
        """___bind items in dll column view___"""

        label_dll = item_list.get_child()
        item = item_list.get_item()
        label_dll.set_label(dll_dict[item.get_label()])

    def cb_factory_fonts_setup(_self, item_list):
        """___setup items in fonts column view___"""

        label_fonts = Gtk.Label(
                            css_name='sw_label_desc',
                            xalign=0,
        )
        pic_fonts = Gtk.Picture(
                            css_name='sw_uncheck',
                            content_fit=Gtk.ContentFit.COVER,
        )
        pic_fonts.set_size_request(32, 32)

        btn_fonts = Gtk.CheckButton(
                            css_name='sw_checkbutton',
                            valign=Gtk.Align.CENTER,
        )
        check = btn_fonts.get_first_child()
        check.set_visible(False)
        btn_fonts.set_child(pic_fonts)
        box_fonts = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        box_fonts.append(btn_fonts)
        box_fonts.append(label_fonts)
        item_list.set_child(box_fonts)

    def cb_factory_fonts_bind(_self, item_list):
        """___bind items in fonts column view___"""

        btn_check = item_list.get_child().get_first_child()
        label_fonts = btn_check.get_next_sibling()
        item = item_list.get_item()
        label_fonts.set_label(item.get_label())
        pic_fonts = btn_check.get_child()

        if 'installed_' in str(item.get_name()):
            pic_fonts.set_filename(IconPath.icon_checked)
            btn_check.set_active(True)
            btn_check.set_sensitive(False)

        btn_check.connect('toggled', on_fonts_toggled, label_fonts, pic_fonts)

    def cb_factory_fonts_desc_setup(_self, item_list):
        """___setup items in fonts column view___"""

        label_desc = Gtk.Label(css_name='sw_label_desc')
        label_desc.set_xalign(0)
        label_desc.set_wrap(True)
        label_desc.set_wrap_mode(Pango.WrapMode.WORD)
        item_list.set_child(label_desc)

    def cb_factory_fonts_desc_bind(_self, item_list):
        """___bind items in fonts column view___"""

        label_fonts = item_list.get_child()
        item = item_list.get_item()
        label_fonts.set_label(fonts_dict[item.get_label()])

    def cb_factory_dll_templates_setup(_self, item_list):
        """___setup dll templates in dropdown list___"""

        label = Gtk.Label(css_name='sw_label_desc', xalign=0)
        item_list.set_child(label)

    def cb_factory_dll_templates_bind(_self, item_list):
        """___bind dll templates in dropdown list___"""

        item = item_list.get_item()
        label = item_list.get_child()
        label.set_label(item.get_label())
        label.set_name(item.get_name())
        label.set_tooltip_markup(item.get_name())

    def request_wine(wine):
        """___wine download request___"""

        def on_thread_wine():

            app_name = get_out()
            app_conf = Path(f"{sw_app_config}/" + str(app_name))
            app_conf_dict = app_conf_info(app_conf, switch_labels)
            debug = app_conf_dict['WINEDBG_DISABLE'].split('=')[1]

            if app_conf_dict.get('CONTROLLER'):
                controller = app_conf_dict.get('CONTROLLER').split('=')[1]
                if controller == '0':
                    rc_dict['controller_active'] = False
                else:
                    rc_dict['bind_profile'] = app_bind_profile

            t = Thread(target=echo_func_name, args=(func_name,))
            t.start()

            winedevice = []
            thread_check_winedevice = Thread(target=check_winedevice, args=[winedevice])
            thread_check_winedevice.start()

            app_path = get_app_path()
            s_time = time()
            parent.set_hide_on_close(True)

            GLib.timeout_add(
                            1000, check_alive, thread_check_winedevice,
                            parent_back, (app_path, s_time), None)

        wine_ver = wine.replace('-amd64', '').replace('-x86_64', '')
        wine_ver = ''.join([e for e in wine_ver if not e.isalpha()]).strip('-')
        name_ver = None

        try:
            func_wine = wine_download_dict[wine]
        except KeyError:
            text_message = [f'{wine} ' + msg.msg_dict['is_not_installed'], '']
            SwDialogQuestion(swgs, f'{sw_program_name} Info', text_message, [msg.msg_dict['cancel'], ], [on_stop, ])
        else:
            if func_wine == 'WINE_1':
                name_ver = 'STAG_VER'

            if func_wine == 'WINE_2':
                name_ver = 'SP_VER'

            if func_wine == 'WINE_3':
                name_ver = 'GE_VER'

            if func_wine == 'WINE_4':
                name_ver = 'STAG_VER'

            if name_ver is not None:
                func_name = f'{name_ver}="{wine_ver}" WINE_OK=1 {func_wine} && RUN_VULKAN'
                text_message = [f"{wine} {msg.msg_dict['wine_not_exists']}", '']
                func = [on_thread_wine, on_stop]
                SwDialogQuestion(swgs, None, text_message, None, func)
            else:
                message = msg.msg_dict['wine_not_found']
                SwCrier(text_message=message, message_type='ERROR').run()
                return on_stop()

    def create_shortcut_from_lnk():
        """___try to create shortcut from lnk after setup___"""
        

    def parent_back(app_path, s_time):
        """___restore the menu after exiting a running application___"""

        rc_dict['controller_active'] = True
        rc_dict['bind_profile'] = default_gui_bind_profile

        if swgs.cfg['auto_stop'] == 'on':
            print('stop')
            on_stop()

        if swgs.cfg['restore_menu'] == 'on':
            parent.set_visible(True)
            parent.set_hide_on_close(False)

        time_in = round(time() - s_time, 2)
        stat_name = (
            app_path.strip('"').replace(' ', '_').replace('/', '_').replace('.', '_')
        )
        app_name = get_out()
        stat_path = f'{sw_fm_cache_stats}/{stat_name}'
        fps_in = read_overlay_output(app_name)

        if not Path(stat_path).exists():
            open(stat_path, 'w').close()

        write_app_stat(stat_path, 'Time', time_in)
        print(f'{tc.VIOLET2}TIME_IN_THE_APP: {tc.GREEN}{time_in}{tc.END}')

        if fps_in is not None:
            write_app_stat(stat_path, 'Fps', fps_in)
            print(f'{tc.VIOLET2}AVERAGE_FPS: {tc.GREEN}{fps_in}{tc.END}')

        if main_stack.get_visible_child_name() == 'startapp_page':
            total_time = read_app_stat(stat_path, 'Time')
            str_time = f'{msg.msg_dict["total_time"]}: {total_time}'
            swgs.label_time.set_label(str_time)

            total_fps = read_app_stat(stat_path, 'Fps')
            str_fps = f'{msg.msg_dict["avg_fps"]}: {total_fps}'
            swgs.label_fps.set_label(str_fps)

    def check_winedevice(winedevice):
        """___Check winedevice process___"""

        found = None
        while found is None:
            winedevice = (
                [
                    p.info['name'] for p in psutil.process_iter(['pid', 'name'])
                    if 'winedevice' in p.info['name']
                ]
            )
            if len(winedevice) == 0:
                sleep(1)
            else:
                found = 1
        else:
            while len(winedevice) != 0:
                winedevice = (
                    [
                        p.info['name'] for p in psutil.process_iter(['pid', 'name'])
                        if 'winedevice' in p.info['name']
                    ]
                )
                print(winedevice)
                sleep(3)

    def cb_btn_start(_self):
        """___run application in vulkan or opengl mode___"""

        return on_start()

    def on_start():
        """___Running application in vulkan or opengl mode___"""

        app_path = get_app_path()
        app_name = get_out()
        app_suffix = get_suffix()

        if app_name == 'StartWine':
            text_message = str_oops
            return overlay_info(main_overlay, None, text_message, None, None, 3)
        else:
            def run_(q):
                """___Running the executable in vulkan or opengl mode___"""

                if len(q) > 0:
                    try:
                        vulkan_dri = q[0]
                    except (Exception,):
                        vulkan_dri = None
                    else:
                        if vulkan_dri == '' or vulkan_dri == 'llvmpipe':
                            vulkan_dri = None
                    try:
                        vulkan_dri2 = q[1]
                    except (Exception,):
                        vulkan_dri2 = None
                    else:
                        if vulkan_dri2 == '' or vulkan_dri2 == 'llvmpipe':
                            vulkan_dri2 = None
                else:
                    vulkan_dri = None
                    vulkan_dri2 = None

                app_path = get_app_path()
                app_name = get_out()
                app_suffix = get_suffix()

                app_conf = Path(f"{sw_app_config}/" + str(app_name))
                app_conf_dict = app_conf_info(app_conf, switch_labels)
                debug = app_conf_dict['WINEDBG_DISABLE'].split('=')[1]

                if app_conf_dict.get('CONTROLLER'):
                    controller = app_conf_dict.get('CONTROLLER').split('=')[1]
                    if controller == '0':
                        rc_dict['controller_active'] = False
                    else:
                        rc_dict['bind_profile'] = app_bind_profile

                if vulkan_dri is None and vulkan_dri2 is None:
                    if debug is None or debug == '1':
                        thread_start = Thread(target=run_opengl)
                        thread_start.start()
                    else:
                        thread_start = Thread(target=debug_opengl)
                        thread_start.start()
                else:
                    if debug is None or debug == '1':
                        thread_start = Thread(target=run_vulkan)
                        thread_start.start()
                    else:
                        thread_start = Thread(target=debug_vulkan)
                        thread_start.start()

                t_info = GLib.timeout_add(100, wait_exe_proc, progress_main, app_suffix)
                timeout_list.append(t_info)

                winedevice = []
                thread_check_winedevice = Thread(target=check_winedevice, args=[winedevice])
                thread_check_winedevice.start()

                s_time = time()
                GLib.timeout_add(100, check_alive, thread_check_winedevice, parent_back, (app_path, s_time), None)

            def wait_exe_proc(bar, app_suffix):
                """___Waiting for the executing process to close the menu___"""

                environ['FRAGMENT_NUM'] = f'{len(fragments_list) - 1}'
                found = find_process(app_suffix)
                if found:
                    bar.set_show_text(False)
                    bar.set_fraction(0.0)
                    bar.set_visible(False)
                    parent.close()
                    if getenv('FRAGMENT_INDEX') is not None:
                        environ['FRAGMENT_NUM'] = str(getenv('FRAGMENT_INDEX'))
                    return False

                stack_progress_main.set_visible_child(progress_main_grid)
                bar.set_visible(True)
                bar.set_show_text(True)
                bar.set_text(progress_dict['app_loading'])
                bar.pulse()
                return True

            wine, exist = check_wine()
            if not exist:
                request_wine(wine)
                t_info = GLib.timeout_add(100, wait_exe_proc, progress_main, app_suffix)
                timeout_list.append(t_info)
            else:
                q = []
                t = Thread(target=vulkan_info, args=(q,))
                t.start()
                f = run_
                t_info = GLib.timeout_add(100, check_alive, t, f, q, parent)
                timeout_list.append(t_info)

    def write_changed_wine(changed_wine):
        """___write changed wine to application config___"""

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/{app_name}")
        app_conf_dict = app_conf_info(app_conf, ['SW_USE_WINE'])

        try:
            app_conf.write_text(
                app_conf.read_text().replace(
                    app_conf_dict['SW_USE_WINE'],
                    f'export SW_USE_WINE="{changed_wine}"'
                )
            )
        except IOError as e:
            print(f'{e}')

    def on_cs_wine(app_name, app_path, func_wine):

        exe_data.set_(app_name, 'path', app_path)

        if not check_exe_logo(app_name):
            swgs.mp_event = mp.Event()
            p = mp.Process(target=get_exe_metadata, args=(app_name, app_path, swgs.mp_event))
            data = {'func': update_exe_data, 'args': (app_name,)}
            Thread(target=process_event_wait, args=(swgs.mp_event, data)).start()
            process_workers.append(p)
            p.start()

        t = Thread(target=cs_wine, args=(func_wine, app_name, app_path))
        t.start()
        progress_main.set_name('create_shortcut')
        GLib.timeout_add(100, progress_on_thread, progress_main, t, None)

    def cb_factory_wine_custom_setup(_self, item_list):

        image_custom_wine = Gtk.Image(css_name='sw_image')
        label_custom_wine = Gtk.Label(
                                    css_name='sw_label_view',
                                    margin_top=8,
                                    margin_bottom=8,
        )
        box_custom_wine = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        box_custom_wine.set_spacing(8)
        box_custom_wine.append(image_custom_wine)
        box_custom_wine.append(label_custom_wine)

        item_list.set_child(box_custom_wine)

    def cb_factory_wine_custom_bind(_self, item_list):

        item = item_list.get_item()
        box = item_list.get_child()

        image = box.get_first_child()
        label = image.get_next_sibling()

        image.set_from_file(IconPath.icon_wine)
        label.set_label(item.get_label())
        label.set_name(item.get_name())

    def update_wine_custom_store():

        swgs.list_store_wine_custom.remove_all()
        wineloader_list = []

        def check_wine_path(wineloader_list):

            for r, d, f in walk(sw_wine):
                for w in f:
                    if w == 'wine':
                        wineloader_list.append(f'{r}/{w}')
                        break
            else:
                for w in wine_list:
                    wine_dir = latest_wine_dict[w]
                    try:
                        wineloader_list.remove(f'{sw_wine}/{wine_dir}/files/bin/wine')
                    except (Exception,):
                        pass
                    try:
                        wineloader_list.remove(f'{sw_wine}/{wine_dir}/bin/wine')
                    except (Exception,):
                        pass

        def update_wine_path(wineloader_list):

            if len(wineloader_list) > 0:
                for wine in wineloader_list:
                    wine_name = (
                                str(Path(wine).parent.parent)
                                .replace(f'{sw_wine}/', '')
                                .replace('/files', '')
                                .replace('/dist', '')
                    )
                    cw_name = str(Path(wine).parent.parent).replace(f'{sw_wine}/', '')
                    label = Gtk.Label(label=wine_name, name=Path(cw_name))
                    swgs.list_store_wine_custom.append(label)

        t = Thread(target=check_wine_path, args=[wineloader_list])
        t.start()
        GLib.timeout_add(25, check_alive, t, update_wine_path, wineloader_list, None)

    def cb_btn_menu_wine_custom(_self):
        """___show pop up wine custom menu___"""

        swgs.scrolled_wine_custom.set_max_content_height(parent.get_height() / 2)
        update_wine_custom_store()
        swgs.popover_wines.popup()

    def on_change_pfx_setup(_self, item_list):
        """___setup change wine items___"""

        label = Gtk.Label(css_name='sw_label_desc')
        label.set_xalign(0)
        item_list.set_child(label)

    def on_change_pfx_bind(_self, item_list):
        """___bind change wine items___"""

        item = item_list.get_item()
        label = item_list.get_child()
        label.set_label(item.get_string())

    def on_change_pfx_activate(self, _gparam):
        """___activate changed wine___"""

        str_pfx = self.get_selected_item().get_string()

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/{app_name}")
        app_conf_dict = app_conf_info(app_conf, ['SW_USE_PFX'])

        if str_pfx == prefix_labels[0]:
            changed_pfx = f'export SW_USE_PFX="pfx_default"'
        else:
            changed_pfx = f'export SW_USE_PFX="pfx_{app_name}"'

        try:
            app_conf.write_text(
                app_conf.read_text().replace(
                    app_conf_dict['SW_USE_PFX'],
                    changed_pfx
                )
            )
        except IOError as e:
            print(f'{e}')

    def set_selected_prefix():

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_dict = app_conf_info(app_conf, ['SW_USE_PFX'])

        if '="pfx_default"' not in app_conf_dict.get(swgs.dropdown_change_pfx.get_name()):
            swgs.dropdown_change_pfx.set_selected(1)
        else:
            swgs.dropdown_change_pfx.set_selected(0)

    def cb_btn_prefix_tools(self):
        """___prefix tools buttons signal handler___"""

        if self.get_name() == prefix_tools_dict['pfx_remove']:
            cb_btn_pfx_remove()

        elif self.get_name() == prefix_tools_dict['pfx_clear']:
            cb_btn_pfx_clear()

        elif self.get_name() == prefix_tools_dict['pfx_reinstall']:
            cb_btn_pfx_reinstall()

        elif self.get_name() == prefix_tools_dict['pfx_backup']:
            cb_btn_pfx_backup()

        elif self.get_name() == prefix_tools_dict['pfx_restore']:
            cb_btn_pfx_restore()

        elif self.get_name() == prefix_tools_dict['saves_backup']:
            cb_btn_app_saves_backup()

        elif self.get_name() == prefix_tools_dict['saves_restore']:
            cb_btn_app_saves_restore()

    def cb_btn_pfx_remove():
        """___remove current prefix___"""

        text_message = [msg.msg_dict['remove_pfx'], '']
        func = [run_pfx_remove, None]
        SwDialogQuestion(swgs, None, text_message, None, func)

    def run_pfx_remove():
        """___remove current prefix___"""

        exe_data.set_(get_out(), 'path', None)

        bar = progress_main
        bar.set_name('pfx_remove')
        t = Thread(target=on_pfx_remove)
        t.start()
        timeout_info = GLib.timeout_add(100, progress_on_thread, bar, t, None)
        timeout_list.append(timeout_info)

    def on_pfx_remove():
        """___remove current prefix___"""

        func_name = f"REMOVE_PFX"
        echo_func_name(func_name)

    def cb_btn_pfx_clear():
        """___clear current prefix___"""

        bar = progress_main
        bar.set_name('pfx_clear')
        t = Thread(target=on_pfx_clear)
        t.start()
        timeout_info = GLib.timeout_add(100, progress_on_thread, bar, t, None)
        timeout_list.append(timeout_info)

    def on_pfx_clear():
        """___clear current prefix___"""

        func_name = f"SW_CLEAR_PFX"
        echo_func_name(func_name)

    def cb_btn_pfx_reinstall():
        """___reinstall current prefix___"""

        bar = progress_main
        bar.set_name('pfx_reinstall')
        t = Thread(target=on_pfx_reinstall)
        t.start()
        timeout_info = GLib.timeout_add(100, progress_on_thread, bar, t, None)
        timeout_list.append(timeout_info)

    def on_pfx_reinstall():
        """___reinstall current prefix___"""

        func_name = f"REINSTALL_PFX"
        echo_func_name(func_name)

    def cb_btn_pfx_backup():
        """___backup current prefix___"""

        bar = progress_main
        bar.set_name('pfx_backup')

        t = Thread(target=on_pfx_backup)
        t.start()
        timeout_info = GLib.timeout_add(100, progress_on_thread, bar, t, None)
        timeout_list.append(timeout_info)

    def on_pfx_backup():
        """___backup current prefix___"""

        func_name = f"SW_PFX_BACKUP"
        echo_func_name(func_name)

    def cb_btn_pfx_restore():
        """___restore current prefix___"""

        bar = progress_main
        bar.set_name('pfx_restore')
        t = Thread(target=on_pfx_restore)
        t.start()
        timeout_info = GLib.timeout_add(100, progress_on_thread, bar, t, None)
        timeout_list.append(timeout_info)

    def on_pfx_restore():
        """___restore current prefix___"""

        func_name = f"SW_PFX_RESTORE"
        echo_func_name(func_name)

    def cb_btn_app_saves_backup():
        """___backup of app saves___"""

        bar = progress_main
        bar.set_name('app_saves_backup')
        t = Thread(target=on_app_saves_backup)
        t.start()
        timeout_info = GLib.timeout_add(100, progress_on_thread, bar, t, None)
        timeout_list.append(timeout_info)

    def on_app_saves_backup():
        """___backup of app saves___"""

        func_name = f"SW_APP_SAVES_BACKUP"
        echo_func_name(func_name)

    def cb_btn_app_saves_restore():
        """___restoring saves from backup___"""

        bar = progress_main
        bar.set_name('app_saves_restore')

        t = Thread(target=on_app_saves_restore)
        t.start()
        timeout_info = GLib.timeout_add(100, progress_on_thread, bar, t, None)
        timeout_list.append(timeout_info)

    def on_app_saves_restore():
        """___restoring saves from backup___"""

        func_name = f"SW_APP_SAVES_RESTORE"
        echo_func_name(func_name)

    def on_change_wine_setup(_self, item_list):
        """___setup change wine items___"""

        label = Gtk.Label(
                        css_name='sw_label_desc',
                        ellipsize=Pango.EllipsizeMode.END,
                        xalign=0,
        )
        item_list.set_child(label)

    def on_change_wine_bind(_self, item_list):
        """___bind change wine items___"""

        item = item_list.get_item()
        label = item_list.get_child()
        label.set_name(item.get_name())
        label.set_label(item.get_label())

    def update_wine_store():
        """___udate wine list in dropdown model___"""

        winever_data, latest_wine_dict, wine_download_dict = get_wine_dicts()
        swgs.wine_store.remove_all()

        def set_wineloader_list(wineloader_list):

            for w in wine_list:
                wine_dir = latest_wine_dict[w]
                if wine_dir is not None:
                    label = Gtk.Label(label=wine_dir, name=f'{wine_dir}')
                    swgs.wine_store.append(label)

            if len(wineloader_list) > 0:
                for wine in wineloader_list:
                    wine_name = (
                                str(Path(wine).parent.parent)
                                .replace(f'{sw_wine}/', '')
                                .replace('/files', '')
                                .replace('/dist', '')
                    )
                    label = Gtk.Label(label=wine_name, name=Path(wine_name))
                    swgs.wine_store.append(label)

            set_selected_wine()

        def get_wineloader_list(wineloader_list):

            for r, d, f in walk(sw_wine):
                for w in f:
                    if w == 'wine':
                        wineloader_list.append(f'{r}/{w}')
                        break
            else:
                for w in wine_list:
                    wine_dir = latest_wine_dict[w]
                    try:
                        wineloader_list.remove(f'{sw_wine}/{wine_dir}/files/bin/wine')
                    except (Exception,):
                        pass
                    try:
                        wineloader_list.remove(f'{sw_wine}/{wine_dir}/bin/wine')
                    except (Exception,):
                        pass

        wineloader_list = []
        t = Thread(target=get_wineloader_list, args=(wineloader_list,))
        t.start()
        GLib.timeout_add(25, check_alive, t, set_wineloader_list, wineloader_list, None)

    def cb_change_wine_activate(self, position):
        """___activate changed wine___"""

        if self.get_model().get_item(position) is not None:
            item = self.get_model().get_item(position).get_name()

            try:
                changed_wine = wine_list_dict[item]
            except (Exception,):
                changed_wine = item

            write_changed_wine(changed_wine)

    def set_selected_wine():

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_dict = app_conf_info(app_conf, ['SW_USE_WINE'])
        exported_wine = None
        if app_conf_dict.get('SW_USE_WINE'):
            exported_wine = app_conf_dict.get('SW_USE_WINE').split('=')[-1]

        for n, x in enumerate(swgs.wine_store):
            if f'="{x.get_name()}"' == f'={exported_wine}':
                swgs.dropdown_change_wine.set_selected(n)
                print(f'{tc.VIOLET2}SELECTED_WINE: {tc.GREEN}{x.get_name()}{tc.END}')

    def cb_btn_wine_tools(self):
        """___wine tools buttons signal handler___"""

        if self.get_name() == wine_tools_dict['wine_settings']:
            return cb_btn_winecfg()

        elif self.get_name() == wine_tools_dict['wine_console']:
            return cb_btn_wineconsole()

        elif self.get_name() == wine_tools_dict['regedit']:
            return cb_btn_regedit()

        elif self.get_name() == wine_tools_dict['file_explorer']:
            return cb_btn_file_explorer()

        elif self.get_name() == wine_tools_dict['uninstaller']:
            return cb_btn_uninstaller()

        elif self.get_name() == wine_tools_dict['winetricks']:
            return cb_btn_winetricks()

        elif self.get_name() == wine_tools_dict['clear_shader_cache']:
            return cb_btn_clear_shader_cache()

    def cb_btn_winecfg():
        """___run wine settings___"""

        bar = progress_main
        bar.set_name('winecfg')

        thread = Thread(target=on_winecfg)
        thread.start()
        GLib.timeout_add(100, progress_on_thread, bar, thread, None)

    def on_winecfg():
        """___run wine settings___"""

        func_name = f"WINECFG"
        echo_func_name(func_name)

    def cb_btn_wineconsole():
        """___run wine console___"""

        bar = progress_main
        bar.set_name('wineconsole')
        thread = Thread(target=on_wineconsole)
        thread.start()
        GLib.timeout_add(100, progress_on_thread, bar, thread, None)

    def on_wineconsole():
        """___run wine console___"""

        func_name = f"WINECONSOLE"
        echo_func_name(func_name)

    def cb_btn_regedit():
        """___run wine regedit___"""

        bar = progress_main
        bar.set_name('regedit')
        thread = Thread(target=on_regedit)
        thread.start()
        GLib.timeout_add(100, progress_on_thread, bar, thread, None)

    def on_regedit():
        """___run wine regedit___"""

        func_name = f"REGEDIT"
        echo_func_name(func_name)

    def cb_btn_file_explorer():
        """___run wine file explorer___"""

        bar = progress_main
        bar.set_name('winefile')

        thread = Thread(target=on_explorer)
        thread.start()
        GLib.timeout_add(100, progress_on_thread, bar, thread, None)

    def on_explorer():
        """___run wine file explorer___"""

        func_name = f"WINEFILE"
        echo_func_name(func_name)

    def cb_btn_uninstaller():
        """___run wine uninstaller___"""

        bar = progress_main
        bar.set_name('uninstaller')
        thread = Thread(target=on_uninstaller)
        thread.start()
        GLib.timeout_add(100, progress_on_thread, bar, thread, None)

    def on_uninstaller():
        """___run wine uninstaller___"""

        func_name = f"UNINSTALLER"
        echo_func_name(func_name)

    def cb_btn_winetricks():
        """___show winetricks list view___"""

        return on_winetricks()

    def on_winetricks():
        """___show winetricks list___"""

        if main_stack.get_visible_child() == scrolled_winetricks:
            pass
        else:
            add_winetricks_view()
            update_dll_store()

            pfx_label = get_pfx_name()[1]
            swgs.winetricks_title.set_label(vl_dict['winetricks'] + f' ({pfx_label})')

            on_show_hidden_widgets(vw_dict['winetricks'])

            main_stack.set_visible_child(scrolled_winetricks)
            swgs.scrolled_dll.set_min_content_width(mon_width*0.2)
            swgs.scrolled_fonts.set_min_content_width(mon_width*0.2)

            update_color_scheme()

    def on_tab_dll(_self):
        swgs.stack_tabs.set_visible_child(swgs.scrolled_dll)

    def on_tab_fonts(_self):
        swgs.stack_tabs.set_visible_child(swgs.scrolled_fonts)

    def on_dll_toggled(self, label, pic):
        """___check_dll_list_on_toggle_button___"""

        if self.get_sensitive():
            if self.get_active():
                self.set_child(pic)
                pic.set_filename(IconPath.icon_checked)
                install_dll_list.append(label.get_label())
            else:
                pic.set_filename(None)
                install_dll_list.remove(label.get_label())

        elif not self.get_sensitive():
            install_dll_list.remove(label.get_label())

    def on_fonts_toggled(self, label, pic):
        """___check_fonts_list_on_toggle_button___"""

        if self.get_sensitive():
            if self.get_active():
                pic.set_filename(IconPath.icon_checked)
                install_dll_list.append(label.get_label())
            else:
                pic.set_filename(None)
                install_dll_list.remove(label.get_label())

        elif not self.get_sensitive():
            install_dll_list.remove(label.get_label())

    def cb_btn_install_dll(_self):
        """___install changed dll from winetricks list___"""

        bar = progress_main
        bar.set_name('install_dll')
        changed_dll = list(dict.fromkeys(install_dll_list))
        sample_dll = swgs.dropdown_dll_templates.get_selected_item().get_name().split(' ')

        w_log = get_dll_info(get_pfx_path())
        for w in w_log:
            for s in sample_dll:
                if s == w:
                    sample_dll.remove(s)
        else:
            dll_list = set(sample_dll + changed_dll)

        if ' '.join(dll_list) == '':
            text_message = msg.msg_dict['no_dll']
            return overlay_info(main_overlay, None, text_message, None, None, 3)
        else:
            t = Thread(target=install_dll, args=[dll_list])
            t.start()
            GLib.timeout_add(100, progress_on_thread, bar, t, None)

    def install_dll(dll_list):
        """___install changed dll from winetricks list___"""

        app_path = get_app_path()
        func_name = f"SW_WINETRICKS \"$@\""
        export_dll = f"export DLL=\"{' '.join(dll_list)}\""
        print(f'{tc.VIOLET2}setup_list: {tc.GREEN}{" ".join(dll_list)}{tc.END}')
        count = 1
        try:
            for _line in fshread:
                count += 1
                sw_fsh.write_text(sw_fsh.read_text().replace(fshread[count], ''))

        except IndexError:
            sw_fsh.write_text(
                fshread[0] + '\n' + fshread[1] + '\n' + export_dll + '\n' + func_name
            )
            run(f"{sw_fsh} {app_path}", shell=True)
            install_dll_list.clear()

    def on_download_wine():
        """___show wine download list___"""

        btn_back_main.set_visible(True)

        if scrolled_install_wine.get_child() is not None:
            if main_stack.get_visible_child_name() != vw_dict['install_wine']:
                set_settings_widget(main_stack, vw_dict['install_wine'], None)
                update_wine_view()
            else:
                activate_install_wine_settings()
                update_wine_view()
        else:
            add_wine_view()
            update_wine_view()
            activate_install_wine_settings()

    def cb_btn_update_wine_view(_self):
        """___Check and update wine list from sources___"""
        return on_update_wine_view()

    def on_update_wine_view():
        """___Check and update wine list from sources___"""

        t = Thread(target=echo_func_name, args=('try_get_wine_ver',))
        t.start()
        progress_main.set_name('install_wine')
        timeout_info = GLib.timeout_add(100, progress_on_thread, progress_main, t, None)
        timeout_list.append(timeout_info)

    def update_wine_view():

        winever_data, latest_wine_dict, wine_download_dict = get_wine_dicts()
        for wine, dropdown in zip(wine_list, dropdown_download_wine_list):
            download_wine_model = dropdown.get_model()
            download_wine_model.remove_all()

            if winever_data is not None:
                for x in winever_data[wine].split(' '):
                    if x != '':
                        wine_dir = Gtk.StringObject.new(str(Path(Path(x).stem).stem))
                        wine_dir_list.append(Path(Path(x).stem).stem)
                        download_wine_model.append(wine_dir)

    def cb_factory_dropdown_wine_setup(_self, item_list):

        label = Gtk.Label(css_name='sw_label_desc', xalign=0)
        item_list.set_child(label)

    def cb_factory_dropdown_wine_bind(_self, item_list):

        item = item_list.get_item()
        label = item_list.get_child()
        label.set_label(item.get_string())
        label.set_name(item.get_string())

    def cb_dropdown_download_wine(_self, _position):
        """___dropdown changed wine version to download___"""

        return activate_install_wine_settings()

    def cb_btn_download_wine(self, dropdown):
        """___download changed wine___"""

        bar = progress_main
        bar.set_name('install_wine')
        wine_ver = dropdown.get_selected_item().get_string()
        wine_ver = wine_ver.replace('-amd64', '').replace('-x86_64', '')
        wine_ver = ''.join([e for e in wine_ver if not e.isalpha()]).strip('-')

        if self.get_name() == 'WINE_1':
            t = Thread(target=cb_btn_wine_1, args=[wine_ver])
            t.start()
            GLib.timeout_add(100, progress_on_thread, bar, t, None)
            self.get_parent().set_visible_child_name('RM_WINE_1')

        elif self.get_name() == 'WINE_2':
            t = Thread(target=cb_btn_wine_2, args=[wine_ver])
            t.start()
            GLib.timeout_add(100, progress_on_thread, bar, t, None)

        elif self.get_name() == 'WINE_3':
            t = Thread(target=cb_btn_wine_3, args=[wine_ver])
            t.start()
            GLib.timeout_add(100, progress_on_thread, bar, t, None)

        elif self.get_name() == 'WINE_4':
            t = Thread(target=cb_btn_wine_4, args=[wine_ver])
            t.start()
            GLib.timeout_add(100, progress_on_thread, bar, t, None)

    def cb_btn_remove_wine(self, dropdown):
        """___remove changed wine___"""

        bar = progress_main
        bar.set_name('install_wine')
        wine_ver = dropdown.get_selected_item().get_string()
        wine_ver = wine_ver.replace('-amd64', '').replace('-x86_64', '')
        wine_ver = ''.join([e for e in wine_ver if not e.isalpha()]).strip('-')

        if self.get_name() == 'RM_WINE_1':
            t = Thread(target=cb_btn_rm_wine_1, args=[wine_ver])
            t.start()
            GLib.timeout_add(100, progress_on_thread, bar, t, None)

        elif self.get_name() == 'RM_WINE_2':
            t = Thread(target=cb_btn_rm_wine_2, args=[wine_ver])
            t.start()
            GLib.timeout_add(100, progress_on_thread, bar, t, None)

        elif self.get_name() == 'RM_WINE_3':
            t = Thread(target=cb_btn_rm_wine_3, args=[wine_ver])
            t.start()
            GLib.timeout_add(100, progress_on_thread, bar, t, None)

        elif self.get_name() == 'RM_WINE_4':
            t = Thread(target=cb_btn_rm_wine_4, args=[wine_ver])
            t.start()
            GLib.timeout_add(100, progress_on_thread, bar, t, None)

    def cb_btn_wine_1(wine_ver):

        name_ver = "STAG_VER"
        wine_name = f"WINE_1"
        echo_wine(wine_name, name_ver, wine_ver)

    def cb_btn_rm_wine_1(wine_ver):

        name_ver = "STAG_VER"
        wine_name = f"RM_WINE_1"
        echo_wine(wine_name, name_ver, wine_ver)

    def cb_btn_wine_2(wine_ver):

        name_ver = "SP_VER"
        wine_name = f"WINE_2"
        echo_wine(wine_name, name_ver, wine_ver)

    def cb_btn_rm_wine_2(wine_ver):

        name_ver = "SP_VER"
        wine_name = f"RM_WINE_2"
        echo_wine(wine_name, name_ver, wine_ver)

    def cb_btn_wine_3(wine_ver):

        name_ver = "GE_VER"
        wine_name = f"WINE_3"
        echo_wine(wine_name, name_ver, wine_ver)

    def cb_btn_rm_wine_3(wine_ver):

        name_ver = "GE_VER"
        wine_name = f"RM_WINE_3"
        echo_wine(wine_name, name_ver, wine_ver)

    def cb_btn_wine_4(wine_ver):

        name_ver = "STAG_VER"
        wine_name = f"WINE_4"
        echo_wine(wine_name, name_ver, wine_ver)

    def cb_btn_rm_wine_4(wine_ver):

        name_ver = "STAG_VER"
        wine_name = f"RM_WINE_4"
        echo_wine(wine_name, name_ver, wine_ver)

    def cb_btn_source_wine(self):

        if self.get_name() == 'wine_staging':
            self.set_uri(wine_source_dict['wine_staging'])

        if self.get_name() == 'wine_steam_proton':
            self.set_uri(wine_source_dict['wine_steam_proton'])

        if self.get_name() == 'wine_proton_ge':
            self.set_uri(wine_source_dict['wine_proton_ge'])

        if self.get_name() == 'wine_staging_tkg':
            self.set_uri(wine_source_dict['wine_staging_tkg'])

    def on_install_launchers():
        """___show launchers grid view___"""

        btn_back_main.set_visible(True)

        if scrolled_install_launchers.get_child() is not None:
            if main_stack.get_visible_child_name() != vw_dict['install_launchers']:
                return set_settings_widget(main_stack, vw_dict['install_launchers'], None)
            else:
                activate_install_launchers_settings()
        else:
            add_install_launchers_view()
            activate_install_launchers_settings()

    def cb_btn_install_launchers(self):
        """___run install launchers function___"""

        self.remove_css_class('install')
        self.add_css_class('installing')
        bar = progress_main
        bar.set_name('install_launchers')
        bar.set_show_text(True)
        bar.set_text(f"{self.get_name()} {progress_dict['installation']}")
        t = Thread(target=run_install_launchers, args=[self.get_name()])
        t.start()
        GLib.timeout_add(100, progress_on_thread, bar, t, None)
        GLib.timeout_add(100, check_alive, t, update_exe_data, (self.get_name(),), None)

    def run_install_launchers(x_name):
        """___run install launchers function___"""

        launcher_name = str(x_name).upper()
        func = f'INSTALL_{launcher_name}'
        echo_func_name(func)

    def cb_btn_settings(self):
        """___show settings submenu___"""

        if self.get_name() == settings_dict['launch_settings']:
            return on_launch_settings()

        if self.get_name() == settings_dict['mangohud_settings']:
            return on_mangohud_settings()

        if self.get_name() == settings_dict['vkbasalt_settings']:
            return on_vkbasalt_settings()

        if self.get_name() == settings_dict['set_app_default']:
            return cb_btn_app_conf_default()

        if self.get_name() == settings_dict['clear_shader_cache']:
            return cb_btn_clear_shader_cache()

    def set_settings_widget(stack, view_widget, title):
        """___activate settings submenu___"""

        app_name = get_out()

        try:
            on_app_conf_activate(view_widget)
        except Exception as e:
            print(e)
            if stack.get_visible_child().get_name() == 'launch_settings':
                text_message = [
                                msg.msg_dict['app_conf_incorrect'] + f' {app_name}.',
                                msg.msg_dict['app_conf_reset']
                ]
                func = [{app_conf_reset_request: (stack, view_widget, title)}, None]
                SwDialogQuestion(swgs, None, text_message, None, func)
        else:
            set_settings_page(stack, view_widget, title)

    def app_conf_reset_request(stack, view_widget, title):
        """___Request for reset application settings___"""

        on_app_conf_default()
        set_settings_page(stack, view_widget, title)

    def set_settings_page(stack, view_widget, title):
        """___show settings submenu___"""

        app_name = get_out()
        on_show_hidden_widgets(view_widget)
        widget = stack.get_child_by_name(view_widget)

        if title is not None:
            if app_name == 'StartWine':
                title.set_label(
                                vl_dict[view_widget]
                                + f' (StartWine)'
                )
            else:
                title.set_label(
                                vl_dict[view_widget]
                                + f' ({app_name})'
                )

        if not widget.is_visible():
            widget.set_visible(True)

        visible_name = str(stack.get_visible_child().get_name())

        if visible_name in view_widgets and visible_name != view_widget:
            if stack == stack_settings:
                stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
            else:
                stack.set_transition_type(Gtk.StackTransitionType.ROTATE_LEFT)

            stack.set_visible_child(widget)
            if type(widget) == Gtk.ScrolledWindow:
                widget.set_min_content_width(mon_width*0.2)

        update_color_scheme()

    def on_app_conf_default():
        """___reset application config to default___"""

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        launcher_conf = Path(f"{sw_app_config}/.default/" + str(app_name))

        if not launcher_conf.exists():
            try:
                app_conf.write_text(sw_default_config.read_text())
            except IOError:
                print('<< app_conf_not_found >>')
            else:
                on_app_conf_activate(vw_dict['launch_settings'])
                on_app_conf_activate(vw_dict['mangohud_settings'])
                on_app_conf_activate(vw_dict['vkbasalt_settings'])
                set_selected_wine()
                set_selected_prefix()
        else:
            try:
                app_conf.write_text(launcher_conf.read_text())
            except IOError:
                print('<< app_conf_not_found >>')
            else:
                on_app_conf_activate(vw_dict['launch_settings'])
                on_app_conf_activate(vw_dict['mangohud_settings'])
                on_app_conf_activate(vw_dict['vkbasalt_settings'])
                set_selected_wine()
                set_selected_prefix()

    def cb_btn_app_conf_default():
        """___request reset apllication config to default___"""

        text_message = [msg.msg_dict['reset_settings'], '']
        func = [on_app_conf_default, None]
        SwDialogQuestion(swgs, None, text_message, None, func)

    def cb_btn_menu_json_default(_self):
        """___request reset menu config to default___"""

        text_message = [msg.msg_dict['reset_settings'], '']
        func = [on_menu_conf_default, None]
        SwDialogQuestion(swgs, None, text_message, None, func)

    def on_menu_conf_default():
        """___request reset menu configuration to default___"""

        set_menu_json_default()
        clear_cache_dir()
        check_bookmarks()
        check_playlist()
        check_css_dark()
        check_css_light()
        check_css_custom()
        on_app_conf_activate(vw_dict['global_settings'])
        swgs.cfg = read_menu_conf()
        change_icon_color()
        change_wc_style()
        activate_global_settings()
        set_sw_logo()

    def activate_global_settings():

        swgs.colorscheme = swgs.cfg.get('color_scheme')
        update_color_scheme()
        btn_scale_icons.set_value(int(swgs.cfg.get('icon_size')))
        btn_scale_shortcuts.set_value(int(swgs.cfg.get('shortcut_size')))

        if swgs.cfg.get('autostart') == '1':
            swgs.switch_autostart.set_active(True)
        else:
            swgs.switch_autostart.set_active(False)

        if swgs.cfg.get('opengl_bg') == 'True':
            swgs.switch_opengl.set_active(True)
            swgs.dropdown_shaders.set_sensitive(True)
        else:
            swgs.switch_opengl.set_active(False)
            swgs.dropdown_shaders.set_sensitive(False)

        count = -1
        for lang in lang_labels:
            count += 1
            if swgs.cfg.get('language') in lang:
                swgs.dropdown_lang.set_selected(count)

        if swgs.cfg.get('icons') == 'custom':
            swgs.switch_icons.set_active(True)
        else:
            swgs.switch_icons.set_active(False)

        if swgs.cfg.get('restore_menu') == 'on':
            swgs.switch_restore_menu.set_active(True)
        else:
            swgs.switch_restore_menu.set_active(False)

        if swgs.cfg.get('auto_stop') == 'on':
            swgs.switch_auto_stop.set_active(True)
        else:
            swgs.switch_auto_stop.set_active(False)

        if swgs.cfg.get('auto_hide_top_header') == 'on':
            swgs.switch_auto_hide_top.set_active(True)
        else:
            swgs.switch_auto_hide_top.set_active(False)
            top_headerbar_revealer.set_reveal_child(True)

        if swgs.cfg.get('auto_hide_bottom_header') == 'on':
            swgs.switch_auto_hide_bottom.set_active(True)
        else:
            swgs.switch_auto_hide_bottom.set_active(False)
            bottom_headerbar_revealer.set_reveal_child(True)

        if swgs.cfg.get('renderer') == 'vulkan':
            swgs.switch_vulkan.set_active(True)
        else:
            swgs.switch_vulkan.set_active(False)

        swgs.entry_def_dir.set_placeholder_text(swgs.cfg.get('default_dir'))
        swgs.dropdown_shaders.set_selected(int(swgs.cfg.get('shader_src')))
        parent.set_default_size(int(swgs.cfg.get('width')), int(swgs.cfg.get('height')))

    def cb_btn_clear_shader_cache():
        """___request clear shader cache___"""

        text_message = [msg.msg_dict['clear_shader_cache'], '']
        func = [on_clear_shader_cache, None]
        SwDialogQuestion(swgs, None, text_message, None, func)

    def on_clear_shader_cache():
        """___clear shader cache___"""

        if sw_mesa_shader_cache.exists():
            for cache in sw_mesa_shader_cache.iterdir():
                if cache.is_dir():
                    shutil.rmtree(cache)
                if cache.is_file():
                    cache.unlink()

        if sw_gl_shader_cache.exists():
            for cache in sw_gl_shader_cache.iterdir():
                if cache.is_dir():
                    shutil.rmtree(cache)
                if cache.is_file():
                    cache.unlink()

        if sw_vulkan_shader_cache.exists():
            for cache in sw_vulkan_shader_cache.iterdir():
                if cache.is_dir():
                    shutil.rmtree(cache)
                if cache.is_file():
                    cache.unlink()

        if sw_gst_home_cache.exists():
            for cache in sw_gst_home_cache.iterdir():
                if cache.is_dir():
                    shutil.rmtree(cache)
                if cache.is_file():
                    cache.unlink()

        print(f'{tc.RED}Clear shader cache...')

    def on_launch_settings():
        """___open application settings menu___"""

        if scrolled_launch_settings.get_child() is not None:
            if main_stack.get_visible_child().get_name() != vw_dict['launch_settings']:
                set_settings_widget(
                                    stack_settings,
                                    vw_dict['launch_settings'],
                                    swgs.pref_group_title)
            else:
                pass
        else:
            add_launch_settings_view()

    def cb_btn_ls_move(_self):
        """___Show application configuration chooser window___"""

        data = list()
        app_conf_replace = AppConfReplace(swgs, data)
        app_conf_replace.run()

    def on_app_conf_activate(x_settings):
        """___activate application config in settings menu___"""

        if x_settings == vw_dict['install_wine']:
            activate_install_wine_settings()

        if x_settings == vw_dict['install_launchers']:
            activate_install_launchers_settings()

        if x_settings == vw_dict['launch_settings']:
            activate_launch_settings()

        if x_settings == vw_dict['mangohud_settings']:
            activate_mangohud_settings()
            activate_mangohud_colors_settings()

        if x_settings == vw_dict['vkbasalt_settings']:
            activate_vkbasalt_settings()

        if x_settings == vw_dict['global_settings']:
            activate_global_colors_settings()

    def activate_install_wine_settings():
        """___disable button if launchers is installed___"""

        for b, d in zip(btn_iw_list, dropdown_download_wine_list):
            if b.get_parent() is not None:
                b.get_parent().set_visible_child_name(b.get_name())
        else:
            for wine_dir in wine_dir_list:
                for b, d in zip(btn_iw_list, dropdown_download_wine_list):
                    if b.get_parent() is not None:
                        ver = d.get_selected_item().get_string()
                        if (wine_dir == ver
                                and Path(f'{sw_wine}/{wine_dir}/bin/wine').exists()):
                            b.get_parent().set_visible_child_name(f'RM_{b.get_name()}')
                            break

    def activate_install_launchers_settings():
        """___disable button if launchers is installed___"""

        for b in btn_il_list:
            b.remove_css_class('installed')
            b.add_css_class('install')
            b.get_first_child().get_last_child().set_label(msg.msg_dict['install'])
            b.set_sensitive(True)
        else:
            for s in sw_shortcuts.iterdir():
                s_isallnum = ''.join([e for e in s.stem if e.isalnum()])
                for i in sw_app_hicons.iterdir():
                    i_stem = i.stem.split('_')[0]
                    if s_isallnum == i_stem:
                        for b in btn_il_list:
                            if i.stem.split('_')[-2].replace(' ', '_') == b.get_name():
                                b.remove_css_class('install')
                                b.remove_css_class('installing')
                                b.add_css_class('installed')
                                b.get_first_child().get_last_child().set_label(msg.msg_dict['installed'])
                                b.set_sensitive(False)
                                break

    def activate_launch_settings():
        """___set launch_settings from application config___"""

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        entry_dict = app_conf_info(app_conf, lp_entry_list)
        combo_dict = app_conf_info(app_conf, lp_title)
        switch_dict = app_conf_info(app_conf, switch_labels)
        fps_dict = app_conf_info(app_conf, [export_fps_limit])
        cpu_dict = app_conf_info(app_conf, [export_cpu_topology])

        for e in row_entry_list:
            if f'{e.get_name()}' in entry_dict[e.get_name()]:
                e.set_text(entry_dict[e.get_name()].split('"')[1])

        count = -1
        for arch in winarch:
            count += 1
            for row in row_combo_list:
                if f'="{winarch_dict[arch]}"' in combo_dict[row.get_name()]:
                    row.set_selected(count)

        count = -1
        for ver in winver:
            count += 1
            for row in row_combo_list:
                if f'="{winver_dict[ver]}"' in combo_dict[row.get_name()]:
                    row.set_selected(count)

        count = -1
        for reg in reg_patches:
            count += 1
            for row in row_combo_list:
                if f'="{reg}"' in combo_dict[row.get_name()]:
                    row.set_selected(count)

        count = -1
        for dxvk in dxvk_ver:
            count += 1
            for row in row_combo_list:
                if f'export SW_USE_DXVK_VER="{dxvk}"' in combo_dict[row.get_name()]:
                    row.set_selected(count)

        count = -1
        for vkd3d in vkd3d_ver:
            count += 1
            for row in row_combo_list:
                if f'export SW_USE_VKD3D_VER="{vkd3d}"' in combo_dict[row.get_name()]:
                    row.set_selected(count)

        count = -1
        for mode in fsr_mode.keys():
            count += 1
            for row in row_combo_list:
                if f'="{fsr_mode[mode]}"' in combo_dict[row.get_name()]:
                    row.set_selected(count)

        for s in switch_ls_list:
            if f'{s.get_name()}=1' in switch_dict[s.get_name()]:
                s.set_active(True)
            else:
                s.set_active(False)

        fps_value = float(fps_dict[export_fps_limit].split('=')[1].strip('"'))
        swgs.btn_spin_fps.set_value(fps_value)

        cpu_value = cpu_dict[export_cpu_topology].split('=')[1].strip('"')
        if cpu_value == "":
            cpu_value = 0.0
        else:
            cpu_value = cpu_value.split(':')[0]

        swgs.btn_spin_cpu.set_value(float(cpu_value))

    def activate_mangohud_settings():
        """___set mangohud settings from application config___"""

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_mh_dict = app_conf_info(app_conf, [export_mangohud_config])
        export_string = app_conf_mh_dict[export_mangohud_config]
        export_name = export_string.split('=')[0]
        export_value = export_string.removeprefix(f'{export_name}=').strip('"')

        if export_value != '':
            value_list = export_value.split(',')

            for b in check_btn_mh_list:
                b.set_active(False)
                for v in value_list:
                    if f'{b.get_name()}' == v:
                        b.set_active(True)

    def activate_vkbasalt_settings():
        """___set vkbasalt settings from application config___"""

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_vk_dict = app_conf_info(app_conf, [export_vkbasalt_effects])

        for v in check_btn_vk_list:
            if f'{v.get_name()}' in app_conf_vk_dict[export_vkbasalt_effects]:
                v.set_active(True)
            else:
                v.set_active(False)

    def activate_mangohud_colors_settings():
        """___set mangohud colors settings from application config___"""

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_mh_dict = app_conf_info(app_conf, [export_mangohud_config])

        export_string = app_conf_mh_dict[export_mangohud_config]
        export_name = export_string.split('=')[0]
        export_value = export_string.removeprefix(f'{export_name}=').strip('"')
        value_list = export_value.split(',')

        for c, e in zip(btn_mh_color_list, entry_mh_color_list):
            for x in value_list:
                if c.get_name() == x.split('=')[0]:
                    x_name = x.split('=')[-1]
                    get_hex = str('#' + ''.join(x_name))
                    get_rgba = ImageColor.getrgb(get_hex)
                    mh_rgba = Gdk.RGBA()
                    mh_rgba.red = float([i/256 for i in get_rgba][0])
                    mh_rgba.green = float([i/256 for i in get_rgba][1])
                    mh_rgba.blue = float([i/256 for i in get_rgba][2])
                    mh_rgba.alpha = 1.0
                    c.set_rgba(mh_rgba)
                    e.set_text(mh_rgba.to_string())
                    break
            else:
                for k, v in default_mangohud_colors.items():
                    if c.get_name() == k:
                        hex_value = str('#' + v)
                        get_rgba = ImageColor.getrgb(hex_value)
                        mh_rgba = Gdk.RGBA()
                        mh_rgba.red = float([i/256 for i in get_rgba][0])
                        mh_rgba.green = float([i/256 for i in get_rgba][1])
                        mh_rgba.blue = float([i/256 for i in get_rgba][2])
                        mh_rgba.alpha = 1.0
                        c.set_rgba(mh_rgba)
                        e.set_text(mh_rgba.to_string())
                        break
                else:
                    c.set_rgba(Gdk.RGBA())
                    e.set_text('')

    def activate_global_colors_settings():
        """___set mangohud colors settings from application config___"""

        css_string_list = sw_css_custom.read_text().splitlines()

        for c, e in zip(btn_theme_color_list, entry_theme_color_list):
            for string in css_string_list:
                if c.get_name() in string:
                    get_hex = string.strip(';').replace(c.get_name() + ' ', '')
                    rgba = Gdk.RGBA()

                    if '#' in get_hex:
                        get_rgba = ImageColor.getrgb(get_hex)
                        rgba.red = float([i/256 for i in get_rgba][0])
                        rgba.green = float([i/256 for i in get_rgba][1])
                        rgba.blue = float([i/256 for i in get_rgba][2])
                        rgba.alpha = 1.0
                        e.set_text(get_hex)

                    elif 'rgba' in get_hex:
                        get_rgba = get_hex.removeprefix('rgba')[1:-1].split(',')
                        rgba.red = float(get_rgba[0])/256
                        rgba.green = float(get_rgba[1])/256
                        rgba.blue = float(get_rgba[2])/256
                        rgba.alpha = float(get_rgba[3])
                        e.set_text(rgba.to_string())

                    c.set_rgba(rgba)

    def on_row_entry_icon_press(self, _position):
        """___writing a value from entry widget to the application config
        when user click the edit button___"""

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_dict = app_conf_info(app_conf, [self.get_name()])

        if app_conf_dict.get(self.get_name()):
            app_conf.write_text(
                app_conf.read_text().replace(
                    app_conf_dict[self.get_name()],
                    app_conf_dict[self.get_name()].split('=')[0] + f'="{self.get_text()}"'
                )
            )

    def on_row_entry_enter(self):
        """___writing a value from entry widget to the application config
        when user press the Enter key___"""

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_dict = app_conf_info(app_conf, [self.get_name()])

        if app_conf_dict.get(self.get_name()):
            app_conf.write_text(
                app_conf.read_text().replace(
                    app_conf_dict[self.get_name()],
                    app_conf_dict[self.get_name()].split('=')[0] + f'="{self.get_text()}"'
                )
            )

    def on_launch_flow_activated(_self, child, switch_ls):
        """___activate flowbox child in launch settings___"""

        if switch_ls.get_name() == child.get_name():
            if not switch_ls.get_active():
                switch_ls.set_active(True)
            else:
                switch_ls.set_active(False)

    def on_combo_setup(_self, item_list):
        """___setup item in combobox item list___"""

        label = Gtk.Label(css_name='sw_label_desc')
        label.set_xalign(0)
        item_list.set_child(label)

    def on_combo_bind(_self, item_list):
        """___bind item in combobox item list___"""

        item = item_list.get_item()
        label = item_list.get_child()
        label.set_label(item.get_string())

    def on_row_combo_activate(self, _gparam):
        """___write selected item in application config___"""

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_dict = app_conf_info(app_conf, lp_title)

        i = self.get_selected_item().get_string()
        try:
            v = winver_dict[i]
        except (Exception,):
            pass
        else:
            app_conf.write_text(
                app_conf.read_text().replace(
                    app_conf_dict[self.get_name()],
                    app_conf_dict[self.get_name()].split('=')[0] + f'="{v}"'
                )
            )

        try:
            a = winarch_dict[i]
        except (Exception,):
            pass
        else:
            app_conf.write_text(
                app_conf.read_text().replace(
                    app_conf_dict[self.get_name()],
                    app_conf_dict[self.get_name()].split('=')[0] + f'="{a}"'
                )
            )

        if 'REGEDIT' in self.get_name():
            if i in reg_patches:
                app_conf.write_text(
                    app_conf.read_text().replace(
                        app_conf_dict[self.get_name()],
                        app_conf_dict[self.get_name()].split('=')[0] + f'="{i}"'
                    )
                )

        if 'DXVK' in self.get_name():
            if i in dxvk_ver:
                app_conf.write_text(
                    app_conf.read_text().replace(
                        app_conf_dict[self.get_name()],
                        app_conf_dict[self.get_name()].split('=')[0] + f'="{i}"'
                    )
                )

        if 'VKD3D' in self.get_name():
            if i in vkd3d_ver:
                app_conf.write_text(
                    app_conf.read_text().replace(
                        app_conf_dict[self.get_name()],
                        app_conf_dict[self.get_name()].split('=')[0] + f'="{i}"'
                    )
                )

        if 'FSR_MODE' in self.get_name():
            if i in fsr_mode.keys():
                app_conf.write_text(
                    app_conf.read_text().replace(
                        app_conf_dict[self.get_name()],
                        app_conf_dict[self.get_name()].split('=')[0] + f'="{fsr_mode[i]}"'
                    )
                )

        if 'LANG_MODE' in self.get_name():
            if i in lang_mode:
                app_conf.write_text(
                    app_conf.read_text().replace(
                        app_conf_dict[self.get_name()],
                        app_conf_dict[self.get_name()].split('=')[0] + f'="{i}"'
                    )
                )

    def on_row_theme_activate(self, _param):
        """___write selected item in custom css___"""
        color = self.get_selected_item().get_string()
        sample = default_themes[color]

        with open(sw_css_custom, 'w') as f:
            f.write(sample)
            f.close()
            activate_global_colors_settings()

    def cb_btn_regedit_patch(_self, combo):
        """___activate registry patch for current prefix___"""

        if combo.get_selected() != 0:
            t = Thread(target=on_regedit_patch)
            t.start()
            stack_progress_main.set_visible_child(progress_main_grid)
            progress_main.set_visible(True)
            progress_main.set_show_text(True)
            progress_main.set_text(msg.tt_dict['registry'])
            spinner.start()
            GLib.timeout_add(100, check_alive, t, on_stop, None, None)

    def on_regedit_patch():
        """___registry patch for current prefix___"""

        echo_func_name('TRY_REGEDIT_PATCH')

    def on_fps_adjustment(self):
        """___write fps value in application config___"""

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        fps = self.get_value()
        fps_dict = app_conf_info(app_conf, [export_fps_limit])

        app_conf.write_text(
            app_conf.read_text().replace(
                fps_dict[export_fps_limit],
                fps_dict[export_fps_limit].split('=')[0] + f'="{fps}"'
            )
        )

    def on_cpu_adjustment(self):
        """___write cpu core value in application config___"""

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        cpu_dict = app_conf_info(app_conf, [export_cpu_topology])
        cpu = int(self.get_value())
        cpu_affinity = ''

        if cpu == 0:
            str_cpu = ''
        else:
            str_cpu = f'{cpu}'

        cpu_idx = []
        for i in range(int(cpu)):
            cpu_idx.append(i)

        idx = str(cpu_idx)[1:-1].replace(' ', '')

        if idx != '' and str_cpu != '':
            cpu_affinity = f'{str_cpu}:{idx}'

        app_conf.write_text(
            app_conf.read_text().replace(
                cpu_dict[export_cpu_topology],
                cpu_dict[export_cpu_topology].split('=')[0] + f'="{cpu_affinity}"'
            )
        )

    def cb_btn_switch_ls(self, _state):
        """___update switch list when changed switch state___"""

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_dict = app_conf_info(app_conf, switch_labels)

        if self.get_active():
            app_conf.write_text(
                app_conf.read_text().replace(
                    app_conf_dict[self.get_name()],
                    app_conf_dict[self.get_name()].replace('0', '1')
                )
            )

        elif not self.get_active():
            app_conf.write_text(
                app_conf.read_text().replace(
                    app_conf_dict[self.get_name()],
                    app_conf_dict[self.get_name()].replace('1', '0')
                )
            )

    def on_mangohud_settings():
        """___activate mangohud settings page___"""

        if scrolled_mangohud_settings.get_child() is not None:
            if main_stack.get_visible_child_name() != vw_dict['mangohud_settings']:
                return set_settings_widget(
                                        stack_settings,
                                        vw_dict['mangohud_settings'],
                                        swgs.pref_group_mh_title,
                )
            else:
                pass
        else:
            add_mangohud_settings_view()

    def on_mango_flow_activated(_self, child, btn_switch_mh):
        """___activate flowbox child in mangohud settings___"""

        if btn_switch_mh.get_name() == child.get_name():
            if not btn_switch_mh.get_active():
                btn_switch_mh.set_active(True)
            else:
                btn_switch_mh.set_active(False)

    def cb_btn_switch_mh(self, _state):
        """___write mangohud config when toggle check button___"""

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        export_mangohud_dict = app_conf_info(app_conf, [export_mangohud_config])
        export_string = export_mangohud_dict[export_mangohud_config]
        export_name = export_string.split('=')[0]
        export_value = export_string.removeprefix(f'{export_name}=').strip('"')
        value_list = export_value.split(',')

        if self.get_active():
            for x in value_list:
                if self.get_name() == x:
                    value_list.remove(x)
            else:
                value_list.append(self.get_name())
                app_conf.write_text(
                    app_conf.read_text().replace(
                        export_value,
                        ','.join(set(value_list))
                    )
                )
        else:
            for x in value_list:
                if self.get_name() == x:
                    value_list.remove(x)
            else:
                app_conf.write_text(
                    app_conf.read_text().replace(
                        export_value,
                        ','.join(set(value_list))
                    )
                )

    def cb_btn_mh_preview(self):
        """___preview opengl cube with mangohud overlay___"""

        def unlock_button(button):
            button.set_sensitive(True)

        self.set_sensitive(False)
        thread_preview = Thread(target=on_btn_mh_preview)
        thread_preview.start()
        GLib.timeout_add(1000, check_alive, thread_preview, unlock_button, self, None)

    def on_btn_mh_preview():

        get_mangohud_config()
        Popen(f"mangohud --dlsym {sw_cube} -v", shell=True)

    def get_mangohud_config():
        """___get mangohud config from application config___"""

        key_reload = 'Control_L+Shift_L+r'
        gl_x = '-12'
        gl_y = '12'

        mh_config = str()
        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_read = app_conf.read_text().splitlines()

        for line in app_conf_read:

            if 'MANGOHUD_CONFIG' in line:
                mh_config = str(line.split('"')[1])

            if 'SW_USE_MESA_OVERLAY_HUD' in line:
                environ["SW_USE_MESA_OVERLAY_HUD"] = str(line.split('=')[1])

            if 'SW_USE_GALLIUM_HUD' in line:
                environ['SW_USE_GALLIUM_HUD'] = str(line.split('=')[1])

        for x in mh_config.split(','):
            if 'reload_cfg' in x:
                mh_config = mh_config.replace(x + ',', '')
                key_reload = 'Control_L+Shift_L+r'

        font_size = int(mon_height/55)
        mhud_conf = (
                    f'reload_cfg={key_reload},offset_x={gl_x},offset_y={gl_y},'
                    + f'{default_mangohud},font_size={font_size},{mh_config}'
        )
        environ["MANGOHUD_CONFIG"] = mhud_conf

    def on_mh_color_set(self, entry):
        """___set custom mangohud indicator colors___"""

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_mh_color_dict = app_conf_info(app_conf, [export_mangohud_config])
        export_string = app_conf_mh_color_dict[export_mangohud_config]
        export_name = export_string.split('=')[0]
        export_value = export_string.removeprefix(f'{export_name}=').strip('"')
        value_list = export_value.split(',')

        get_rgb = self.get_rgba().to_string().replace('rgb', '')[1:-1].split(',')
        r = int(get_rgb[0])
        g = int(get_rgb[1])
        b = int(get_rgb[2])
        hex_color = f"={r:02x}{g:02x}{b:02x}"

        for x in value_list:
            if self.get_name() == x.split('=')[0]:
                value_list.remove(x)
        else:
            value_list.append(self.get_name() + hex_color)
            app_conf.write_text(
                app_conf.read_text().replace(
                    export_value,
                    ','.join(set(value_list))
                )
            )
        entry.set_text(self.get_rgba().to_string())

    def on_theme_color_set(self, _gparam, entry):
        """___set custom color scheme colors___"""

        entry.set_text(self.get_rgba().to_string())

    def on_row_entry_color(self, _position):
        """___save custom color from entry string___"""

        color_value = self.get_text()
        color_name = self.get_name()
        css_string_list = sw_css_custom.read_text().splitlines()

        for string in css_string_list:
            if color_name in string:
                change = color_name + ' ' + color_value + ';'
                sw_css_custom.write_text(
                    sw_css_custom.read_text().replace(
                        string,
                        change
                        )
                    )

    def cb_btn_save_theme(_self):
        """___apply custom color scheme___"""

        accent_color = None
        colorscheme = 'dark'
        css_change_list.clear()
        avg_colors = dict()
        css_string_list = sw_css_custom.read_text().splitlines()

        for entry, invert in zip(entry_theme_color_list, invert_dcolors):
            color = f' {entry.get_text()}' + ';'
            split_color = entry.get_text().replace('rgba', '').replace('rgb', '')[1:-1].split(',')
            avg_color = (int(split_color[0]) + int(split_color[1]) + int(split_color[2])) / 3
            r = int(split_color[0])
            g = int(split_color[1])
            b = int(split_color[2])

            format_color = color
            if len(split_color) == 3:
                format_color = f' rgba({int(r)}, {int(g)}, {int(b)}, 1.0)' + ';'
            if len(split_color) == 4:
                a = float(split_color[3])
                format_color = f' rgba({r}, {g}, {b}, {a})' + ';'

            if avg_color < 64:
                avg_color = avg_color + 128

            elif 64 <= avg_color < 96:
                avg_color = avg_color + 96

            elif 96 <= avg_color < 128:
                avg_color = avg_color + 64

            elif 128 <= avg_color < 160:
                avg_color = avg_color - 96

            elif 160 <= avg_color < 192:
                avg_color = avg_color - 128

            elif 192 <= avg_color <= 255:
                avg_color = avg_color - 160

            avg_colors[f'{invert}'] = f' rgba({int(avg_color)}, {int(avg_color)}, {int(avg_color)}, 1.0)' + ';'

            print(entry.get_name())
            if entry.get_name() == '@define-color sw_bg_color':
                if (r + g + b) / 3 >= 160:
                    logo_colorscheme = 'light'
                else:
                    logo_colorscheme = 'dark'

            if entry.get_name() == '@define-color sw_header_bg_color':
                if (r + g + b) / 3 >= 160:
                    environ['SW_CUSTOM_WC_COLOR_SCHEME'] = 'light'
                else:
                    environ['SW_CUSTOM_WC_COLOR_SCHEME'] = 'dark'

            if entry.get_name() == '@define-color sw_accent_fg_color':
                accent_color = (r, g, b)
                define_ipc = '@define-color sw_invert_progress_color'
                invert_progress_color = f' rgba({255 - r}, {255 - g}, {255 - b}, 1.0)' + ';'
                for string in css_string_list:
                    if define_ipc in string:
                        sw_css_custom.write_text(
                            sw_css_custom.read_text().replace(
                                string,
                                define_ipc + invert_progress_color
                            )
                        )

            change = entry.get_name() + format_color
            for string in css_string_list:
                if entry.get_name() in string:
                    sw_css_custom.write_text(
                        sw_css_custom.read_text().replace(
                            string,
                            change
                        )
                    )
        else:
            for string in css_string_list:
                for k, v in avg_colors.items():
                    if k in string:
                        sw_css_custom.write_text(
                            sw_css_custom.read_text().replace(
                                string,
                                k + v
                            )
                        )

        if accent_color is not None:
            create_svg_logo(accent_color, logo_colorscheme, f'{sw_gui_icons}/{sw_logo_custom}')

        on_toggled_custom(btn_custom, pic_custom)
        btn_custom.set_active(True)

    def cb_change_icon_color(self, child):
        """___set changed color for the built-in icon theme___"""

        for box in swgs.icon_check_box_list:
            box.set_visible(False)

        child.get_child().get_last_child().set_visible(True)
        icon_color = child.get_name()
        environ['SW_ICON_COLOR'] = f'{icon_color}'
        set_gtk_icon_theme_name(gtk_settings, icon_color)

    def change_icon_color():
        """___set default color for the built-in icon theme___"""

        icon_color = default_ini.get('icon_color')
        environ['SW_ICON_COLOR'] = icon_color

        for box in swgs.icon_check_box_list:
            box.set_visible(False)
            if box.get_name() == icon_color:
                box.set_visible(True)

        set_gtk_icon_theme_name(gtk_settings, icon_color)

    def cb_change_wc_style(self, child):
        """___set changed style for the window control buttons___"""

        style = child.get_name()
        check_box = child.get_child().get_last_child()
        for box in swgs.wc_check_box_list:
            box.set_visible(False)
        check_box.set_visible(True)
        return set_wc_style(style)

    def change_wc_style():
        """___set default style for the window control buttons___"""

        style = default_ini.get('wc_style')
        environ['SW_WC_STYLE'] = style

        for box in swgs.wc_check_box_list:
            box.set_visible(False)
            if box.get_name() == style:
                box.set_visible(True)

        return set_wc_style(style)

    def set_gtk_icon_theme_name(gtk_settings_, icon_color_):
        """___set changed color for the built-in icon theme___"""

        gtk_settings_.props.gtk_icon_theme_name = f"SWSuru++-{icon_color_}"
        print(f'{tc.VIOLET} BUILTIN_ICONS: {tc.BLUE}SWSuru++-{icon_color_}')

    def on_vkbasalt_settings():
        """___activate vkbasalt settings page___"""

        if scrolled_vkbasalt_settings.get_child() is not None:
            if main_stack.get_visible_child_name() != vw_dict['vkbasalt_settings']:
                return set_settings_widget(
                                    stack_settings,
                                    vw_dict['vkbasalt_settings'],
                                    swgs.pref_group_vk_title,
                )
            else:
                pass
        else:
            add_vkbasalt_settings_view()

    def on_vk_flow_activated(_self, child, btn_switch_vk):
        """___switch vkbasalt parameters when flowbox pressed___"""

        if btn_switch_vk.get_name() == child.get_name():
            if not btn_switch_vk.get_active():
                btn_switch_vk.set_active(True)
            else:
                btn_switch_vk.set_active(False)

    def cb_btn_switch_vk(self, _state):
        """___switch vkbasalt parameters___"""

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_vk_dict = app_info(app_conf)

        if self.get_active():
            app_conf_vk_list.append(self.get_name())
            app_conf.write_text(
                app_conf.read_text().replace(
                    app_conf_vk_dict[export_vkbasalt_effects],
                    '"cas:' + ':'.join(app_conf_vk_list) + '"'
                )
            )

        elif not self.get_active():
            app_conf_vk_list.remove(self.get_name())
            app_conf.write_text(
                app_conf.read_text().replace(
                    app_conf_vk_dict[export_vkbasalt_effects],
                    '"cas:' + ':'.join(app_conf_vk_list) + '"'
                )
            )

    def on_set_vk_intensity(vk_adjustment):
        """___set_vkbasalt_effect_entensity___"""

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_vk_dict = app_info(app_conf)

        effect_value = vk_adjustment.get_value() / 100

        app_conf.write_text(
            app_conf.read_text().replace(
                app_conf_vk_dict[export_vkbasalt_cas],
                '"' + str(effect_value) + '"'
            )
        )

###___Global_settings___.

    def on_global_settings():
        """___activate insterface settings page___"""

        btn_back_main.set_visible(True)

        if scrolled_global_settings.get_child() is not None:
            if main_stack.get_visible_child_name() != vw_dict['global_settings']:
                return set_settings_widget(
                                    main_stack,
                                    vw_dict['global_settings'],
                                    None,
                )
            else:
                pass
        else:
            add_global_settings_view()

    def on_select_file(x_path):
        """___set new path to executable file___"""

        title = sw_program_name
        dialog = SwDialogDirectory(title=title)
        dialog.open(
                    parent=parent,
                    cancellable=Gio.Cancellable(),
                    callback=get_file,
                    user_data=x_path
                    )

    def get_file(self, res, data):
        """___async callback result with changed path___"""

        try:
            result = self.open_finish(res)
        except GLib.GError as e:
            print(e.message)
            result = None
        else:
            if result.get_path() is not None:
                new_path = result.get_path()
                write_app_conf(Path(new_path))

                with open(data, 'w', encoding='utf-8') as f:
                    f.write(f'Exec="{new_path}"')
                    f.close()
                print(f'{tc.YELLOW}Writing new executable path: {tc.RED}{new_path}{tc.END}')
            else:
                text_message = msg.msg_dict['correct_path']
                overlay_info(main_overlay, None, text_message, None, None, 3)

        return result

    def get_folder(self, res):
        """___async callback result with changed path___"""

        try:
            result = self.select_folder_finish(res)
        except GLib.GError as e:
            print(e.message)
            result = None
        else:
            swgs.entry_def_dir.set_text(str(result.get_path()))
            on_def_dir()

        return result

    def cb_btn_def_dir(_self):
        """___run dialog directory selection___"""

        dialog = SwDialogDirectory(title=sw_program_name)
        dialog.select_folder(
                    parent=parent,
                    cancellable=Gio.Cancellable(),
                    callback=get_folder,
                    )

    def cb_entry_def_dir(_self, _position):
        """___set the default directory to open files___"""

        return on_def_dir()

    def on_def_dir():
        """___set the default directory to open files___"""

        string = swgs.entry_def_dir.get_text()
        if string != '' and Path(string).exists():
            swgs.cfg['default_dir'] = f'{string}'
        else:
            text_message = str_wrong_path
            return overlay_info(main_overlay, None, text_message, None, None, 3)

    def cb_lang_setup(_self, item_list):
        """___setup language item list___"""

        label = Gtk.Label(css_name='sw_label_desc')
        label.set_xalign(0)
        item_list.set_child(label)

    def cb_lang_bind(_self, item_list):
        """___bind language item list___"""

        item = item_list.get_item()
        label = item_list.get_child()
        label.set_label(item.get_string())

    def on_lang_activate(self, _gparam):
        """___set the locale of the selected language___"""

        str_lang = self.get_selected_item().get_string()
        environ['SW_LOCALE'] = str(str_lang)

        for lang in lang_labels:
            if str_lang in lang:
                swgs.cfg['language'] = f'{lang}'

    def on_shaders_setup(_self, item_list):
        """___setup shaders item list___"""

        label = Gtk.Label(css_name='sw_label_desc')
        label.set_xalign(0)
        item_list.set_child(label)

    def on_shaders_bind(_self, item_list):
        """___bind shaders item list___"""

        item = item_list.get_item()
        label = item_list.get_child()
        label.set_label(item.get_string())

    def on_shaders_activate(self, _gparam):
        """___activate changed shaders for opengl background___"""

        if self.get_selected_item() is not None:
            str_shader = self.get_selected_item().get_string()

            count = -1
            for fragment, name in zip(fragments_list, fragments_labels):
                count += 1
                if str_shader == name.capitalize():
                    environ['FRAGMENT_NUM'] = str(count)
                    environ['FRAGMENT_INDEX'] = str(count)
                    write_changed_shaders(count)
                    break
        else:
            environ['FRAGMENT_NUM'] = int(default_ini['shader_src'])
            environ['FRAGMENT_INDEX'] = int(default_ini['shader_src'])
            write_changed_shaders(int(default_ini['shader_src']))

    def write_changed_shaders(count):
        """___write changed shaders for opengl background___"""

        swgs.cfg['shader_src'] = f'{count}'

    def on_switch_opengl_bg(self, _state):
        """___enable or disable opengl background___"""

        if self.get_active():
            environ['SW_OPENGL'] = '1'
            swgs.cfg['opengl_bg'] = 'True'
            swgs.dropdown_shaders.set_sensitive(True)

        elif not self.get_active():
            environ['SW_OPENGL'] = '0'
            swgs.cfg['opengl_bg'] = 'False'
            swgs.dropdown_shaders.set_sensitive(False)

    def on_switch_vulkan_renderer(self, _state):
        """___enable or disable vulkan renderer___"""

        if self.get_active():
            environ['SW_RENDERER'] = 'vulkan'
            swgs.cfg['renderer'] = 'vulkan'

        elif not self.get_active():
            environ['SW_RENDERER'] = 'opengl'
            swgs.cfg['renderer'] = 'opengl'

    def on_flow_render(self, child):

        switch = child.get_child().get_last_child()
        if isinstance(switch, Gtk.Switch):
            active = not switch.get_active()
            switch.set_active(active)

    def on_switch_autostart(self, _state):
        """___create or delete autostart tray shortcut___"""

        if self.get_active():
            swgs.cfg['autostart'] = '1'
            if not sw_tray_autostart.parent.exists():
                sw_tray_autostart.parent.mkdir(parents=True, exist_ok=True)
                sw_tray_autostart.write_text(sample_tray_desktop)
                sw_tray_autostart.chmod(0o755)
            else:
                if not sw_tray_autostart.exists():
                    sw_tray_autostart.write_text(sample_tray_desktop)
                    sw_tray_autostart.chmod(0o755)

        if not self.get_active():
            swgs.cfg['autostart'] = '0'
            if sw_tray_autostart.exists():
                sw_tray_autostart.unlink()

    def get_sys_icons():
        """___try get system icons theme___"""

        sys_icons = getenv('SW_GTK_ICON_THEME')
        if sys_icons is None:
            gtk_ini = f'{Path.home()}/.config/gtk-3.0/settings.ini'
            if Path(gtk_ini).exists():
                sys_icons = [
                    x.split('=')[1] for x in Path(gtk_ini).read_text().splitlines()
                    if 'gtk-icon-theme-name=' in x
                ]
                if len(sys_icons) != 0:
                    sys_icons = sys_icons[0]
                else:
                    sys_icons = 'SWSuru++-blue'
            else:
                sys_icons = 'SWSuru++-blue'
        else:
            sys_icons = 'SWSuru++-blue'

        return sys_icons

    def on_switch_icons(self, _state):
        """___switch icons theme___"""

        icon_theme = getenv('SW_ICON_THEME')

        if self.get_active():
            if icon_theme and icon_theme != 'custom':
                environ['SW_ICON_THEME'] = 'custom'
                sys_icons = get_sys_icons()
                gtk_settings.props.gtk_icon_theme_name = f"{sys_icons}"
                print(f'{tc.VIOLET}SYSTEM_ICONS: {tc.BLUE}{sys_icons}')

        if not self.get_active():
            if icon_theme and icon_theme != 'builtin':
                environ['SW_ICON_THEME'] = 'builtin'
                icon_color = getenv('SW_ICON_COLOR')
                if icon_color is not None:
                    gtk_settings.props.gtk_icon_theme_name = f"SWSuru++-{icon_color}"
                    print(f'{tc.VIOLET} BUILTIN_ICONS: {tc.BLUE}SWSuru++-{icon_color}')
                else:
                    gtk_settings.props.gtk_icon_theme_name = "SWSuru++-blue"
                    print(f'{tc.VIOLET} BUILTIN_ICONS: {tc.BLUE}SWSuru++-blue')

    def on_switch_restore_menu(self, _state):
        """___switch restore menu mode___"""

        if self.get_active():
            swgs.cfg['restore_menu'] = 'on'

        if not self.get_active():
            swgs.cfg['restore_menu'] = 'off'

    def on_switch_auto_stop(self, _state):
        """___switch auto stop mode___"""

        if self.get_active():
            swgs.cfg['auto_stop'] = 'on'

        if not self.get_active():
            swgs.cfg['auto_stop'] = 'off'

    def on_switch_auto_hide_top_header(self, _state):
        """___switch auto hide headers mode___"""

        if self.get_active():
            swgs.cfg['auto_hide_top_header'] = 'on'
            environ['SW_AUTO_HIDE_TOP_HEADER'] = '1'
            top_headerbar_revealer.set_reveal_child(False)

        if not self.get_active():
            swgs.cfg['auto_hide_top_header'] = 'off'
            environ['SW_AUTO_HIDE_TOP_HEADER'] = '0'
            top_headerbar_revealer.set_reveal_child(True)

    def on_switch_auto_hide_bottom_header(self, _state):
        """___switch auto hide headers mode___"""

        if self.get_active():
            swgs.cfg['auto_hide_bottom_header'] = 'on'
            environ['SW_AUTO_HIDE_BOTTOM_HEADER'] = '1'
            bottom_headerbar_revealer.set_reveal_child(False)

        if not self.get_active():
            swgs.cfg['auto_hide_bottom_header'] = 'off'
            environ['SW_AUTO_HIDE_BOTTOM_HEADER'] = '0'
            bottom_headerbar_revealer.set_reveal_child(True)

    def on_switch_tray():
        """___enable or disable tray at startup___"""

        if swgs.cfg['on_tray'] == 'True':
            swgs.cfg['on_tray'] = 'False'
        else:
            swgs.cfg['on_tray'] = 'True'

    def cb_flow_startup(self, child):
        switch = child.get_child().get_last_child()
        if isinstance(switch, Gtk.Switch):
            is_active = not switch.get_active()
            switch.set_active(is_active)

    def on_controller_settings():
        """______"""
        pass

    def check_sw_update():
        """______"""

        func_name = f"try_update_sw"
        echo_func_name(func_name)

    def cb_btn_about(self):
        """___show_about_submenu___"""

        if self.get_name() == 'about_update':
            t = Thread(target=check_sw_update)
            t.start()
        else:
            stack_sidebar.set_visible_child(frame_stack)
            grid = swgs.stack_about.get_child_by_name(self.get_name())
            swgs.btn_back_about.unparent()
            swgs.label_back_about.set_label(about_dict[self.get_name()])
            grid.attach(swgs.btn_back_about, 0, 0, 1, 1)
            swgs.stack_about.set_visible_child_name(self.get_name())

    def cb_btn_back_about(_self):
        """___back to main about submenu page___"""

        stack_sidebar.set_visible_child(frame_about)

    def on_about():
        """___show_about_menu___"""

        if scrolled_about.get_child() is None:
            add_about()

        str_sw_version = check_sw_version()
        swgs.title_news.set_label(sw_program_name + ' ' + str_sw_version,)
        swgs.about_version.set_label(str_sw_version)

        if not sidebar_revealer.get_reveal_child():
            on_sidebar()

        if stack_sidebar.get_visible_child() == frame_about:
            #on_back_main()
            btn_back_main.set_visible(False)
            stack_sidebar.set_visible_child(frame_main)
        else:
            btn_back_main.set_visible(True)
            stack_sidebar.set_visible_child(frame_about)

        update_color_scheme()

    def cb_btn_news(self):
        """___open source page on github___"""
        self.set_uri(news_source)

    def cb_btn_website(self):
        """___open source page on github___"""
        self.set_uri(website_source)

    def cb_btn_github(self):
        """___open source page on github___"""
        self.set_uri(github_source)

    def cb_btn_discord(self):
        """___open web page invite to discord___"""
        self.set_uri(discord_source)

    def cb_btn_telegram(self):
        """___open web page invite to telegram___"""
        self.set_uri(telegram_source)

    def cb_btn_license(self):
        """___open web page about license___"""
        self.set_uri(license_source)

    def cb_btn_donation(self):
        """___open web page about donation___"""

        if self.get_name() != '':
            if (self.get_name().startswith('https://')
                    or self.get_name().startswith('http://')):
                self.set_uri(self.get_name())
            else:
                clipboard.set(str(self.get_name()))
                text_message = msg.msg_dict['copied_to_clipboard']
                return overlay_info(main_overlay, None, text_message, None, None, 3)

    def on_stop():
        """___terminate all wine process and stop progress___"""

        winedevices = (
            [
                p.info['pid'] for p in psutil.process_iter(['pid', 'name'])
                if 'winedevice' in p.info['name']
            ]
        )
        for proc in winedevices:
            psutil.Process(proc).kill()

        webkits = (
            [
                p.info['pid'] for p in psutil.process_iter(['pid', 'name'])
                if 'WebKitNetworkProcess' in p.info['name']
            ]
        )
        for proc in webkits:
            psutil.Process(proc).kill()

        timeout_list_clear(None)

        progress_main.set_fraction(0)
        progress_main.set_show_text(False)
        progress_main.set_visible(False)
        stack_progress_main.set_visible_child(stack_panel)
        spinner.stop()
        environ['FRAGMENT_NUM'] = str(getenv('FRAGMENT_INDEX'))

        overlay_info(main_overlay, None, msg.msg_dict['termination'], None, None, 3)
        Popen(f"{sw_scripts}/sw_stop", shell=True)

    def cb_btn_popover_colors(_self):
        """___popup cloor scheme chooser menu___"""

        popover_colors.popup()

    def cb_btn_popover_scale(_self):
        """___popup icon scale button___"""

        path = Path(entry_path.get_name())

        if path == sw_shortcuts:
            popover_scale_sc.popup()
        else:
            popover_scale.popup()

    def on_toggled_dark(self, pic):
        """___toggle color scheme___"""

        if self.get_active():
            pic.add_css_class('checked')
            on_change_color_scheme('dark', sw_css_dark)
        else:
            pic.remove_css_class('checked')

        popover_colors.popdown()

    def on_toggled_light(self, pic):
        """___toggle color scheme___"""

        if self.get_active():
            pic.add_css_class('checked')
            on_change_color_scheme('light', sw_css_light)
        else:
            pic.remove_css_class('checked')

        popover_colors.popdown()

    def on_toggled_custom(self, pic):
        """___toggle color scheme___"""

        if self.get_active():
            if getenv('SW_CUSTOM_WC_COLOR_SCHEME') is not None:
                swgs.cfg['wc_color_scheme'] = str(getenv('SW_CUSTOM_WC_COLOR_SCHEME'))
            pic.add_css_class('checked')
            on_change_color_scheme('custom', sw_css_custom)
        else:
            pic.remove_css_class('checked')

        popover_colors.popdown()

    def on_change_color_scheme(colorscheme_type, css_path):
        """___set color scheme___"""

        swgs.colorscheme = colorscheme_type
        swgs.cfg['color_scheme'] = colorscheme_type

        set_define_colors()
        set_sw_logo()
        if getenv('SW_WC_STYLE'):
            set_wc_style(str(getenv('SW_WC_STYLE')))

        css_provider.load_from_file(Gio.File.new_for_path(bytes(css_path)))
        Gtk.StyleContext.add_provider_for_display(
                                        display,
                                        css_provider,
                                        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

    def cb_btn_icon_position(_self):
        """___change shortcut icons position in view___"""

        if swgs.cfg['icon_position'] == 'horizontal':
            environ['ICON_POSITION'] = 'vertical'
            swgs.cfg['icon_position'] = 'vertical'

        elif swgs.cfg['icon_position'] == 'vertical':
            environ['ICON_POSITION'] = 'horizontal'
            swgs.cfg['icon_position'] = 'horizontal'

        parent_file = get_parent_file()
        if parent_file.get_path() is not None:
            update_grid_view(parent_file.get_path())
        else:
            update_grid_view_uri(parent_file.get_uri())

    def cb_ctrl_enter_bookmarks(_self, _x, _y, btn_remove):
        """___cursor position signal handler___"""

        btn_remove.set_visible(True)

    def cb_ctrl_leave_bookmarks(_self, btn_remove):
        """___cursor position signal handler___"""

        btn_remove.set_visible(False)

    def cb_ctrl_enter_media(_self, _x, _y, btn_remove):
        """___cursor position signal handler___"""

        btn_remove.set_visible(True)

    def cb_ctrl_leave_media(_self, btn_remove):
        """___cursor position signal handler___"""

        btn_remove.set_visible(False)

    def cb_btn_sidebar(_self):
        """___reveal show or hide main menu___"""

        return on_sidebar()

    def on_sidebar():

        swgs.flap_locked

        if parent.get_width() < 960:
            if not sidebar_revealer.get_reveal_child():
                swgs.flap_locked = True
                sidebar_revealer.set_reveal_child(True)
            else:
                sidebar_revealer.set_reveal_child(False)
        else:
            if swgs.flap_locked:
                swgs.flap_locked = False
            else:
                swgs.flap_locked = True

            if sidebar_revealer.get_reveal_child():
                sidebar_revealer.set_reveal_child(False)
            else:
                sidebar_revealer.set_reveal_child(True)
                if stack_sidebar.get_visible_child() != frame_main:
                    btn_back_main.set_visible(True)

        grid_sidebar_btn.get_first_child().grab_focus()

    def cb_btn_drive(_self):
        """___show or hide mounted volumes___"""

        return on_drive()

    def cb_btn_bookmarks(_self):
        """___show or hide bookmarks list___"""

        return on_bookmarks()

    def cb_btn_playlist(_self):
        """___show or hide bookmarks list___"""

        return on_playlist()

    def on_bookmarks():
        """___show or hide bookmarks list___"""

        if scrolled_bookmarks.get_child() is None:
            add_bookmarks_menu()

        if not sidebar_revealer.get_reveal_child():
            sidebar_revealer.set_reveal_child(True)
            update_bookmarks()
            stack_sidebar.set_visible_child(frame_bookmarks)
            update_color_scheme()
            btn_back_main.set_visible(True)

        elif stack_sidebar.get_visible_child() == frame_bookmarks:
            #on_back_main()
            btn_back_main.set_visible(False)
            stack_sidebar.set_visible_child(frame_main)
        else:
            update_bookmarks()
            btn_back_main.set_visible(True)
            stack_sidebar.set_visible_child(frame_bookmarks)
            update_color_scheme()

    def on_playlist():
        """___show or hide media playlist___"""

        if scrolled_playlist.get_child() is None:
            add_playlist_menu()

        if not sidebar_revealer.get_reveal_child():
            sidebar_revealer.set_reveal_child(True)
            update_playlist()
            btn_back_main.set_visible(True)
            stack_sidebar.set_visible_child(frame_playlist)
            update_color_scheme()

        elif stack_sidebar.get_visible_child() == frame_playlist:
            #on_back_main()
            btn_back_main.set_visible(False)
            stack_sidebar.set_visible_child(frame_main)
        else:
            update_playlist()
            btn_back_main.set_visible(True)
            stack_sidebar.set_visible_child(frame_playlist)
            update_color_scheme()

    def cb_btn_overlay(self):
        """___main buttons signal handler___"""

        if self.get_name() == 'btn_next':
            return cb_btn_next(self)

        if self.get_name() == 'btn_prev':
            return cb_btn_prev(self)

    def cb_ctrl_scroll_view(self, _x, y, data):
        """___mouse scroll event to scroll gridview___"""

        if self.get_unit() == Gdk.ScrollUnit.WHEEL:
            data.append(y)
            if y == -1.0:
                if len(data) > 3:
                    data.clear()
                    cb_btn_overlay(self.get_widget().get_last_child().get_first_child())
            elif y == 1.0:
                if len(data) > 3:
                    data.clear()
                    cb_btn_overlay(self.get_widget().get_first_child().get_first_child())

    def cb_btn_next(self):
        """___activate next view list___"""

        self.set_sensitive(False)
        self.set_can_focus(False)
        self.set_focusable(False)
        GLib.timeout_add(250, set_btn_sensitive, self)
        return on_next()

    def on_next():
        """___show next view page___"""

        main_stack.set_transition_type(Gtk.StackTransitionType.ROTATE_LEFT)
        w_name = str(main_stack.get_visible_child().get_name())

        if w_name == 'files' or w_name == 'web_view' or w_name == 'winetricks' or w_name == 'startapp_page':
            w_name = 'shortcuts'

        if w_name in next_vw:
            w_next = next_vw_dict[w_name]

            if w_next == 'global_settings':
                return on_global_settings()
            if w_next == 'install_wine':
                return on_download_wine()
            if w_next == 'install_launchers':
                return on_install_launchers()
            if w_next == 'shortcuts':
                return on_shortcuts()

    def cb_btn_prev(self):
        """___show previous view page___"""

        self.set_sensitive(False)
        self.set_can_focus(False)
        self.set_focusable(False)
        GLib.timeout_add(250, set_btn_sensitive, self)
        return on_prev()

    def on_prev():
        """___show previous view page___"""

        main_stack.set_transition_type(Gtk.StackTransitionType.ROTATE_RIGHT)
        w_name = str(main_stack.get_visible_child().get_name())

        if (w_name == 'files' or w_name == 'web_view' or w_name == 'winetricks'
                or w_name == 'startapp_page'):
            w_name = 'shortcuts'

        if w_name in prev_vw:
            w_prev = prev_vw_dict[w_name]

            if w_prev == 'install_launchers':
                return on_install_launchers()
            if w_prev == 'shortcuts':
                return on_shortcuts()
            if w_prev == 'global_settings':
                return on_global_settings()
            if w_prev == 'install_wine':
                return on_download_wine()

    def set_btn_sensitive(btn_widget):
        """___set sensitive button in overlay control panel___"""

        btn_widget.set_sensitive(True)
        btn_widget.set_can_focus(True)
        btn_widget.set_focusable(True)
        #btn_widget.grab_focus()

    def set_sw_logo():
        """___get application icon for start mode in sidebar___"""

        if swgs.colorscheme == 'dark':
            sw_logo = sw_logo_light
        elif swgs.colorscheme == 'light':
            sw_logo = sw_logo_dark
        else:
            sw_logo = sw_logo_custom

        image_sidebar_logo.set_file(Gio.File.new_for_path(f'{sw_gui_icons}/{sw_logo}'))
        image_sidebar_logo.set_content_fit(Gtk.ContentFit.SCALE_DOWN)
        image_sidebar_logo.queue_draw()

    def set_wc_style(wc_style):
        """___set style for window control buttons___"""

        environ['SW_WC_STYLE'] = wc_style

        if swgs.colorscheme == 'light' or getenv('SW_CUSTOM_WC_COLOR_SCHEME') == 'light':
            if scrolled_global_settings.get_child():
                swgs.image_br_close.set_from_paintable(swgs.paintable_icon_br_close_light)
                swgs.image_br_max.set_from_paintable(swgs.paintable_icon_br_max_light)
                swgs.image_br_min.set_from_paintable(swgs.paintable_icon_br_min_light)
                swgs.image_adw_close.set_from_paintable(swgs.paintable_icon_close_light)
                swgs.image_adw_max.set_from_paintable(swgs.paintable_icon_max_light)
                swgs.image_adw_min.set_from_paintable(swgs.paintable_icon_min_light)
        else:
            if scrolled_global_settings.get_child():
                swgs.image_br_close.set_from_paintable(swgs.paintable_icon_br_close)
                swgs.image_br_max.set_from_paintable(swgs.paintable_icon_br_max)
                swgs.image_br_min.set_from_paintable(swgs.paintable_icon_br_min)
                swgs.image_adw_close.set_from_paintable(swgs.paintable_icon_close)
                swgs.image_adw_max.set_from_paintable(swgs.paintable_icon_max)
                swgs.image_adw_min.set_from_paintable(swgs.paintable_icon_min)

        if wc_style == 'breeze':
            wc_close.remove_css_class('wc_color')
            wc_minimize.remove_css_class('wc_color')
            wc_maximize.remove_css_class('wc_color')
            wc_close.remove_css_class('wc_mac')
            wc_minimize.remove_css_class('wc_mac')
            wc_maximize.remove_css_class('wc_mac')
            wc_close.set_child(image_wc_close)
            wc_minimize.set_child(image_wc_min)
            wc_maximize.set_child(image_wc_max)

            if swgs.colorscheme == 'light' or getenv('SW_CUSTOM_WC_COLOR_SCHEME') == 'light':
                image_wc_close.set_from_paintable(paintable_wc_br_close_light)
                image_wc_min.set_from_paintable(paintable_wc_br_min_light)
                image_wc_max.set_from_paintable(paintable_wc_br_max_light)
            else:
                image_wc_close.set_from_paintable(paintable_wc_br_close)
                image_wc_min.set_from_paintable(paintable_wc_br_min)
                image_wc_max.set_from_paintable(paintable_wc_br_max)

        elif wc_style == 'adwaita':
            wc_close.remove_css_class('wc_color')
            wc_minimize.remove_css_class('wc_color')
            wc_maximize.remove_css_class('wc_color')
            wc_close.remove_css_class('wc_mac')
            wc_minimize.remove_css_class('wc_mac')
            wc_maximize.remove_css_class('wc_mac')
            wc_close.set_child(image_wc_close)
            wc_minimize.set_child(image_wc_min)
            wc_maximize.set_child(image_wc_max)

            if swgs.colorscheme == 'light' or getenv('SW_CUSTOM_WC_COLOR_SCHEME') == 'light':
                image_wc_close.set_from_paintable(paintable_wc_close_light)
                image_wc_min.set_from_paintable(paintable_wc_min_light)
                image_wc_max.set_from_paintable(paintable_wc_max_light)
            else:
                image_wc_close.set_from_paintable(paintable_wc_close)
                image_wc_min.set_from_paintable(paintable_wc_min)
                image_wc_max.set_from_paintable(paintable_wc_max)

        elif wc_style == 'macos':
            wc_close.remove_css_class('wc_color')
            wc_minimize.remove_css_class('wc_color')
            wc_maximize.remove_css_class('wc_color')
            wc_close.set_child(None)
            wc_minimize.set_child(None)
            wc_maximize.set_child(None)
            wc_close.add_css_class('wc_mac')
            wc_minimize.add_css_class('wc_mac')
            wc_maximize.add_css_class('wc_mac')

        else:
            wc_close.remove_css_class('wc_mac')
            wc_minimize.remove_css_class('wc_mac')
            wc_maximize.remove_css_class('wc_mac')
            wc_close.set_child(None)
            wc_minimize.set_child(None)
            wc_maximize.set_child(None)
            wc_close.add_css_class('wc_color')
            wc_minimize.add_css_class('wc_color')
            wc_maximize.add_css_class('wc_color')

    def check_parent_state():
        """___check_parent_window_state___"""

        clear_tmp()

        environ['ICON_POSITION'] = swgs.cfg['icon_position']
        environ['LAST_VIEW_PAGE'] = swgs.cfg['view_widget']
        environ['SW_HIDDEN_FILES'] = swgs.cfg['hidden_files']

        if (swgs.cfg['view_widget'] == vw_dict['shortcuts']
                or swgs.cfg['view_widget'] == vw_dict['startapp_page']):
            on_shortcuts()

        elif swgs.cfg['view_widget'] == vw_dict['files']:
            swgs.current_dir = swgs.cfg['current_dir']

            if Path(swgs.current_dir).exists():
                on_files(Path(swgs.current_dir))
            else:
                swgs.default_dir = swgs.cfg['default_dir']
                on_files(Path(swgs.default_dir))
        else:
            swgs.default_dir = swgs.cfg['default_dir']
            on_files(Path(swgs.default_dir))

        if swgs.cfg['view_mode'] == 'column':
            if scrolled_left_files.get_child().get_name() != 'left_column_view':
                add_column_view()
            else:
                scrolled_left_files.set_child(left_grid_view)

        if swgs.cfg['control_panel'] == 'hide':
            sidebar_revealer.set_reveal_child(False)

        elif swgs.cfg['control_panel'] == 'show':
            sidebar_revealer.set_reveal_child(True)

        if swgs.cfg.get('wc_style') is not None:
            environ['SW_WC_STYLE'] = swgs.cfg.get('wc_style')
            style = swgs.cfg.get('wc_style')

        if swgs.cfg['color_scheme'] == 'dark':
            btn_dark.set_active(True)

        if swgs.cfg['color_scheme'] == 'light':
            btn_light.set_active(True)

        if swgs.cfg['color_scheme'] == 'custom':
            btn_custom.set_active(True)

        if swgs.cfg['wc_color_scheme'] == 'light':
            environ['SW_CUSTOM_WC_COLOR_SCHEME'] = 'light'
        else:
            environ['SW_CUSTOM_WC_COLOR_SCHEME'] = 'dark'

        icon_color = 'blue'
        if swgs.cfg.get('icon_color') is not None:
            icon_color = swgs.cfg['icon_color']

        environ['SW_ICON_COLOR'] = f'{icon_color}'

        if swgs.cfg['icons'] == 'custom':
            sys_icons = get_sys_icons()
            environ['SW_ICON_THEME'] = 'custom'
            gtk_settings.props.gtk_icon_theme_name = f"{sys_icons}"
            print(f'{tc.VIOLET}SYSTEM_ICONS: {tc.BLUE}{sys_icons}')
        else:
            environ['SW_ICON_THEME'] = 'builtin'
            gtk_settings.props.gtk_icon_theme_name = f"SWSuru++-{icon_color}"
            print(f'{tc.VIOLET} BUILTIN_ICONS: {tc.BLUE}SWSuru++-{icon_color}')

        if swgs.cfg['auto_hide_top_header'] == 'on':
            environ['SW_AUTO_HIDE_TOP_HEADER'] = '1'
            top_headerbar_revealer.set_reveal_child(False)
        else:
            environ['SW_AUTO_HIDE_TOP_HEADER'] = '0'
            top_headerbar_revealer.set_reveal_child(True)

        if swgs.cfg['auto_hide_bottom_header'] == 'on':
            environ['SW_AUTO_HIDE_BOTTOM_HEADER'] = '1'
            bottom_headerbar_revealer.set_reveal_child(False)
        else:
            environ['SW_AUTO_HIDE_BOTTOM_HEADER'] = '0'
            bottom_headerbar_revealer.set_reveal_child(True)

        if swgs.cfg.get('terminal_handle_position'):
            environ['TERMINAL_HANDLE_POSITION'] = str(swgs.cfg['terminal_handle_position'])

        #"WenQuanYi Micro Hei 12" #"Sans 12"
        gtk_settings.props.gtk_font_name = "Noto Sans 12"
        gtk_settings.props.gtk_application_prefer_dark_theme = True
        gtk_settings.props.gtk_theme_name = "Sw-dark"

    def on_write_parent_state(_self):
        """___write parent window state in config___"""

        parent.set_hide_on_close(True)
        return write_parent_state()

    def write_parent_state():
        """___write parent window state in config___"""

        clear_tmp()

        h = parent.get_height()
        w = parent.get_width()

        if Path(get_parent_file().get_path()) == sw_shortcuts:
            swgs.cfg['current_dir'] = get_parent_file().get_path()
            if main_stack.get_visible_child_name() == 'startapp_page':
                swgs.cfg['view_widget'] = vw_dict['startapp_page']
            else:
                swgs.cfg['view_widget'] = vw_dict['shortcuts']
        else:
            swgs.cfg['current_dir'] = get_parent_file().get_path()
            if main_stack.get_visible_child_name() == 'startapp_page':
                swgs.cfg['view_widget'] = vw_dict['startapp_page']
            else:
                swgs.cfg['view_widget'] = vw_dict['files']

        if scrolled_left_files.get_child().get_name() == 'left_column_view':
            swgs.cfg['view_mode'] = 'column'
        else:
            swgs.cfg['view_mode'] = 'grid'

        if not sidebar_revealer.get_reveal_child():
            swgs.cfg['control_panel'] = 'hide'
        else:
            swgs.cfg['control_panel'] = 'show'

        if w != 0:
            swgs.cfg['width'] = w

        if h != 0:
            swgs.cfg['height'] = h

        if getenv('SW_OPENGL') == '1':
            swgs.cfg['opengl_bg'] = 'True'
        else:
            swgs.cfg['opengl_bg'] = 'False'

        swgs.cfg['icon_size'] = round(btn_scale_icons.get_value())
        swgs.cfg['shortcut_size'] = round(btn_scale_shortcuts.get_value())
        swgs.cfg['sound'] = 'off'

        if getenv('SW_ICON_THEME'):
            swgs.cfg['icons'] = str(getenv('SW_ICON_THEME'))

        if getenv('SW_ICON_COLOR'):
            swgs.cfg['icon_color'] = str(getenv('SW_ICON_COLOR'))

        if getenv('TERMINAL_HANDLE_POSITION'):
            swgs.cfg['terminal_handle_position'] = int(getenv('TERMINAL_HANDLE_POSITION'))
        else:
            swgs.cfg['terminal_handle_position'] = int(swgs.height*0.5)

        if getenv('SW_WC_STYLE'):
            swgs.cfg['wc_style'] = str(getenv('SW_WC_STYLE'))

        if getenv('SW_RENDERER'):
            swgs.cfg['renderer'] = str(getenv('SW_RENDERER'))

        write_json_data(sw_exe_data_json, exe_data)
        return write_menu_conf(swgs.cfg)

    def check_file_monitor_event():
        """___update file grid view on file monitor events___"""

        path_type = 'None'

        if len(swgs.f_mon_event) != 0:
            print(swgs.f_mon_event)

            if swgs.f_mon_event[0].get_parent() is not None:
                if swgs.f_mon_event[0].get_parent().get_path() is not None:
                    event_path = swgs.f_mon_event[0].get_parent().get_path()
                    path_type = 'file'
                elif swgs.f_mon_event[0].get_parent().get_uri() is not None:
                    event_path = swgs.f_mon_event[0].get_parent().get_uri()
                    path_type = 'uri'
                else:
                    event_path = None
            else:
                event_path = None

            if swgs.f_mon_event[1] == Gio.FileMonitorEvent.CHANGED:
                swgs.f_mon_event.clear()

            elif (swgs.f_mon_event[1] == Gio.FileMonitorEvent.ATTRIBUTE_CHANGED
                    or swgs.f_mon_event[1] == Gio.FileMonitorEvent.CHANGES_DONE_HINT):
                if event_path is not None:
                    paned_store = get_list_store()
                    if paned_store is not None:
                        for n, x in enumerate(paned_store):
                            if x is not None:
                                if str(x.get_path()) == str(event_path):
                                    paned_store.remove(n)
                                    update_view(paned_store, x)
                                    swgs.f_mon_event.clear()
                                    break
                                else:
                                    swgs.f_mon_event.clear()
                                    if path_type == 'file':
                                        update_grid_view(event_path)
                                    else:
                                        update_grid_view_uri(event_path)
                    else:
                        pass
                else:
                    pass
            else:
                if event_path is not None:
                    swgs.f_mon_event.clear()
                    if path_type == 'file':
                        update_grid_view(event_path)
                    else:
                        update_grid_view_uri(event_path)
                else:
                    pass

            if scrolled_gvol.get_child() is not None:
                update_gvolume()

            swgs.f_mon_event.clear()

        return True

    def check_reveal_flap():
        """___Сhecking the size and position status of sidebar widgets___"""

        if main_stack.get_visible_child() == files_view_grid:
            btn_gmount.set_visible(True)
            btn_bookmarks.set_visible(True)
            btn_playlist.set_visible(True)
            btn_popover_scale.set_visible(True)

            if Path(entry_path.get_name()) == sw_shortcuts:
                btn_icon_position.set_visible(True)
            else:
                btn_icon_position.set_visible(False)

            if terminal_revealer.get_reveal_child() and scrolled_gvol.get_visible():
                environ['TERMINAL_HANDLE_POSITION'] = str(files_view_grid.get_position())
        else:
            btn_gmount.set_visible(False)
            btn_bookmarks.set_visible(False)
            btn_playlist.set_visible(False)
            btn_popover_scale.set_visible(False)
            btn_icon_position.set_visible(False)

        swgs.width = parent.get_width()
        swgs.height = parent.get_height()

        return True

    def check_volume():
        """___Сhecking the playing media file volume value___"""

        if len(vol_dict) > 0:
            volume = vol_dict.get('volume') if vol_dict.get('volume') else 1.0
            if volume <= 0.0:
                volume = 0.0
            if volume >= 1.0:
                volume = 1.0
            if media_file.get_playing() and volume != media_file.get_volume():
                media_file.set_volume(volume)
                print(f'{tc.GREEN}SW_MEDIA_VOLUME:{tc.END}', volume)
        return True

    def get_sidebar_position(_self, widget, allocation):
        """___get overlay child position___"""

        sidebar_scale_width = 320 * xft_dpi
        relative_parent_width = parent.get_width() * 0.2

        if relative_parent_width > sidebar_scale_width:
            if relative_parent_width < 640:
                sidebar_width = relative_parent_width
                stack_sidebar.set_size_request(sidebar_width, -1)
            else:
                sidebar_width = 640
                stack_sidebar.set_size_request(sidebar_width, -1)
        else:
            sidebar_width = sidebar_scale_width
            stack_sidebar.set_size_request(sidebar_scale_width, -1)

        if allocation.width <= 960:
            if not swgs.flap_locked:
                widget.set_reveal_child(False)
            empty_box.set_size_request(0, -1)
            empty_box.set_visible(False)

        elif allocation.width > 960:
            if not swgs.flap_locked:
                widget.set_reveal_child(True)
            if sidebar_revealer.get_reveal_child():
                swgs.flap_locked = False
                empty_box.set_size_request(sidebar_width, -1)
                empty_box.set_visible(True)
            else:
                empty_box.set_size_request(0, -1)
                empty_box.set_visible(False)

    def on_parent_close(_self):
        """___window_close___"""

        parent.close()

    def on_parent_minimize(_self):
        """___window_minimize___"""

        parent.minimize()

    def on_parent_maximize(_self):
        """___window_maximize___"""

        if parent.is_maximized():
            parent.unmaximize()
        else:
            parent.maximize()

    def on_parent_fullscreen():
        """___window_fullscreen___"""

        if parent.is_fullscreen():
            parent.unfullscreen()
        else:
            #parent.fullscreen()
            parent.fullscreen_on_monitor(monitor)

    def on_show_hotkeys():
        """___show hotkeys settings window___"""

        grid_keys_0 = Gtk.Grid(css_name='sw_grid')
        grid_keys_0.set_column_spacing(8)
        grid_keys_0.set_row_spacing(8)

        grid_keys_1 = Gtk.Grid(css_name='sw_grid')
        grid_keys_1.set_column_spacing(8)
        grid_keys_1.set_row_spacing(8)

        keys_flow_child_0 = Gtk.FlowBoxChild(css_name='sw_box_view')
        keys_flow_child_0.set_child(grid_keys_0)
        keys_flow_child_1 = Gtk.FlowBoxChild(css_name='sw_box_view')
        keys_flow_child_1.set_child(grid_keys_1)

        keys_flow = Gtk.FlowBox(
                                css_name='sw_box',
                                margin_bottom=16,
                                column_spacing=8,
                                row_spacing=8,
                                homogeneous=True,
                                min_children_per_line=2,
                                max_children_per_line=4,
                                )
        keys_flow.append(keys_flow_child_0)
        keys_flow.append(keys_flow_child_1)

        count = -1
        for k, d in zip(hotkey_list, hotkey_desc):
            count += 1

            label_mod = Gtk.Label(css_name='sw_label', label=k[0])
            label_x = Gtk.Label(css_name='sw_label', label=k[1])
            label_y = Gtk.Label(css_name='sw_label', label=k[2])

            key_mod = Gtk.Button(css_name='sw_action_row')
            key_mod.add_css_class('key')
            key_mod.set_sensitive(False)
            key_mod.set_size_request(72, -1)
            key_mod.set_child(label_mod)

            label_desc_x = Gtk.Label(
                                    css_name='sw_label_desc',
                                    label=d.capitalize(),
                                    xalign=0,
                                    wrap=True,
                                    natural_wrap_mode=True
                                    )
            label_desc_x.set_xalign(0)

            if k[2] == '':
                plus_y = Gtk.Label(css_name='sw_label', label='')
                key_y = Gtk.Label(css_name='sw_label', label='')
            else:
                plus_y = Gtk.Label(css_name='sw_label', label='+')
                key_y = Gtk.Button(css_name='sw_action_row')
                key_y.add_css_class('key')
                key_y.set_size_request(72, -1)
                key_y.set_sensitive(False)
                key_y.set_child(label_y)

            if k[1] == '':
                plus_x = Gtk.Label(css_name='sw_label', label='')
                key_x = Gtk.Label(css_name='sw_label', label='')
            else:
                plus_x = Gtk.Label(css_name='sw_label', label='+')
                key_x = Gtk.Button(css_name='sw_action_row')
                key_x.add_css_class('key')
                key_x.set_size_request(72, -1)
                key_x.set_sensitive(False)
                key_x.set_child(label_x)

            if count < len(hotkey_list) / 2:
                grid_keys_0.attach(key_mod, 0, count, 1, 1)
                grid_keys_0.attach(plus_x, 1, count, 1, 1)
                grid_keys_0.attach(key_x, 2, count, 1, 1)
                grid_keys_0.attach(plus_y, 3, count, 1, 1)
                grid_keys_0.attach(key_y, 4, count, 1, 1)
                grid_keys_0.attach(label_desc_x, 5, count, 1, 1)
            else:
                grid_keys_1.attach(key_mod, 0, count, 1, 1)
                grid_keys_1.attach(plus_x, 1, count, 1, 1)
                grid_keys_1.attach(key_x, 2, count, 1, 1)
                grid_keys_1.attach(plus_y, 3, count, 1, 1)
                grid_keys_1.attach(key_y, 4, count, 1, 1)
                grid_keys_1.attach(label_desc_x, 5, count, 1, 1)

        title_hotkeys = Gtk.Label(
                                css_name='sw_label_title',
                                label=str_title_hotkeys,
                                xalign=0,
                                margin_top=8,
                                margin_start=4,
                                )
        subtitle_hotkeys = Gtk.Label(
                                css_name='sw_label_info',
                                label=str_subtitle_hotkeys,
                                xalign=0,
                                margin_start=4,
                                )
        group_hotkeys = Gtk.Box(
                                css_name='sw_pref_box',
                                orientation=Gtk.Orientation.VERTICAL,
                                spacing=4,
                                margin_start=16,
                                margin_end=16,
                                )
        group_hotkeys.append(title_hotkeys)
        group_hotkeys.append(subtitle_hotkeys)
        group_hotkeys.append(keys_flow)

        keyboard_scrolled = Gtk.ScrolledWindow(css_name='sw_scrolled_view', child=group_hotkeys)
        keyboard_scrolled.set_size_request(-1, 688)

        pad_flow = Gtk.FlowBox(
            css_name='sw_box', margin_bottom=16, column_spacing=8, row_spacing=8,
            homogeneous=True, min_children_per_line=2, max_children_per_line=4,
        )
        count = -1
        for pad, desc in hotpad_dict.items():
            count += 1
            pad_mod = (
                pad[0].replace('_', ' ').replace('rt', '').replace('lt', '')
                .replace('up', '').replace('dn', '')
            )
            box_hotpad = Gtk.Box(
                css_name='sw_box', orientation=Gtk.Orientation.HORIZONTAL,
                spacing=8,
            )
            label_mod = Gtk.Label(css_name='sw_label', label=pad_mod)
            image_mod = Gtk.Image(css_name='sw_image')
            image_mod.set_pixel_size(32)
            image_mod.set_from_file(controller_icons.get(pad[0]))

            box_mod = Gtk.Box(
                css_name='sw_action_row', orientation=Gtk.Orientation.HORIZONTAL,
                spacing=8,
            )
            box_mod.set_sensitive(False)
            box_mod.add_css_class('key')
            box_mod.set_size_request(72, -1)
            box_mod.append(image_mod)
            #box_mod.append(label_mod)

            box_hotpad.append(box_mod)

            if len(pad) >= 2:
                pad0 = (
                    pad[1].replace('_', ' ').replace('rt', '').replace('lt', '')
                    .replace('up', '').replace('dn', '')
                )
                label_plus0 = Gtk.Label(css_name='sw_label', label='+')
                label_pad0 = Gtk.Label(css_name='sw_label', label=pad0)
                image_pad0 = Gtk.Image(css_name='sw_image')
                image_pad0.set_pixel_size(32)
                icon = controller_icons.get(pad[1])
                image_pad0.set_from_file(icon)

                box_pad0 = Gtk.Box(
                    css_name='sw_action_row', orientation=Gtk.Orientation.HORIZONTAL,
                    spacing=8,
                )
                box_pad0.set_sensitive(False)
                box_pad0.add_css_class('key')
                box_pad0.set_size_request(72, -1)
                box_pad0.append(image_pad0)
                #box_pad0.append(label_pad0)

                box_hotpad.append(label_plus0)
                box_hotpad.append(box_pad0)

            if len(pad) >= 3:
                pad1 = (
                    pad[2].replace('_', ' ').replace('rt', '').replace('lt', '')
                    .replace('up', '').replace('dn', '')
                )
                label_plus1 = Gtk.Label(css_name='sw_label', label='+')
                label_pad1 = Gtk.Label(css_name='sw_label', label=pad1)
                image_pad1 = Gtk.Image(css_name='sw_image')
                image_pad1.set_pixel_size(32)
                icon = controller_icons.get(pad[2])
                image_pad1.set_from_file(icon)

                box_pad1 = Gtk.Box(
                    css_name='sw_action_row', orientation=Gtk.Orientation.HORIZONTAL,
                    spacing=8,
                )
                box_pad1.set_sensitive(False)
                box_pad1.add_css_class('key')
                box_pad1.set_size_request(72, -1)
                box_pad1.append(image_pad1)
                #box_pad1.append(label_pad1)

                box_hotpad.append(label_plus1)
                box_hotpad.append(box_pad1)

            label_desc = Gtk.Label(
                css_name='sw_label_desc', label=desc.capitalize(), xalign=0,
                wrap=True, natural_wrap_mode=True
            )
            box = Gtk.Box(
                css_name='sw_box', orientation=Gtk.Orientation.HORIZONTAL,
                spacing=8,
            )
            box.append(box_hotpad)
            box.append(label_desc)

            pad_flow_child = Gtk.FlowBoxChild(css_name='sw_box_view')
            pad_flow_child.set_child(box)
            pad_flow.append(pad_flow_child)

        title_controller = Gtk.Label(
                                css_name='sw_label_title',
                                label=str_title_hotkeys,
                                xalign=0,
                                margin_top=8,
                                margin_start=4,
                                )
        subtitle_controller = Gtk.Label(
                                css_name='sw_label_info',
                                label=str_subtitle_hotkeys,
                                xalign=0,
                                margin_start=4,
                                )
        group_controller = Gtk.Box(
                                css_name='sw_pref_box',
                                orientation=Gtk.Orientation.VERTICAL,
                                spacing=4,
                                margin_start=16,
                                margin_end=16,
                                )
        group_controller.append(title_controller)
        group_controller.append(subtitle_controller)
        group_controller.append(pad_flow)

        controller_scrolled = Gtk.ScrolledWindow(css_name='sw_scrolled_view', child=group_controller)
        controller_scrolled.set_size_request(-1, 688)

        stack = Gtk.Stack(css_name='sw_stack', transition_duration=250,
            transition_type=Gtk.StackTransitionType.SLIDE_LEFT_RIGHT
        )
        stack.add_titled(keyboard_scrolled, 'hotkeys', msg.tt_dict['keyboard'])
        stack.add_titled(controller_scrolled, 'controller', msg.tt_dict['controller'])

        stack_switcher = Gtk.StackSwitcher(css_name='sw_stackswitcher', stack=stack)
        hotkey_box = Gtk.Box(
            css_name='sw_box', orientation=Gtk.Orientation.VERTICAL, vexpand=True
        )
        hotkey_box.append(stack_switcher)
        hotkey_box.append(stack)

        win = Gtk.Window(css_name='sw_window', application=swgs)

        close = Gtk.Button(css_name='sw_wc_close', valign=Gtk.Align.CENTER)
        close.connect('clicked', cb_btn_close, win)

        headerbar = Gtk.HeaderBar(css_name='sw_header_top', show_title_buttons=False)
        headerbar.pack_end(close)

        win.remove_css_class('background')
        win.add_css_class('sw_background')
        win.set_titlebar(headerbar)
        win.set_default_size(1248, 688)
        win.set_transient_for(parent)
        win.set_modal(True)
        win.set_child(hotkey_box)
        win.present()

    def cb_btn_close(_self, win):
        """___close hotkeys settings window___"""

        win.close()

    def cb_bookmark_activate(self, position):
        """___open bookmark directory in file manager___"""

        string_path = self.get_model().get_item(position).get_string()
        file = Gio.File.new_for_commandline_arg(string_path)

        if file.get_path() is None:
            update_grid_view_uri(file.get_uri())
        else:
            on_files(file.get_path())

    def get_gl_image():
        """___Get opengl background image___"""
        gl_image = None
        if sw_background.exists():
            for x in sw_background.iterdir():
                if x.is_file():
                    for s in ['.jpeg', '.jpg', '.png', '.tiff']:
                        if x.suffix == s:
                            gl_image = GdkPixbuf.Pixbuf.new_from_file(f'{x}')
        return gl_image

    def on_shutdown():
        """___Shutdown all process and close application___"""

        #run(f"{sw_scripts}/sw_stop", shell=True)
        swgs.connection.flush(callback=flush_connection, user_data=None)

    def add_overlay_prefix_tools():
        """___build prefix tools menu___"""

        grid_prefix_tools = Gtk.Grid(css_name='sw_grid', name='grid_prefix_tools')
        grid_prefix_tools.set_vexpand(True)
        grid_prefix_tools.set_row_spacing(8)

        count = 1
        for name, icon in zip(prefix_tools_labels, prefix_tools_icons):
            count += 1

            image = Gtk.Image(css_name='sw_image')
            image.set_from_file(icon)
            label = Gtk.Label(
                            css_name='sw_label', label=name,
                            ellipsize=Pango.EllipsizeMode.END
            )
            box_pfx_tools = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            box_pfx_tools.append(image)
            box_pfx_tools.append(label)

            btn = Gtk.Button(css_name='sw_button', hexpand=True)
            btn.set_name(name)
            btn.set_child(box_pfx_tools)
            btn.connect('clicked', cb_btn_prefix_tools)

            grid_prefix_tools.attach(btn, 0, count, 1, 1)

        title_frame_prefix_tools = Gtk.Label(
                                        css_name='sw_label_title',
                                        label=btn_dict['prefix_tools'],
                                        margin_bottom=8,
        )
        frame_box_prefix_tools = Gtk.Frame(
                                css_name='sw_box',
                                label_widget=title_frame_prefix_tools,
                                child=grid_prefix_tools,
        )
        return frame_box_prefix_tools

    def add_overlay_wine_tools():
        """___build wine tools menu___"""

        grid_wine_tools = Gtk.Grid(css_name='sw_grid', name='grid_wine_tools')
        grid_wine_tools.set_vexpand(True)
        grid_wine_tools.set_row_spacing(8)

        count = 1
        for name, icon in zip(wine_tools_labels, wine_tools_icons):
            count += 1

            image = Gtk.Image(css_name='sw_image')
            image.set_from_file(icon)
            label = Gtk.Label(
                            css_name='sw_label', label=name,
                            ellipsize=Pango.EllipsizeMode.END
            )
            box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            box.append(image)
            box.append(label)

            btn = Gtk.Button(css_name='sw_button', hexpand=True)
            btn.set_name(name)
            btn.set_child(box)
            btn.connect('clicked', cb_btn_wine_tools)

            grid_wine_tools.attach(btn, 0, count, 1, 1)

        title_frame_wine_tools = Gtk.Label(
                                        css_name='sw_label_title',
                                        label=btn_dict['wine_tools'],
                                        margin_bottom=8,
        )
        frame_box_wine_tools = Gtk.Frame(
                                css_name='sw_box',
                                label_widget=title_frame_wine_tools,
                                child=grid_wine_tools,
        )
        return frame_box_wine_tools

    def add_files_info():
        """___build files info widgets___"""

        swgs.label_file_name = Gtk.Label(
                                    css_name='sw_label_desc',
                                    wrap=True,
                                    wrap_mode=Pango.WrapMode.CHAR,
                                    natural_wrap_mode=True,
                                    selectable=True,
        )
        swgs.label_file_mime = Gtk.Label(
                                    css_name='sw_label_desc',
                                    wrap=True,
                                    natural_wrap_mode=True,
                                    selectable=True,
        )
        swgs.label_file_size = Gtk.Label(
                                    css_name='sw_label_desc',
                                    wrap=True,
                                    natural_wrap_mode=True,
                                    selectable=True,
        )
        swgs.label_disk_size = Gtk.Label(
                                    css_name='sw_label_desc',
                                    wrap=True,
                                    natural_wrap_mode=True,
                                    selectable=True,
        )
        swgs.box_header_info = Gtk.Box(
                                css_name='sw_box_row',
                                orientation=Gtk.Orientation.VERTICAL,
                                spacing=4
        )
        swgs.image_file_info = Gtk.Image(css_name='sw_image')
        swgs.image_file_info.set_margin_start(32)
        swgs.image_file_info.set_margin_end(32)
        swgs.image_file_info.set_margin_bottom(16)

        swgs.box_header_info.append(swgs.image_file_info)
        swgs.box_header_info.append(swgs.label_file_name)
        swgs.box_header_info.append(swgs.label_file_mime)
        swgs.box_header_info.append(swgs.label_file_size)
        swgs.box_header_info.append(swgs.label_disk_size)

        swgs.box_file_path = Gtk.Box(
                                css_name='sw_box_row',
                                orientation=Gtk.Orientation.VERTICAL,
                                spacing=4
                                )

        swgs.title_file_path = Gtk.Label(
                                css_name='sw_label',
                                xalign=0,
                                label=msg.msg_dict['path']
                                )

        swgs.label_file_path = Gtk.Label(
                                css_name='sw_label_desc',
                                wrap=True,
                                wrap_mode=Pango.WrapMode.CHAR,
                                natural_wrap_mode=True,
                                xalign=0,
                                selectable=True
                                )

        swgs.box_file_path.append(swgs.title_file_path)
        swgs.box_file_path.append(swgs.label_file_path)

        swgs.title_file_uid = Gtk.Label(
                                css_name='sw_label',
                                xalign=0,
                                label=msg.msg_dict['user_group']
                                )

        swgs.title_file_rw = Gtk.Label(
                                css_name='sw_label',
                                xalign=0,
                                label=msg.msg_dict['access']
                                )

        swgs.title_file_modified = Gtk.Label(
                                css_name='sw_label',
                                xalign=0,
                                label=msg.msg_dict['file_modified']
                                )

        swgs.title_file_created = Gtk.Label(
                                css_name='sw_label',
                                xalign=0,
                                label=msg.msg_dict['file_created']
                                )

        swgs.label_file_uid = Gtk.Label(
                                css_name='sw_label_desc',
                                wrap=True,
                                natural_wrap_mode=True,
                                xalign=0
                                )

        swgs.label_file_gid = Gtk.Label(
                                css_name='sw_label_desc',
                                wrap=True,
                                natural_wrap_mode=True,
                                xalign=0
                                )

        swgs.label_file_rw = Gtk.Label(
                                css_name='sw_label_desc',
                                wrap=True,
                                natural_wrap_mode=True,
                                xalign=0
                                )

        swgs.label_file_modified = Gtk.Label(
                                css_name='sw_label_desc',
                                wrap=True,
                                natural_wrap_mode=True,
                                xalign=0
                                )
        swgs.label_file_created = Gtk.Label(
                                css_name='sw_label_desc',
                                wrap=True,
                                natural_wrap_mode=True,
                                xalign=0
                                )

        swgs.box_file_info = Gtk.Box(
                                css_name='sw_box_row',
                                orientation=Gtk.Orientation.VERTICAL,
                                spacing=4
                                )

        swgs.box_file_info.append(swgs.title_file_uid)
        swgs.box_file_info.append(swgs.label_file_uid)
        swgs.box_file_info.append(swgs.title_file_rw)
        swgs.box_file_info.append(swgs.label_file_rw)
        swgs.box_file_info.append(swgs.title_file_modified)
        swgs.box_file_info.append(swgs.label_file_modified)
        swgs.box_file_info.append(swgs.title_file_created)
        swgs.box_file_info.append(swgs.label_file_created)

        swgs.box_file_execute = Gtk.Box(
                                css_name='sw_box_row',
                                orientation=Gtk.Orientation.HORIZONTAL,
                                spacing=4
                                )
        swgs.title_file_execute = Gtk.Label(
                                css_name='sw_label',
                                xalign=0,
                                label=msg.msg_dict['file_executable'].title(),
                                hexpand=True
                                )
        swgs.switch_file_execute = Gtk.Switch(css_name='sw_switch', margin_end=4)
        swgs.switch_file_execute.set_halign(Gtk.Align.END)
        swgs.switch_file_execute.set_valign(Gtk.Align.CENTER)
        swgs.switch_file_execute.connect('state-set', on_switch_file_exec)

        swgs.box_file_execute.append(swgs.title_file_execute)
        swgs.box_file_execute.append(swgs.switch_file_execute)

        swgs.grid_files_info = Gtk.Grid()
        swgs.grid_files_info.set_vexpand(True)
        swgs.grid_files_info.set_row_spacing(10)
        swgs.grid_files_info.set_margin_top(16)
        swgs.grid_files_info.set_margin_bottom(16)
        swgs.grid_files_info.set_margin_start(16)
        swgs.grid_files_info.set_margin_end(16)
        swgs.grid_files_info.set_halign(Gtk.Align.CENTER)

        swgs.grid_files_info.attach(swgs.box_header_info, 0, 0, 1, 1)
        swgs.grid_files_info.attach(swgs.box_file_path, 0, 1, 1, 1)
        swgs.grid_files_info.attach(swgs.box_file_info, 0, 2, 1, 1)
        swgs.grid_files_info.attach(swgs.box_file_execute, 0, 3, 1, 1)

        scrolled_files_info.set_child(swgs.grid_files_info)

    def add_about():
        """___build about menu widgets___"""

        paintable_about = Gtk.IconPaintable.new_for_file(
                            Gio.File.new_for_path(IconPath.icon_app), 256, 1,
        )
        about_picture = Gtk.Picture(css_name='sw_picture')
        about_picture.set_margin_start(32)
        about_picture.set_margin_end(32)
        about_picture.set_size_request(-1, 32)
        about_picture.set_paintable(paintable_about)

        about_name = Gtk.Label(
                            css_name='sw_label',
                            label=sw_program_name
                            )
        swgs.about_version = Gtk.Label(css_name='sw_label', label=str_sw_version)

        box_about_version = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        box_about_version.set_spacing(12)
        box_about_version.append(about_picture)
        box_about_version.append(about_name)
        box_about_version.append(swgs.about_version)

        pref_group_about = Gtk.Box(
                                css_name='sw_preferencesgroup',
                                orientation=Gtk.Orientation.VERTICAL,
                                spacing=8
                                )
        pref_group_about.set_size_request(280, -1)

        grid_about = Gtk.Grid()
        grid_about.set_vexpand(True)
        grid_about.set_row_spacing(10)
        grid_about.set_margin_top(16)
        grid_about.set_margin_bottom(16)
        grid_about.set_margin_start(16)
        grid_about.set_margin_end(16)
        grid_about.set_halign(Gtk.Align.CENTER)
        grid_about.attach(box_about_version, 0, 0, 1, 1)
        grid_about.attach(pref_group_about, 0, 1, 1, 1)

        swgs.stack_about = Gtk.Stack()
        swgs.stack_about.set_transition_duration(250)
        swgs.stack_about.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)

        image_back_about = Gtk.Image()
        image_back_about.set_from_file(IconPath.icon_back)

        swgs.label_back_about = Gtk.Label(css_name='sw_label')

        box_btn_back_about = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        box_btn_back_about.set_spacing(8)
        box_btn_back_about.append(image_back_about)
        box_btn_back_about.append(swgs.label_back_about)

        swgs.btn_back_about = Gtk.Button(css_name='sw_button')
        swgs.btn_back_about.set_size_request(280, -1)
        swgs.btn_back_about.set_child(box_btn_back_about)
        swgs.btn_back_about.connect('clicked', cb_btn_back_about)

        count = 0
        for name, widget in zip(about_labels, about_widgets):
            count += 1
            if count < 7:
                label_a = Gtk.Label(
                                    css_name='sw_label',
                                    label=name,
                                    xalign=0.0
                )
                btn_a = Gtk.Button(css_name='sw_button')
                btn_a.set_child(label_a)
                btn_a.set_name(widget)
                btn_a.connect('clicked', cb_btn_about)

                pref_group_about.append(btn_a)

                grid_about_content = Gtk.Grid()
                grid_about_content.set_row_spacing(10)
                grid_about_content.set_vexpand(True)
                grid_about_content.set_margin_top(16)
                grid_about_content.set_margin_start(16)
                grid_about_content.set_margin_end(16)
                grid_about_content.set_margin_bottom(16)
                grid_about_content.set_halign(Gtk.Align.CENTER)
                grid_about_content.set_name(widget)

                swgs.stack_about.add_named(grid_about_content, widget)

        grid_about_news = swgs.stack_about.get_child_by_name(list(about_dict)[0])
        grid_about_details = swgs.stack_about.get_child_by_name(list(about_dict)[1])
        grid_about_authors = swgs.stack_about.get_child_by_name(list(about_dict)[2])
        grid_about_license = swgs.stack_about.get_child_by_name(list(about_dict)[3])
        grid_about_donation = swgs.stack_about.get_child_by_name(list(about_dict)[4])
        # grid_about_update = swgs.stack_about.get_child_by_name(list(about_dict)[5])

        format_news = '\n \u2022 '.join([s for s in str_news.splitlines()])
        label_news = Gtk.Label(css_name='sw_label_desc', label=format_news)
        label_news.set_xalign(0)
        label_news.set_wrap(True)
        label_news.set_wrap_mode(Pango.WrapMode.WORD)

        swgs.title_news = Gtk.Label(
                                css_name='sw_label',
                                label=sw_program_name + ' ' + str_sw_version,
                                xalign=0.0,
                                )

        pref_group_about_news = Gtk.Box(
                                        css_name='sw_box_row',
                                        orientation=Gtk.Orientation.VERTICAL
                                        )
        pref_group_about_news.set_size_request(280, -1)
        pref_group_about_news.append(swgs.title_news)
        pref_group_about_news.append(label_news)

        label_btn_news = Gtk.Label(
            css_name='sw_label', label=about_dict['about_news']
        )
        btn_link_news = Gtk.LinkButton(css_name='sw_link')
        btn_link_news.set_child(label_btn_news)
        btn_link_news.connect('activate-link', cb_btn_news)

        grid_about_news.attach(pref_group_about_news, 0, 1, 1, 1)
        grid_about_news.attach(btn_link_news, 0, 2, 1, 1)

        image_btn_website = Gtk.Image(css_name='sw_image')
        image_btn_website.set_from_file(IconPath.icon_global)

        label_btn_website = Gtk.Label(
                                    css_name='sw_label',
                                    label=about_dict['about_website']
                                    )
        label_btn_website.set_xalign(0)

        box_btn_website = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        box_btn_website.set_spacing(8)
        box_btn_website.append(image_btn_website)
        box_btn_website.append(label_btn_website)

        btn_website = Gtk.LinkButton(css_name='sw_link')
        btn_website.set_child(box_btn_website)
        btn_website.connect('activate-link', cb_btn_website)

        image_btn_github = Gtk.Image(css_name='sw_image')
        image_btn_github.set_from_file(IconPath.icon_github)

        label_btn_github = Gtk.Label(
                                    css_name='sw_label',
                                    label=about_dict['about_github']
                                    )
        label_btn_github.set_xalign(0)

        box_btn_github = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        box_btn_github.set_spacing(8)
        box_btn_github.append(image_btn_github)
        box_btn_github.append(label_btn_github)

        btn_github = Gtk.LinkButton(css_name='sw_link')
        btn_github.set_child(box_btn_github)
        btn_github.connect('activate-link', cb_btn_github)

        image_btn_discord = Gtk.Image()
        image_btn_discord.set_from_file(IconPath.icon_discord)

        label_btn_discord = Gtk.Label(
                                    css_name='sw_label',
                                    label=about_dict['about_discord']
                                    )
        label_btn_discord.set_xalign(0)

        box_btn_discord = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        box_btn_discord.set_spacing(8)
        box_btn_discord.append(image_btn_discord)
        box_btn_discord.append(label_btn_discord)

        btn_discord = Gtk.LinkButton(css_name='sw_link')
        btn_discord.set_child(box_btn_discord)
        btn_discord.connect('activate-link', cb_btn_discord)

        image_btn_telegram = Gtk.Image()
        image_btn_telegram.set_from_file(IconPath.icon_telegram)

        label_btn_telegram = Gtk.Label(
                                    css_name='sw_label',
                                    label=about_dict['about_telegram']
                                    )
        label_btn_telegram.set_xalign(0)

        box_btn_telegram = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        box_btn_telegram.set_spacing(8)
        box_btn_telegram.append(image_btn_telegram)
        box_btn_telegram.append(label_btn_telegram)

        btn_telegram = Gtk.LinkButton(css_name='sw_link')
        btn_telegram.set_child(box_btn_telegram)
        btn_telegram.connect('activate-link', cb_btn_telegram)

        label_details = Gtk.Label(css_name='sw_label_desc', label=str_about)
        label_details.set_xalign(0)
        label_details.set_wrap(True)
        label_details.set_wrap_mode(Pango.WrapMode.WORD)

        title_details = Gtk.Label(
                                css_name='sw_label',
                                label=sw_program_name,
                                )
        title_details.set_xalign(0)

        pref_group_about_details = Gtk.Box(
                                        css_name='sw_box_row',
                                        orientation=Gtk.Orientation.VERTICAL
                                        )
        pref_group_about_details.set_size_request(280, -1)
        pref_group_about_details.append(title_details)
        pref_group_about_details.append(label_details)

        grid_about_details.attach(pref_group_about_details, 0, 1, 1, 1)
        grid_about_details.attach(btn_website, 0, 2, 1, 1)
        grid_about_details.attach(btn_github, 0, 3, 1, 1)
        grid_about_details.attach(btn_discord, 0, 4, 1, 1)
        grid_about_details.attach(btn_telegram, 0, 5, 1, 1)

        title_authors = Gtk.Label(
                                css_name='sw_label',
                                label=about_dict['about_authors']
                                )
        title_authors.set_xalign(0)

        label_authors = Gtk.Label(css_name='sw_label_desc', label=str_authors)
        label_authors.set_xalign(0)
        label_authors.set_wrap(True)
        label_authors.set_wrap_mode(Pango.WrapMode.WORD)

        title_coders = Gtk.Label(
                                css_name='sw_label',
                                label=about_dict['about_code']
                                )
        title_coders.set_xalign(0)

        label_coders = Gtk.Label(css_name='sw_label_desc', label=str_developers)
        label_coders.set_xalign(0)
        label_coders.set_wrap(True)
        label_coders.set_wrap_mode(Pango.WrapMode.WORD)

        title_members = Gtk.Label(
                                css_name='sw_label',
                                label=about_dict['about_members']
                                )
        title_members.set_xalign(0)

        label_members = Gtk.Label(css_name='sw_label_desc', label=str_members)
        label_members.set_xalign(0)
        label_members.set_wrap(True)
        label_members.set_wrap_mode(Pango.WrapMode.WORD)

        title_projects = Gtk.Label(
                                css_name='sw_label',
                                label=about_dict['about_projects']
                                )
        title_projects.set_xalign(0)

        label_projects = Gtk.Label(css_name='sw_label_desc', label=str_projects)
        label_projects.set_xalign(0)
        label_projects.set_wrap(True)
        label_projects.set_wrap_mode(Pango.WrapMode.WORD)

        title_design = Gtk.Label(
                                css_name='sw_label',
                                label=about_dict['about_design']
                                )
        title_design.set_xalign(0)

        label_design = Gtk.Label(css_name='sw_label_desc', label=str_design)
        label_design.set_xalign(0)
        label_design.set_wrap(True)
        label_design.set_wrap_mode(Pango.WrapMode.WORD)

        pref_group_about_authors = Gtk.Box(
                                        css_name='sw_box_row',
                                        orientation=Gtk.Orientation.VERTICAL
                                        )
        pref_group_about_authors.set_size_request(280, -1)
        pref_group_about_authors.append(title_authors)
        pref_group_about_authors.append(label_authors)

        pref_group_about_coders = Gtk.Box(
                                        css_name='sw_box_row',
                                        orientation=Gtk.Orientation.VERTICAL
                                        )
        pref_group_about_coders.set_size_request(280, -1)
        pref_group_about_coders.append(title_coders)
        pref_group_about_coders.append(label_coders)

        pref_group_about_members = Gtk.Box(
                                        css_name='sw_box_row',
                                        orientation=Gtk.Orientation.VERTICAL
                                        )
        pref_group_about_members.set_size_request(280, -1)
        pref_group_about_members.append(title_members)
        pref_group_about_members.append(label_members)

        pref_group_about_projects = Gtk.Box(
                                        css_name='sw_box_row',
                                        orientation=Gtk.Orientation.VERTICAL
                                        )
        pref_group_about_projects.set_size_request(280, -1)
        pref_group_about_projects.append(title_projects)
        pref_group_about_projects.append(label_projects)

        pref_group_about_design = Gtk.Box(
                                        css_name='sw_box_row',
                                        orientation=Gtk.Orientation.VERTICAL
                                        )
        pref_group_about_design.set_size_request(280, -1)
        pref_group_about_design.append(title_design)
        pref_group_about_design.append(label_design)

        grid_about_authors.attach(pref_group_about_authors, 0, 1, 1, 1)
        grid_about_authors.attach(pref_group_about_coders, 0, 2, 1, 1)
        grid_about_authors.attach(pref_group_about_members, 0, 3, 1, 1)
        grid_about_authors.attach(pref_group_about_projects, 0, 4, 1, 1)
        grid_about_authors.attach(pref_group_about_design, 0, 5, 1, 1)

        label_btn_license = Gtk.Label(
                                    css_name='sw_label',
                                    label=about_dict['about_license']
                                    )
        btn_license = Gtk.LinkButton(css_name='sw_link')
        btn_license.set_child(label_btn_license)
        btn_license.connect('activate-link', cb_btn_license)

        label_license = Gtk.Label(css_name='sw_label_desc', label=str_license)
        label_license.set_xalign(0)
        label_license.set_wrap(True)
        label_license.set_wrap_mode(Pango.WrapMode.WORD)

        title_license = Gtk.Label(
                                css_name='sw_label',
                                label=str_gpl
                                )
        title_license.set_xalign(0)

        pref_group_about_license = Gtk.Box(
                                        css_name='sw_box_row',
                                        orientation=Gtk.Orientation.VERTICAL
                                        )
        pref_group_about_license.set_size_request(280, -1)
        pref_group_about_license.append(title_license)
        pref_group_about_license.append(label_license)

        grid_about_license.attach(pref_group_about_license, 0, 1, 1, 1)
        grid_about_license.attach(btn_license, 0, 2, 1, 1)

        count = 1
        for k, v in donation_source.items():
            count += 1

            label_link_donation = Gtk.Label(
                                        css_name='sw_label',
                                        label=v,
                                        xalign=0,
                                        wrap=True,
                                        wrap_mode=Pango.WrapMode.CHAR,
                                        selectable=False,
            )
            link_donation = Gtk.LinkButton(css_name='sw_link', name=v)
            link_donation.set_child(label_link_donation)
            link_donation.connect('activate-link', cb_btn_donation)
            btn_expander = Gtk.Expander(label=k)
            btn_expander.set_child(link_donation)
            grid_about_donation.attach(btn_expander, 0, count, 1, 1)

        label_donation = Gtk.Label(
                                css_name='sw_label_desc',
                                label=str_donation,
                                xalign=0,
                                wrap=True,
                                wrap_mode=Pango.WrapMode.WORD,
        )
        title_donation = Gtk.Label(
                                css_name='sw_label',
                                label=str_contribute,
                                xalign=0,
        )
        pref_group_about_donation = Gtk.Box(
                                        css_name='sw_box_row',
                                        orientation=Gtk.Orientation.VERTICAL
        )
        pref_group_about_donation.set_size_request(280, -1)
        pref_group_about_donation.append(title_donation)
        pref_group_about_donation.append(label_donation)

        grid_about_donation.attach(pref_group_about_donation, 0, 1, 1, 1)

        scrolled_about.set_child(grid_about)
        scrolled_stack.set_child(swgs.stack_about)

    def add_launch_settings_view():
        """___build launch settings view page___"""

        swgs.label_ls_move = Gtk.Label(css_name='sw_label', label=str_move_settings)

        swgs.btn_ls_move = Gtk.Button(css_name='sw_button')
        swgs.btn_ls_move.set_hexpand(True)
        swgs.btn_ls_move.set_halign(Gtk.Align.END)
        swgs.btn_ls_move.set_valign(Gtk.Align.START)
        swgs.btn_ls_move.set_child(swgs.label_ls_move)
        swgs.btn_ls_move.set_tooltip_markup(msg.tt_dict['choose_app'])
        swgs.btn_ls_move.connect('clicked', cb_btn_ls_move)

        swgs.launch_settings = Gtk.Box(
                                        css_name='sw_box',
                                        orientation=Gtk.Orientation.VERTICAL
        )
        swgs.pref_group_title = Gtk.Label(
                                        css_name='sw_label_title',
                                        label=vl_dict['launch_settings'],
                                        xalign=0.0,
                                        ellipsize=Pango.EllipsizeMode.END,
        )
        swgs.pref_group_subtitle = Gtk.Label(
                                        css_name='sw_label_desc',
                                        label=str_lp_subtitle,
                                        xalign=0.0,
                                        wrap=True,
                                        natural_wrap_mode=True
        )
        swgs.pref_group_ls_title_box = Gtk.Box(
                                        css_name='sw_box_view',
                                        orientation=Gtk.Orientation.VERTICAL
        )
        swgs.pref_group_ls_title_box.append(swgs.pref_group_title)
        swgs.pref_group_ls_title_box.append(swgs.pref_group_subtitle)

        swgs.pref_group_ls_title_grid = Gtk.Grid(css_name='sw_box_view')
        swgs.pref_group_ls_title_grid.attach(swgs.pref_group_ls_title_box, 0, 0, 1, 1)
        swgs.pref_group_ls_title_grid.attach(swgs.btn_ls_move, 1, 0, 1, 1)

        swgs.launch_flow = Gtk.FlowBox(css_name='sw_preferencesgroup')
        swgs.launch_flow.set_homogeneous(True)
        swgs.launch_flow.set_min_children_per_line(1)
        swgs.launch_flow.set_max_children_per_line(8)

        swgs.pref_group_flow = Gtk.Box(
                                css_name='sw_box',
                                orientation=Gtk.Orientation.VERTICAL,
        )
        swgs.pref_group_flow.append(swgs.pref_group_ls_title_grid)
        swgs.pref_group_flow.append(swgs.launch_flow)

        swgs.launch_settings.append(swgs.pref_group_flow)

        swgs.winarch_list_model = Gtk.StringList()
        swgs.winver_list_model = Gtk.StringList()
        swgs.reg_list_model = Gtk.StringList()
        swgs.dxvk_list_model = Gtk.StringList()
        swgs.vkd3d_list_model = Gtk.StringList()
        swgs.fsr_list_model = Gtk.StringList()
        swgs.lang_mode_list_model = Gtk.StringList()

        swgs.combo_list_model = []
        swgs.combo_list_model.append(swgs.winarch_list_model)
        swgs.combo_list_model.append(swgs.winver_list_model)
        swgs.combo_list_model.append(swgs.reg_list_model)
        swgs.combo_list_model.append(swgs.dxvk_list_model)
        swgs.combo_list_model.append(swgs.vkd3d_list_model)
        swgs.combo_list_model.append(swgs.fsr_list_model)
        swgs.combo_list_model.append(swgs.lang_mode_list_model)

        for a in winarch:
            swgs.winarch_list_model.append(a)

        for v in winver:
            swgs.winver_list_model.append(v)

        for r in reg_patches:
            swgs.reg_list_model.append(r)

        for dxvk in dxvk_ver:
            swgs.dxvk_list_model.append(dxvk)

        for vkd3d in vkd3d_ver:
            swgs.vkd3d_list_model.append(vkd3d)

        for key in fsr_mode.keys():
            swgs.fsr_list_model.append(key)

        for lang in lang_mode:
            swgs.lang_mode_list_model.append(lang)

        swgs.lp_combo_list_factory = Gtk.SignalListItemFactory()
        swgs.lp_combo_list_factory.connect('setup', on_combo_setup)
        swgs.lp_combo_list_factory.connect('bind', on_combo_bind)

        count = -1
        for lpt, lpd in zip(lp_title, lp_desc):
            count += 1
            if lpt in lp_entry_list:

                row_entry_title = Gtk.Label(css_name='sw_label', label=lpt)
                row_entry_title.set_xalign(0)
                row_entry_title.set_wrap(True)
                row_entry_title.set_wrap_mode(Pango.WrapMode.CHAR)

                row_entry = Gtk.Entry(css_name='sw_entry')
                row_entry.set_progress_pulse_step(0.1)
                row_entry.set_icon_from_icon_name(
                                            Gtk.EntryIconPosition.SECONDARY, 'edit'
                )
                row_entry.set_activates_default(True)
                row_entry.set_icon_sensitive(
                                            Gtk.EntryIconPosition.SECONDARY, True
                )
                row_entry.set_icon_activatable(
                                            Gtk.EntryIconPosition.SECONDARY, True
                )
                row_entry.set_icon_tooltip_markup(
                                            Gtk.EntryIconPosition.SECONDARY,
                                            msg.msg_dict['save']
                )
                row_entry.set_placeholder_text(str_example[count])
                row_entry.set_hexpand(True)
                row_entry.connect('icon-press', on_row_entry_icon_press)
                row_entry.connect('activate', on_row_entry_enter)
                row_entry.set_name(lpt)
                row_entry_list.append(row_entry)

                box_row_entry = Gtk.Box(
                                        css_name='sw_box_view',
                                        orientation=Gtk.Orientation.VERTICAL
                                        )
                box_row_entry.append(row_entry_title)
                box_row_entry.append(row_entry)

                entry_child = Gtk.FlowBoxChild(css_name='sw_flowboxchild')
                entry_child.set_name(lpt)
                entry_child.set_child(box_row_entry)
                swgs.launch_flow.append(entry_child)

        count = -1
        for lpt, lpd in zip(lp_title, lp_desc):
            count += 1
            if lpt in lp_combo_list:

                row_combo_title = Gtk.Label(
                                        css_name='sw_label',
                                        label=lpt,
                                        xalign=0,
                                        wrap=True,
                                        wrap_mode=Pango.WrapMode.WORD,
                )
                row_combo_desc = Gtk.Label(
                                        css_name='sw_label_desc',
                                        label=lpd,
                                        hexpand=True,
                                        xalign=0,
                                        max_width_chars=4,
                                        wrap=True,
                                        natural_wrap_mode=True,
                                        wrap_mode=Pango.WrapMode.WORD,
                )
                row_combo = Gtk.DropDown(
                                        css_name='sw_dropdown',
                                        name=lpt,
                                        hexpand=True,
                                        valign=Gtk.Align.CENTER,
                                        halign=Gtk.Align.END,
                                        show_arrow=True,
                )
                row_combo.set_size_request(240, -1)
                row_combo_list.append(row_combo)

                row_grid = Gtk.Grid(css_name='sw_grid')

                if lpt == 'REGEDIT_PATCH':
                    image_regedit_patch = Gtk.Image(css_name='sw_image')
                    image_regedit_patch.set_from_file(IconPath.icon_save)

                    btn_regedit_patch = Gtk.Button(
                                                css_name='sw_button',
                                                name=lpt,
                                                child=image_regedit_patch,
                                                hexpand=True,
                                                halign=Gtk.Align.END,
                                                valign=Gtk.Align.CENTER,
                                                tooltip_markup=(
                                                    msg.tt_dict['apply']
                                                    + ' ' + msg.tt_dict['registry']),
                    )
                    btn_regedit_patch.connect('clicked', cb_btn_regedit_patch, row_combo)

                    box_reg_combo = Gtk.Box(
                                        css_name='sw_box',
                                        orientation=Gtk.Orientation.HORIZONTAL,
                                        hexpand=True,
                                        halign=Gtk.Align.END,
                                        spacing=8,
                    )
                    box_reg_combo.append(btn_regedit_patch)
                    box_reg_combo.append(row_combo)

                    row_grid.attach(row_combo_desc, 0, count, 1, 1)
                    row_grid.attach(box_reg_combo, 1, count, 1, 1)

                else:
                    row_grid.attach(row_combo_desc, 0, count, 1, 1)
                    row_grid.attach(row_combo, 1, count, 1, 1)

                try:
                    if count < 9:
                        row_combo.set_model(swgs.combo_list_model[count-2])
                        #row_combo.set_factory(lp_combo_list_factory)
                        row_combo.connect('notify::selected-item', on_row_combo_activate)
                except (Exception,):
                    pass

                box_row_combo = Gtk.Box(
                                        css_name='sw_box_view',
                                        orientation=Gtk.Orientation.VERTICAL
                )
                box_row_combo.append(row_combo_title)
                box_row_combo.append(row_grid)

                combo_child = Gtk.FlowBoxChild(css_name='sw_flowboxchild')
                combo_child.set_name(lpt)
                combo_child.set_child(box_row_combo)
                swgs.launch_flow.append(combo_child)

        swgs.lp_fps_title = Gtk.Label(css_name='sw_label', label=str_fps_limit)
        swgs.lp_fps_title.set_xalign(0)
        swgs.lp_fps_title.set_wrap(True)
        swgs.lp_fps_title.set_wrap_mode(Pango.WrapMode.WORD)

        swgs.lp_fps_desc = Gtk.Label(
                                css_name='sw_label_desc',
                                label=lp_desc_dict['fps_limit']
        )
        swgs.lp_fps_desc.set_halign(Gtk.Align.START)
        swgs.lp_fps_desc.set_xalign(0)
        swgs.lp_fps_desc.set_wrap(True)
        swgs.lp_fps_desc.set_natural_wrap_mode(True)
        swgs.lp_fps_desc.set_wrap_mode(Pango.WrapMode.WORD)

        swgs.fps_adjustment = Gtk.Adjustment()
        swgs.fps_adjustment.set_lower(0)
        swgs.fps_adjustment.set_upper(360)
        swgs.fps_adjustment.set_step_increment(10)
        swgs.fps_adjustment.set_page_increment(1)

        swgs.btn_spin_fps = Gtk.SpinButton(css_name='sw_spinbutton')
        swgs.btn_spin_fps.set_name(str_fps_limit)
        swgs.btn_spin_fps.set_hexpand(True)
        swgs.btn_spin_fps.set_size_request(160, -1)
        swgs.btn_spin_fps.set_valign(Gtk.Align.CENTER)
        swgs.btn_spin_fps.set_halign(Gtk.Align.END)
        swgs.btn_spin_fps.set_adjustment(swgs.fps_adjustment)
        swgs.btn_spin_fps.connect('value-changed', on_fps_adjustment)

        swgs.grid_lp_fps = Gtk.Grid(css_name='sw_grid')
        swgs.grid_lp_fps.set_hexpand(True)
        swgs.grid_lp_fps.attach(swgs.lp_fps_desc, 0, 0, 1, 1)
        swgs.grid_lp_fps.attach(swgs.btn_spin_fps, 1, 0, 1, 1)

        swgs.box_lp_fps = Gtk.Box(
                                css_name='sw_box_view',
                                orientation=Gtk.Orientation.VERTICAL
        )
        swgs.box_lp_fps.append(swgs.lp_fps_title)
        swgs.box_lp_fps.append(swgs.grid_lp_fps)

        swgs.fps_child = Gtk.FlowBoxChild(css_name='sw_flowboxchild')
        swgs.fps_child.set_name(str_fps_limit)
        swgs.fps_child.set_child(swgs.box_lp_fps)

        swgs.launch_flow.append(swgs.fps_child)

        swgs.lp_cpu_topology_title = Gtk.Label(css_name='sw_label', label=str_cpu_topology)
        swgs.lp_cpu_topology_title.set_xalign(0)
        swgs.lp_cpu_topology_title.set_wrap(True)
        swgs.lp_cpu_topology_title.set_wrap_mode(Pango.WrapMode.WORD)

        swgs.lp_cpu_topology_desc = Gtk.Label(
                                css_name='sw_label_desc',
                                label=lp_desc_dict['cpu_topology']
                                )
        swgs.lp_cpu_topology_desc.set_halign(Gtk.Align.START)
        swgs.lp_cpu_topology_desc.set_xalign(0)
        swgs.lp_cpu_topology_desc.set_wrap(True)
        swgs.lp_cpu_topology_desc.set_natural_wrap_mode(True)
        swgs.lp_cpu_topology_desc.set_wrap_mode(Pango.WrapMode.WORD)

        cpu_core_num = get_cpu_core_num()

        swgs.cpu_adjustment = Gtk.Adjustment()
        swgs.cpu_adjustment.set_lower(0)

        if cpu_core_num is not None:
            swgs.cpu_adjustment.set_upper(cpu_core_num)
        else:
            swgs.cpu_adjustment.set_upper(0)

        swgs.cpu_adjustment.set_step_increment(1)
        swgs.cpu_adjustment.set_page_increment(1)

        swgs.btn_spin_cpu = Gtk.SpinButton(css_name='sw_spinbutton')
        swgs.btn_spin_cpu.set_name(str_cpu_topology)
        swgs.btn_spin_cpu.set_hexpand(True)
        swgs.btn_spin_cpu.set_size_request(160, -1)
        swgs.btn_spin_cpu.set_valign(Gtk.Align.CENTER)
        swgs.btn_spin_cpu.set_halign(Gtk.Align.END)
        swgs.btn_spin_cpu.set_adjustment(swgs.cpu_adjustment)
        swgs.btn_spin_cpu.connect('value-changed', on_cpu_adjustment)

        swgs.grid_lp_cpu = Gtk.Grid(css_name='sw_grid')
        swgs.grid_lp_cpu.set_hexpand(True)
        swgs.grid_lp_cpu.attach(swgs.lp_cpu_topology_desc, 0, 0, 1, 1)
        swgs.grid_lp_cpu.attach(swgs.btn_spin_cpu, 1, 0, 1, 1)

        swgs.box_lp_cpu = Gtk.Box(
                                    css_name='sw_box_view',
                                    orientation=Gtk.Orientation.VERTICAL
        )
        swgs.box_lp_cpu.append(swgs.lp_cpu_topology_title)
        swgs.box_lp_cpu.append(swgs.grid_lp_cpu)

        swgs.cpu_topology_child = Gtk.FlowBoxChild(css_name='sw_flowboxchild')
        swgs.cpu_topology_child.set_name(str_cpu_topology)
        swgs.cpu_topology_child.set_child(swgs.box_lp_cpu)

        swgs.launch_flow.append(swgs.cpu_topology_child)

        count = -1
        for name, description in zip(switch_labels, switch_descriptions):
            count += 1
            switch_ls = Gtk.Switch(css_name='sw_switch')
            switch_ls.set_margin_start(16)
            switch_ls.set_name(name)
            switch_ls.set_valign(Gtk.Align.CENTER)
            switch_ls.set_halign(Gtk.Align.START)
            switch_ls.connect('state-set', cb_btn_switch_ls)
            switch_ls_list.append(switch_ls)

            ls_title = Gtk.Label(css_name='sw_label', label=name)
            ls_title.set_hexpand(True)
            ls_title.set_halign(Gtk.Align.START)
            ls_title.set_xalign(0)

            ls_desc = Gtk.Label(css_name='sw_label_desc', label=description)
            ls_desc.set_size_request(180, -1)
            ls_desc.set_hexpand(True)
            ls_desc.set_xalign(0)
            ls_desc.set_max_width_chars(0)
            ls_desc.set_wrap(True)
            ls_desc.set_natural_wrap_mode(True)
            ls_desc.set_wrap_mode(Pango.WrapMode.WORD)

            grid_switch = Gtk.Grid(css_name='sw_grid')
            grid_switch.attach(ls_desc, 0, count, 1, 1)
            grid_switch.attach(switch_ls, 1, count, 1, 1)

            ls_box = Gtk.Box(
                            css_name='sw_box_view',
                            orientation=Gtk.Orientation.VERTICAL
            )
            ls_box.append(ls_title)
            ls_box.append(grid_switch)

            launch_child = Gtk.FlowBoxChild(css_name='sw_flowboxchild')
            launch_child.set_name(name)
            launch_child.set_child(ls_box)
            swgs.launch_flow.append(launch_child)
            swgs.launch_flow.connect('child-activated', on_launch_flow_activated, switch_ls)

        scrolled_launch_settings.set_child(swgs.launch_settings)

        return set_settings_widget(
                                    stack_settings,
                                    vw_dict['launch_settings'],
                                    swgs.pref_group_title,
        )

    def add_install_launchers_view():
        """___build install launchers view page___"""

        swgs.launchers_menu = Gtk.Box(
                                name='install_launchers',
                                css_name='sw_flowbox',
                                orientation=Gtk.Orientation.VERTICAL,
                                halign=Gtk.Align.CENTER
        )
        swgs.pref_group_launchers_title = Gtk.Label(
                                    css_name='sw_label_title',
                                    label=msg.msg_dict['install_desc'],
                                    xalign=0.0
        )
        swgs.pref_group_launchers_subtitle = Gtk.Label(
                                        css_name='sw_label_desc',
                                        label=str_il_subtitle,
                                        xalign=0.0,
                                        wrap=True,
                                        natural_wrap_mode=True
        )
        swgs.pref_group_launchers_box = Gtk.Box(
                                css_name='sw_box_view',
                                orientation=Gtk.Orientation.VERTICAL
        )
        swgs.pref_group_launchers_box.append(swgs.pref_group_launchers_title)
        swgs.pref_group_launchers_box.append(swgs.pref_group_launchers_subtitle)

        swgs.pref_group_launchers_title_grid = Gtk.Grid(css_name='sw_box_view')
        swgs.pref_group_launchers_title_grid.attach(swgs.pref_group_launchers_box, 0, 0, 1, 1)

        swgs.launchers_flow = Gtk.FlowBox(
                                        css_name='sw_preferencesgroup',
                                        vexpand=True, valign=Gtk.Align.START
        )
        swgs.launchers_flow.set_margin_top(16)
        swgs.launchers_flow.set_homogeneous(True)
        swgs.launchers_flow.set_min_children_per_line(1)
        swgs.launchers_flow.set_max_children_per_line(8)

        swgs.pref_group_launchers_flow = Gtk.Box(
                                css_name='sw_pref_box',
                                orientation=Gtk.Orientation.VERTICAL,
        )
        swgs.pref_group_launchers_flow.append(swgs.pref_group_launchers_title_grid)
        swgs.pref_group_launchers_flow.append(swgs.launchers_flow)

        swgs.launchers_menu.append(swgs.pref_group_launchers_flow)

        count = -1
        for launcher in sorted(launchers_list):
            count += 1
            image_il = Gtk.Picture(css_name='sw_image')
            image_il.add_css_class('sw_shadow')
            paintable_launcher_icon = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(bytes(Path(launcher))), 320, 180,
            )
            image_il.set_paintable(paintable_launcher_icon)
            image_il.set_content_fit(Gtk.ContentFit.COVER)
            image_il.set_size_request(320, 180)
            image_il.set_halign(Gtk.Align.START)
            image_il.set_hexpand(True)
            image_il.set_vexpand(True)
            image_il.set_valign(Gtk.Align.START)

            image_btn_il = Gtk.Image(css_name='sw_image')
            image_btn_il.set_from_file(IconPath.icon_download)
            label_btn_il = Gtk.Label(css_name='sw_label_view', label=msg.msg_dict['install'])
            box_btn_il = Gtk.Box(
                                css_name='sw_box',
                                orientation=Gtk.Orientation.HORIZONTAL,
                                spacing=8,
            )
            box_btn_il.append(image_btn_il)
            box_btn_il.append(label_btn_il)

            btn_il = Gtk.Button(
                                css_name='sw_button',
                                name=Path(launcher).stem,
                                valign=Gtk.Align.START,
                                halign=Gtk.Align.END,
                                child=box_btn_il
            )
            btn_il.set_size_request(160, -1)
            btn_il.add_css_class('install')
            btn_il.connect('clicked', cb_btn_install_launchers)
            btn_il_list.append(btn_il)

            il_name = Path(launcher).stem.replace('_', ' ')
            il_title = Gtk.Label(css_name='sw_label_title', label=il_name)
            il_title.set_hexpand(True)
            il_title.set_halign(Gtk.Align.START)
            il_title.set_valign(Gtk.Align.START)
            il_title.set_xalign(0)

            il_desc = Gtk.Label(
                                css_name='sw_label_desc',
                                label=str(launchers_descriptions[Path(launcher).stem]),
                                valign=Gtk.Align.START,
                                xalign=0,
                                hexpand=True,
                                max_width_chars=0,
                                wrap=True,
                                natural_wrap_mode=True,
                                wrap_mode=Pango.WrapMode.WORD,
            )
            il_desc.set_size_request(260, -1)

            box_il_title = Gtk.Box(
                                css_name='sw_box',
                                orientation=Gtk.Orientation.HORIZONTAL,
                                spacing=16,
            )
            box_il_title.append(il_title)
            box_il_title.append(btn_il)

            box_il_desc = Gtk.Box(
                                css_name='sw_box',
                                orientation=Gtk.Orientation.HORIZONTAL,
                                spacing=16,
                                vexpand=True,
                                valign=Gtk.Align.START
            )
            box_il_desc.append(image_il)
            box_il_desc.append(il_desc)

            grid_il = Gtk.Grid(css_name='sw_grid')
            grid_il.set_vexpand(True)
            grid_il.set_row_spacing(8)
            grid_il.set_margin_bottom(16)
            grid_il.set_margin_top(16)
            grid_il.set_margin_start(16)
            grid_il.set_margin_end(16)
            grid_il.set_valign(Gtk.Align.START)
            grid_il.attach(box_il_title, 0, count, 1, 1)
            grid_il.attach(box_il_desc, 0, count+1, 1, 1)

            launchers_child = Gtk.FlowBoxChild(css_name='sw_flowboxchild')
            launchers_child.set_name(Path(launcher).stem)
            launchers_child.set_child(grid_il)
            swgs.launchers_flow.append(launchers_child)

        scrolled_install_launchers.set_child(swgs.launchers_menu)

        return set_settings_widget(
                            main_stack,
                            vw_dict['install_launchers'],
                            None,
        )

    def add_wine_view():
        """___build wine list view page___"""

        swgs.label_update_wine_list = Gtk.Label(
                                        css_name='sw_label',
                                        label=msg.msg_dict['check_wine_updates']
        )
        swgs.btn_update_wine_list = Gtk.Button(
                                css_name='sw_button',
                                hexpand=True,
                                halign=Gtk.Align.END,
                                valign=Gtk.Align.START,
                                child=swgs.label_update_wine_list,
                                tooltip_markup=msg.tt_dict['check_wine_updates']
        )
        swgs.btn_update_wine_list.connect('clicked', cb_btn_update_wine_view)

        swgs.wine_menu = Gtk.Box(
                                css_name='sw_flowbox',
                                orientation=Gtk.Orientation.VERTICAL,
                                halign=Gtk.Align.CENTER,
        )
        swgs.pref_group_wine_title = Gtk.Label(
                                        css_name='sw_label_title',
                                        label=vl_dict['install_wine'],
                                        xalign=0.0
        )
        swgs.pref_group_wine_subtitle = Gtk.Label(
                                        css_name='sw_label_desc',
                                        label=str_iw_title_desc,
                                        xalign=0.0,
                                        wrap=True,
                                        natural_wrap_mode=True
        )
        swgs.pref_group_wine_box = Gtk.Box(
                                        css_name='sw_box_view',
                                        orientation=Gtk.Orientation.VERTICAL
        )
        swgs.pref_group_wine_box.append(swgs.pref_group_wine_title)
        swgs.pref_group_wine_box.append(swgs.pref_group_wine_subtitle)

        swgs.pref_group_wine_title_grid = Gtk.Grid(css_name='sw_box_view')
        swgs.pref_group_wine_title_grid.attach(swgs.pref_group_wine_box, 0, 0, 1, 1)
        swgs.pref_group_wine_title_grid.attach(swgs.btn_update_wine_list, 1, 0, 1, 1)

        swgs.wine_flow = Gtk.FlowBox(
                                    css_name='sw_preferencesgroup',
                                    vexpand=True, valign=Gtk.Align.START
        )
        swgs.wine_flow.set_margin_top(16)
        swgs.wine_flow.set_homogeneous(True)
        swgs.wine_flow.set_min_children_per_line(1)
        swgs.wine_flow.set_max_children_per_line(8)

        swgs.pref_group_wine_flow = Gtk.Box(
                                        css_name='sw_pref_box',
                                        orientation=Gtk.Orientation.VERTICAL,
        )
        swgs.pref_group_wine_flow.append(swgs.pref_group_wine_title_grid)
        swgs.pref_group_wine_flow.append(swgs.wine_flow)

        swgs.wine_menu.append(swgs.pref_group_wine_flow)

        count = 0
        for wine, wine_image in zip(wine_list, wine_image_list):
            count += 1
            download_wine_model = Gio.ListStore()

            factory_dropdown_wine_list = Gtk.SignalListItemFactory()
            factory_dropdown_wine_list.connect('setup', cb_factory_dropdown_wine_setup)
            factory_dropdown_wine_list.connect('bind', cb_factory_dropdown_wine_bind)

            dropdown_download_wine = Gtk.DropDown(css_name='sw_dropdown')
            dropdown_download_wine.set_size_request(280, 40)
            dropdown_download_wine.set_hexpand(False)
            dropdown_download_wine.set_valign(Gtk.Align.START)
            dropdown_download_wine.set_halign(Gtk.Align.END)
            dropdown_download_wine.set_name(wine)
            dropdown_download_wine_list.append(dropdown_download_wine)
            dropdown_download_wine.set_model(download_wine_model)
            dropdown_download_wine.set_factory(factory_dropdown_wine_list)
            drop_wine_list_view = (
                                    dropdown_download_wine
                                    .get_last_child()
                                    .get_first_child()
                                    .get_first_child()
                                    .get_first_child()
                                    .get_next_sibling()
                                    .get_first_child()
            )
            drop_wine_list_view.connect('activate', cb_dropdown_download_wine)

            paintable_wine_icon = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(bytes(Path(wine_image))), 180, 1,
            )
            image_iw = Gtk.Picture(css_name='sw_picture')
            image_iw.set_paintable(paintable_wine_icon)
            image_iw.set_content_fit(Gtk.ContentFit.COVER)
            image_iw.set_size_request(320, 180)

            image_btn_iw = Gtk.Image(css_name='sw_image')
            image_btn_iw.set_from_file(IconPath.icon_download)
            label_btn_iw = Gtk.Label(
                                    css_name='sw_label_view',
                                    label=msg.msg_dict['install']
            )
            box_btn_iw = Gtk.Box(
                                css_name='sw_box',
                                orientation=Gtk.Orientation.HORIZONTAL,
                                spacing=8,
            )
            box_btn_iw.append(image_btn_iw)
            box_btn_iw.append(label_btn_iw)

            btn_iw = Gtk.Button(css_name='sw_button')
            btn_iw.set_name(f'WINE_{count}')
            btn_iw.set_valign(Gtk.Align.CENTER)
            btn_iw.set_halign(Gtk.Align.END)
            btn_iw.set_child(box_btn_iw)
            btn_iw.set_size_request(120, -1)
            btn_iw.add_css_class('install')
            btn_iw.connect('clicked', cb_btn_download_wine, dropdown_download_wine)
            btn_iw_list.append(btn_iw)

            image_btn_iw_rm = Gtk.Image(css_name='sw_image')
            image_btn_iw_rm.set_from_file(IconPath.icon_remove)
            label_btn_iw_rm = Gtk.Label(
                                        css_name='sw_label_view',
                                        label=msg.msg_dict['remove']
            )
            box_btn_iw_rm = Gtk.Box(
                                css_name='sw_box',
                                orientation=Gtk.Orientation.HORIZONTAL,
                                spacing=8,
            )
            box_btn_iw_rm.append(image_btn_iw_rm)
            box_btn_iw_rm.append(label_btn_iw_rm)

            btn_iw_rm = Gtk.Button(css_name='sw_button')
            btn_iw_rm.set_name(f'RM_WINE_{count}')
            btn_iw_rm.set_valign(Gtk.Align.CENTER)
            btn_iw_rm.set_halign(Gtk.Align.END)
            btn_iw_rm.set_child(box_btn_iw_rm)
            btn_iw_rm.set_size_request(120, -1)
            btn_iw_rm.add_css_class('installed')
            btn_iw_rm.connect('clicked', cb_btn_remove_wine, dropdown_download_wine)
            btn_iw_rm_list.append(btn_iw_rm)

            stack_btn_iw = Gtk.Stack(css_name='sw_stack')
            stack_btn_iw.set_transition_duration(10)
            stack_btn_iw.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
            stack_btn_iw.add_named(btn_iw, f'WINE_{count}')
            stack_btn_iw.add_named(btn_iw_rm, f'RM_WINE_{count}')

            image_iw_source = Gtk.Image(css_name='sw_image')
            image_iw_source.set_from_file(IconPath.icon_github)
            label_iw_source = Gtk.Label(
                                css_name='sw_label_info', label='GitHub Source'
            )
            box_btn_iw_source = Gtk.Box(
                                css_name='sw_box',
                                orientation=Gtk.Orientation.HORIZONTAL,
                                spacing=16,
            )
            box_btn_iw_source.append(image_iw_source)
            box_btn_iw_source.append(label_iw_source)

            btn_iw_source = Gtk.LinkButton(
                                        css_name='sw_link',
                                        halign=Gtk.Align.START,
                                        valign=Gtk.Align.START
            )
            btn_iw_source.set_name(wine)
            btn_iw_source.set_child(box_btn_iw_source)
            btn_iw_source.set_tooltip_markup(wine_source_dict[wine])
            btn_iw_source.connect('activate-link', cb_btn_source_wine)

            iw_title = Gtk.Label(
                                css_name='sw_label_title',
                                label=wine_dict[wine].replace('_', ' ').title(),
                                hexpand=True,
                                halign=Gtk.Align.START,
                                valign=Gtk.Align.START,
                                xalign=0,
            )
            iw_desc = Gtk.Label(
                                css_name='sw_label_desc',
                                label=str(wine_descriptions[wine]),
                                valign=Gtk.Align.START,
                                xalign=0,
                                hexpand=True,
                                max_width_chars=0,
                                wrap=True,
                                natural_wrap_mode=True,
                                wrap_mode=Pango.WrapMode.WORD,
            )
            iw_desc.set_size_request(260, -1)

            box_iw_title = Gtk.Box(
                                css_name='sw_box',
                                orientation=Gtk.Orientation.HORIZONTAL,
                                spacing=8,
            )
            box_iw_title.append(iw_title)
            box_iw_title.append(dropdown_download_wine)
            box_iw_title.append(stack_btn_iw)

            box_iw_desc_source = Gtk.Box(
                                css_name='sw_box',
                                orientation=Gtk.Orientation.VERTICAL,
                                spacing=8,
            )
            box_iw_desc_source.append(iw_desc)
            box_iw_desc_source.append(btn_iw_source)

            box_iw_desc = Gtk.Box(
                                css_name='sw_box',
                                orientation=Gtk.Orientation.HORIZONTAL,
                                spacing=16,
            )
            box_iw_desc.append(image_iw)
            box_iw_desc.append(box_iw_desc_source)

            grid_iw = Gtk.Grid(css_name='sw_grid')
            grid_iw.set_vexpand(True)
            grid_iw.set_row_spacing(16)
            grid_iw.set_margin_bottom(16)
            grid_iw.set_margin_top(16)
            grid_iw.set_margin_start(16)
            grid_iw.set_margin_end(16)
            grid_iw.set_valign(Gtk.Align.START)
            grid_iw.attach(box_iw_title, 0, count, 1, 1)
            grid_iw.attach(box_iw_desc, 0, count+1, 1, 1)

            wine_child = Gtk.FlowBoxChild(css_name='sw_flowboxchild')
            wine_child.set_name(Path(l).stem)
            wine_child.set_child(grid_iw)
            swgs.wine_flow.append(wine_child)

        scrolled_install_wine.set_child(swgs.wine_menu)
        return set_settings_widget(main_stack, vw_dict['install_wine'], None)

    def add_mangohud_settings_view():
        """___build mangohud settings view page___"""

        swgs.label_mh_preview_0 = Gtk.Label(css_name='sw_label', label=preview_label)

        swgs.btn_mh_preview_0 = Gtk.Button(css_name='sw_button')
        swgs.btn_mh_preview_0.set_hexpand(True)
        swgs.btn_mh_preview_0.set_halign(Gtk.Align.END)
        swgs.btn_mh_preview_0.set_valign(Gtk.Align.START)
        swgs.btn_mh_preview_0.set_child(swgs.label_mh_preview_0)
        swgs.btn_mh_preview_0.connect('clicked', cb_btn_mh_preview)

        swgs.pref_group_mh_title = Gtk.Label(
                                        css_name='sw_label_title',
                                        label=vl_dict['mangohud_settings'],
                                        xalign=0.0,
                                        wrap=True,
                                        natural_wrap_mode=True
                                        )

        swgs.pref_group_mh_subtitle = Gtk.Label(
                                        css_name='sw_label_desc',
                                        label=str_mh_subtitle,
                                        xalign=0.0,
                                        wrap=True,
                                        natural_wrap_mode=True
                                        )

        swgs.pref_group_mh_label_box = Gtk.Box(
                                        css_name='sw_box_view',
                                        orientation=Gtk.Orientation.VERTICAL
                                        )
        swgs.pref_group_mh_label_box.append(swgs.pref_group_mh_title)
        swgs.pref_group_mh_label_box.append(swgs.pref_group_mh_subtitle)

        swgs.pref_group_mh_title_grid = Gtk.Grid(css_name='sw_box_view')
        swgs.pref_group_mh_title_grid.attach(swgs.pref_group_mh_label_box, 0, 0, 1, 1)
        swgs.pref_group_mh_title_grid.attach(swgs.btn_mh_preview_0, 1, 0, 1, 1)

        swgs.mangohud_flow = Gtk.FlowBox(css_name='sw_preferencesgroup')
        swgs.mangohud_flow.set_homogeneous(True)
        swgs.mangohud_flow.set_min_children_per_line(1)
        swgs.mangohud_flow.set_max_children_per_line(8)

        swgs.pref_group_mh_flow = Gtk.Box(
                                        css_name='sw_box',
                                        orientation=Gtk.Orientation.VERTICAL
        )
        swgs.pref_group_mh_flow.append(swgs.pref_group_mh_title_grid)
        swgs.pref_group_mh_flow.append(swgs.mangohud_flow)

        swgs.mangohud_settings = Gtk.Box(
                                        css_name='sw_box',
                                        orientation=Gtk.Orientation.VERTICAL
        )
        swgs.mangohud_settings.append(swgs.pref_group_mh_flow)

        count = -1
        for name, description in sorted(zip(check_mh_labels, check_mh_description)):
            count += 1
            btn_switch_mh = Gtk.Switch(
                                    css_name='sw_switch',
                                    valign=Gtk.Align.CENTER,
                                    halign=Gtk.Align.START,
                                    name=name,
            )
            btn_switch_mh.connect('state-set', cb_btn_switch_mh)
            check_btn_mh_list.append(btn_switch_mh)

            title_mh = Gtk.Label(
                                css_name='sw_label',
                                label=name.upper(),
                                hexpand=True,
                                halign=Gtk.Align.START,
                                xalign=0,
            )
            desc_mh = Gtk.Label(
                                css_name='sw_label_desc',
                                label=description,
                                hexpand=True,
                                valign=Gtk.Align.CENTER,
                                xalign=0,
                                max_width_chars=0,
                                wrap=True,
                                natural_wrap_mode=True,
                                wrap_mode=Pango.WrapMode.WORD,
            )
            desc_mh.set_size_request(360, -1)

            grid_mh = Gtk.Grid(css_name='sw_grid')
            grid_mh.attach(title_mh, 0, count, 1, 1)
            grid_mh.attach(btn_switch_mh, 1, count, 1, 1)

            pref_group_mh = Gtk.Box(
                                    css_name='sw_box_view',
                                    orientation=Gtk.Orientation.VERTICAL
            )
            pref_group_mh.append(grid_mh)
            pref_group_mh.append(desc_mh)

            mangohud_child = Gtk.FlowBoxChild(css_name='sw_flowboxchild', name=name)
            mangohud_child.set_child(pref_group_mh)

            swgs.mangohud_flow.append(mangohud_child)
            swgs.mangohud_flow.connect('child-activated', on_mango_flow_activated, btn_switch_mh)

        swgs.label_preview = Gtk.Label(css_name='sw_label', label=preview_label)

        swgs.btn_mh_preview = Gtk.Button(css_name='sw_button')
        swgs.btn_mh_preview.set_hexpand(True)
        swgs.btn_mh_preview.set_valign(Gtk.Align.START)
        swgs.btn_mh_preview.set_halign(Gtk.Align.END)
        swgs.btn_mh_preview.set_child(swgs.label_preview)
        swgs.btn_mh_preview.connect('clicked', cb_btn_mh_preview)

        swgs.colors_flow_mh = Gtk.FlowBox(css_name='sw_preferencesgroup')
        swgs.colors_flow_mh.set_margin_bottom(32)
        swgs.colors_flow_mh.set_homogeneous(True)
        swgs.colors_flow_mh.set_min_children_per_line(1)
        swgs.colors_flow_mh.set_max_children_per_line(4)

        swgs.colors_mh_title = Gtk.Label(
                                        css_name='sw_label_title',
                                        label=str_mh_colors_title,
                                        xalign=0.0,
                                        wrap=True,
                                        natural_wrap_mode=True
        )
        swgs.colors_mh_subtitle = Gtk.Label(
                                        css_name='sw_label_desc',
                                        label=str_mh_colors_subtitle,
                                        xalign=0.0,
                                        wrap=True,
                                        natural_wrap_mode=True
        )
        swgs.colors_mh_label_box = Gtk.Box(
                                        css_name='sw_box_view',
                                        orientation=Gtk.Orientation.VERTICAL,
                                        halign=Gtk.Align.START
        )
        swgs.colors_mh_label_box.append(swgs.colors_mh_title)
        swgs.colors_mh_label_box.append(swgs.colors_mh_subtitle)

        swgs.colors_mh_title_grid = Gtk.Grid(css_name='sw_box_view')
        swgs.colors_mh_title_grid.attach(swgs.colors_mh_label_box, 0, 0, 1, 1)
        swgs.colors_mh_title_grid.attach(swgs.btn_mh_preview, 1, 0, 1, 1)

        swgs.colors_pref_mh = Gtk.Box(
                                    css_name='sw_box',
                                    orientation=Gtk.Orientation.VERTICAL
        )
        swgs.colors_pref_mh.append(swgs.colors_mh_title_grid)
        swgs.colors_pref_mh.append(swgs.colors_flow_mh)

        count = -1
        for c, d in zip(mh_colors, mh_colors_description):
            count += 1

            entry_mh_color = Gtk.Entry(css_name='sw_entry')
            entry_mh_color.set_tooltip_markup(msg.tt_dict['current'])
            entry_mh_color.set_hexpand(True)
            entry_mh_color.set_name(c)
            entry_mh_color.set_sensitive(False)
            entry_mh_color_list.append(entry_mh_color)

            btn_mh_color = Gtk.ColorButton(css_name='sw_buttoncolor')
            btn_mh_color.set_name(c)
            btn_mh_color.set_hexpand(True)
            btn_mh_color.set_valign(Gtk.Align.CENTER)
            btn_mh_color.set_halign(Gtk.Align.END)
            btn_mh_color.set_size_request(32, 32)
            btn_mh_color.set_tooltip_markup(msg.tt_dict['color'])
            btn_mh_color.connect('color-set', on_mh_color_set, entry_mh_color)
            btn_mh_color_list.append(btn_mh_color)

            btn_mh_color.get_first_child().remove_css_class('color')
            btn_mh_color.get_first_child().add_css_class('sw_color')

            title_mh_color = Gtk.Label(css_name='sw_label', label=d)
            title_mh_color.set_size_request(200, -1)
            title_mh_color.set_hexpand(True)
            title_mh_color.set_halign(Gtk.Align.START)
            title_mh_color.set_xalign(0)

            grid_mh_color = Gtk.Grid(css_name='sw_grid')
            grid_mh_color.attach(entry_mh_color, 0, count, 1, 1)
            grid_mh_color.attach(btn_mh_color, 1, count, 1, 1)

            pref_box_mh_color = Gtk.Box(
                                        css_name='sw_box_view',
                                        orientation=Gtk.Orientation.VERTICAL
                                        )
            pref_box_mh_color.append(title_mh_color)
            pref_box_mh_color.append(grid_mh_color)

            colors_flow_mh_child = Gtk.FlowBoxChild(css_name='sw_flowboxchild')
            colors_flow_mh_child.set_name(d)
            colors_flow_mh_child.set_child(pref_box_mh_color)

            swgs.colors_flow_mh.append(colors_flow_mh_child)

        swgs.mangohud_settings.append(swgs.colors_pref_mh)
        scrolled_mangohud_settings.set_child(swgs.mangohud_settings)

        return set_settings_widget(
                            stack_settings,
                            vw_dict['mangohud_settings'],
                            swgs.pref_group_mh_title,
        )

    def add_vkbasalt_settings_view():
        """___build vkbasalt settings view page___"""

        swgs.label_vk_scale = Gtk.Label(
                                        css_name='sw_label_desc',
                                        label=str_vk_intensity,
                                        xalign=0,
                                        yalign=0.5,
                                        wrap=True,
                                        wrap_mode=Pango.WrapMode.WORD,
        )
        swgs.vk_adjustment = Gtk.Adjustment()
        swgs.vk_adjustment.set_lower(0)
        swgs.vk_adjustment.set_upper(100)
        swgs.vk_adjustment.connect('value-changed', on_set_vk_intensity)

        swgs.btn_vk_scale = Gtk.Scale(css_name='sw_scale')
        swgs.btn_vk_scale.set_hexpand(True)
        swgs.btn_vk_scale.set_halign(Gtk.Align.END)
        swgs.btn_vk_scale.set_valign(Gtk.Align.START)
        swgs.btn_vk_scale.set_size_request(140, -1)
        swgs.btn_vk_scale.set_draw_value(True)
        swgs.btn_vk_scale.set_round_digits(0)
        swgs.btn_vk_scale.set_adjustment(swgs.vk_adjustment)

        swgs.vk_scale_box = Gtk.Box(
                                    css_name='sw_box_view',
                                    orientation=Gtk.Orientation.HORIZONTAL,
                                    halign=Gtk.Align.END,
                                    valign=Gtk.Align.START,
                                    spacing=8,
        )
        swgs.vk_scale_box.append(swgs.label_vk_scale)
        swgs.vk_scale_box.append(swgs.btn_vk_scale)

        swgs.pref_group_vk_title = Gtk.Label(
                                        css_name='sw_label_title',
                                        label=vl_dict['vkbasalt_settings'],
                                        xalign=0.0,
                                        wrap=True,
                                        natural_wrap_mode=True
        )
        swgs.pref_group_vk_subtitle = Gtk.Label(
                                        css_name='sw_label_desc',
                                        label=str_vk_subtitle,
                                        xalign=0.0,
                                        wrap=True,
                                        natural_wrap_mode=True
        )
        swgs.pref_group_vk_label_box = Gtk.Box(
                                        css_name='sw_box_view',
                                        orientation=Gtk.Orientation.VERTICAL,
                                        halign=Gtk.Align.START
        )
        swgs.pref_group_vk_label_box.append(swgs.pref_group_vk_title)
        swgs.pref_group_vk_label_box.append(swgs.pref_group_vk_subtitle)

        swgs.pref_group_vk_title_grid = Gtk.Grid(css_name='sw_box_view')
        swgs.pref_group_vk_title_grid.attach(swgs.pref_group_vk_label_box, 0, 0, 1, 1)
        swgs.pref_group_vk_title_grid.attach(swgs.vk_scale_box, 1, 0, 1, 1)

        swgs.vkbasalt_flow = Gtk.FlowBox(css_name='sw_preferencesgroup')
        swgs.vkbasalt_flow.set_homogeneous(True)
        swgs.vkbasalt_flow.set_min_children_per_line(1)
        swgs.vkbasalt_flow.set_max_children_per_line(8)

        swgs.pref_group_vk_flow = Gtk.Box(
                                    css_name='sw_box',
                                    orientation=Gtk.Orientation.VERTICAL
        )
        swgs.pref_group_vk_flow.append(swgs.pref_group_vk_title_grid)
        swgs.pref_group_vk_flow.append(swgs.vkbasalt_flow)

        swgs.vkbasalt_settings = Gtk.Box(
                                    css_name='sw_box',
                                    orientation=Gtk.Orientation.VERTICAL
        )
        swgs.vkbasalt_settings.append(swgs.pref_group_vk_flow)

        count = -1
        for name, description in sorted(vkbasalt_dict.items()):
            count += 1

            btn_switch_vk = Gtk.Switch(css_name='sw_switch')
            btn_switch_vk.set_name(name)
            btn_switch_vk.set_valign(Gtk.Align.CENTER)
            btn_switch_vk.set_halign(Gtk.Align.START)
            btn_switch_vk.connect('state-set', cb_btn_switch_vk)
            check_btn_vk_list.append(btn_switch_vk)

            title_vk = Gtk.Label(css_name='sw_label', label=name.upper())
            title_vk.set_hexpand(True)
            title_vk.set_halign(Gtk.Align.START)
            title_vk.set_xalign(0)

            desc_vk = Gtk.Label(css_name='sw_label_desc', label=description)
            desc_vk.set_size_request(360, -1)
            desc_vk.set_hexpand(True)
            desc_vk.set_valign(Gtk.Align.CENTER)
            desc_vk.set_xalign(0)
            desc_vk.set_max_width_chars(0)
            desc_vk.set_wrap(True)
            desc_vk.set_natural_wrap_mode(True)

            #expand_desc_vk = Gtk.Expander(css_name='sw_expander', label=about_dict['about_details'])
            #expand_desc_vk.set_child(desc_vk)

            grid_vk = Gtk.Grid(css_name='sw_grid')
            grid_vk.attach(title_vk, 0, count, 1, 1)
            grid_vk.attach(btn_switch_vk, 1, count, 1, 1)

            pref_group_vk = Gtk.Box(
                                    css_name='sw_box_view',
                                    orientation=Gtk.Orientation.VERTICAL
            )
            pref_group_vk.append(grid_vk)
            pref_group_vk.append(desc_vk)

            vkbasalt_child = Gtk.FlowBoxChild(css_name='sw_flowboxchild')
            vkbasalt_child.set_name(name)
            vkbasalt_child.set_child(pref_group_vk)
            swgs.vkbasalt_flow.insert(vkbasalt_child, position=count)
            swgs.vkbasalt_flow.connect('child-activated', on_vk_flow_activated, btn_switch_vk)

        scrolled_vkbasalt_settings.set_child(swgs.vkbasalt_settings)

        app_name = get_out()
        app_conf = f"{sw_app_config}/{app_name}"
        app_dict = app_info(app_conf)
        swgs.vk_adjustment.set_value(float(app_dict['export SW_USE_VKBASALT_CAS'][1:-1])*100)

        return set_settings_widget(
                                stack_settings,
                                vw_dict['vkbasalt_settings'],
                                swgs.pref_group_vk_title
        )

    def add_global_settings_view():
        """___build global settings view page___"""

        swgs.global_settings_title = Gtk.Label(
                                        css_name='sw_label_title',
                                        label=vl_dict['global_settings'],
                                        xalign=0.0,
                                        wrap=True,
                                        natural_wrap_mode=True,
        )
        swgs.global_settings_subtitle = Gtk.Label(
                                            css_name='sw_label_desc',
                                            label=str_global_subtitle,
                                            xalign=0.0,
                                            wrap=True,
                                            natural_wrap_mode=True,
        )
        swgs.label_btn_global_settings = Gtk.Label(css_name='sw_label', label=str_reset_menu_settings)

        swgs.btn_global_settings_reset = Gtk.Button(css_name='sw_button')
        swgs.btn_global_settings_reset.set_hexpand(True)
        swgs.btn_global_settings_reset.set_halign(Gtk.Align.END)
        swgs.btn_global_settings_reset.set_valign(Gtk.Align.START)
        swgs.btn_global_settings_reset.set_child(swgs.label_btn_global_settings)
        swgs.btn_global_settings_reset.connect('clicked', cb_btn_menu_json_default)

        swgs.global_settings_label_box = Gtk.Box(
                                    css_name='sw_box_view',
                                    orientation=Gtk.Orientation.VERTICAL,
                                    halign=Gtk.Align.START
        )
        swgs.global_settings_label_box.append(swgs.global_settings_title)
        swgs.global_settings_label_box.append(swgs.global_settings_subtitle)

        swgs.global_settings_title_grid = Gtk.Grid(css_name='sw_box_view')
        swgs.global_settings_title_grid.attach(swgs.global_settings_label_box, 0, 0, 1, 1)
        swgs.global_settings_title_grid.attach(swgs.btn_global_settings_reset, 1, 0, 1, 1)

        swgs.title_autostart = Gtk.Label(
                                        css_name='sw_label',
                                        label=str_title_autostart,
                                        xalign=0,
                                        margin_start=4,
        )
        swgs.subtitle_autostart = Gtk.Label(
                                            css_name='sw_label_desc',
                                            label=str_subtitle_autostart,
                                            xalign=0,
                                            margin_start=4,
        )
        swgs.grid_autostart_labels = Gtk.Grid(css_name='sw_grid')
        swgs.grid_autostart_labels.set_hexpand(True)
        swgs.grid_autostart_labels.attach(swgs.title_autostart, 0, 0, 1, 1)
        swgs.grid_autostart_labels.attach(swgs.subtitle_autostart, 0, 1, 1, 1)

        swgs.switch_autostart = Gtk.Switch(css_name='sw_switch', margin_end=4)
        swgs.switch_autostart.set_valign(Gtk.Align.CENTER)
        swgs.switch_autostart.set_halign(Gtk.Align.END)
        swgs.switch_autostart.connect('state-set', on_switch_autostart)

        swgs.box_autostart = Gtk.Box(
                                    css_name='sw_box',
                                    orientation=Gtk.Orientation.HORIZONTAL,
                                    spacing=4
        )
        swgs.box_autostart.append(swgs.grid_autostart_labels)
        swgs.box_autostart.append(swgs.switch_autostart)

        swgs.row_autostart = Gtk.FlowBoxChild(css_name='sw_action_row')
        swgs.row_autostart.set_child(swgs.box_autostart)

        swgs.title_lang = Gtk.Label(
                                    css_name='sw_label',
                                    label=str_title_lang,
                                    xalign=0,
                                    margin_start=4,
        )
        swgs.subtitle_lang = Gtk.Label(
                                    css_name='sw_label_desc',
                                    label=str_subtitle_lang,
                                    xalign=0,
                                    margin_start=4,
        )
        swgs.grid_lang_labels = Gtk.Grid(css_name='sw_grid')
        swgs.grid_lang_labels.set_hexpand(True)
        swgs.grid_lang_labels.attach(swgs.title_lang, 0, 0, 1, 1)
        swgs.grid_lang_labels.attach(swgs.subtitle_lang, 0, 1, 1, 1)

        swgs.lang_list_model = Gtk.StringList()

        for lang in lang_labels:
            swgs.lang_list_model.append(lang)

        swgs.lang_list_factory = Gtk.SignalListItemFactory()
        swgs.lang_list_factory.connect('setup', cb_lang_setup)
        swgs.lang_list_factory.connect('bind', cb_lang_bind)

        swgs.dropdown_lang = Gtk.DropDown(css_name='sw_dropdown')
        swgs.dropdown_lang.set_valign(Gtk.Align.CENTER)
        swgs.dropdown_lang.set_halign(Gtk.Align.END)
        swgs.dropdown_lang.set_model(swgs.lang_list_model)
        swgs.dropdown_lang.connect('notify::selected-item', on_lang_activate)

        swgs.box_lang = Gtk.Box(
                                css_name='sw_box',
                                orientation=Gtk.Orientation.HORIZONTAL,
                                spacing=4
        )
        swgs.box_lang.append(swgs.grid_lang_labels)
        swgs.box_lang.append(swgs.dropdown_lang)

        swgs.row_lang = Gtk.FlowBoxChild(css_name='sw_action_row')
        swgs.row_lang.set_child(swgs.box_lang)

        swgs.title_icons = Gtk.Label(
                                    css_name='sw_label',
                                    label=str_title_icons,
                                    xalign=0,
                                    margin_start=4,
        )
        swgs.subtitle_icons = Gtk.Label(
                                        css_name='sw_label_desc',
                                        label=str_subtitle_icons,
                                        xalign=0,
                                        margin_start=4,
        )
        swgs.grid_icons_labels = Gtk.Grid(css_name='sw_grid')
        swgs.grid_icons_labels.set_hexpand(True)
        swgs.grid_icons_labels.attach(swgs.title_icons, 0, 0, 1, 1)
        swgs.grid_icons_labels.attach(swgs.subtitle_icons, 0, 1, 1, 1)

        swgs.switch_icons = Gtk.Switch(css_name='sw_switch', margin_end=4)
        swgs.switch_icons.set_valign(Gtk.Align.CENTER)
        swgs.switch_icons.set_halign(Gtk.Align.END)
        swgs.switch_icons.connect('state-set', on_switch_icons)

        swgs.box_icons = Gtk.Box(
                                css_name='sw_box',
                                orientation=Gtk.Orientation.HORIZONTAL,
                                spacing=4
        )
        swgs.box_icons.append(swgs.grid_icons_labels)
        swgs.box_icons.append(swgs.switch_icons)

        swgs.row_icons = Gtk.FlowBoxChild(css_name='sw_action_row')
        swgs.row_icons.set_child(swgs.box_icons)

        swgs.title_restore_menu = Gtk.Label(
                                            css_name='sw_label',
                                            label=str_title_restore_menu,
                                            xalign=0,
                                            margin_start=4,
        )
        swgs.subtitle_restore_menu = Gtk.Label(
                                            css_name='sw_label_desc',
                                            label=str_subtitle_restore_menu,
                                            xalign=0,
                                            margin_start=4,
        )
        swgs.grid_restore_menu_labels = Gtk.Grid(css_name='sw_grid')
        swgs.grid_restore_menu_labels.set_hexpand(True)
        swgs.grid_restore_menu_labels.attach(swgs.title_restore_menu, 0, 0, 1, 1)
        swgs.grid_restore_menu_labels.attach(swgs.subtitle_restore_menu, 0, 1, 1, 1)

        swgs.switch_restore_menu = Gtk.Switch(css_name='sw_switch', margin_end=4)
        swgs.switch_restore_menu.set_valign(Gtk.Align.CENTER)
        swgs.switch_restore_menu.set_halign(Gtk.Align.END)
        swgs.switch_restore_menu.connect('state-set', on_switch_restore_menu)

        swgs.box_restore_menu = Gtk.Box(
                                        css_name='sw_box',
                                        orientation=Gtk.Orientation.HORIZONTAL,
                                        spacing=4
        )
        swgs.box_restore_menu.append(swgs.grid_restore_menu_labels)
        swgs.box_restore_menu.append(swgs.switch_restore_menu)

        swgs.row_restore_menu = Gtk.FlowBoxChild(css_name='sw_action_row')
        swgs.row_restore_menu.set_child(swgs.box_restore_menu)

        swgs.title_auto_stop = Gtk.Label(
                                        css_name='sw_label',
                                        label=str_title_auto_stop,
                                        xalign=0,
                                        margin_start=4,
        )
        swgs.subtitle_auto_stop = Gtk.Label(
                                            css_name='sw_label_desc',
                                            label=str_subtitle_auto_stop,
                                            xalign=0,
                                            margin_start=4,
                                            wrap=True,
                                            natural_wrap_mode=True,
        )
        swgs.grid_auto_stop_labels = Gtk.Grid(css_name='sw_grid')
        swgs.grid_auto_stop_labels.set_hexpand(True)
        swgs.grid_auto_stop_labels.attach(swgs.title_auto_stop, 0, 0, 1, 1)
        swgs.grid_auto_stop_labels.attach(swgs.subtitle_auto_stop, 0, 1, 1, 1)

        swgs.switch_auto_stop = Gtk.Switch(css_name='sw_switch', margin_end=4)
        swgs.switch_auto_stop.set_valign(Gtk.Align.CENTER)
        swgs.switch_auto_stop.set_halign(Gtk.Align.END)
        swgs.switch_auto_stop.connect('state-set', on_switch_auto_stop)

        swgs.box_auto_stop = Gtk.Box(
                                    css_name='sw_box',
                                    orientation=Gtk.Orientation.HORIZONTAL,
                                    spacing=4
        )
        swgs.box_auto_stop.append(swgs.grid_auto_stop_labels)
        swgs.box_auto_stop.append(swgs.switch_auto_stop)

        swgs.row_auto_stop = Gtk.FlowBoxChild(css_name='sw_action_row')
        swgs.row_auto_stop.set_child(swgs.box_auto_stop)

        swgs.title_auto_hide_top = Gtk.Label(
                                            css_name='sw_label',
                                            label=str_title_auto_hide_top,
                                            xalign=0,
                                            margin_start=4,
        )
        swgs.subtitle_auto_hide_top = Gtk.Label(
                                            css_name='sw_label_desc',
                                            label=str_subtitle_auto_hide_top,
                                            xalign=0,
                                            margin_start=4,
                                            wrap=True,
                                            natural_wrap_mode=True,
        )
        swgs.grid_auto_hide_top = Gtk.Grid(css_name='sw_grid')
        swgs.grid_auto_hide_top.set_hexpand(True)
        swgs.grid_auto_hide_top.attach(swgs.title_auto_hide_top, 0, 0, 1, 1)
        swgs.grid_auto_hide_top.attach(swgs.subtitle_auto_hide_top, 0, 1, 1, 1)

        swgs.switch_auto_hide_top = Gtk.Switch(css_name='sw_switch', margin_end=4)
        swgs.switch_auto_hide_top.set_valign(Gtk.Align.CENTER)
        swgs.switch_auto_hide_top.set_halign(Gtk.Align.END)
        swgs.switch_auto_hide_top.connect('state-set', on_switch_auto_hide_top_header)

        swgs.box_auto_hide_top = Gtk.Box(
                                        css_name='sw_box',
                                        orientation=Gtk.Orientation.HORIZONTAL,
                                        spacing=4
        )
        swgs.box_auto_hide_top.append(swgs.grid_auto_hide_top)
        swgs.box_auto_hide_top.append(swgs.switch_auto_hide_top)

        swgs.row_auto_hide_top = Gtk.FlowBoxChild(css_name='sw_action_row')
        swgs.row_auto_hide_top.set_child(swgs.box_auto_hide_top)

        swgs.title_auto_hide_bottom = Gtk.Label(
                                            css_name='sw_label',
                                            label=str_title_auto_hide_bottom,
                                            xalign=0,
                                            margin_start=4,
        )
        swgs.subtitle_auto_hide_bottom = Gtk.Label(
                                            css_name='sw_label_desc',
                                            label=str_subtitle_auto_hide_bottom,
                                            xalign=0,
                                            margin_start=4,
                                            wrap=True,
                                            natural_wrap_mode=True,
                                            hexpand=True,
        )
        swgs.grid_auto_hide_bottom = Gtk.Grid(css_name='sw_grid')
        swgs.grid_auto_hide_bottom.attach(swgs.title_auto_hide_bottom, 0, 0, 1, 1)
        swgs.grid_auto_hide_bottom.attach(swgs.subtitle_auto_hide_bottom, 0, 1, 1, 1)

        swgs.switch_auto_hide_bottom = Gtk.Switch(css_name='sw_switch', margin_end=4)
        swgs.switch_auto_hide_bottom.set_valign(Gtk.Align.CENTER)
        swgs.switch_auto_hide_bottom.set_halign(Gtk.Align.END)
        swgs.switch_auto_hide_bottom.connect('state-set', on_switch_auto_hide_bottom_header)

        swgs.box_auto_hide_bottom = Gtk.Box(
                                        css_name='sw_box',
                                        orientation=Gtk.Orientation.HORIZONTAL,
                                        spacing=4,
        )
        swgs.box_auto_hide_bottom.append(swgs.grid_auto_hide_bottom)
        swgs.box_auto_hide_bottom.append(swgs.switch_auto_hide_bottom)

        swgs.row_auto_hide_bottom = Gtk.FlowBoxChild(css_name='sw_action_row')
        swgs.row_auto_hide_bottom.set_child(swgs.box_auto_hide_bottom)

        swgs.title_def_dir = Gtk.Label(
                                        css_name='sw_label_title',
                                        label=str_title_def_dir,
                                        xalign=0,
                                        margin_start=4,
        )
        swgs.subtitle_def_dir = Gtk.Label(
                                        css_name='sw_label_info',
                                        label=str_subtitle_def_dir,
                                        xalign=0,
                                        margin_start=4,
                                        wrap=True,
                                        natural_wrap_mode=True
        )
        swgs.grid_def_dir_labels = Gtk.Grid(css_name='sw_grid', row_spacing=4)
        swgs.grid_def_dir_labels.set_hexpand(True)
        swgs.grid_def_dir_labels.attach(swgs.title_def_dir, 0, 0, 1, 1)
        swgs.grid_def_dir_labels.attach(swgs.subtitle_def_dir, 0, 1, 1, 1)

        swgs.entry_def_dir = Gtk.Entry(css_name='sw_entry')
        swgs.entry_def_dir.set_hexpand(True)
        swgs.entry_def_dir.set_icon_from_icon_name(Gtk.EntryIconPosition.SECONDARY, 'edit')
        swgs.entry_def_dir.set_icon_sensitive(Gtk.EntryIconPosition.SECONDARY, True)
        swgs.entry_def_dir.set_icon_activatable(Gtk.EntryIconPosition.SECONDARY, True)
        swgs.entry_def_dir.set_icon_tooltip_markup(
                                            Gtk.EntryIconPosition.SECONDARY,
                                            msg.tt_dict['save']
        )
        swgs.entry_def_dir.connect('icon-press', cb_entry_def_dir)

        swgs.image_def_dir = Gtk.Image(css_name='sw_image')
        swgs.image_def_dir.set_from_file(IconPath.icon_folder)

        swgs.btn_def_dir = Gtk.Button(css_name='sw_button', margin_end=4)
        swgs.btn_def_dir.set_valign(Gtk.Align.CENTER)
        swgs.btn_def_dir.set_halign(Gtk.Align.END)
        swgs.btn_def_dir.set_tooltip_markup(msg.tt_dict['directory'])
        swgs.btn_def_dir.set_child(swgs.image_def_dir)
        swgs.btn_def_dir.connect('clicked', cb_btn_def_dir)

        swgs.row_def_dir = Gtk.Box(
                                    css_name='sw_action_row',
                                    orientation=Gtk.Orientation.HORIZONTAL,
                                    spacing=4
        )
        swgs.row_def_dir.append(swgs.entry_def_dir)
        swgs.row_def_dir.append(swgs.btn_def_dir)

        swgs.title_render = Gtk.Label(
                                        css_name='sw_label_title',
                                        label=str_title_render,
                                        xalign=0,
                                        margin_start=4,
        )
        swgs.subtitle_render = Gtk.Label(
                                        css_name='sw_label_info',
                                        label=str_subtitle_render,
                                        xalign=0,
                                        margin_start=4,
                                        wrap=True,
                                        natural_wrap_mode=True
        )
        swgs.grid_render_labels = Gtk.Grid(css_name='sw_grid', row_spacing=4)
        swgs.grid_render_labels.set_hexpand(True)
        swgs.grid_render_labels.attach(swgs.title_render, 0, 0, 1, 1)
        swgs.grid_render_labels.attach(swgs.subtitle_render, 0, 1, 1, 1)

        swgs.title_vulkan = Gtk.Label(
                                    css_name='sw_label',
                                    label=str_title_vulkan,
                                    xalign=0,
                                    margin_start=4,
                                    hexpand=True
        )
        swgs.subtitle_vulkan = Gtk.Label(
                                        css_name='sw_label_desc',
                                        label=str_subtitle_vulkan,
                                        xalign=0,
                                        margin_start=4,
                                        wrap=True,
                                        natural_wrap_mode=True,
                                        hexpand=True
        )
        swgs.switch_vulkan = Gtk.Switch(css_name='sw_switch', margin_end=4)
        swgs.switch_vulkan.set_halign(Gtk.Align.END)
        swgs.switch_vulkan.set_valign(Gtk.Align.CENTER)
        swgs.switch_vulkan.connect('state-set', on_switch_vulkan_renderer)

        swgs.box_vulkan = Gtk.Grid(css_name='sw_grid')
        swgs.box_vulkan.attach(swgs.title_vulkan, 0, 0, 1, 1)
        swgs.box_vulkan.attach(swgs.subtitle_vulkan, 0, 1, 1, 1)
        swgs.box_vulkan.attach(swgs.switch_vulkan, 1, 0, 1, 1)

        swgs.row_vulkan = Gtk.FlowBoxChild(css_name='sw_action_row', name='vulkan')
        swgs.row_vulkan.set_child(swgs.box_vulkan)

        swgs.title_opengl = Gtk.Label(
                                    css_name='sw_label',
                                    label=str_title_opengl,
                                    xalign=0,
                                    margin_start=4,
                                    hexpand=True
        )
        swgs.subtitle_opengl = Gtk.Label(
                                        css_name='sw_label_desc',
                                        label=str_subtitle_opengl,
                                        xalign=0,
                                        margin_start=4,
                                        wrap=True,
                                        natural_wrap_mode=True,
                                        hexpand=True
        )
        swgs.title_shaders = Gtk.Label(
                                        css_name='sw_label',
                                        label=str_title_shaders,
                                        xalign=0,
                                        margin_start=4,
        )
        swgs.subtitle_shaders = Gtk.Label(
                                        css_name='sw_label_desc',
                                        label=str_subtitle_shaders,
                                        xalign=0,
                                        margin_start=4,
                                        wrap=True,
                                        natural_wrap_mode=True
        )
        swgs.switch_opengl = Gtk.Switch(css_name='sw_switch', margin_end=4)
        swgs.switch_opengl.set_halign(Gtk.Align.END)
        swgs.switch_opengl.set_valign(Gtk.Align.CENTER)
        swgs.switch_opengl.connect('state-set', on_switch_opengl_bg)

        swgs.box_opengl = Gtk.Grid(css_name='sw_grid')
        swgs.box_opengl.attach(swgs.title_opengl, 0, 0, 1, 1)
        swgs.box_opengl.attach(swgs.subtitle_opengl, 0, 1, 1, 1)
        swgs.box_opengl.attach(swgs.switch_opengl, 1, 0, 1, 1)

        swgs.row_opengl = Gtk.FlowBoxChild(css_name='sw_action_row', name='opengl_bg')
        swgs.row_opengl.set_child(swgs.box_opengl)

        swgs.grid_shader_labels = Gtk.Grid(css_name='sw_grid')
        swgs.grid_shader_labels.set_hexpand(True)
        swgs.grid_shader_labels.attach(swgs.title_shaders, 0, 0, 1, 1)
        swgs.grid_shader_labels.attach(swgs.subtitle_shaders, 0, 1, 1, 1)

        swgs.shaders_list_model = Gtk.StringList()

        for fragment_name in fragments_labels:
            swgs.shaders_list_model.append(fragment_name.capitalize())

        swgs.shaders_list_factory = Gtk.SignalListItemFactory()
        swgs.shaders_list_factory.connect('setup', on_shaders_setup)
        swgs.shaders_list_factory.connect('bind', on_shaders_bind)

        swgs.dropdown_shaders = Gtk.DropDown(css_name='sw_dropdown')
        swgs.dropdown_shaders.set_valign(Gtk.Align.CENTER)
        swgs.dropdown_shaders.set_halign(Gtk.Align.END)
        swgs.dropdown_shaders.set_model(swgs.shaders_list_model)
        swgs.dropdown_shaders.connect('notify::selected-item', on_shaders_activate)

        swgs.box_shaders = Gtk.Box(
                                    css_name='sw_box',
                                    orientation=Gtk.Orientation.HORIZONTAL,
                                    spacing=4
        )
        swgs.box_shaders.append(swgs.grid_shader_labels)
        swgs.box_shaders.append(swgs.dropdown_shaders)

        swgs.row_shaders = Gtk.FlowBoxChild(css_name='sw_action_row', name='shaders')
        swgs.row_shaders.set_child(swgs.box_shaders)

        swgs.flow_render = Gtk.FlowBox(
                                        css_name='sw_preferencesgroup',
                                        min_children_per_line=1,
                                        max_children_per_line=4,
                                        homogeneous=True,
        )
        swgs.flow_render.append(swgs.row_vulkan)
        swgs.flow_render.append(swgs.row_opengl)
        swgs.flow_render.append(swgs.row_shaders)
        swgs.flow_render.connect('child-activated', on_flow_render)

        swgs.title_startup = Gtk.Label(
                                        css_name='sw_label_title',
                                        label=str_title_startup,
                                        xalign=0,
                                        margin_top=4,
                                        margin_start=4,
        )
        swgs.subtitle_startup = Gtk.Label(
                                        css_name='sw_label_info',
                                        label=str_subtitle_startup,
                                        xalign=0,
                                        margin_start=4,
                                        wrap=True,
                                        natural_wrap_mode=True,
        )
        swgs.title_startup_grid = Gtk.Grid(css_name='sw_grid')
        swgs.title_startup_grid.attach(swgs.title_startup, 0, 0, 1, 1)
        swgs.title_startup_grid.attach(swgs.subtitle_startup, 0, 1, 1, 1)

        swgs.flow_startup = Gtk.FlowBox(
                                        css_name='sw_preferencesgroup',
                                        min_children_per_line=1,
                                        max_children_per_line=4,
                                        homogeneous=True,
        )
        swgs.flow_startup.append(swgs.row_autostart)
        swgs.flow_startup.append(swgs.row_restore_menu)
        swgs.flow_startup.append(swgs.row_lang)
        swgs.flow_startup.append(swgs.row_icons)
        swgs.flow_startup.append(swgs.row_auto_stop)
        swgs.flow_startup.append(swgs.row_auto_hide_top)
        swgs.flow_startup.append(swgs.row_auto_hide_bottom)
        swgs.flow_startup.connect('child_activated', cb_flow_startup)

        swgs.group_startup = Gtk.Box(
                                    css_name='sw_preferencesgroup',
                                    orientation=Gtk.Orientation.VERTICAL,
                                    spacing=4,
                                    margin_start=16,
                                    margin_end=16,
        )
        swgs.group_startup.append(swgs.title_startup_grid)
        swgs.group_startup.append(swgs.flow_startup)

        swgs.group_fm = Gtk.Box(
                                css_name='sw_preferencesgroup',
                                orientation=Gtk.Orientation.VERTICAL,
                                spacing=4,
                                margin_start=16,
                                margin_end=16,
        )
        swgs.group_fm.append(swgs.grid_def_dir_labels)
        swgs.group_fm.append(swgs.row_def_dir)

        swgs.group_render = Gtk.Box(
                                css_name='sw_preferencesgroup',
                                orientation=Gtk.Orientation.VERTICAL,
                                spacing=4,
                                margin_start=16,
                                margin_end=16,
        )
        swgs.group_render.append(swgs.grid_render_labels)
        swgs.group_render.append(swgs.flow_render)

        swgs.colors_flow_theme = Gtk.FlowBox(css_name='sw_preferencesgroup')
        swgs.colors_flow_theme.set_margin_bottom(32)
        swgs.colors_flow_theme.set_homogeneous(True)
        swgs.colors_flow_theme.set_min_children_per_line(1)
        swgs.colors_flow_theme.set_max_children_per_line(4)

        swgs.colors_theme_title = Gtk.Label(
                                            css_name='sw_label_title',
                                            label=str_theme_colors_title,
                                            xalign=0.0,
                                            wrap=True,
                                            natural_wrap_mode=True
        )
        swgs.colors_theme_subtitle = Gtk.Label(
                                            css_name='sw_label_info',
                                            label=str_theme_colors_subtitle,
                                            xalign=0.0,
                                            wrap=True,
                                            natural_wrap_mode=True
        )
        swgs.colors_theme_label_box = Gtk.Box(
                                            css_name='sw_box_view',
                                            orientation=Gtk.Orientation.VERTICAL,
                                            halign=Gtk.Align.START
        )
        swgs.colors_theme_label_box.append(swgs.colors_theme_title)
        swgs.colors_theme_label_box.append(swgs.colors_theme_subtitle)

        swgs.dropdown_theme = Gtk.DropDown(
                                        css_name='sw_dropdown',
                                        hexpand=True,
                                        valign=Gtk.Align.CENTER,
                                        halign=Gtk.Align.START,
                                        show_arrow=True,
        )
        swgs.dropdown_theme.set_size_request(280, -1)
        swgs.themes_model = Gtk.StringList()

        for theme in list(default_themes):
            swgs.themes_model.append(theme)

        swgs.themes_list_factory = Gtk.SignalListItemFactory()
        swgs.themes_list_factory.connect('setup', on_combo_setup)
        swgs.themes_list_factory.connect('bind', on_combo_bind)

        #dropdown_theme.set_factory(themes_list_factory)
        swgs.dropdown_theme.set_model(swgs.themes_model)
        swgs.dropdown_theme.connect('notify::selected-item', on_row_theme_activate)

        swgs.label_sample = Gtk.Label(
                                    css_name='sw_label',
                                    xalign=0,
                                    label=msg.ctx_dict["sample"].capitalize(),
        )
        swgs.box_theme = Gtk.Box(
                                css_name='sw_box',
                                orientation=Gtk.Orientation.HORIZONTAL,
                                spacing=8,
                                margin_start=8,
        )
        swgs.box_theme.append(swgs.label_sample)
        swgs.box_theme.append(swgs.dropdown_theme)

        swgs.label_save = Gtk.Label(css_name='sw_label', label=confirm_label)

        swgs.btn_save_theme = Gtk.Button(css_name='sw_button')
        swgs.btn_save_theme.set_hexpand(True)
        swgs.btn_save_theme.set_valign(Gtk.Align.START)
        swgs.btn_save_theme.set_halign(Gtk.Align.END)
        swgs.btn_save_theme.set_margin_bottom(16)
        swgs.btn_save_theme.set_child(swgs.label_save)
        swgs.btn_save_theme.connect('clicked', cb_btn_save_theme)

        swgs.colors_theme_title_grid = Gtk.Grid(css_name='sw_box_view')
        swgs.colors_theme_title_grid.attach(swgs.colors_theme_label_box, 0, 0, 1, 1)
        swgs.colors_theme_title_grid.attach(swgs.btn_save_theme, 1, 0, 1, 1)
        swgs.colors_theme_title_grid.attach(swgs.box_theme, 0, 1, 1, 1)

        swgs.colors_theme = Gtk.Box(
                                css_name='sw_preferencesgroup',
                                orientation=Gtk.Orientation.VERTICAL,
                                valign=Gtk.Align.START,
                                spacing=4,
                                margin_start=16,
                                margin_end=16,
        )
        swgs.colors_theme.append(swgs.colors_theme_title_grid)
        swgs.colors_theme.append(swgs.colors_flow_theme)

        count = -1
        for name, description in zip(dcolor_names, dcolor_labels):
            count += 1

            entry_theme_color = Gtk.Entry(css_name='sw_entry')
            entry_theme_color.set_icon_from_icon_name(
                                            Gtk.EntryIconPosition.SECONDARY, 'edit'
            )
            entry_theme_color.set_icon_sensitive(
                                            Gtk.EntryIconPosition.SECONDARY, True
            )
            entry_theme_color.set_icon_activatable(
                                            Gtk.EntryIconPosition.SECONDARY, True
            )
            entry_theme_color.set_icon_tooltip_markup(
                                            Gtk.EntryIconPosition.SECONDARY,
                                            msg.tt_dict['save']
            )
            entry_theme_color.set_hexpand(True)
            entry_theme_color.set_tooltip_markup(msg.tt_dict['edit'])
            entry_theme_color.connect('icon-press', on_row_entry_color)
            entry_theme_color.set_name(name)
            entry_theme_color_list.append(entry_theme_color)

            color_dialog = Gtk.ColorDialog()

            btn_theme_color = Gtk.ColorDialogButton(css_name='sw_buttoncolor')
            btn_theme_color.set_vexpand(True)
            btn_theme_color.set_hexpand(True)
            btn_theme_color.set_valign(Gtk.Align.CENTER)
            btn_theme_color.set_halign(Gtk.Align.END)
            btn_theme_color.set_size_request(32, 32)
            btn_theme_color.set_name(name)
            btn_theme_color.set_tooltip_markup(msg.tt_dict['color'])
            btn_theme_color.set_dialog(color_dialog)
            btn_theme_color.connect('notify::rgba', on_theme_color_set, entry_theme_color)
            btn_theme_color_list.append(btn_theme_color)

            btn_theme_color.get_first_child().remove_css_class('color')
            btn_theme_color.get_first_child().add_css_class('sw_color')

            title_theme_color = Gtk.Label(css_name='sw_label', label=description)
            title_theme_color.set_size_request(200, -1)
            title_theme_color.set_hexpand(True)
            title_theme_color.set_halign(Gtk.Align.START)
            title_theme_color.set_xalign(0)

            grid_theme_color = Gtk.Grid(css_name='sw_grid')
            grid_theme_color.attach(entry_theme_color, 0, count, 1, 1)
            grid_theme_color.attach(btn_theme_color, 1, count, 1, 1)

            pref_box_theme_color = Gtk.Box(
                                        css_name='sw_box_view',
                                        orientation=Gtk.Orientation.VERTICAL
            )
            pref_box_theme_color.append(title_theme_color)
            pref_box_theme_color.append(grid_theme_color)

            colors_flow_theme_child = Gtk.FlowBoxChild(css_name='sw_action_row')
            colors_flow_theme_child.set_name(description)
            colors_flow_theme_child.set_child(pref_box_theme_color)
            swgs.colors_flow_theme.append(colors_flow_theme_child)

        swgs.wc_flow_theme = Gtk.FlowBox(css_name='sw_preferencesgroup')
        swgs.wc_flow_theme.set_margin_bottom(32)
        swgs.wc_flow_theme.set_homogeneous(True)
        swgs.wc_flow_theme.set_min_children_per_line(2)
        swgs.wc_flow_theme.set_max_children_per_line(4)

        swgs.wc_theme_title = Gtk.Label(
                                        css_name='sw_label_title',
                                        label=str_wc_style_title,
                                        xalign=0.0,
                                        wrap=True,
                                        natural_wrap_mode=True
        )
        swgs.wc_theme_subtitle = Gtk.Label(
                                        css_name='sw_label_info',
                                        label=str_wc_style_subtitle,
                                        xalign=0.0,
                                        wrap=True,
                                        natural_wrap_mode=True
        )
        swgs.wc_theme_label_box = Gtk.Box(
                                        css_name='sw_box_view',
                                        orientation=Gtk.Orientation.VERTICAL,
                                        halign=Gtk.Align.START
        )
        swgs.wc_theme_label_box.append(swgs.wc_theme_title)
        swgs.wc_theme_label_box.append(swgs.wc_theme_subtitle)

        swgs.wc_check_box_list = list()
        for style, data in wc_style_dict.items():
            box_wc_color_style = Gtk.Box(
                css_name='sw_box', orientation=Gtk.Orientation.HORIZONTAL,
                halign=Gtk.Align.END
            )
            box_wc_adw_style = Gtk.Box(
                css_name='sw_box', orientation=Gtk.Orientation.HORIZONTAL,
                halign=Gtk.Align.END
            )
            box_wc_br_style = Gtk.Box(
                css_name='sw_box', orientation=Gtk.Orientation.HORIZONTAL,
                halign=Gtk.Align.END
            )
            box_wc_mac_style = Gtk.Box(
                css_name='sw_box', orientation=Gtk.Orientation.HORIZONTAL,
                halign=Gtk.Align.END
            )
            box_wc_color_style.add_css_class('padding_4')
            box_wc_adw_style.add_css_class('padding_4')
            box_wc_br_style.add_css_class('padding_4')
            box_wc_mac_style.add_css_class('padding_4')

            wc_overlay = Gtk.Overlay(css_name='sw_box', name=style)

            if style == 'default':
                image_color_close = Gtk.Image(css_name='sw_wc_close', valign=Gtk.Align.CENTER)
                image_color_max = Gtk.Image(css_name='sw_wc_maximize', valign=Gtk.Align.CENTER)
                image_color_min = Gtk.Image(css_name='sw_wc_minimize', valign=Gtk.Align.CENTER)
                image_color_close.add_css_class('wc_color')
                image_color_max.add_css_class('wc_color')
                image_color_min.add_css_class('wc_color')
                box_wc_color_style.append(image_color_min)
                box_wc_color_style.append(image_color_max)
                box_wc_color_style.append(image_color_close)
                wc_overlay.set_child(box_wc_color_style)

            if style == 'macos':
                image_mac_close = Gtk.Image(css_name='sw_wc_close', valign=Gtk.Align.CENTER)
                image_mac_max = Gtk.Image(css_name='sw_wc_maximize', valign=Gtk.Align.CENTER)
                image_mac_min = Gtk.Image(css_name='sw_wc_minimize', valign=Gtk.Align.CENTER)
                image_mac_close.add_css_class('wc_mac')
                image_mac_max.add_css_class('wc_mac')
                image_mac_min.add_css_class('wc_mac')
                box_wc_mac_style.append(image_mac_min)
                box_wc_mac_style.append(image_mac_max)
                box_wc_mac_style.append(image_mac_close)
                wc_overlay.set_child(box_wc_mac_style)

            if style == 'adwaita':
                swgs.image_adw_close = Gtk.Image(css_name='sw_wc_close', valign=Gtk.Align.CENTER)
                swgs.image_adw_max = Gtk.Image(css_name='sw_wc_maximize', valign=Gtk.Align.CENTER)
                swgs.image_adw_min = Gtk.Image(css_name='sw_wc_minimize', valign=Gtk.Align.CENTER)
                swgs.paintable_icon_close = Gtk.IconPaintable.new_for_file(
                    Gio.File.new_for_path(IconPath.icon_close), 32, 1)
                swgs.paintable_icon_max = Gtk.IconPaintable.new_for_file(
                    Gio.File.new_for_path(IconPath.icon_max), 32, 1)
                swgs.paintable_icon_min = Gtk.IconPaintable.new_for_file(
                    Gio.File.new_for_path(IconPath.icon_min), 32, 1)
                swgs.paintable_icon_close_light = Gtk.IconPaintable.new_for_file(
                    Gio.File.new_for_path(IconPath.icon_close_light), 32, 1)
                swgs.paintable_icon_max_light = Gtk.IconPaintable.new_for_file(
                    Gio.File.new_for_path(IconPath.icon_max_light), 32, 1)
                swgs.paintable_icon_min_light = Gtk.IconPaintable.new_for_file(
                    Gio.File.new_for_path(IconPath.icon_min_light), 32, 1)
                swgs.image_adw_close.set_pixel_size(32)
                swgs.image_adw_max.set_pixel_size(32)
                swgs.image_adw_min.set_pixel_size(32)
                box_wc_adw_style.append(swgs.image_adw_min)
                box_wc_adw_style.append(swgs.image_adw_max)
                box_wc_adw_style.append(swgs.image_adw_close)
                wc_overlay.set_child(box_wc_adw_style)

                swgs.image_adw_close.set_from_paintable(swgs.paintable_icon_close)
                swgs.image_adw_max.set_from_paintable(swgs.paintable_icon_max)
                swgs.image_adw_min.set_from_paintable(swgs.paintable_icon_min)

                if swgs.colorscheme == 'light' or getenv('SW_CUSTOM_WC_COLOR_SCHEME') == 'light':
                    swgs.image_adw_close.set_from_paintable(swgs.paintable_icon_close_light)
                    swgs.image_adw_max.set_from_paintable(swgs.paintable_icon_max_light)
                    swgs.image_adw_min.set_from_paintable(swgs.paintable_icon_min_light)

            if style == 'breeze':
                swgs.image_br_close = Gtk.Image(css_name='sw_wc_close', valign=Gtk.Align.CENTER)
                swgs.image_br_max = Gtk.Image(css_name='sw_wc_maximize', valign=Gtk.Align.CENTER)
                swgs.image_br_min = Gtk.Image(css_name='sw_wc_minimize', valign=Gtk.Align.CENTER)
                swgs.paintable_icon_br_close = Gtk.IconPaintable.new_for_file(
                    Gio.File.new_for_path(IconPath.icon_br_close), 32, 1)
                swgs.paintable_icon_br_max = Gtk.IconPaintable.new_for_file(
                    Gio.File.new_for_path(IconPath.icon_br_max), 32, 1)
                swgs.paintable_icon_br_min = Gtk.IconPaintable.new_for_file(
                    Gio.File.new_for_path(IconPath.icon_br_min), 32, 1)
                swgs.paintable_icon_br_close_light = Gtk.IconPaintable.new_for_file(
                    Gio.File.new_for_path(IconPath.icon_br_close_light), 32, 1)
                swgs.paintable_icon_br_max_light = Gtk.IconPaintable.new_for_file(
                    Gio.File.new_for_path(IconPath.icon_br_max_light), 32, 1)
                swgs.paintable_icon_br_min_light = Gtk.IconPaintable.new_for_file(
                    Gio.File.new_for_path(IconPath.icon_br_min_light), 32, 1)
                swgs.image_br_close.set_pixel_size(32)
                swgs.image_br_max.set_pixel_size(32)
                swgs.image_br_min.set_pixel_size(32)
                box_wc_br_style.append(swgs.image_br_min)
                box_wc_br_style.append(swgs.image_br_max)
                box_wc_br_style.append(swgs.image_br_close)
                wc_overlay.set_child(box_wc_br_style)

                swgs.image_br_close.set_from_paintable(swgs.paintable_icon_br_close)
                swgs.image_br_max.set_from_paintable(swgs.paintable_icon_br_max)
                swgs.image_br_min.set_from_paintable(swgs.paintable_icon_br_min)

                if swgs.colorscheme == 'light' or getenv('SW_CUSTOM_WC_COLOR_SCHEME') == 'light':
                    swgs.image_br_close.set_from_paintable(swgs.paintable_icon_br_close_light)
                    swgs.image_br_max.set_from_paintable(swgs.paintable_icon_br_max_light)
                    swgs.image_br_min.set_from_paintable(swgs.paintable_icon_br_min_light)

            icon_wc_check = Gtk.Picture(
                        css_name='sw_uncheck', hexpand=True, halign=Gtk.Align.START,
                        content_fit=Gtk.ContentFit.SCALE_DOWN, vexpand=True,
                        valign=Gtk.Align.END,
            )
            icon_wc_check.set_size_request(32, 32)
            icon_wc_check.set_filename(IconPath.icon_checked)

            wc_check_box = Gtk.Box(
                                    css_name='sw_box', name=style,
                                    orientation=Gtk.Orientation.HORIZONTAL,
                                    hexpand=True,
            )
            wc_check_box.append(icon_wc_check)
            wc_check_box.add_css_class('darkened')
            wc_check_box.set_visible(False)

            if getenv('SW_WC_STYLE') == style:
                wc_check_box.set_visible(True)

            swgs.wc_check_box_list.append(wc_check_box)
            wc_overlay.add_overlay(wc_check_box)

            wc_flow_theme_child = Gtk.FlowBoxChild(css_name='sw_flowboxchild')
            wc_flow_theme_child.set_child(wc_overlay)
            wc_flow_theme_child.set_name(style)

            swgs.wc_flow_theme.append(wc_flow_theme_child)

        swgs.wc_flow_theme.connect('child-activated', cb_change_wc_style)

        swgs.colors_theme.append(swgs.wc_theme_label_box)
        swgs.colors_theme.append(swgs.wc_flow_theme)

        swgs.icons_flow_theme = Gtk.FlowBox(css_name='sw_preferencesgroup')
        swgs.icons_flow_theme.set_margin_bottom(32)
        swgs.icons_flow_theme.set_homogeneous(True)
        swgs.icons_flow_theme.set_min_children_per_line(1)
        swgs.icons_flow_theme.set_max_children_per_line(32)

        swgs.icons_theme_title = Gtk.Label(
                                            css_name='sw_label_title',
                                            label=str_icon_colors_title,
                                            xalign=0.0,
                                            wrap=True,
                                            natural_wrap_mode=True
        )
        swgs.icons_theme_subtitle = Gtk.Label(
                                            css_name='sw_label_info',
                                            label=str_icon_colors_subtitle,
                                            xalign=0.0,
                                            wrap=True,
                                            natural_wrap_mode=True
        )
        swgs.icons_theme_label_box = Gtk.Box(
                                            css_name='sw_box_view',
                                            orientation=Gtk.Orientation.VERTICAL,
                                            halign=Gtk.Align.START
        )
        swgs.icons_theme_label_box.append(swgs.icons_theme_title)
        swgs.icons_theme_label_box.append(swgs.icons_theme_subtitle)

        swgs.icon_check_box_list = list()
        for color in builtin_icon_colors:
            image_icon_color = Gtk.Image(css_name='sw_image')
            if Path(folder_colors[color]).exists():
                paintable_icon_color = Gtk.IconPaintable.new_for_file(
                    Gio.File.new_for_path(folder_colors[color]), 256, 1)
                image_icon_color.set_from_paintable(paintable_icon_color)
                image_icon_color.set_pixel_size(72)

            icon_check = Gtk.Picture(
                        css_name='sw_uncheck', hexpand=True, halign=Gtk.Align.START,
                        content_fit=Gtk.ContentFit.SCALE_DOWN, vexpand=True,
                        valign=Gtk.Align.END,
            )
            icon_check.set_size_request(32, 32)
            icon_check.set_filename(IconPath.icon_checked)

            icon_check_box = Gtk.Box(
                                    css_name='sw_box', name=color,
                                    orientation=Gtk.Orientation.HORIZONTAL,
                                    hexpand=True,
            )
            icon_check_box.append(icon_check)
            icon_check_box.add_css_class('darkened')
            icon_check_box.set_visible(False)

            if getenv('SW_ICON_COLOR') == color:
                icon_check_box.set_visible(True)

            swgs.icon_check_box_list.append(icon_check_box)

            icon_overlay = Gtk.Overlay(css_name='sw_overlay')
            icon_overlay.set_child(image_icon_color)
            icon_overlay.add_overlay(icon_check_box)

            icon_flow_child = Gtk.FlowBoxChild(css_name='sw_flowboxchild')
            icon_flow_child.set_child(icon_overlay)
            icon_flow_child.set_name(color)

            swgs.icons_flow_theme.append(icon_flow_child)

        swgs.icons_flow_theme.connect('child-activated', cb_change_icon_color)
        swgs.colors_theme.append(swgs.icons_theme_label_box)
        swgs.colors_theme.append(swgs.icons_flow_theme)

        swgs.global_box = Gtk.Box(
                                css_name='sw_pref_box',
                                orientation=Gtk.Orientation.VERTICAL,
                                spacing=16,
                                halign=Gtk.Align.CENTER
        )
        swgs.global_box.append(swgs.global_settings_title_grid)
        swgs.global_box.append(swgs.group_startup)
        swgs.global_box.append(swgs.group_fm)
        swgs.global_box.append(swgs.group_render)
        swgs.global_box.append(swgs.colors_theme)

        swgs.global_settings = Gtk.Box(
                                    css_name='sw_flowbox',
                                    orientation=Gtk.Orientation.VERTICAL,
                                    halign=Gtk.Align.CENTER
        )
        swgs.global_settings.append(swgs.global_box)
        scrolled_global_settings.set_child(swgs.global_settings)

        activate_global_settings()
        return set_settings_widget(
                                main_stack,
                                vw_dict['global_settings'],
                                None
        )

    def add_winetricks_view():
        """___build winetricks view page___"""

        swgs.list_store_dll_0 = Gio.ListStore()
        swgs.list_store_dll_1 = Gio.ListStore()
        swgs.item_list_dll = Gtk.ListItem()

        swgs.factory_dll_0 = Gtk.SignalListItemFactory()
        swgs.factory_dll_0.connect('setup', cb_factory_dll_0_setup)
        swgs.factory_dll_0.connect('bind', cb_factory_dll_0_bind)

        swgs.factory_dll_desc_0 = Gtk.SignalListItemFactory()
        swgs.factory_dll_desc_0.connect('setup', cb_factory_dll_0_desc_setup)
        swgs.factory_dll_desc_0.connect('bind', cb_factory_dll_0_desc_bind)

        swgs.factory_dll_1 = Gtk.SignalListItemFactory()
        swgs.factory_dll_1.connect('setup', cb_factory_dll_1_setup)
        swgs.factory_dll_1.connect('bind', cb_factory_dll_1_bind)

        swgs.factory_dll_desc_1 = Gtk.SignalListItemFactory()
        swgs.factory_dll_desc_1.connect('setup', cb_factory_dll_1_desc_setup)
        swgs.factory_dll_desc_1.connect('bind', cb_factory_dll_1_desc_bind)

        swgs.model_dll_0 = Gtk.SingleSelection.new(swgs.list_store_dll_0)
        swgs.model_dll_1 = Gtk.SingleSelection.new(swgs.list_store_dll_1)

        swgs.column_view_dll_0 = Gtk.ColumnViewColumn(
                                    title=libs_column_label,
                                    visible=True,
                                    factory=swgs.factory_dll_0,
                                    fixed_width=240,
        )
        swgs.column_view_desc_0 = Gtk.ColumnViewColumn(
                                    title=description_label,
                                    expand=True,
                                    factory=swgs.factory_dll_desc_0,
        )
        swgs.column_view_dll_1 = Gtk.ColumnViewColumn(
                                    title=libs_column_label,
                                    visible=True,
                                    factory=swgs.factory_dll_1,
                                    fixed_width=240,
        )
        swgs.column_view_desc_1 = Gtk.ColumnViewColumn(
                                    title=description_label,
                                    expand=True,
                                    factory=swgs.factory_dll_desc_1,
        )
        swgs.view_dll_0 = Gtk.ColumnView(
                                    css_name='sw_columnview',
                                    show_column_separators=True,
                                    show_row_separators=True,
                                    model=swgs.model_dll_0,
        )
        swgs.view_dll_0.append_column(swgs.column_view_dll_0)
        swgs.view_dll_0.append_column(swgs.column_view_desc_0)
        swgs.dll_0_title = swgs.view_dll_0.get_first_child().get_first_child()
        swgs.dll_0_title.add_css_class('title')
        swgs.desc_0_title = swgs.dll_0_title.get_next_sibling()
        swgs.desc_0_title.add_css_class('title')

        swgs.view_dll_1 = Gtk.ColumnView(
                                    css_name='sw_columnview',
                                    show_column_separators=True,
                                    show_row_separators=True,
                                    model=swgs.model_dll_1,
        )
        swgs.view_dll_1.append_column(swgs.column_view_dll_1)
        swgs.view_dll_1.append_column(swgs.column_view_desc_1)
        swgs.dll_1_title = swgs.view_dll_1.get_first_child().get_first_child()
        swgs.dll_1_title.add_css_class('title')
        swgs.desc_1_title = swgs.dll_1_title.get_next_sibling()
        swgs.desc_1_title.add_css_class('title')

        swgs.view_dll = Gtk.Box(
                        orientation=Gtk.Orientation.VERTICAL,
                        vexpand=True,
                        hexpand=True,
                        homogeneous=True,
        )
        swgs.view_dll.append(swgs.view_dll_0)
        swgs.view_dll.append(swgs.view_dll_1)

        swgs.list_store_fonts = Gio.ListStore()
        swgs.item_list_fonts = Gtk.ListItem()

        swgs.factory_fonts = Gtk.SignalListItemFactory()
        swgs.factory_fonts.connect('setup', cb_factory_fonts_setup)
        swgs.factory_fonts.connect('bind', cb_factory_fonts_bind)

        swgs.factory_fonts_desc = Gtk.SignalListItemFactory()
        swgs.factory_fonts_desc.connect('setup', cb_factory_fonts_desc_setup)
        swgs.factory_fonts_desc.connect('bind', cb_factory_fonts_desc_bind)

        swgs.model_fonts = Gtk.SingleSelection.new(swgs.list_store_fonts)

        swgs.column_view_fonts = Gtk.ColumnViewColumn(fixed_width=240)
        swgs.column_view_fonts.set_title(fonts_column_label)
        swgs.column_view_fonts.set_factory(swgs.factory_fonts)

        swgs.column_view_fonts_desc = Gtk.ColumnViewColumn(fixed_width=240)
        swgs.column_view_fonts_desc.set_title(description_label)
        swgs.column_view_fonts_desc.set_expand(True)
        swgs.column_view_fonts_desc.set_factory(swgs.factory_fonts_desc)

        swgs.view_fonts = Gtk.ColumnView(css_name='sw_columnview')
        swgs.view_fonts.set_show_column_separators(True)
        swgs.view_fonts.set_show_row_separators(True)
        swgs.view_fonts.append_column(swgs.column_view_fonts)
        swgs.view_fonts.append_column(swgs.column_view_fonts_desc)
        swgs.view_fonts.set_model(swgs.model_fonts)

        swgs.fonts_title = swgs.view_fonts.get_first_child().get_first_child()
        swgs.fonts_title.add_css_class('title')
        swgs.fonts_desc_title = swgs.fonts_title.get_next_sibling()
        swgs.fonts_desc_title.add_css_class('title')

        swgs.scrolled_dll = Gtk.ScrolledWindow(
                                        css_name='sw_scrolledwindow',
                                        name=vw_dict['winetricks'],
                                        vexpand=True,
                                        hexpand=True,
                                        valign=Gtk.Align.FILL,
                                        halign=Gtk.Align.FILL,
                                        child=swgs.view_dll,
        )
        swgs.scrolled_fonts = Gtk.ScrolledWindow(
                                        css_name='sw_scrolledwindow',
                                        name=vw_dict['winetricks'],
                                        vexpand=True,
                                        hexpand=True,
                                        valign=Gtk.Align.FILL,
                                        halign=Gtk.Align.FILL,
                                        child=swgs.view_fonts,
        )

        ###___Winetricks_Tabs___.

        swgs.label_install_dll = Gtk.Label(
                                    css_name='sw_label',
                                    label=confirm_install_label
        )
        swgs.btn_install_dll = Gtk.Button(
                                    css_name='sw_button',
                                    hexpand=True,
                                    halign=Gtk.Align.END,
                                    valign=Gtk.Align.START,
                                    child=swgs.label_install_dll,
        )
        swgs.btn_install_dll.connect('clicked', cb_btn_install_dll)

        swgs.label_tab_dll = Gtk.Label(
                                css_name='sw_label',
                                label=libs_tab_label
        )
        swgs.label_tab_fonts = Gtk.Label(
                                css_name='sw_label',
                                label=fonts_tab_label
        )
        swgs.btn_tab_dll = Gtk.Button(css_name='sw_button')
        swgs.btn_tab_dll.set_child(swgs.label_tab_dll)
        swgs.btn_tab_dll.connect('clicked', on_tab_dll)

        swgs.btn_tab_fonts = Gtk.Button(css_name='sw_button')
        swgs.btn_tab_fonts.set_child(swgs.label_tab_fonts)
        swgs.btn_tab_fonts.connect('clicked', on_tab_fonts)

        swgs.model_templates_dll = Gio.ListStore()
        swgs.factory_dll_templates = Gtk.SignalListItemFactory()
        swgs.factory_dll_templates.connect('setup', cb_factory_dll_templates_setup)
        swgs.factory_dll_templates.connect('bind', cb_factory_dll_templates_bind)

        for k, v in dll_templates_dict.items():
            template = Gtk.Label(name=v, label=k)
            swgs.model_templates_dll.append(template)

        swgs.dropdown_dll_templates = Gtk.DropDown(
                                                css_name='sw_dropdown',
                                                hexpand=True,
                                                selected=0,
        )
        swgs.dropdown_dll_templates.set_size_request(180, -1)
        swgs.dropdown_dll_templates.set_model(swgs.model_templates_dll)
        swgs.dropdown_dll_templates.set_factory(swgs.factory_dll_templates)

        swgs.label_templates = Gtk.Label(
                                    css_name='sw_label',
                                    label=msg.ctx_dict["sample"].capitalize(),
        )
        swgs.box_templates = Gtk.Box(
                        css_name='sw_box_tab',
                        orientation=Gtk.Orientation.HORIZONTAL,
                        hexpand=True,
                        spacing=8,
                        halign=Gtk.Align.END
        )
        swgs.box_templates.append(swgs.label_templates)
        swgs.box_templates.append(swgs.dropdown_dll_templates)

        swgs.box_tabs = Gtk.Box(
                        css_name='sw_box_tab',
                        orientation=Gtk.Orientation.HORIZONTAL,
                        hexpand=True,
                        spacing=8,
        )
        swgs.box_tabs.append(swgs.btn_tab_dll)
        swgs.box_tabs.append(swgs.btn_tab_fonts)
        swgs.box_tabs.append(swgs.box_templates)

        swgs.stack_tabs = Gtk.Stack(css_name='sw_stack')
        swgs.stack_tabs.add_child(swgs.scrolled_dll)
        swgs.stack_tabs.add_child(swgs.scrolled_fonts)

        swgs.winetricks_title = Gtk.Label(
                                    css_name='sw_label_title',
                                    label=vl_dict['winetricks'],
                                    xalign=0.0,
        )
        swgs.winetricks_subtitle = Gtk.Label(
                                    css_name='sw_label_desc',
                                    label=str_winetricks_subtitle,
                                    xalign=0.0,
                                    wrap=True,
                                    natural_wrap_mode=True
        )
        swgs.winetricks_label_box = Gtk.Box(
                                    css_name='sw_box_view',
                                    orientation=Gtk.Orientation.VERTICAL,
                                    halign=Gtk.Align.START
        )
        swgs.winetricks_label_box.append(swgs.winetricks_title)
        swgs.winetricks_label_box.append(swgs.winetricks_subtitle)

        swgs.winetricks_title_grid = Gtk.Grid(css_name='sw_box_view')
        swgs.winetricks_title_grid.attach(swgs.winetricks_label_box, 0, 0, 1, 1)
        swgs.winetricks_title_grid.attach(swgs.btn_install_dll, 1, 0, 1, 1)

        swgs.pref_group_winetricks = Gtk.Box(
                                    css_name='sw_pref_box',
                                    orientation=Gtk.Orientation.VERTICAL
        )
        swgs.pref_group_winetricks.append(swgs.winetricks_title_grid)
        swgs.pref_group_winetricks.append(swgs.box_tabs)
        swgs.pref_group_winetricks.append(swgs.stack_tabs)

        scrolled_winetricks.set_child(swgs.pref_group_winetricks)

    def add_column_view():
        """___build files_column_view___"""

        swgs.column_view = Gtk.ColumnView(
                                    name='left_column_view',
                                    css_name='sw_columnview_view',
                                    show_row_separators=True,
                                    show_column_separators=True,
        )
        column_factory_file = Gtk.SignalListItemFactory()
        column_factory_file.connect('setup', cb_factory_setup, swgs.column_view)
        column_factory_file.connect('bind', cb_factory_bind, swgs.column_view)

        column_factory_size = Gtk.SignalListItemFactory()
        column_factory_size.connect('setup', cb_column_factory_size_setup)
        column_factory_size.connect('bind', cb_column_factory_size_bind)

        column_factory_type = Gtk.SignalListItemFactory()
        column_factory_type.connect('setup', cb_column_factory_type_setup)
        column_factory_type.connect('bind', cb_column_factory_type_bind)

        column_factory_uid = Gtk.SignalListItemFactory()
        column_factory_uid.connect('setup', cb_column_factory_uid_setup)
        column_factory_uid.connect('bind', cb_column_factory_uid_bind)

        column_factory_created = Gtk.SignalListItemFactory()
        column_factory_created.connect('setup', cb_column_factory_created_setup)
        column_factory_created.connect('bind', cb_column_factory_created_bind)

        swgs.column_view_file = Gtk.ColumnViewColumn()
        swgs.column_view_file.set_resizable(False)
        swgs.column_view_file.set_factory(column_factory_file)

        swgs.column_view_type = Gtk.ColumnViewColumn()
        swgs.column_view_type.set_resizable(True)
        swgs.column_view_type.set_expand(True)
        swgs.column_view_type.set_factory(column_factory_type)

        swgs.column_view_size = Gtk.ColumnViewColumn()
        swgs.column_view_size.set_resizable(True)
        swgs.column_view_size.set_expand(True)
        swgs.column_view_size.set_factory(column_factory_size)

        swgs.column_view_uid = Gtk.ColumnViewColumn()
        swgs.column_view_uid.set_resizable(True)
        swgs.column_view_uid.set_expand(True)
        swgs.column_view_uid.set_factory(column_factory_uid)

        swgs.column_view_created = Gtk.ColumnViewColumn()
        swgs.column_view_created.set_resizable(True)
        swgs.column_view_created.set_expand(True)
        swgs.column_view_created.set_factory(column_factory_created)

        swgs.column_view.append_column(swgs.column_view_file)
        swgs.column_view.append_column(swgs.column_view_type)
        swgs.column_view.append_column(swgs.column_view_size)
        swgs.column_view.append_column(swgs.column_view_uid)
        swgs.column_view.append_column(swgs.column_view_created)
        swgs.column_view.set_model(list_model)
        swgs.column_view.connect('activate', cb_item_activate)

        ctrl_lclick_column_view = Gtk.GestureClick()
        ctrl_lclick_column_view.connect('pressed', cb_ctrl_lclick_view)
        ctrl_lclick_column_view.set_button(1)

        ctrl_rclick_column_view = Gtk.GestureClick()
        ctrl_rclick_column_view.connect('pressed', cb_ctrl_rclick_view)
        ctrl_rclick_column_view.set_button(3)

        swgs.column_view.add_controller(ctrl_lclick_column_view)
        swgs.column_view.add_controller(ctrl_rclick_column_view)

        swgs.title_file = swgs.column_view.get_first_child().get_first_child()
        swgs.title_file.add_css_class('title')

        swgs.title_size = swgs.title_file.get_next_sibling()
        swgs.title_size.add_css_class('title')

        swgs.title_type = swgs.title_size.get_next_sibling()
        swgs.title_type.add_css_class('title')

        swgs.title_user = swgs.title_type.get_next_sibling()
        swgs.title_user.add_css_class('title')

        swgs.title_created = swgs.title_user.get_next_sibling()
        swgs.title_created.add_css_class('title')

        scrolled_left_files.set_child(swgs.column_view)

    def add_gvol_view():
        """___build gio volumes view___"""

        swgs.list_gvol_store = Gio.ListStore()
        list_gvol_item = Gtk.ListItem()
        list_gvol_item.set_activatable(True)

        gvol_model = Gtk.SingleSelection.new(swgs.list_gvol_store)

        gvol_factory = Gtk.SignalListItemFactory()
        gvol_factory.connect('setup', cb_gvol_factory_setup)
        gvol_factory.connect('bind', cb_gvol_factory_bind)

        gvol_id_factory = Gtk.SignalListItemFactory()
        gvol_id_factory.connect('setup', cb_gvol_id_factory_setup)
        gvol_id_factory.connect('bind', cb_gvol_id_factory_bind)

        gvol_uuid_factory = Gtk.SignalListItemFactory()
        gvol_uuid_factory.connect('setup', cb_gvol_uuid_factory_setup)
        gvol_uuid_factory.connect('bind', cb_gvol_uuid_factory_bind)

        gvol_drive_factory = Gtk.SignalListItemFactory()
        gvol_drive_factory.connect('setup', cb_gvol_drive_factory_setup)
        gvol_drive_factory.connect('bind', cb_gvol_drive_factory_bind)

        gvol_size_factory = Gtk.SignalListItemFactory()
        gvol_size_factory.connect('setup', cb_gvol_size_factory_setup)
        gvol_size_factory.connect('bind', cb_gvol_size_factory_bind)

        column_gvol = Gtk.ColumnViewColumn()
        column_gvol.set_title(msg.msg_dict['device_name'])
        column_gvol.set_expand(True)
        column_gvol.set_factory(gvol_factory)

        column_gvol_id = Gtk.ColumnViewColumn()
        column_gvol_id.set_title(msg.msg_dict['device_id'])
        column_gvol_id.set_expand(True)
        column_gvol_id.set_factory(gvol_id_factory)

        column_gvol_uuid = Gtk.ColumnViewColumn()
        column_gvol_uuid.set_title(msg.msg_dict['device_uuid'])
        column_gvol_uuid.set_expand(True)
        column_gvol_uuid.set_factory(gvol_uuid_factory)

        swgs.column_gvol_drive = Gtk.ColumnViewColumn()
        swgs.column_gvol_drive.set_title(msg.msg_dict['device_drive'])
        swgs.column_gvol_drive.set_expand(True)
        swgs.column_gvol_drive.set_factory(gvol_drive_factory)

        column_gvol_size = Gtk.ColumnViewColumn()
        column_gvol_size.set_title(msg.msg_dict['device_size'])
        column_gvol_size.set_expand(True)
        column_gvol_size.set_factory(gvol_size_factory)

        column_gvol_view = Gtk.ColumnView(
                                    css_name='sw_columnview_view',
                                    show_row_separators=True,
                                    show_column_separators=True,
        )
        column_gvol_view.append_column(column_gvol)
        column_gvol_view.append_column(column_gvol_size)
        column_gvol_view.append_column(column_gvol_id)
        column_gvol_view.append_column(swgs.column_gvol_drive)
        column_gvol_view.append_column(column_gvol_uuid)
        column_gvol_view.set_model(gvol_model)
        column_gvol_view.connect('activate', cb_gvol_activate)

        vol_title = column_gvol_view.get_first_child().get_first_child()
        vol_title.add_css_class('title')
        dev_title = vol_title.get_next_sibling()
        dev_title.add_css_class('title')
        uuid_title = dev_title.get_next_sibling()
        uuid_title.add_css_class('title')
        drive_title = uuid_title.get_next_sibling()
        drive_title.add_css_class('title')
        size_title = drive_title.get_next_sibling()
        size_title.add_css_class('title')

        swgs.gmount_ops = Gtk.MountOperation.new(parent)
        swgs.gmount_ops.set_display(display)

        swgs.gvolume_monitor = Gio.VolumeMonitor.get()

        swgs.gvolume_monitor.connect('volume-added', cb_volume_ops)
        swgs.gvolume_monitor.connect('volume-changed', cb_volume_ops)
        swgs.gvolume_monitor.connect('volume-removed', cb_volume_ops)

        swgs.gvolume_monitor.connect('mount-added', cb_volume_ops)
        swgs.gvolume_monitor.connect('mount-changed', cb_volume_ops)
        swgs.gvolume_monitor.connect('mount-removed', cb_volume_ops)

        swgs.gvolume_monitor.connect('drive-changed', cb_volume_ops)
        swgs.gvolume_monitor.connect('drive-connected', cb_volume_ops)
        swgs.gvolume_monitor.connect('drive-disconnected', cb_volume_ops)

        scrolled_gvol.set_child(column_gvol_view)

    def add_bookmarks_menu():
        """___build bookmarks menu___"""

        swgs.bookmarks_store = Gio.ListStore()
        bookmarks_model = Gtk.SingleSelection.new(swgs.bookmarks_store)

        bookmarks_factory = Gtk.SignalListItemFactory()
        bookmarks_factory.connect('setup', cb_bookmarks_factory_setup)
        bookmarks_factory.connect('bind', cb_bookmarks_factory_bind)

        list_view_bookmarks = Gtk.ListView(
                                    css_name='sw_listview',
                                    single_click_activate=True,
                                    show_separators=True,
        )
        list_view_bookmarks.set_factory(bookmarks_factory)
        list_view_bookmarks.set_model(bookmarks_model)
        list_view_bookmarks.connect('activate', cb_bookmark_activate)

        scrolled_bookmarks.set_child(list_view_bookmarks)

    def add_playlist_menu():
        """___build media playlist menu___"""

        swgs.playlist_store = Gio.ListStore()
        playlist_model = Gtk.SingleSelection.new(swgs.playlist_store)

        playlist_factory = Gtk.SignalListItemFactory()
        playlist_factory.connect('setup', cb_playlist_factory_setup)
        playlist_factory.connect('bind', cb_playlist_factory_bind)

        list_view_playlist = Gtk.ListView(
                                    css_name='sw_listview',
                                    single_click_activate=True,
                                    show_separators=True,
        )
        list_view_playlist.set_factory(playlist_factory)
        list_view_playlist.set_model(playlist_model)
        list_view_playlist.connect('activate', cb_playlist_activate)

        scrolled_playlist.set_child(list_view_playlist)

    def add_controller_settings_view():
        """___build gamepad controller settings___"""
        pass

    def get_define_colors():
        """___Get current define colors from css provider___"""

        css_list = css_provider.to_string().splitlines()
        define_colors = dict()
        for x in css_list:
            if '@define-color sw_' in x:
                if len([x.split(' ')[2].strip(';')]) > 0:
                    define_colors[x.split(' ')[1]] = [x.split(' ')[2].strip(';')][0]

        return define_colors

    def set_define_colors():

        dcolors = get_define_colors()
        progress_main.set_font_size(8)
        progress_main.set_foreground(dcolors['sw_invert_header_bg_color'])
        progress_main.set_background(dcolors['sw_header_bg_color'])
        progress_main.set_progress_color(
                                        dcolors['sw_invert_progress_color'],
                                        dcolors['sw_accent_fg_color'],
        )
        progress_main.set_border_color(dcolors['sw_accent_fg_color'])
        progress_main.set_shadow_color(dcolors['sw_header_bg_color'])

    def set_parent_layer(window, monitor):
        """___Set parent window surface as a background layer.___"""

        LayerShell.init_for_window(window)
        LayerShell.set_layer(window, LayerShell.Layer.TOP)
        #LayerShell.set_anchor(window, LayerShell.Edge.TOP, True)
        LayerShell.set_monitor(window, monitor)

        LayerShell.set_margin(window, LayerShell.Edge.BOTTOM, 0)
        LayerShell.set_margin(window, LayerShell.Edge.TOP, 0)
        LayerShell.auto_exclusive_zone_enable(window)

####___Build_main_menu___.

    display = Gdk.Display().get_default()

    try:
        monitor = display.get_monitors()[0]
    except (Exception,):
        mon_width = 1280
        mon_height = 720
        print(tc.RED, f'MONITOR_SIZE: not found, set {mon_width}x{mon_height}{tc.END}')
    else:
        mon_width = monitor.get_geometry().width
        mon_height = monitor.get_geometry().height
        env_dict['SW_HUD_SIZE'] = f'{int(mon_height / 55)}'
        print(tc.VIOLET, f'MONITOR_SIZE: {tc.YELLOW}{mon_width}x{mon_height}{tc.END}')

    clipboard = display.get_clipboard()
    css_provider = Gtk.CssProvider()
    gtk_settings = Gtk.Settings.get_for_display(display)

    if gtk_settings.props.gtk_xft_dpi is not None:
        xft_dpi = (gtk_settings.props.gtk_xft_dpi / 1024) / 96
        if xft_dpi < 1.0:
            xft_dpi = 1.0
    else:
        xft_dpi = 1.0

    print(tc.VIOLET, 'XFT_DPI:', tc.YELLOW, xft_dpi, gtk_settings.props.gtk_xft_dpi, tc.END)

    icon_theme = Gtk.IconTheme.get_for_display(display)
    icon_theme.add_resource_path(f'{sw_gui_icons}')
    icon_theme.add_search_path(f'{sw_gui_icons}')

####___Parent_window___.

    parent = Gtk.Window(application=swgs, css_name='sw_window', name='parent_window')
    parent.remove_css_class('background')
    parent.add_css_class('sw_background')
    parent.set_default_size(swgs.width, swgs.height)
    parent.set_resizable(True)
    parent.set_default_icon_name(sw_program_name)

    swgs.connection.register_object(
                            "/ru/launcher/StartWine",
                            swgs.gdbus_node.interfaces[0],
                            gdbus_method_call,
                            None,
                            None
    )

####___Headerbars___.

    entry_search = Gtk.SearchEntry(
                                css_name='sw_entry',
                                placeholder_text='search...',
                                valign=Gtk.Align.CENTER,
                                hexpand=True,
                                search_delay=500,
    )
    entry_search.connect('search-changed', cb_entry_search_changed)
    entry_search.connect('stop-search', cb_entry_search_stop)

    entry_web = Gtk.Entry(
                        css_name='sw_entry',
                        placeholder_text='url...',
                        valign=Gtk.Align.CENTER,
                        hexpand=True,
    )
    entry_web.connect('activate', cb_entry_web_activate)

    entry_path = Gtk.Entry(
                        name=str(swgs.default_dir),
                        css_name='sw_entry',
                        text=str(swgs.default_dir),
                        valign=Gtk.Align.CENTER,
                        hexpand=True,
    )
    entry_path.connect("activate", cb_entry_path_activate)

    image_search = Gtk.Image(css_name='sw_image')
    image_search.set_from_file(IconPath.icon_search)

    image_web = Gtk.Image(css_name='sw_image')
    image_web.set_from_file(IconPath.icon_global)

    image_path = Gtk.Image(css_name='sw_image')
    image_path.set_from_file(IconPath.icon_folder)

    image_back_path = Gtk.Image(css_name='sw_image')
    image_back_path.set_from_file(IconPath.icon_folder)

    btn_search = Gtk.Button(css_name='sw_button_header', name='btn_search')
    btn_search.set_valign(Gtk.Align.CENTER)
    btn_search.set_tooltip_markup(msg.tt_dict['search'])
    btn_search.set_child(image_search)
    btn_search.connect('clicked', cb_btn_search)

    btn_web = Gtk.Button(css_name='sw_button_header', name='btn_path')
    btn_web.set_valign(Gtk.Align.CENTER)
    btn_web.set_tooltip_markup(msg.tt_dict['web'])
    btn_web.set_child(image_web)
    btn_web.set_sensitive(False)

    btn_path = Gtk.Button(css_name='sw_button_header', name='btn_path')
    btn_path.set_valign(Gtk.Align.CENTER)
    btn_path.set_tooltip_markup(msg.tt_dict['path'])
    btn_path.set_child(image_path)
    btn_path.connect('clicked', cb_btn_path)

    btn_back_path = Gtk.Button(css_name='sw_button_header', name='btn_back_path')
    btn_back_path.set_valign(Gtk.Align.CENTER)
    btn_back_path.set_child(image_back_path)
    btn_back_path.connect('clicked', cb_btn_back_path)

    box_side = Gtk.Box(
                    orientation=Gtk.Orientation.HORIZONTAL,
                    spacing=4,
                    valign=Gtk.Align.CENTER,
                    hexpand=True,
                    )
    box_side.append(btn_back_path)
    box_side.append(entry_path)

    ctrl_scroll_path = Gtk.EventControllerScroll()
    ctrl_scroll_path.set_flags(Gtk.EventControllerScrollFlags.VERTICAL)
    ctrl_scroll_path.connect('scroll', cb_ctrl_scroll_path)

    box_scrolled = Gtk.Box(
                        css_name='sw_entry',
                        orientation=Gtk.Orientation.HORIZONTAL,
                        spacing=4,
                        valign=Gtk.Align.CENTER,
                        hexpand=True,
    )
    hadjustment_path = Gtk.Adjustment()

    scrolled_path = Gtk.ScrolledWindow(
                        css_name='sw_scrolledwindow',
                        valign=Gtk.Align.CENTER,
                        hexpand=True,
                        min_content_width=mon_width*0.25,
                        max_content_width=mon_width*0.66,
                        propagate_natural_width=True,
    )
    scrolled_path.set_policy(Gtk.PolicyType.EXTERNAL, Gtk.PolicyType.NEVER)
    scrolled_path.set_hadjustment(hadjustment_path)
    scrolled_path.set_child(box_scrolled)
    scrolled_path.add_controller(ctrl_scroll_path)

    box_path = Gtk.Box(
                    css_name='sw_box',
                    orientation=Gtk.Orientation.HORIZONTAL,
                    spacing=4,
                    valign=Gtk.Align.CENTER,
                    hexpand=True,
                    )
    box_path.append(btn_search)
    box_path.append(scrolled_path)

    box_search = Gtk.Box(
                    name='box_search',
                    orientation=Gtk.Orientation.HORIZONTAL,
                    spacing=4,
                    valign=Gtk.Align.CENTER,
                    hexpand=True,
                    )
    box_search.append(btn_path)
    box_search.append(entry_search)

    box_web = Gtk.Box(
                    name='box_web',
                    orientation=Gtk.Orientation.HORIZONTAL,
                    spacing=4,
                    valign=Gtk.Align.CENTER,
                    hexpand=True,
                    )
    box_web.append(btn_web)
    box_web.append(entry_web)

    stack_search_path = Gtk.Stack()
    stack_search_path.set_hexpand(True)
    stack_search_path.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
    stack_search_path.add_child(box_path)
    stack_search_path.add_child(box_side)
    stack_search_path.add_child(box_search)
    stack_search_path.add_child(box_web)
    stack_search_path.set_visible(False)

    ####___Navigate_headerbar_buttons___.

    image_home = Gtk.Image(css_name='sw_image')
    image_home.set_from_file(IconPath.icon_home)

    image_back = Gtk.Image(css_name='sw_image')
    image_back.set_from_file(IconPath.icon_back)

    image_more = Gtk.Image(css_name='sw_image')
    image_more.set_from_file(IconPath.icon_view_more)

    image_up = Gtk.Image(css_name='sw_image')
    image_up.set_from_file(IconPath.icon_up)

    image_menu = Gtk.Image(css_name='sw_image')
    image_menu.set_from_file(IconPath.icon_menu)

    btn_home = Gtk.Button(
                        name='btn_home',
                        css_name='sw_button_header',
                        valign=Gtk.Align.CENTER,
                        tooltip_markup=msg.tt_dict['go_home'],
                        child=image_home,
                        visible=False,
    )
    btn_home.connect('clicked', cb_btn_home)

    btn_back_main = Gtk.Button(
                        name='btn_back_main',
                        css_name='sw_button_header',
                        valign=Gtk.Align.CENTER,
                        tooltip_markup=msg.tt_dict['back_main'],
                        child=image_back,
                        visible=False,
    )
    btn_back_main.connect('clicked', cb_btn_back_main)

    btn_more = Gtk.Button(
                        css_name='sw_button_header',
                        name='view_more',
                        valign=Gtk.Align.CENTER,
                        tooltip_markup=msg.tt_dict['view_more'],
                        child=image_more,
                        visible=False,
    )
    btn_more.connect('clicked', cb_btn_view_more)

    btn_header_menu = Gtk.Button(
                        css_name='sw_wc_menu',
                        name='header_menu',
                        valign=Gtk.Align.CENTER,
                        tooltip_markup=msg.tt_dict['view_menu'],
                        child=image_menu,
                        margin_end=8,
    )
    btn_header_menu.connect('clicked', cb_btn_view_header_menu)

    btn_back_up = Gtk.Button(
                        css_name='sw_button_header',
                        valign=Gtk.Align.CENTER,
                        tooltip_markup=msg.tt_dict['back_up'],
                        child=image_up,
                        visible=False,
    )
    btn_back_up.connect('clicked', cb_btn_back_up)

    top_headerbar_start_box = Gtk.Grid(
                                valign=Gtk.Align.CENTER,
                                margin_start=4,
                                margin_top=4,
                                margin_bottom=4,
                                column_spacing=4,
    )
    top_headerbar_end_box = Gtk.Box(
                                orientation=Gtk.Orientation.HORIZONTAL,
                                hexpand=True,
                                valign=Gtk.Align.CENTER,
                                halign=Gtk.Align.END,
                                margin_start=4,
                                margin_top=4,
                                margin_bottom=4,
                                spacing=4,
    )
    top_headerbar_center_box = Gtk.Box(
                                orientation=Gtk.Orientation.HORIZONTAL,
                                hexpand=True,
                                vexpand=True,
                                valign=Gtk.Align.CENTER,
                                halign=Gtk.Align.CENTER,
                                baseline_position=Gtk.BaselinePosition.CENTER,
                                spacing=4,
                                margin_start=8,
                                margin_end=8,
    )
    top_headerbar_center_box.append(btn_home)
    top_headerbar_center_box.append(stack_search_path)
    top_headerbar_center_box.append(btn_more)
    top_headerbar_center_box.append(btn_back_up)

    image_wc_close = Gtk.Image(css_name='sw_image', pixel_size=22, hexpand=True, vexpand=True)
    paintable_wc_close = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(IconPath.icon_close), 24, 24,
    )
    paintable_wc_close_light = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(IconPath.icon_close_light), 24, 24,
    )
    image_wc_min = Gtk.Image(css_name='sw_image', pixel_size=22, hexpand=True, vexpand=True)
    paintable_wc_min = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(IconPath.icon_min), 24, 24,
    )
    paintable_wc_min_light = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(IconPath.icon_min_light), 24, 24,
    )
    image_wc_max = Gtk.Image(css_name='sw_image', pixel_size=22, hexpand=True, vexpand=True)
    paintable_wc_max = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(IconPath.icon_max), 22, 24,
    )
    paintable_wc_max_light = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(IconPath.icon_max_light), 22, 24,
    )
    paintable_wc_br_close = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(IconPath.icon_br_close), 24, 24,
    )
    paintable_wc_br_close_light = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(IconPath.icon_br_close_light), 24, 24,
    )
    paintable_wc_br_min = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(IconPath.icon_br_min), 24, 24,
    )
    paintable_wc_br_min_light = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(IconPath.icon_br_min_light), 24, 24,
    )
    paintable_wc_br_max = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(IconPath.icon_br_max), 22, 24,
    )
    paintable_wc_br_max_light = Gtk.IconPaintable.new_for_file(
                        Gio.File.new_for_path(IconPath.icon_br_max_light), 22, 24,
    )
    wc_close = Gtk.Button(css_name='sw_wc_close')
    wc_close.set_child(image_wc_close)
    wc_close.connect('clicked', on_parent_close)

    wc_minimize = Gtk.Button(css_name='sw_wc_minimize')
    wc_minimize.set_child(image_wc_min)
    wc_minimize.connect('clicked', on_parent_minimize)

    wc_maximize = Gtk.Button(css_name='sw_wc_maximize')
    wc_maximize.set_child(image_wc_max)
    wc_maximize.connect('clicked', on_parent_maximize)

    top_headerbar_start_box.attach(btn_back_main, 0, 0, 1, 1)

    top_headerbar_end_box.append(btn_header_menu)
    top_headerbar_end_box.append(wc_minimize)
    top_headerbar_end_box.append(wc_maximize)
    top_headerbar_end_box.append(wc_close)

    top_headerbar = Gtk.HeaderBar(css_name='sw_header_top')
    top_headerbar.set_title_widget(top_headerbar_center_box)
    top_headerbar.pack_start(top_headerbar_start_box)
    top_headerbar.pack_end(top_headerbar_end_box)
    top_headerbar.set_size_request(-1, 46)
    top_headerbar.set_show_title_buttons(False)

    header_box = Gtk.Box(css_name='sw_box')
    header_box.set_visible(False)
    parent.set_titlebar(header_box)

    ####___Bottom_headerbar buttons___.

    image_hide = Gtk.Image(css_name='sw_image')
    image_hide.set_from_file(IconPath.icon_hide)

    btn_sidebar = Gtk.Button(css_name='sw_button_header')
    btn_sidebar.set_tooltip_markup(msg.tt_dict['sidebar'])
    btn_sidebar.set_valign(Gtk.Align.CENTER)
    btn_sidebar.set_child(image_hide)
    btn_sidebar.connect('clicked', cb_btn_sidebar)
    btn_sidebar.set_visible(False)

    image_gmount = Gtk.Image(css_name='sw_image')
    image_gmount.set_from_file(IconPath.icon_eject)

    btn_gmount = Gtk.Button(css_name='sw_button_header')
    btn_gmount.set_tooltip_markup(msg.tt_dict['gmount'])
    btn_gmount.set_valign(Gtk.Align.CENTER)
    btn_gmount.set_child(image_gmount)
    btn_gmount.connect('clicked', cb_btn_drive)
    btn_gmount.set_visible(False)

    image_bookmarks = Gtk.Image(css_name='sw_image')
    image_bookmarks.set_from_file(IconPath.icon_bookmarks)

    btn_bookmarks = Gtk.Button(css_name='sw_button_header')
    btn_bookmarks.set_tooltip_markup(msg.tt_dict['bookmarks'])
    btn_bookmarks.set_valign(Gtk.Align.CENTER)
    btn_bookmarks.set_child(image_bookmarks)
    btn_bookmarks.connect('clicked', cb_btn_bookmarks)
    btn_bookmarks.set_visible(False)

    image_playlist = Gtk.Image(css_name='sw_image')
    image_playlist.set_from_file(IconPath.icon_playlist)

    btn_playlist = Gtk.Button(css_name='sw_button_header')
    btn_playlist.set_tooltip_markup(msg.tt_dict['playlist'])
    btn_playlist.set_valign(Gtk.Align.CENTER)
    btn_playlist.set_child(image_playlist)
    btn_playlist.connect('clicked', cb_btn_playlist)
    btn_playlist.set_visible(False)

    ####___Bottom_headerbar stack panel___.

    progress_main = SwProgressBar(
                        css_name='sw_progressbar',
                        valign=Gtk.Align.CENTER,
                        halign=Gtk.Align.CENTER,
                        hexpand=True,
                        vexpand=True,
    )
    progress_main.set_size_request(480, 20)
    progress_main.set_visible(False)

    spinner = Gtk.Spinner(css_name='sw_spinner')

    progress_main_grid = Gtk.Grid(css_name='sw_grid')
    progress_main_grid.attach(progress_main, 0, 0, 1, 1)
    progress_main_grid.attach(spinner, 1, 0, 1, 1)

    image_media_info = Gtk.Image(css_name='sw_image')
    image_media_info.set_from_file(IconPath.icon_info)
    btn_media_info = Gtk.Button(
        css_name='sw_button_header', child=image_media_info, valign=Gtk.Align.CENTER
    )
    btn_media_info.connect('clicked', cb_media_info)

    media_file = Gtk.MediaFile.new()
    media_controls = Gtk.MediaControls(css_name="sw_media_controls", hexpand=True)
    media_controls.set_media_stream(media_file)
    media_controls.set_size_request(200, -1)

    media_main_grid = Gtk.Grid(css_name='sw_media_controls')
    media_main_grid.attach(btn_media_info, 0, 0, 1, 1)
    media_main_grid.attach(media_controls, 1, 0, 1, 1)

    stack_progress_main = Gtk.Stack(
                            transition_duration=250,
                            transition_type=Gtk.StackTransitionType.SLIDE_LEFT_RIGHT,
                            valign=Gtk.Align.CENTER,
                            halign=Gtk.Align.CENTER,
                            hexpand=True,
                            margin_start=16,
                            margin_end=16,
    )
    stack_panel = Gtk.Stack(
                            css_name='sw_stack',
                            transition_duration=350,
                            transition_type=Gtk.StackTransitionType.SLIDE_LEFT_RIGHT,
                            halign=Gtk.Align.CENTER
    )
    for k, v in vl_dict.items():
        box = Gtk.Box(
                    css_name='sw_box', orientation=Gtk.Orientation.HORIZONTAL,
                    spacing=8,
                    halign=Gtk.Align.CENTER,
        )
        stack_panel.add_named(box, k)
        for i in range(3):
            if i == 0:
                image = Gtk.Image(css_name='sw_image')
                image.set_from_file(IconPath.icon_back)
                label = Gtk.Label(css_name='sw_label_desc', ellipsize=Pango.EllipsizeMode.END)
                label.set_size_request(100, -1)
                box_child = Gtk.Box(
                    css_name='sw_box', orientation=Gtk.Orientation.HORIZONTAL,
                    spacing=8,
                )
                box_child.append(label)
                box_child.append(image)
                btn_prev = Gtk.Button(css_name='sw_box', name='btn_prev', child=box_child)
                btn_prev.connect('clicked', cb_btn_overlay)
                box.append(btn_prev)
            if i == 1:
                label = Gtk.Label(css_name='sw_label')
                label.set_size_request(200, -1)
                label.add_css_class('button')
                box.append(label)
            if i == 2:
                image = Gtk.Image(css_name='sw_image')
                image.set_from_file(IconPath.icon_next)
                label = Gtk.Label(css_name='sw_label_desc', ellipsize=Pango.EllipsizeMode.END)
                label.set_size_request(100, -1)
                box_child = Gtk.Box(
                    css_name='sw_box', orientation=Gtk.Orientation.HORIZONTAL,
                    spacing=8,
                )
                box_child.append(image)
                box_child.append(label)
                btn_next = Gtk.Button(css_name='sw_box', name='btn_next', child=box_child)
                btn_next.connect('clicked', cb_btn_overlay)
                box.append(btn_next)

    stack_progress_main.add_child(stack_panel)
    stack_progress_main.add_child(progress_main_grid)
    stack_progress_main.add_child(media_main_grid)

    scroll_data = list()
    ctrl_scroll_view = Gtk.EventControllerScroll()
    ctrl_scroll_view.set_flags(Gtk.EventControllerScrollFlags.VERTICAL)
    ctrl_scroll_view.connect('scroll', cb_ctrl_scroll_view, scroll_data)

    ctrl_swipe = Gtk.GestureSwipe()
    ctrl_swipe.set_button(1)
    ctrl_swipe.set_propagation_phase(Gtk.PropagationPhase.BUBBLE)
    #ctrl_swipe.connect('swipe', cb_ctrl_swipe_panel, stack_panel)

    stack_panel.add_controller(ctrl_swipe)
    stack_panel.add_controller(ctrl_scroll_view)

    ####___bottom headerbar popovers___.

    scale_step = 12

    btn_scale_icons = Gtk.SpinButton(css_name='sw_spinbutton')
    btn_scale_icons.set_hexpand(True)
    btn_scale_icons.set_halign(Gtk.Align.FILL)
    btn_scale_icons.set_climb_rate(0)
    btn_scale_icons.set_digits(0)
    btn_scale_icons.set_increments(scale_step, 1)
    btn_scale_icons.set_numeric(True)
    btn_scale_icons.set_range(24, 216)
    btn_scale_icons.set_snap_to_ticks(True)
    btn_scale_icons.set_update_policy(Gtk.SpinButtonUpdatePolicy.IF_VALID)
    btn_scale_icons.set_value(swgs.cfg['icon_size'])
    btn_scale_icons.connect('value-changed', on_set_px_size)

    btn_scale_shortcuts = Gtk.SpinButton(css_name='sw_spinbutton')
    btn_scale_shortcuts.set_hexpand(True)
    btn_scale_shortcuts.set_halign(Gtk.Align.FILL)
    btn_scale_shortcuts.set_climb_rate(0)
    btn_scale_shortcuts.set_digits(0)
    btn_scale_shortcuts.set_increments(scale_step, 1)
    btn_scale_shortcuts.set_numeric(True)
    btn_scale_shortcuts.set_range(96, 288)
    btn_scale_shortcuts.set_snap_to_ticks(True)
    btn_scale_shortcuts.set_update_policy(Gtk.SpinButtonUpdatePolicy.IF_VALID)
    btn_scale_shortcuts.set_value(swgs.cfg['shortcut_size'])
    btn_scale_shortcuts.connect('value-changed', on_set_px_size)

    menu_box = Gtk.Grid()
    menu_box.set_size_request(mon_width*0.1, mon_height*0.01)
    menu_box.set_hexpand(True)
    menu_box.set_halign(Gtk.Align.FILL)
    menu_box.attach(btn_scale_icons, 0, 0, 1, 1)

    menu_box_sc = Gtk.Grid()
    menu_box_sc.set_size_request(mon_width*0.1, mon_height*0.01)
    menu_box_sc.set_hexpand(True)
    menu_box_sc.set_halign(Gtk.Align.FILL)
    menu_box_sc.attach(btn_scale_shortcuts, 0, 0, 1, 1)

    image_scale = Gtk.Image(css_name='sw_image')
    image_scale.set_from_file(IconPath.icon_scale)

    btn_popover_scale = Gtk.Button(css_name='sw_button_header')
    btn_popover_scale.set_tooltip_markup(msg.tt_dict['resize_icons'])
    btn_popover_scale.set_valign(Gtk.Align.CENTER)
    btn_popover_scale.set_child(image_scale)
    btn_popover_scale.connect('clicked', cb_btn_popover_scale)

    popover_scale = Gtk.Popover(css_name='sw_popover', position=Gtk.PositionType.LEFT)
    popover_scale.set_child(menu_box)
    popover_scale.set_autohide(True)
    popover_scale.set_default_widget(btn_popover_scale)
    popover_scale.set_parent(btn_popover_scale)

    popover_scale_sc = Gtk.Popover(css_name='sw_popover', position=Gtk.PositionType.LEFT)
    popover_scale_sc.set_child(menu_box_sc)
    popover_scale_sc.set_autohide(True)
    popover_scale_sc.set_default_widget(btn_popover_scale)
    popover_scale_sc.set_parent(btn_popover_scale)

    ####___popover_colors___.
    label_dark = Gtk.Label(
                        css_name='sw_label_popover',
                        label=theme_dict['dark'],
    )
    label_light = Gtk.Label(
                        css_name='sw_label_popover',
                        label=theme_dict['light'],
    )
    label_custom = Gtk.Label(
                        css_name='sw_label_popover',
                        label=theme_dict['custom'],
    )
    pic_dark = Gtk.Picture(
                        css_name='sw_check_dark',
                        content_fit=Gtk.ContentFit.COVER,
    )
    pic_light = Gtk.Picture(
                        css_name='sw_check_light',
                        content_fit=Gtk.ContentFit.COVER,
    )
    pic_custom = Gtk.Picture(
                        css_name='sw_check_custom',
                        content_fit=Gtk.ContentFit.COVER,
    )
    btn_dark = Gtk.CheckButton(
                        css_name='sw_checkbutton',
                        valign=Gtk.Align.CENTER,
                        child=pic_dark,
    )
    btn_light = Gtk.CheckButton(
                        label=theme_dict['light'],
                        css_name='sw_checkbutton',
                        valign=Gtk.Align.CENTER,
                        child=pic_light,
    )
    btn_custom = Gtk.CheckButton(
                        label=theme_dict['custom'],
                        css_name='sw_checkbutton',
                        valign=Gtk.Align.CENTER,
                        child=pic_custom,
    )
    btn_dark.get_first_child().set_visible(False)
    btn_light.get_first_child().set_visible(False)
    btn_custom.get_first_child().set_visible(False)
    btn_dark.set_group(btn_light)
    btn_custom.set_group(btn_light)

    btn_dark.connect('toggled', on_toggled_dark, pic_dark)
    btn_light.connect('toggled', on_toggled_light, pic_light)
    btn_custom.connect('toggled', on_toggled_custom, pic_custom)

    colors_box = Gtk.Grid(css_name='sw_grid')
    colors_box.set_column_spacing(4)
    colors_box.attach(btn_dark, 0, 0, 1, 1)
    colors_box.attach(label_dark, 1, 0, 1, 1)
    colors_box.attach(btn_light, 2, 0, 1, 1)
    colors_box.attach(label_light, 3, 0, 1, 1)
    colors_box.attach(btn_custom, 4, 0, 1, 1)
    colors_box.attach(label_custom, 5, 0, 1, 1)

    image_colors = Gtk.Image(css_name='sw_image')
    image_colors.set_from_file(IconPath.icon_colors)

    btn_popover_colors = Gtk.Button(css_name='sw_button_header')
    btn_popover_colors.set_tooltip_markup(msg.tt_dict['change_theme'])
    btn_popover_colors.set_valign(Gtk.Align.CENTER)
    btn_popover_colors.set_child(image_colors)

    popover_colors = Gtk.Popover(css_name='sw_popover')
    popover_colors.set_child(colors_box)
    popover_colors.set_autohide(True)
    popover_colors.set_position(Gtk.PositionType.LEFT)
    popover_colors.set_parent(btn_popover_colors)

    btn_popover_colors.connect('clicked', cb_btn_popover_colors)

    ####___button_icon_position___.

    image_icon_position = Gtk.Image(css_name='sw_image')
    image_icon_position.set_from_file(IconPath.icon_rotate)

    btn_icon_position = Gtk.Button(css_name='sw_button_header')
    btn_icon_position.set_child(image_icon_position)
    btn_icon_position.set_tooltip_markup(msg.tt_dict['icon_position'])
    btn_icon_position.connect('clicked', cb_btn_icon_position)

    ####___bottom headerbar boxes___.

    bottom_headerbar_start_box = Gtk.Box(
                                    orientation=Gtk.Orientation.HORIZONTAL,
                                    margin_start=4,
                                    margin_top=4,
                                    margin_bottom=4,
                                    spacing=4,
                                    )

    bottom_headerbar_center_box = Gtk.Box(
                                    orientation=Gtk.Orientation.HORIZONTAL,
                                    hexpand=True,
                                    halign=Gtk.Align.CENTER,
                                    baseline_position=Gtk.BaselinePosition.CENTER,
                                    )

    bottom_headerbar_end_box = Gtk.Box(
                                    orientation=Gtk.Orientation.HORIZONTAL,
                                    margin_end=4,
                                    margin_top=4,
                                    margin_bottom=4,
                                    spacing=4,
                                    )

    bottom_headerbar_start_box.append(btn_sidebar)
    bottom_headerbar_start_box.append(btn_gmount)
    bottom_headerbar_start_box.append(btn_bookmarks)
    bottom_headerbar_start_box.append(btn_playlist)

    bottom_headerbar_center_box.append(stack_progress_main)

    bottom_headerbar_end_box.append(btn_popover_scale)
    bottom_headerbar_end_box.append(btn_popover_colors)
    bottom_headerbar_end_box.append(btn_icon_position)

    bottom_headerbar = Gtk.HeaderBar(
                                    css_name='sw_header_bottom',
                                    title_widget=bottom_headerbar_center_box,
                                    show_title_buttons=False,
                                    
                                    )
    bottom_headerbar.set_size_request(-1, 46)
    bottom_headerbar.pack_start(bottom_headerbar_start_box)
    bottom_headerbar.pack_end(bottom_headerbar_end_box)

####___Sidebar main grids___.

    grid_main = Gtk.Grid()
    grid_main.set_hexpand(True)
    grid_main.set_vexpand(True)

    grid_sidebar_btn = Gtk.Grid(css_name='sw_grid')
    grid_sidebar_btn.set_vexpand(True)
    grid_sidebar_btn.set_valign(Gtk.Align.START)
    grid_sidebar_btn.set_row_spacing(10)

    grid_main_btn = Gtk.Grid()
    grid_main_btn.set_vexpand(True)
    grid_main_btn.set_row_spacing(10)
    grid_main_btn.set_margin_start(16)
    grid_main_btn.set_margin_end(16)
    grid_main_btn.set_margin_top(16)
    grid_main_btn.set_margin_bottom(16)
    grid_main_btn.set_halign(Gtk.Align.CENTER)

####___Sidebar_menu_buttons___.

    image_sidebar_logo = Gtk.Picture(css_name='sw_picture')
    image_sidebar_logo.set_hexpand(True)
    image_sidebar_logo.set_valign(Gtk.Align.START)
    image_sidebar_logo.set_size_request(-1, 128)

    count = -1
    for widget_name, icon_path in zip(sidebar_widgets, sidebar_icons):
        count += 1
        image_btn = Gtk.Picture(css_name='sw_picture')
        image_btn.set_vexpand(True)
        image_btn.set_halign(Gtk.Align.START)
        icon_paintable = Gtk.IconPaintable.new_for_file(
                                        Gio.File.new_for_path(icon_path), 48, 1,
        )
        image_btn.set_paintable(icon_paintable)
        label_btn = Gtk.Label(css_name='sw_label', label=btn_dict[widget_name], xalign=0.0)
        label_btn.add_css_class('font_size_13')

        box_btn = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, valign=Gtk.Align.CENTER)
        box_btn.append(image_btn)
        box_btn.append(label_btn)

        btn = Gtk.Button(css_name='sw_button')
        btn.set_hexpand(True)
        btn.set_name(widget_name)
        btn.set_child(box_btn)
        btn.connect('clicked', cb_btn_main)

        grid_sidebar_btn.attach(btn, 0, count, 1, 1)

    grid_main_btn.attach(image_sidebar_logo, 0, 0, 1, 1)
    grid_main_btn.attach(grid_sidebar_btn, 0, 1, 1, 1)

####___Vte_terminal___.

    terminal_stack = Gtk.Stack()
    terminal_stack.set_transition_duration(0)
    terminal_stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)

    terminal_revealer = Gtk.Revealer()
    terminal_revealer.set_transition_duration(0)
    terminal_revealer.set_transition_type(Gtk.RevealerTransitionType.SLIDE_UP)
    terminal_revealer.set_reveal_child(False)

    terminal = Vte.Terminal(css_name='sw_vte')
    shell = '/bin/sh'
    terminal.spawn_async(
                        Vte.PtyFlags.DEFAULT, None, [shell], None,
                        GLib.SpawnFlags.DEFAULT, None, None, -1, None,
                        cb_terminal_changed, Path.cwd(),
    )
    ctrl_rclick_term = Gtk.GestureClick()
    ctrl_rclick_term.connect('pressed', cb_ctrl_rclick_term)
    ctrl_rclick_term.set_button(3)

    ctrl_key_term = Gtk.EventControllerKey()
    ctrl_key_term.connect('key_pressed', cb_ctrl_key_term, terminal)

    terminal.connect('selection-changed', cb_terminal_selection_changed)

    terminal.set_scrollback_lines(8192)
    term_font = Pango.FontDescription("Regular 12")
    terminal.set_font(term_font)
    terminal.set_clear_background(True)
    terminal.set_cursor_shape(Vte.CursorShape.BLOCK)    # IBEAM,UNDERLINE
    terminal.set_backspace_binding(Vte.EraseBinding.ASCII_DELETE)
    terminal.set_scroll_on_keystroke(True)
    terminal.set_scroll_on_output(True)

    term_bg = Gdk.RGBA()
    term_bg.red = 0.0
    term_bg.green = 0.0
    term_bg.blue = 0.0
    term_bg.alpha = 0.8

    term_fg = Gdk.RGBA()
    term_fg.red = 0.9
    term_fg.green = 0.7
    term_fg.blue = 0.2
    term_fg.alpha = 1.0

    term_colors = [
        (0.2, 0.2, 0.2), (0.6, 0.1, 0.1), (0.1, 0.6, 0.3), (0.6, 0.5, 0.1),
        (0.3, 0.3, 0.6), (0.3, 0.1, 0.6), (0.1, 0.6, 0.6), (0.6, 0.6, 0.6),
        (0.3, 0.3, 0.3), (0.8, 0.4, 0.4), (0.2, 0.8, 0.4), (0.8, 0.7, 0.4),
        (0.4, 0.4, 0.8), (0.5, 0.2, 0.8), (0.4, 0.8, 0.8), (0.8, 0.8, 0.8),
    ]
    term_pallete = []
    for i in term_colors:
        p = Gdk.RGBA()
        p.red = i[0]
        p.green = i[1]
        p.blue = i[2]
        p.alpha = 1.0
        term_pallete.append(p)

    terminal.set_color_background(term_bg)
    terminal.set_color_foreground(term_fg)
    terminal.set_colors(term_fg, term_bg, term_pallete)
    terminal.set_visible(False)
    terminal.add_controller(ctrl_rclick_term)
    terminal.add_controller(ctrl_key_term)

    video_player = Gtk.Video()

####___file_view_lists___.

    list_store = Gio.ListStore()
    left_dir_list = Gtk.DirectoryList()
    left_dir_list.set_file(Gio.File.new_for_path(swgs.current_dir))
    left_dir_list.set_monitored(True)

    right_list_store = Gio.ListStore()
    right_dir_list = Gtk.DirectoryList()
    right_dir_list.set_monitored(True)

    grid_factory = Gtk.SignalListItemFactory()
    list_model = Gtk.MultiSelection.new(list_store)
    list_model.connect('selection-changed', cb_model_selection_changed)

    left_grid_view = Gtk.GridView(name='left_grid_view', css_name='sw_gridview')
    left_grid_view.set_enable_rubberband(True)
    left_grid_view.set_min_columns(1)
    left_grid_view.set_max_columns(16)
    left_grid_view.set_tab_behavior(Gtk.ListTabBehavior.ITEM)

    left_grid_view.set_factory(grid_factory)
    left_grid_view.set_model(list_model)
    left_grid_view.connect('activate', cb_item_activate)

    grid_factory.connect('setup', cb_factory_setup, left_grid_view)
    grid_factory.connect('bind', cb_factory_bind, left_grid_view)
    grid_factory.connect('teardown', cb_grid_factory_teardown)
    grid_factory.connect('unbind', cb_grid_factory_unbind)

    ctrl_lclick_view = Gtk.GestureClick()
    ctrl_lclick_view.connect('pressed', cb_ctrl_lclick_view)
    ctrl_lclick_view.set_button(1)

    ctrl_rclick_view = Gtk.GestureClick()
    ctrl_rclick_view.connect('pressed', cb_ctrl_rclick_view)
    ctrl_rclick_view.set_button(3)

    ctrl_drag_source = Gtk.DragSource()
    ctrl_drag_source.set_actions(Gdk.DragAction.MOVE)
    ctrl_drag_source.connect('prepare', cb_ctrl_drag_prepare)
    ctrl_drag_source.connect('drag-end', cb_ctrl_drag_end)
    ctrl_drag_source.connect('drag-cancel', cb_ctrl_drag_cancel)

    ctrl_drop_target = Gtk.DropTarget()
    types = (Gdk.FileList, Gio.File)
    # action_copy = Gdk.DragAction.COPY
    action_move = Gdk.DragAction.MOVE
    # action_ask = Gdk.DragAction.ASK

    ctrl_drop_target.set_gtypes(types)
    ctrl_drop_target.set_actions(action_move)
    ctrl_drop_target.set_preload(True)
    ctrl_drop_target.connect('drop', cb_ctrl_drop_target)

    ctrl_left_view_motion = Gtk.EventControllerMotion()
    ctrl_left_view_motion.connect('enter', cb_ctrl_left_view_motion)

    ctrl_left_view_focus = Gtk.EventControllerFocus()
    #ctrl_left_view_focus.connect('enter', cb_ctrl_left_view_focus)
    # ctrl_left_view_focus.connect('leave', cb_ctrl_left_view_focus)

    left_grid_view.add_controller(ctrl_drag_source)
    left_grid_view.add_controller(ctrl_lclick_view)
    left_grid_view.add_controller(ctrl_rclick_view)
    left_grid_view.add_controller(ctrl_left_view_motion)
    left_grid_view.add_controller(ctrl_left_view_focus)

####___Scrolled_window___.

    scrolled_main = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    vexpand=True,
                                    hexpand=False,
                                    min_content_height=(mon_height*0.2),
                                    child=grid_main_btn,
    )
    scrolled_about = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    vexpand=True,
                                    valign=Gtk.Align.FILL,
                                    halign=Gtk.Align.FILL,
    )
    scrolled_stack = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    vexpand=True,
                                    valign=Gtk.Align.FILL,
                                    halign=Gtk.Align.FILL,
    )
    scrolled_files_info = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    vexpand=True,
                                    valign=Gtk.Align.FILL,
                                    halign=Gtk.Align.FILL,
    )
    scrolled_bookmarks = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    vexpand=True,
                                    valign=Gtk.Align.FILL,
                                    halign=Gtk.Align.FILL,
    )
    scrolled_playlist = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    vexpand=True,
                                    valign=Gtk.Align.FILL,
                                    halign=Gtk.Align.FILL,
    )
    scrolled_gvol = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    propagate_natural_height=True,
                                    propagate_natural_width=True,
                                    halign=Gtk.Align.FILL,
                                    valign=Gtk.Align.FILL,
    )
    terminal_stack.add_child(scrolled_gvol)
    terminal_stack.add_child(terminal)
    terminal_stack.add_child(video_player)

    terminal_revealer.set_child(terminal_stack)

    scrolled_left_files = Gtk.ScrolledWindow(
                                    css_name='sw_scrolled_view',
                                    name='left_files',
                                    vexpand=True,
                                    hexpand=True,
                                    valign=Gtk.Align.FILL,
                                    halign=Gtk.Align.FILL,
                                    child=left_grid_view,
    )
    paned_grid_view = Gtk.Paned(
                                css_name='sw_grid',
                                orientation=Gtk.Orientation.HORIZONTAL,
                                min_position=320,
                                wide_handle=False,
    )
    paned_grid_view.set_start_child(scrolled_left_files)
    paned_grid_view.connect('cycle_child_focus', cb_paned_cycle_child_focus)
    paned_grid_view.connect('cycle_handle_focus', cb_paned_cycle_handle_focus)

    files_view_grid = Gtk.Paned(
                                name='files', css_name='sw_grid',
                                orientation=Gtk.Orientation.VERTICAL,
    )
    files_view_grid.set_start_child(paned_grid_view)
    files_view_grid.set_end_child(terminal_revealer)

    scrolled_startapp_page = Gtk.ScrolledWindow(
                                            css_name='sw_scrolledwindow',
                                            name=vw_dict['startapp_page'],
                                            vexpand=True,
                                            hexpand=True,
                                            valign=Gtk.Align.FILL,
                                            halign=Gtk.Align.FILL,
    )
    overlay_startapp_page = Gtk.Overlay(
                                            name=vw_dict['startapp_page'],
                                            vexpand=True,
                                            hexpand=True,
    )
    scrolled_install_wine = Gtk.ScrolledWindow(
                                            css_name='sw_scrolledwindow',
                                            name=vw_dict['install_wine'],
                                            vexpand=True,
                                            hexpand=True,
                                            valign=Gtk.Align.FILL,
                                            halign=Gtk.Align.FILL,
    )
    scrolled_install_launchers = Gtk.ScrolledWindow(
                                            css_name='sw_scrolledwindow',
                                            name=vw_dict['install_launchers'],
                                            vexpand=True,
                                            hexpand=True,
                                            valign=Gtk.Align.FILL,
                                            halign=Gtk.Align.FILL,
    )
    scrolled_launch_settings = Gtk.Frame(
                                            css_name='sw_scrolledwindow',
                                            name=vw_dict['launch_settings'],
                                            vexpand=True,
                                            hexpand=True,
                                            valign=Gtk.Align.FILL,
                                            halign=Gtk.Align.FILL,
    )
    scrolled_mangohud_settings = Gtk.Frame(
                                            css_name='sw_scrolledwindow',
                                            name=vw_dict['mangohud_settings'],
                                            vexpand=True,
                                            hexpand=True,
                                            valign=Gtk.Align.FILL,
                                            halign=Gtk.Align.FILL,
    )
    scrolled_vkbasalt_settings = Gtk.Frame(
                                            css_name='sw_scrolledwindow',
                                            name=vw_dict['vkbasalt_settings'],
                                            vexpand=True,
                                            hexpand=True,
                                            valign=Gtk.Align.FILL,
                                            halign=Gtk.Align.FILL,
    )
    scrolled_global_settings = Gtk.ScrolledWindow(
                                            css_name='sw_scrolledwindow',
                                            name=vw_dict['global_settings'],
                                            vexpand=True,
                                            hexpand=True,
                                            valign=Gtk.Align.FILL,
                                            halign=Gtk.Align.FILL,
    )
    box_web_bar = Gtk.Box(
                        orientation=Gtk.Orientation.HORIZONTAL,
                        spacing=4,
                        valign=Gtk.Align.CENTER,
                        hexpand=True,
    )
    for key, value in url_source.items():
        label_web_page = Gtk.Label(css_name='sw_label_info', label=key.capitalize())
        icon_web_page = Gtk.Picture.new_for_filename(value[1])
        icon_web_page.set_content_fit(Gtk.ContentFit.SCALE_DOWN)
        icon_web_page.set_size_request(16, 16)
        box_web_page = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        box_web_page.append(icon_web_page)
        box_web_page.append(label_web_page)
        btn_web_page = Gtk.Button(css_name='sw_button_path', name=value[0])
        btn_web_page.set_child(box_web_page)
        btn_web_page.connect('clicked', cb_btn_add_webview)
        box_web_bar.append(btn_web_page)

    scrolled_web_bar = Gtk.ScrolledWindow(
                                            css_name='sw_scrolledwindow',
                                            valign=Gtk.Align.CENTER,
                                            hexpand=True,
                                            min_content_width=mon_width*0.25,
                                            max_content_width=mon_width*0.66,
                                            propagate_natural_width=True,
                                            child=box_web_bar,
    )
    scrolled_web_bar.set_policy(Gtk.PolicyType.EXTERNAL, Gtk.PolicyType.NEVER)
    stack_web = Gtk.Notebook(css_name='sw_stack', scrollable=True)
    overlay_web = Gtk.Overlay(css_name='sw_overlay')
    overlay_web.set_child(stack_web)
    label_overlay = Gtk.Label(
                            css_name='sw_row', visible=False,
                            valign=Gtk.Align.END, halign=Gtk.Align.START,
                            margin_bottom=8,
    )
    overlay_web.add_overlay(label_overlay)

    grid_web = Gtk.Grid(
                        css_name='sw_grid', name='web_view'
    )
    grid_web.attach(scrolled_web_bar, 0, 0, 1, 1)
    grid_web.attach(overlay_web, 0, 1, 1, 1)

    scrolled_gc_settings = Gtk.ScrolledWindow(
                                            css_name='sw_scrolledwindow',
                                            name=vw_dict['gc_settings'],
                                            vexpand=True,
                                            hexpand=True,
                                            valign=Gtk.Align.FILL,
                                            halign=Gtk.Align.FILL,
                                            #child=gc_settings,
    )
    scrolled_winetricks = Gtk.ScrolledWindow(
                                            css_name='sw_flowbox',
                                            name=vw_dict['winetricks'],
                                            visible=False,
                                            #child=pref_group_winetricks,
    )

####___Sidebar_frames___.

    frame_main = Gtk.Frame(
                        css_name='sw_frame',
                        child=scrolled_main,
    )
    label_about = Gtk.Label(
                            css_name='sw_label_title',
                            label=btn_dict['about']
    )
    label_about.set_margin_top(12)

    frame_about = Gtk.Frame(
                            css_name='sw_frame',
                            label_widget=label_about,
                            child=scrolled_about,
    )
    frame_about.set_label_align(0.5)

    label_files_info = Gtk.Label(
                                css_name='sw_label_title',
                                label=btn_dict['files_info'],
                                margin_top=12,
    )
    frame_stack = Gtk.Frame(
                            css_name='sw_frame',
                            child=scrolled_stack,
    )
    frame_files_info = Gtk.Frame(
                                css_name='sw_frame',
                                label_widget=label_files_info,
                                child=scrolled_files_info,
    )
    frame_files_info.set_label_align(0.5)

    label_bookmarks = Gtk.Label(
                                css_name='sw_label_title',
                                label=btn_dict['bookmarks'],
                                margin_top=12,
    )
    frame_bookmarks = Gtk.Frame(
                                css_name='sw_frame',
                                label_widget=label_bookmarks,
                                child=scrolled_bookmarks,
    )
    frame_bookmarks.set_label_align(0.5)

    label_playlist = Gtk.Label(
                                css_name='sw_label_title',
                                label=btn_dict['playlist'],
                                margin_top=12,
    )
    frame_playlist = Gtk.Frame(
                                css_name='sw_frame',
                                label_widget=label_playlist,
                                child=scrolled_playlist,
    )
    frame_playlist.set_label_align(0.5)

    ####___Add_widgets_to_stack___.

    stack_sidebar = Gtk.Stack(css_name='sw_stack')
    stack_sidebar.set_transition_duration(200)
    stack_sidebar.set_transition_type(Gtk.StackTransitionType.ROTATE_LEFT_RIGHT)
    stack_sidebar.add_child(frame_main)
    stack_sidebar.add_child(frame_about)
    stack_sidebar.add_child(frame_stack)
    stack_sidebar.add_child(frame_files_info)
    stack_sidebar.add_child(frame_bookmarks)
    stack_sidebar.add_child(frame_playlist)

    ####___Add_view_pages_to_stack___.

    stack_settings = Gtk.Stack(
                    transition_duration=250,
                    transition_type=Gtk.StackTransitionType.SLIDE_LEFT_RIGHT,
                    vhomogeneous=False,
    )
    stack_settings.add_named(scrolled_launch_settings, vw_dict['launch_settings'])
    stack_settings.add_named(scrolled_mangohud_settings, vw_dict['mangohud_settings'])
    stack_settings.add_named(scrolled_vkbasalt_settings, vw_dict['vkbasalt_settings'])

    main_stack = Gtk.Stack(css_name='sw_stack')
    main_stack.set_transition_duration(250)
    main_stack.set_transition_type(Gtk.StackTransitionType.ROTATE_LEFT)
    main_stack.add_named(files_view_grid, vw_dict['files'])
    main_stack.add_named(scrolled_global_settings, vw_dict['global_settings'])
    main_stack.add_named(scrolled_install_launchers, vw_dict['install_launchers'])
    main_stack.add_named(scrolled_install_wine, vw_dict['install_wine'])
    main_stack.add_named(scrolled_winetricks, vw_dict['winetricks'])
    main_stack.add_named(grid_web, vw_dict['web_view'])
    main_stack.add_named(scrolled_gc_settings, vw_dict['gc_settings'])
    main_stack.add_named(overlay_startapp_page, 'startapp_page')

    ####___Overlay___.

    main_overlay = Gtk.Overlay(css_name='sw_overlay')
    main_overlay.set_name('main_overlay')
    main_overlay.set_child(main_stack)

    ####___Grid_info___.

    title_info = Gtk.Label(
                        css_name='sw_label',
                        xalign=0,
                        wrap=True,
                        natural_wrap_mode=True,
                        hexpand=True,
                        vexpand=True,
                        halign=Gtk.Align.FILL,
                        valign=Gtk.Align.CENTER,
    )
    label_info = Gtk.Label(
                        css_name='sw_label_desc',
                        xalign=0,
                        wrap=True,
                        natural_wrap_mode=True,
                        hexpand=True,
                        vexpand=True,
                        halign=Gtk.Align.FILL,
                        valign=Gtk.Align.CENTER,
    )
    image_info = Gtk.Image(
                        css_name='sw_picture', width_request=24,
                        height_request=24
    )
    btn_info_response = Gtk.Button(css_name='sw_button', child=image_info)
    btn_info_response.set_visible(False)
    btn_info_box = Gtk.Box(
                        css_name='sw_box',
                        orientation=Gtk.Orientation.HORIZONTAL,
                        spacing=4,
                        hexpand=True,
                        vexpand=True,
                        halign=Gtk.Align.END,
                        valign=Gtk.Align.CENTER,
    )
    btn_info_box.append(btn_info_response)
    btn_info_exit = Gtk.Button(
                        css_name='sw_wc_close',
                        hexpand=True,
                        vexpand=True,
                        halign=Gtk.Align.END,
                        valign=Gtk.Align.CENTER,
    )
    grid_info = Gtk.Grid(
                        css_name='sw_row',
                        row_spacing=8,
                        column_spacing=8,
                        hexpand=True,
                        vexpand=True,
                        halign=Gtk.Align.END,
                        valign=Gtk.Align.END,
                        margin_bottom=16,
                        margin_end=16,
    )
    grid_info.set_size_request(280, -1)
    grid_info.attach(title_info, 0, 0, 1, 1)
    grid_info.attach(btn_info_exit, 1, 0, 1, 1)
    grid_info.attach(label_info, 0, 1, 1, 1)
    grid_info.attach(btn_info_box, 1, 1, 1, 1)
    grid_info.set_visible(False)
    grid_info.add_css_class('padding_8')

    main_overlay.add_overlay(grid_info)

    ####___Revealer___.

    sidebar_revealer = Gtk.Revealer(css_name='sw_revealer')
    sidebar_revealer.set_name('sidebar')
    sidebar_revealer.set_hexpand(True)
    sidebar_revealer.set_halign(Gtk.Align.START)
    sidebar_revealer.set_transition_duration(250)
    sidebar_revealer.set_transition_type(Gtk.RevealerTransitionType.SLIDE_RIGHT)
    sidebar_revealer.set_child(stack_sidebar)

    empty_box = Gtk.Box(css_name="sw_shade_box")
    empty_box.set_size_request(320, -1)

    flap_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
    flap_box.append(empty_box)
    flap_box.append(main_overlay)

    flap_overlay = Gtk.Overlay()
    flap_overlay.set_vexpand(True)
    flap_overlay.set_child(flap_box)
    flap_overlay.add_overlay(sidebar_revealer)
    flap_overlay.connect('get-child-position', get_sidebar_position)

    top_headerbar_revealer = Gtk.Revealer(css_name='sw_revealer')
    top_headerbar_revealer.set_transition_duration(250)
    top_headerbar_revealer.set_transition_type(Gtk.RevealerTransitionType.SLIDE_DOWN)
    top_headerbar_revealer.set_child(top_headerbar)
    top_headerbar_revealer.set_reveal_child(True)

    bottom_headerbar_revealer = Gtk.Revealer(css_name='sw_revealer')
    bottom_headerbar_revealer.set_transition_duration(250)
    bottom_headerbar_revealer.set_transition_type(Gtk.RevealerTransitionType.SLIDE_UP)
    bottom_headerbar_revealer.set_child(bottom_headerbar)
    bottom_headerbar_revealer.set_reveal_child(True)

    grid_main.attach(top_headerbar_revealer, 0, 0, 1, 1)
    grid_main.attach(flap_overlay, 0, 1, 1, 1)
    grid_main.attach(bottom_headerbar_revealer, 0, 2, 1, 1)

    ####___Event_controllers___.
    ctrl_key = Gtk.EventControllerKey()
    ctrl_key.connect('key_pressed', cb_ctrl_key_pressed, parent)

    ctrl_lclick = Gtk.GestureClick()
    ctrl_lclick.connect('pressed', cb_ctrl_lclick_parent)
    ctrl_lclick.set_button(1)

    swgs.x = 0
    swgs.y = 0
    ctrl_motion = Gtk.EventControllerMotion()
    ctrl_motion.connect('motion', cb_ctrl_motion_headerbar, parent)

    ####___GL_Area_overlay___.
    gl_image = get_gl_image()
    gl_cover = Gtk.Overlay()
    gl_cover.add_overlay(grid_main)
    gl_cover.set_child(SwRenderArea(parent, gl_image))
    gl_cover.set_size_request(784, 508)

    ####___add controllers to widgets___.
    parent.set_child(gl_cover)
    parent.add_controller(ctrl_key)
    parent.add_controller(ctrl_lclick)
    parent.add_controller(ctrl_motion)
    parent.add_controller(ctrl_drop_target)
    parent.connect('close-request', on_write_parent_state)

    ####___Check_states___.
    check_reveal_flap()
    check_parent_state()
    preload_runlib(True)

    if '--silent' not in argv:
        #set_parent_layer(parent, monitor)
        parent.present()

    ####___event handlers___.
    GLib.timeout_add(200, check_reveal_flap)
    GLib.timeout_add(350, check_file_monitor_event)
    GLib.timeout_add(200, check_volume)
    GLib.timeout_add(100, key_event_handler)

    ####___Sound_check___.
    if swgs.cfg.get('sound') == 'on':
        if Path(sw_startup_sounds).exists():
            samples = get_samples_list(sw_startup_sounds)
            if len(samples) > 0:
                media_play(media_file, samples, media_controls, 0.7, False)

    set_print_run_time(True)


if __name__ == '__main__':

    mp_event = mp.Event()
    mgr = mp.Manager()
    kc_dict = mgr.dict()
    vol_dict = mgr.dict()
    rc_dict = mgr.dict()

    kc = SwKeyController(kc_dict)
    kc_proc = mp.Process(target=kc.run)
    process_workers.append(kc_proc)
    kc_proc.start()

    rc_dict['controller_active'] = True
    rc_dict['bind_profile'] = default_gui_bind_profile
    rc_proc =  mp.Process(target=run_zero_device_redirection, args=(mp_event, rc_dict))
    process_workers.append(rc_proc)
    rc_proc.start()

    if not sw_appid_json.exists():
        mp_process = mp.Process(target=try_get_appid_json)
        process_workers.append(mp_process)
        mp_process.start()

    if len(argv) == 3:
        check_arg(argv[2])
    else:
        check_arg(None)

    if get_app_path() != 'StartWine':
        create_app_conf()
        get_exe_icon()
        mp_event = mp.Event()
        try_get_exe_logo(mp_event)

    start_tray()
    sw = StartWineGraphicalShell()
    try:
        sw.run()
    except KeyboardInterrupt:
        for p in process_workers:
            p.terminate()
        sw.quit()

    set_print_mem_info(False)

