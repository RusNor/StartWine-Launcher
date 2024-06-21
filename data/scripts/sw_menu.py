#!/usr/bin/env python3

####___Core modules___.

import time
from time import time, process_time, sleep, strftime, perf_counter
start_counter = perf_counter()
start_process = process_time()
start_time = time()
import io
import random
import platform
from platform import python_version
import os
from os import environ, getenv, pathsep, kill, walk, scandir
from os.path import join
from os import stat as Stat
from sys import argv, exit
from sys import stdout as sys_stdout
from sys import stderr as sys_stderr
from subprocess import Popen, run, PIPE, STDOUT, DEVNULL
from pathlib import Path
from threading import Thread, Timer
import multiprocessing as mp
import asyncio
from warnings import filterwarnings
import mimetypes
import urllib.request
from urllib.request import Request, urlopen, urlretrieve
from urllib.error import HTTPError
import re
import json
import codecs
import shutil
import tarfile
import zipfile
import evdev
from evdev import UInput, AbsInfo, InputDevice, ecodes, categorize
from markdown import markdown
import itertools

####__Export backend for OpenGL

filterwarnings("ignore")
ls_gpu_in_use = "lspci -nnk | grep -i vga -A3 | grep 'in use' | cut -d ' ' -f5-100"
environ['WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS'] = '1'

try:
    gpu_in_use = run(ls_gpu_in_use, shell=True, stdout=PIPE, encoding='UTF-8').stdout.splitlines()[0]
except IndexError as e:
    gpu_in_use = None
    print(e)
    print('GPU_IN_USE:', gpu_in_use)
else:
    print('GPU_IN_USE:', gpu_in_use)

if getenv('XDG_SESSION_TYPE') == 'wayland':

    if gpu_in_use == 'nvidia':
        cat_ver = "cat /sys/module/nvidia/version"
        smi_ver = "nvidia-smi --query-gpu driver_version --format=csv,noheader"

        try:
            nv_drv_ver = run(cat_ver, shell=True, stdout=PIPE, encoding='UTF-8').stdout.splitlines()[0]
        except Exception as e:
            try:
                nv_drv_ver = run(smi_ver, shell=True, stdout=PIPE, encoding='UTF-8').stdout.splitlines()[0]
            except Exception as e:
                nv_drv_ver = None
            else:
                print(f'NVIDIA_DRIVER_VERSION: {nv_drv_ver}')
        else:
            print(f'NVIDIA_DRIVER_VERSION: {nv_drv_ver}')

        if nv_drv_ver is not None:
            if int(nv_drv_ver.split('.')[0]) >= 545:
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
            environ['PYOPENGL_PLATFORM'] = 'posix'
            environ['GDK_DEBUG'] = 'gl-glx'
            environ['GDK_BACKEND'] = 'x11'
            environ['GSK_RENDERER'] = 'opengl'
    else:
        environ['PYOPENGL_PLATFORM'] = 'egl'
        environ['GDK_DEBUG'] = 'gl-prefer-gl'
        environ['GDK_BACKEND'] = 'wayland'
        environ['GSK_RENDERER'] = 'opengl'
else:
    if gpu_in_use == 'nvidia':
        environ['PYOPENGL_PLATFORM'] = 'egl'
        environ['GDK_DEBUG'] = 'gl-prefer-gl'
        environ['GDK_BACKEND'] = 'x11'
        environ['GSK_RENDERER'] = 'opengl'
    else:
        environ['PYOPENGL_PLATFORM'] = 'posix'
        environ['GDK_DEBUG'] = 'gl-glx'
        environ['GDK_BACKEND'] = 'x11'
        environ['GSK_RENDERER'] = 'opengl'

####___Third party modules___.
#environ["LD_LIBRARY_PATH"] = os.path.sep + f'/usr/local/lib'
#environ['GI_TYPELIB_PATH'] = os.path.sep + f'/usr/local/lib/girepository-1.0'
#from ctypes import CDLL
#CDLL('/usr/local/lib/libgtk4-layer-shell.so.1.0.1')

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Gdk', '4.0')
gi.require_version('WebKit', '6.0')
gi.require_version('Notify', '0.7')
gi.require_version('Vte', '3.91')

from gi.repository import Gtk, Gdk, Gsk, Gio, GLib, Pango, GObject, Graphene
from gi.repository import WebKit
from gi.repository import GdkPixbuf
from gi.repository import Notify
from gi.repository import Vte
#from gi.repository import Gtk4LayerShell as LayerShell

from PIL import Image, ImageColor
import psutil
from psutil import Process

####___Local data modules___.

import sw_data
from sw_data import *
from sw_data import Msg as msg
from sw_data import TermColors as tc
from sw_crier import SwDialogQuestion as dialog_question
from sw_crier import SwDialogEntry as dialog_entry
from sw_crier import SwDialogDirectory as dialog_directory
from sw_crier import SwCrier as dialog_info
from sw_crier import SwProgressBar, SwWidget
from sw_opengl import RenderArea

####___Add_mime_types___.
try:
    mimetypes.add_type(exe_mime_types[0], '.exe', strict=True)
    mimetypes.add_type(exe_mime_types[1], '.msi', strict=True)
except:
    print(f'{tc.VIOLET2}ADD_MIME_TYPES: {tc.RED}failed')

def check_arg(arg):
    '''___check system comanline arg and set to environment___'''

    if arg is None or arg == 'None':
        try:
            arg = argv[2]
        except:
            arg = None

    if arg is not None and arg != '%F':
        if Path(arg).exists():
            g_file = Gio.File.new_for_commandline_arg(arg)
            g_info = g_file.query_info('*', Gio.FileQueryInfoFlags.NONE)
            arg_type = g_info.get_content_type()

            if Path(arg).suffix == '.desktop' or Path(arg).suffix == '.swd':
                arg = [x.split('=')[1].strip('"') for x in Path(arg).read_text().splitlines() if 'Exec=' in x]

                if len(arg) > 0:
                    commandline = arg[0]
                    exe = [x for x in arg[0].split('"') if '.exe' in x.lower()]
                    msi = [x for x in arg[0].split('"') if '.msi' in x.lower()]
                    bat = [x for x in arg[0].split('"') if '.bat' in x.lower()]
                    lnk = [x for x in arg[0].split('"') if '.lnk' in x.lower()]

                    if len(exe) > 0:
                        x_path = exe[0]

                    elif len(msi) > 0:
                        x_path = msi[0]

                    elif len(bat) > 0:
                        x_path = bat[0]

                    elif len(lnk) > 0:
                        x_path = lnk[0]
                    else:
                        x_path = None

                    if x_path is not None and Path(x_path).exists():
                        environ['SW_COMMANDLINE'] = f'"{x_path}"'
                        environ['SW_EXEC'] = f'"{x_path}"'
                    else:
                        print(f'Executable is {arg[0]}')
                        environ['SW_COMMANDLINE'] = f'"{arg[0]}"'
                        environ['SW_EXEC'] = 'StartWine'
                else:
                    print('Executable not exists...')
                    environ['SW_COMMANDLINE'] = 'None'
                    environ['SW_EXEC'] = 'StartWine'

            elif (Path(arg).suffix.lower() == '.exe'
                or Path(arg).suffix.lower() == '.msi'
                or Path(arg).suffix.lower() == '.bat'
                or Path(arg).suffix.lower() == '.lnk'):
                    print(f'Executable is {arg_type} mimetype...')
                    environ['SW_COMMANDLINE'] = f'"{arg}"'
                    environ['SW_EXEC'] = f'"{arg}"'

            elif arg_type in exe_mime_types:
                    print(f'Executable is {arg_type} mimetype...')
                    environ['SW_COMMANDLINE'] = f'"{arg}"'
                    environ['SW_EXEC'] = f'"{arg}"'
            else:
                print(f'Executable is {arg_type} mimetype...')
                environ['SW_COMMANDLINE'] = f'"{arg}"'
                environ['SW_EXEC'] = 'StartWine'
        else:
            print('Executable not exists...')
            environ['SW_COMMANDLINE'] = 'None'
            environ['SW_EXEC'] = 'StartWine'
    else:
        print('Running without args...')
        environ['SW_COMMANDLINE'] = 'None'
        environ['SW_EXEC'] = 'StartWine'

    print(f'{tc.RED}SW_EXEC: {tc.GREEN}{getenv("SW_EXEC")}')

def get_arg_mimetype():
    '''___get exe path from system comanline arg___'''

    try:
        exc_type = tuple(mimetypes.guess_type(f'{argv[2]}', strict=True))[0]
    except:
        exc_type = tuple(mimetypes.guess_type(f'{argv[0]}', strict=True))[0]
    else:
        if Path(argv[2]).suffix in swd_mime_types:
            exc_type = 'application-x-swd'

    return exc_type

def set_print_id_info(swgs, show):
    '''___print default display and application id info___'''

    if show:
        display = Gdk.DisplayManager.get().get_default_display()
        py_ver = str(python_version())
        exc_type = get_arg_mimetype()

        print(
            f'\n{tc.SELECTED + tc.BEIGE}'
            +f'--------------< STARTWINE {str_sw_version} >-------------{tc.END}\n'
        )
        print(
            f'{tc.VIOLET2}APPLICATION_ID: {tc.GREEN}{swgs.get_application_id()}\n'
            f"{tc.VIOLET2}DISPLAY:        {tc.GREEN}{str(display).split(' ')[0].strip('<')}\n"
            f'{tc.VIOLET2}PYTHON_VERSION: {tc.GREEN}{py_ver}{tc.END}\n'
            f'{tc.VIOLET2}ADD_MIME_TYPES: {tc.GREEN}{", ".join(exe_mime_types)}\n'
            f'{tc.VIOLET2}EXE_MIME_TYPE:  {tc.GREEN}{exc_type}{tc.END}'
            + tc.END
        )
    else:
        return None

def set_print_start_info(app_name, app_icon, app_dict, show):
    '''___print application start mode: name, icon, wine, prefix info___'''

    if show:
        print(
            tc.SELECTED + tc.BLUE
            + '\n----------------< START_MODE >----------------\n'
            + tc.END + '\n',
            f'{tc.VIOLET2}APPLICATION_NAME:   {tc.YELLOW}{app_name}\n',
            f'{tc.VIOLET2}APPLICATION_ICON:   {tc.YELLOW}{Path(app_icon).name}\n',
            f"{tc.VIOLET2}APPLICATION_PREFIX: {tc.YELLOW}{app_dict['export SW_USE_PFX'][1:-1]}\n",
            f"{tc.VIOLET2}APPLICATION_WINE:   {tc.YELLOW}{app_dict['export SW_USE_WINE'][1:-1]}",
            tc.END
            )
    else:
        return None

def set_print_run_time(show):
    '''___print program run time info___'''

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

def set_print_mem_info(mapped):
    '''___print used memory info___'''

    mem_info = Process().memory_full_info()
    mem_map = Process().memory_maps(grouped=True)

    print(
        tc.SELECTED + tc.YELLOW
        + "\n----------------< MEMORY_INFO >----------------\n"
        + tc.END, "\n",
        tc.VIOLET2 + 'SW MEMORY:     ' + tc.GREEN
        + str(round(mem_info.rss / (1024**2), 2)
            - round(mem_info.shared / (1024**2), 2)) + tc.END, "\n",
        tc.VIOLET2 + 'RSS MEMORY:    ' + tc.GREEN
        + str(round(mem_info.rss / (1024**2), 2)) + tc.END, "\n",
        tc.VIOLET2 + 'VMS_MEMORY:    ' + tc.GREEN
        + str(round(mem_info.vms / (1024**2), 2)) + tc.END, "\n",
        tc.VIOLET2 + 'TEXT_MEMORY:   ' + tc.GREEN
        + str(round(mem_info.text / (1024**2), 2)) + tc.END, "\n",
        tc.VIOLET2 + 'SHARED_MEMORY: ' + tc.GREEN
        + str(round(mem_info.shared / (1024**2), 2)) + tc.END, "\n",
        tc.VIOLET2 + 'LIB_MEMORY:    ' + tc.GREEN
        + str(round(mem_info.lib / (1024**2), 2)) + tc.END, "\n",
        tc.VIOLET2 + 'DATA_MEMORY:   ' + tc.GREEN
        + str(round(mem_info.data / (1024**2), 2)) + tc.END, "\n",
        tc.VIOLET2 + 'USS_MEMORY:    ' + tc.GREEN
        + str(round(mem_info.uss / (1024**2), 2)) + tc.END, "\n",
        tc.VIOLET2 + 'PSS_MEMORY:    ' + tc.GREEN
        + str(round(mem_info.pss / (1024**2), 2)) + tc.END, "\n",
        tc.VIOLET2 + 'SWAP_MEMORY:   ' + tc.GREEN
        + str(round(mem_info.swap / (1024**2), 2)) + tc.END, "\n"
        )

    if mapped:
        for x in mem_map:
            try:
                print(x[0], x[1])
            except Exception as e:
                pass
    else:
        return None

def get_app_path():
    '''___get application path___'''

    app_path = getenv('SW_EXEC')
    if app_path == '' or  app_path is None:
        app_path = 'StartWine'

    return app_path

def get_out():
    '''___get application name___'''

    app_path = get_app_path()

    if app_path == str('StartWine'):
        app_name = app_path
    else:
        app_name = str(Path(app_path).stem).strip('"').replace(' ', '_')

    return app_name

def get_suffix():
    '''___get application suffix___'''

    app_path = get_app_path()
    app_suffix = str(Path(app_path).suffix).strip('"')

    return app_suffix

def get_lnk_data(lnk_path):

    lnk_path = lnk_path.strip('"')

    with open(lnk_path, 'rb') as f:
        text = f.read().decode(errors='replace')
        f.close()

    try:
        decode_string = [x for x in text.split(':') if '.exe' in x.lower()]
    except Exception as e:
        return None, None, None
    else:
        if len(decode_string) > 0:
            decode_exe = decode_string[-1].replace('\\', '/')
            re_suffix = '.exe'
        else:
            try:
                decode_string = [x for x in text.split(':') if '.bat' in x.lower()]
            except Exception as e:
                return None, None, None
            else:
                if len(decode_string) > 0:
                    decode_exe = decode_string[-1].replace('\\', '/')
                    re_suffix = '.bat'
                else:
                    try:
                        decode_string = [x for x in text.split(':') if '.msi' in x.lower()]
                    except Exception as e:
                        return None, None, None
                    else:
                        if len(decode_string) > 0:
                            decode_exe = decode_string[-1].replace('\\', '/')
                            re_suffix = '.msi'
                        else:
                            decode_exe = None
                            re_suffix = None

        if decode_exe is not None:
            parent_path = Path(decode_exe).parent
            if str(parent_path).startswith('/'):
                parent_path = Path(str(parent_path).lstrip('/'))

            format_name = Path(decode_exe).stem
            suffix = Path(decode_exe).suffix
            suffix = '.' + ''.join([e for e in suffix if e.isalpha()])
            trash_symbols = re.sub(f'(?i){re_suffix}', '', suffix)
            format_suffix = suffix.replace(trash_symbols, '')
            format_path = Path(f'{parent_path}/{format_name}{format_suffix}')

            print(
                f'APP_NAME={format_name}\n'
                + f'APP_SUFFIX={format_suffix}\n'
                + f'APP_PATH={format_path}'
            )
            return format_name, format_suffix, format_path
        else:
            return None, None, None

def write_lnk_data(app_name, app_path, app_suffix, app_lnk_path):

    pfx_path = get_pfx_path()
    app_path = get_app_path()

    if app_lnk_path is None:
        text_message = msg.msg_dict['lnk_error']
        return dialog_info(text_message=text_message, message_type='ERROR').run()

    if app_name is None:
        text_message = msg.msg_dict['lnk_error']
        return dialog_info(text_message=text_message, message_type='ERROR').run()

    if app_suffix is None:
        text_message = msg.msg_dict['lnk_error']
        return dialog_info(text_message=text_message, message_type='ERROR').run()

    if f'{app_lnk_path}' in f'{Path(app_path.strip('"')).parent}/{app_name}{app_suffix}':
        app_path = f'{Path(app_path.strip('"')).parent}/{app_name}{app_suffix}'
        environ['SW_EXEC'] = f'"{app_path}"'
    else:
        if f'{pfx_path}' == f'{sw_pfx}/pfx_default':
            for r, d, f in walk(pfx_path.strip('"')):
                for x in f:
                    if f'{app_name}{app_suffix}'.lower() in x.lower():
                        app_path = f'{Path(join(r, x))}'
                        environ['SW_EXEC'] = f'"{app_path}"'
        else:
            for r, d, f in walk(f'{sw_pfx}/pfx_{app_name}'):
                for x in f:
                    if f'{app_name}{app_suffix}'.lower() in x.lower():
                        app_path = f'{Path(join(r, x))}'
                        environ['SW_EXEC'] = f'"{app_path}"'

def create_app_conf():
    '''___create application config___'''

    app_name = get_out()
    app_conf = Path(f"{sw_app_config}/" + str(app_name))
    launcher_conf = Path(f"{sw_app_config}/.default/" + str(app_name))
    sw_exe_path = get_app_path()

    if not app_conf.exists():
        if sw_exe_path == 'StartWine':
            app_conf = Path(f"{sw_app_config}/StartWine")
            try:
                app_conf.write_text(sw_default_config.read_text())
            except IOError as e:
                print(e)
            else:
                app_conf.chmod(0o755)
        else:
            if not launcher_conf.exists():
                try:
                    app_conf.write_text(sw_default_config.read_text())
                except IOError as e:
                    print(e)
                else:
                    app_conf.chmod(0o755)
            else:
                try:
                    app_conf.write_text(launcher_conf.read_text())
                except IOError as e:
                    print(e)
                else:
                    app_conf.chmod(0o755)

        print(f'{tc.RED}Create app conf... {tc.GREEN}{app_conf}')

def clear_tmp():
    '''___remove shortcuts from tmp directory___'''

    if sw_tmp.exists():
        for x in scandir(path=sw_tmp):
            if x.is_file():
                if '.desktop' in str(x):
                    Path(x).unlink()

def start_tray():
    '''___run menu in system tray___'''

    if sw_on_tray == 'True':
        app_path = get_app_path()
        p = Popen(['ps', '-AF'], stdout=PIPE, encoding='UTF-8')
        out, err = p.communicate()

        is_active = []
        for line in out.splitlines():
            if str('sw_tray.py') in line:
                is_active.append('1')

        if len(is_active) == 0:
            sw_tray_log = f'{sw_logs}/sw_tray.log'
            try:
                sys_stderr = open(sw_tray_log, 'w')
            except Exception as e:
                sys_stderr = None
            else:
                Popen([sw_tray, app_path], stderr=sys_stderr)
                print(tc.SELECTED + tc.VIOLET2)
                print('-----------------< SW_TRAY >------------------', tc.END)
                print(f'\n {tc.VIOLET2}SW_TRAY: {tc.GREEN}done', tc.END)

def get_pfx_path():
    '''___get current prefix path___'''

    try:
        dpath = Path(f"{sw_app_config}/" + get_out())
        pfx = dpath.read_text().splitlines()
    except:
        dpath = Path(f"{sw_app_config}/StartWine")
        pfx = dpath.read_text().splitlines()

    if str('export SW_USE_PFX="pfx_default"') in pfx:
        pfx_name = f"pfx_default"
        pfx_path = f"{sw_pfx}/{pfx_name}"
    else:
        pfx_name = f"pfx_" + get_out().replace('StartWine', 'default').replace('default_', 'default')
        pfx_path = f"{sw_pfx}/{pfx_name}"

    return pfx_path

def get_pfx_name():

    pfx_path = get_pfx_path()
    pfx_name = str(Path(pfx_path).stem)
    pfx_label = pfx_name.replace('pfx_', '')
    pfx_names = [pfx_name, pfx_label]

    return pfx_names

def write_app_conf(x_path):
    '''___create application config when create shortcut___'''

    app_name = str(Path(x_path).stem).strip('"').replace(' ', '_')
    launcher_conf = Path(f"{sw_app_config}/.default/" + str(app_name))
    app_conf = Path(f"{sw_app_config}/" + str(app_name))

    if not app_conf.exists():
        if not launcher_conf.exists():
            app_conf.write_text(sw_default_config.read_text())
            app_conf.chmod(0o755)
        else:
            app_conf.write_text(launcher_conf.read_text())
            app_conf.chmod(0o755)

def write_app_stat(stat_path: str, var: str, val: float):
    '''___Writing total time in the app___'''

    if Path(stat_path).exists():
        text = Path(stat_path).read_text()
        lines = text.splitlines()
        line = [x for x in lines if f'{var}=' in x]
        if len(line) > 0:
            cur_val = line[0].split('=')[1]

            if var == 'Time':
                new_val = round(float(val) + float(cur_val), 2)
            elif var == 'Fps':
                new_val = round(float(val) + float(cur_val), 2) / 2

            new_line = f'{var}={new_val}'
            with open(stat_path, 'w') as f:
                f.write(text.replace(line[0], new_line))
                f.close()
        else:
            new_val = round(float(val), 2)
            new_line = f'\n{var}={new_val}'
            with open(stat_path, 'a') as f:
                f.write(new_line)
                f.close()
    else:
        print(f'{stat_path} not exists')

def read_app_stat(stat_path: str, var: str):
    '''___Reading total time in the app___'''

    if Path(stat_path).exists():
        lines = Path(stat_path).read_text().splitlines()
        line = [line for line in lines if f'{var}=' in line]

        if len(line) > 0:
            val = line[0].split('=')[1]
        else:
            val = 0.0

        if var == 'Time':
            if float(val) < 60:
                t_val = msg.msg_dict['seconds']
                val = round(float(val), 2)
                return f'{val} {t_val}'

            elif 60 < float(val) < 3600:
                t_val = msg.msg_dict['minutes']
                val = round(float(val) / 60, 2)
                return f'{val} {t_val}'

            elif 3600 <= float(val) < 86400:
                t_val = msg.msg_dict['hours']
                val = round(float(val) / 3600, 2)
                return f'{val} {t_val}'

            elif float(val) > 86400:
                t_val = msg.msg_dict['days']
                val = round(float(val) / 86400, 2)
                return f'{val} {t_val}'

            else:
                val = f'0.0 {msg.msg_dict["seconds"]}'
                return val
        else:
            return val
    else:
        val = 0.0
        return val

def read_overlay_output(app_name: str):
    '''___Getting average fps from output log___'''

    fps_tmp = f'{sw_tmp}/stats/{app_name}.txt'

    if Path(fps_tmp).exists():
        with open(fps_tmp, 'r') as f:
            lines = f.read().splitlines()
            f.close()

        if lines != []:
            count = 0
            val = 0
            for line in lines:
                count += 1
                try:
                    val += float(line.split(', ')[2])
                except Exception as e:
                    pass
            else:
                fps = float(val / count)
                return fps
        else:
            return None
    else:
        return None

def app_info(x_path):
    '''___get application settings dictionary___'''

    if Path(x_path).exists():
        x_path = x_path
    elif str(sw_app_config) in str(x_path):
        x_path = f'{sw_app_config}/StartWine'
    else:
        x_path = None
        raise ValueError(f'{tc.RED}file {x_path} not exist {tc.END}')

    if x_path is not None:
        read_text = Path(x_path).read_text().splitlines()
        text_list = [x for x in read_text if '=' in x]
        count = range(len(text_list))

        for i in count:
            app_dict[(text_list[i].split('=')[0])] = text_list[i].split('=')[1]

        return app_dict
    return None

def app_conf_info(x_path, x_list):
    '''___get application config dictionary___'''

    if Path(x_path).exists():
        x_path = x_path
    elif str(sw_app_config) in str(x_path):
        x_path = f'{sw_app_config}/StartWine'
    else:
        x_path = None
        raise ValueError(f'{tc.RED}file {x_path} not exist {tc.END}')

    if x_path is not None:
        read_text = Path(x_path).read_text().splitlines()
        text_list = [x for x in read_text if 'export' in x]
        count = range(len(text_list))

        for x in x_list:
            for t in text_list:
                if x + '=' in t:
                    app_conf_dict[x] = t

        return app_conf_dict
    return None

def preload_runlib(enable_env: bool):
    '''___preload runlib functions'''

    app_name = get_out()
    app_conf = Path(f"{sw_app_config}/{app_name}")

    if enable_env:
        for k, v in env_dict.items():
            print(tc.BLUE, f'{k}={tc.GREEN}{v}')
            environ[f'{k}'] = f'{v}'

    cmd = f"{sw_scripts}/sw_runlib {app_name}"
    run(cmd, shell=True)

    print(tc.VIOLET2, f'PRELOAD_RUNLIB: {tc.YELLOW}done{tc.END}')

def get_exe_icon():
    '''___get icon from exe file___'''

    app_name = get_out()
    if not Path(f'{sw_img}/{app_name}_x256.png').exists():
        func = f"CREATE_ICON \"$@\""
        app_path = get_app_path()
        app_suffix = get_suffix()

        if app_suffix:
            count = 1
            try:
                for line in fshread:
                    count += 1
                    sw_fsh.write_text(sw_fsh.read_text().replace(fshread[count], ''))
            except IndexError as e:
                print(tc.YELLOW)
                sw_fsh.write_text(fshread[0] + '\n' + fshread[1] + '\n' + func)
                run(f"{sw_fsh} {app_path}", shell=True)

        print(f'{tc.RED}Create exe icon...{tc.GREEN}{sw_img}/{app_name}_x256.png')

def try_get_appid_json():
    '''___get json data file from url___'''

    try:
        response = Request(url_app_id, headers=request_headers)
    except HTTPError as e:
        print(e)
    else:
        page = urlopen(response)
        id_list = page.read().decode('utf-8')

        with codecs.open(sw_appid_source, mode='w', encoding='utf-8') as f:
            f.write(id_list)
            f.close()

        with open(sw_appid_source, mode='r', encoding='utf-8') as f:
            json_data = json.load(f)
            app_data = json_data['applist']['apps']
            filter_data = app_data

            for r in remove_json_list:
                filter_data = [x for x in filter_data if r not in x['name']]
            else:
                for x in filter_data:
                    for l in exclude_letters:
                        x['name'] = x['name'].replace(l[0], l[1])
                else:
                    filter_data = [x for x in filter_data if x['name'] != '']
                    f.close()

        with open(sw_appid_json, 'w', encoding='utf-8') as f:
            f.write(json.dumps(filter_data, indent=0))
            f.close()

            print(f'{tc.RED}Write app id json data...{tc.END}')

def convert_image(in_file, out_file, width, height):
    '''___generate thumbnail for image mime type files___'''

    size = width, height

    try:
        image = Image.open(in_file)
    except IOError as e:
        print(e)
        return False
    else:
        try:
            image.thumbnail(size, Image.Resampling.LANCZOS)
        except IOError as e:
            print(e)
            return False
        else:
            image.save(out_file, 'jpeg')
            return True

def request_urlopen(url, dest, auth):

    key = f'9bd57c167c0f9b466539d0c8f9bdbd70'

    if auth:
        request_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101 Safari/537.36",
            "Accept-Language": "fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive",
            "Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
            "Authorization": f"Bearer {key}",
        }
    else:
        request_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101 Safari/537.36",
            "Accept-Language": "fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive",
            "Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
        }
    try:
        response = urlopen(Request(url, headers=request_headers))
    except HTTPError as e:
        print(e)
        try:
            urllib.request.urlretrieve(url, filename)
        except HTTPError as e:
            print(e)
    else:
        with response as res, open(dest, 'wb') as out:
            shutil.copyfileobj(res, out)
            res.close()

def try_download_logo(app_id, app_name, original_name, orientation):
    '''___try download application logo by id___'''

    if orientation == 'horizontal':
        if not str(app_id) in str([x.name for x in list(sw_app_hicons.iterdir())]):
            app_name_isalnum = ''.join(e for e in app_name if e.isalnum())
            file_hicon = f'{sw_app_hicons}/{app_name_isalnum}_horizontal_{original_name}_{app_id}.jpg'

            try:
                url_app_logo = f'https://cdn.cloudflare.steamstatic.com/steam/apps/{app_id}/header.jpg'
                urllib.request.urlretrieve(url_app_logo, file_hicon)
                #request_urlopen(url_app_logo, file_hicon)
            except Exception as e:
                print(f'{tc.RED} Download: {e} {tc.END}')
                return False
            else:
                print(f'{tc.GREEN} Download horizontal icon complete: {tc.YELLOW} {app_id} {tc.RED} {original_name} {tc.END}')
                return True
        else:
            print(f'{tc.RED} Download horizontal icon: Skip {tc.END}')
            return True

    elif orientation == 'vertical':
        if not str(app_id) in str([x.name for x in list(sw_app_vicons.iterdir())]):
            app_name_isalnum = ''.join(e for e in app_name if e.isalnum())
            file_vicon = f'{sw_app_icons}/tmp/{app_name_isalnum}_vertical_{original_name}_{app_id}.jpg'

            try:
                url_app_logo = f'https://cdn.cloudflare.steamstatic.com/steam/apps/{app_id}/library_600x900_2x.jpg'
                urllib.request.urlretrieve(url_app_logo, file_vicon)
                #request_urlopen(url_app_logo, file_vicon)
            except Exception as e:
                print(f'{tc.RED} Download: {e} {tc.END}')
                return False
            else:
                print(f'{tc.GREEN} Download vertical icon complete: {tc.YELLOW} {app_id} {tc.RED} {original_name} {tc.END}')
                file_out = f'{sw_app_vicons}/{app_name_isalnum}_vertical_{original_name}_{app_id}.jpg'
                converted = convert_image(file_vicon, file_out, 480, 720)
                if not converted:
                    shutil.copy2(file_vicon, file_out)
                    print(f'{tc.GREEN} Copy vertical icon: {tc.YELLOW} {app_id} {tc.RED} {original_name} {tc.END}')
                else:
                    print(f'{tc.GREEN} Convert: Vertical icon size: {tc.YELLOW} {app_id} {tc.RED} {original_name} {tc.END}')

                if Path(f'{file_vicon}').exists():
                    Path(f'{file_vicon}').unlink()

                return True
        else:
            print(f'{tc.RED} Download vertical icon: Skip {tc.END}')
            return True
    else:
        print(f'{tc.RED} Download icon: Skip {tc.END}')
        return False

def compare_name(orig_name, orig_name_, desc_name, desc_name_,
                dir_name, dir_name_, exe_name, exe_name_, app_name, info_list):
    '''___compare application metadata info with app id data___'''

    app_id_dict.clear()
    name_dict.clear()

    with open(sw_appid_json) as json_file:
        json_data = json.load(json_file)
        app_data = json_data
        json_file.close()

    for app in app_data:
        key_name = str(app['name'])

        for word in exclude_double_words:
            if word[0] in key_name:
                key_name = key_name.replace(word[0], word[1])
        else:
            key_name = ''.join(e for e in key_name.upper() if  e.isalnum())
            key_name = str_to_roman(key_name)

        if orig_name is not None:
            if orig_name.upper() == key_name:
                app_id = app['appid']
                name = app['name']
                app_id_dict[f'original_{app_id}'] = app_id
                name_dict[f'original_{app_id}'] = name
                print(tc.BEIGE + f'match = {info_list[0]}: ' + str(app) + tc.END)

        if desc_name is not None:
            if desc_name.upper() == key_name:
                app_id = app['appid']
                name = app['name']
                app_id_dict['description_{app_id}'] = app_id
                name_dict['description_{app_id}'] = name
                print(tc.BEIGE + f'match = {info_list[1]}: ' + str(app) + tc.END)

        if dir_name is not None:
            if dir_name.upper() == key_name:
                app_id = app['appid']
                name = app['name']
                app_id_dict['directory_{app_id}'] = app_id
                name_dict['directory_{app_id}'] = name
                print(tc.BEIGE + f'match = {info_list[2]}: ' + str(app) + tc.END)

        if exe_name is not None:
            if exe_name.upper() == key_name:
                app_id = app['appid']
                name = app['name']
                app_id_dict['exe_{app_id}'] = app_id
                name_dict['exe_{app_id}'] = name
                print(tc.BEIGE + f'match = {info_list[3]}: ' + str(app) + tc.END)
    else:
        print(f'{tc.GREEN}Check and download vertical sgdb icon {tc.END}')
        if orig_name_ is not None:
            check_db_vert = check_download_sgdb(orig_name_, app_name, '600', '900', 'vertical')
            if check_db_vert is None:
                check_db_vert = check_download_sgdb(orig_name_, app_name, '660', '930', 'vertical')
        else:
            check_db_vert = None

        if check_db_vert is None:
            if desc_name_ is not None:
                check_db_vert = check_download_sgdb(desc_name_, app_name, '600', '900', 'vertical')
                if check_db_vert is None:
                    check_db_vert = check_download_sgdb(desc_name_, app_name, '660', '930', 'vertical')
            else:
                check_db_vert = None

            if check_db_vert is None:
                if dir_name_ is not None:
                    check_db_vert = check_download_sgdb(dir_name_, app_name, '600', '900', 'vertical')
                    if check_db_vert is None:
                        check_db_vert = check_download_sgdb(dir_name_, app_name, '660', '930', 'vertical')
                else:
                    check_db_vert = None

                if check_db_vert is None:
                    if exe_name_ is not None:
                        check_db_vert = check_download_sgdb(exe_name_, app_name, '600', '900', 'vertical')
                        if check_db_vert is None:
                            check_db_vert = check_download_sgdb(exe_name_, app_name, '660', '930', 'vertical')
                    else:
                        check_db_vert = None

                    if check_db_vert is None:
                        check_db_vert = check_download_sgdb(app_name, app_name, '600', '900', 'vertical')
                        if check_db_vert is None:
                            check_db_vert = check_download_sgdb(app_name, app_name, '660', '930', 'vertical')
                            if check_db_vert is None:
                                check_db_vert = download_steam_vert = check_download_logo(app_id_dict, app_name, name_dict, 'vertical')

        print(f'{tc.GREEN}Check and download horizontal sgdb icon {tc.END}')
        if orig_name_ is not None:
            check_db_horiz = check_download_sgdb(orig_name_, app_name, '460', '215', 'horizontal')
            if check_db_horiz is None:
                check_db_horiz = check_download_sgdb(orig_name_, app_name, '920', '430', 'horizontal')
        else:
            check_db_horiz = None

        if check_db_horiz is None:
            if desc_name_ is not None:
                check_db_horiz = check_download_sgdb(desc_name_, app_name, '460', '215', 'horizontal')
                if check_db_horiz is None:
                    check_db_horiz = check_download_sgdb(desc_name_, app_name, '920', '430', 'horizontal')
            else:
                check_db_horiz = None

            if check_db_horiz is None:
                if dir_name_ is not None:
                    check_db_horiz = check_download_sgdb(dir_name_, app_name, '460', '215', 'horizontal')
                    if check_db_horiz is None:
                        check_db_horiz = check_download_sgdb(dir_name_, app_name, '920', '430', 'horizontal')
                else:
                    check_db_horiz = None

                if check_db_horiz is None:
                    if exe_name_ is not None:
                        check_db_horiz = check_download_sgdb(exe_name_, app_name, '460', '215', 'horizontal')
                        if check_db_horiz is None:
                            check_db_horiz = check_download_sgdb(exe_name_, app_name, '920', '430', 'horizontal')
                    else:
                        check_db_horiz = None

                    if check_db_horiz is None:
                        check_db_horiz = check_download_sgdb(app_name, app_name, '460', '215', 'horizontal')
                        if check_db_horiz is None:
                            check_db_horiz = check_download_sgdb(app_name, app_name, '920', '430', 'horizontal')
                            if check_db_horiz is None:
                                download_steam_horiz = check_download_logo(app_id_dict, app_name, name_dict, 'horizontal')

def check_download_sgdb(cur_name, app_name, width, height, orientation):

    if cur_name is not None:
        app_name_isalnum = ''.join(e for e in app_name if e.isalnum())

        length = len(cur_name)
        is_lower_around = (lambda: cur_name[i-1].islower() or 
                           length > (i + 1) and cur_name[i + 1].islower()
        )
        count = 0
        parts = []
        for i in range(1, length):
            if cur_name[i].isupper() and is_lower_around():
                parts.append(cur_name[count: i])
                count = i
        parts.append(cur_name[count:])

        edited_name = '_'.join(parts)

        url_search = f'https://www.steamgriddb.com/api/v2/search/autocomplete/{edited_name}'
        try:
            request_urlopen(url_search, f'{sw_fm_cache_database}/{edited_name}.json', True)
        except Exception as e:
            print(e)
        else:
            with open(f'{sw_fm_cache_database}/{edited_name}.json', mode='r', encoding='utf-8') as f:
                json_data = json.load(f)
                data = json_data['data']
                app_id_list = list()
                name_list = list()
                if len(data) > 0:
                    for app in data:
                        key_name = str(app['name'])
                        key_name = re.sub(r'[ЁёА-я]', '', key_name)

                        for l in exclude_letters:
                            key_name = key_name.replace(l[0], l[1])

                        for word in exclude_double_words:
                            if word[0] in key_name:
                                key_name = key_name.replace(word[0], word[1])
                        else:
                            key_name = ''.join(e for e in key_name.upper() if e.isalnum())
                            key_name = str_to_roman(key_name)

                            cur_name = ''.join(e for e in cur_name.upper() if e.isalnum())
                            cur_name = str_to_roman(cur_name)

                        if cur_name.upper() == key_name:
                            app_id_list.append(app['id'])
                            name_list.append(app['name'])
                    else:
                        if len(app_id_list) > 0:
                            print(app_id_list, name_list)
                            app_id = app_id_list[0]
                            data_name = name_list[0]
                        else:
                            app_id = None
                            data_name = None
                else:
                    app_id = None
                    data_name = None

                f.close()

            if app_id is not None:
                url_app_id = f'https://www.steamgriddb.com/api/v2/grids/game/{app_id}?dimentions={width}x{height}'
                check_sgdb_heroes(app_name_isalnum, app_id, data_name)

                try:
                    request_urlopen(url_app_id, f'{sw_fm_cache_database}/{app_name_isalnum}_{orientation}_{app_id}.json', True)
                except Exception as e:
                    print(e)
                else:
                    with open(f'{sw_fm_cache_database}/{app_name_isalnum}_{orientation}_{app_id}.json', mode='r', encoding='utf-8') as f:
                        json_data = json.load(f)

                        url_icon = []
                        if len(json_data['data']) > 0:
                            for value in json_data['data']:
                                if int(value['width']) == int(width):
                                    url_icon.append(value['url'])
                                    break

                        f.close()

                    if len(url_icon) > 0:
                        print(url_icon)

                        try:
                            request_urlopen(url_icon[0], f'{sw_fm_cache_database}/{app_name_isalnum}_{orientation}_{data_name}_{app_id}.jpg', False)
                        except Exception as e:
                            print(e)
                        else:
                            file_hicon = f'{sw_app_hicons}/{app_name_isalnum}_horizontal_{data_name}_{app_id}.jpg'
                            file_vicon = f'{sw_app_vicons}/{app_name_isalnum}_vertical_{data_name}_{app_id}.jpg'
                            cache_icon = f'{sw_fm_cache_database}/{app_name_isalnum}_{orientation}_{data_name}_{app_id}.jpg'

                            if orientation == 'horizontal':
                                try:
                                    converted = convert_image(cache_icon, file_hicon, 460, 215)
                                except:
                                    shutil.copy2(cache_icon, file_hicon)
                                    print(f'{tc.GREEN} Copy horizontal icon: {tc.YELLOW} {app_id} {tc.RED} {data_name} {tc.END}')
                                else:
                                    print(f'{tc.GREEN} Convert horizontal icon: {tc.YELLOW} {app_id} {tc.RED} {data_name} {tc.END}')

                            elif orientation == 'vertical':
                                try:
                                    converted = convert_image(cache_icon, file_vicon, 480, 720)
                                except:
                                    shutil.copy2(cache_icon, file_vicon)
                                    print(f'{tc.GREEN} Copy vertical icon: {tc.YELLOW} {app_id} {tc.RED} {data_name} {tc.END}')
                                else:
                                    print(f'{tc.GREEN} Convert vertical icon: {tc.YELLOW} {app_id} {tc.RED} {data_name} {tc.END}')
                            else:
                                print(f'{tc.GREEN} icon not found {tc.YELLOW} {app_id} {tc.RED} {data_name} {tc.END}')

                            if Path(f'{cache_icon}').exists():
                                for path in Path(f'{sw_fm_cache_database}').iterdir():
                                    if path.is_file():
                                        path.unlink()

                            print('done')
                            return 0
                    else:
                        print('icon not found...')
                        return None
            else:
                print('icon not found...')
                return None
    else:
        print('icon not found...')
        return None

def check_sgdb_heroes(app_name_isalnum, app_id, data_name):

    size_dict = {3840: 1240, 1920: 620, 1600: 650}
    url_heroes_icon = []

    for width, height in size_dict.items():
        url_heroes = f'https://www.steamgriddb.com/api/v2/heroes/game/{app_id}?dimentions={width}x{height}'
        try:
            request_urlopen(url_heroes, f'{sw_fm_cache_database}/{app_name_isalnum}_heroes_{app_id}.json', True)
        except Exception as e:
            print(e)
        else:
            with open(f'{sw_fm_cache_database}/{app_name_isalnum}_heroes_{app_id}.json', mode='r', encoding='utf-8') as f:
                json_data = json.load(f)
                if len(json_data['data']) > 0:
                    for value in json_data['data']:
                        if (str(value['style']) == 'alternate'
                            and int(value['width']) == int(width)):
                                url_heroes_icon.append(value['url'])
                                break
                f.close()
    else:
        if len(url_heroes_icon) > 0:
            print(url_heroes_icon)

            try:
                request_urlopen(url_heroes_icon[0], f'{sw_fm_cache_database}/{app_name_isalnum}_heroes_{data_name}_{app_id}.jpg', False)
            except Exception as e:
                print(e)
            else:
                file_heroes_icon = f'{sw_app_heroes_icons}/{app_name_isalnum}_heroes_{data_name}_{app_id}.jpg'
                cache_icon = f'{sw_fm_cache_database}/{app_name_isalnum}_heroes_{data_name}_{app_id}.jpg'
                shutil.copy2(cache_icon, file_heroes_icon)
                print(f'{tc.GREEN} Copy heroes icon: {tc.YELLOW} {app_id} {tc.RED} {data_name} {tc.END}')
        else:
            print('icon not found...')
            return None

def check_download_logo(app_id_dict, app_name, name_dict, orientation):

    if len(list(app_id_dict)) > 0:
        for key, name in zip(list(app_id_dict), list(name_dict)):
            if 'original' in key:
                print(tc.VIOLET2 + f'Try download by OriginalName: {app_id_dict[key]} {name_dict[name]}' + tc.END)
                check_io = try_download_logo(app_id_dict[key], app_name, name_dict[name], orientation)
                if check_io:
                    break
            else:
                check_io = False
        else:
            if not check_io:
                for key, name in zip(list(app_id_dict), list(name_dict)):
                    if 'description' in key:
                        print(tc.VIOLET2 + f'Try download by Description: {app_id_dict[key]} {name_dict[name]}' + tc.END)
                        check_io = try_download_logo(app_id_dict[key], app_name, name_dict[name], orientation)
                        if check_io:
                            break
                    else:
                        check_io = False
                else:
                    if not check_io:
                        for key, name in zip(list(app_id_dict), list(name_dict)):
                            if 'directory' in key:
                                print(tc.VIOLET2 + f'Try download by DirectoryName: {app_id_dict[key]} {name_dict[name]}' + tc.END)
                                check_io = try_download_logo(app_id_dict[key], app_name, name_dict[name], orientation)
                                if check_io:
                                    break
                            else:
                                check_io = False
                        else:
                            if not check_io:
                                for key, name in zip(list(app_id_dict), list(name_dict)):
                                    if 'exe' in key:
                                        print(tc.VIOLET2 + f'Try download by ExeName: {app_id_dict[key]} {name_dict[name]}' + tc.END)
                                        check_io = try_download_logo(app_id_dict[key], app_name, name_dict[name], orientation)
                                        if check_io:
                                            break
                                    else:
                                        check_io = False
                                else:
                                    print(tc.RED + f'application id not found' + tc.END)
                                    return False
        return check_io
    else:
        print(tc.RED + f'application id not found' + tc.END)
        return False

def get_meta_prod(metadata):
    '''___get exe product name info from metadata___'''

    try:
        md_prod = metadata['ProductName']
    except:
        print(f'<< ProductName: metadata not found >>')
        return None
    else:
        return md_prod

def get_meta_orig(app_name, app_path, metadata):
    '''___get exe original name info from metadata___'''

    try:
        original = metadata['OriginalFileName']
    except:
        try:
            original_path = [x for x in list(Path(Path(app_path.strip('"')).parent).rglob('*.exe')) if '-Win64-Shipping.exe' in str(x)]

            if original_path == []:
                    original_path = [x for x in list(Path(Path(app_path.strip('"')).parent).rglob('*.exe')) if f'{app_name}' in str(x)]

            if original_path != []:
                if len(original_path) == 1:
                    cmd = f'{sw_exiftool} -j "{original_path[0]}"'
                elif len(original_path) > 1:
                    cmd = f'{sw_exiftool} -j "{original_path[1]}"'

                out_cmd = run(cmd, shell=True, start_new_session=True, stdout=PIPE).stdout
                metadata_original = json.loads(out_cmd)[0]
                md_orig_prod = metadata_original['ProductName']

                return md_orig_prod
        except:
            print(f'<< OriginalFileName: metadata not found >>')
            return None
    else:
        try:
            original_path = [x for x in list(Path(Path(app_path.strip('"')).parent).rglob('*.exe')) if '-Win64-Shipping.exe' in str(x)]

            if original_path == []:
                    original_path = [x for x in list(Path(Path(app_path.strip('"')).parent).rglob('*.exe')) if f'{app_name}' in str(x)]

            if original_path != []:
                if len(original_path) == 1:
                    cmd = f'{sw_exiftool} -j "{original_path[0]}"'

                elif len(original_path) > 1:
                    cmd = f'{sw_exiftool} -j "{original_path[1]}"'

                out_cmd = run(cmd, shell=True, start_new_session=True, stdout=PIPE).stdout
                metadata_original = json.loads(out_cmd)[0]
                md_orig_prod = metadata_original['ProductName']

                return md_orig_prod
        except:
            print(f'<< OriginalFileName: metadata not found >>')
            return None

def get_meta_desc(metadata):
    '''___get exe description info from metadata___'''

    try:
        md_desc = metadata['FileDescription']
    except:
        return None
    else:
        return md_desc

def get_exe_logo(app_name, app_path):
    '''___get exe logo id from json data___'''

    app_dir_list = list()
    orig_name = None
    desc_name = None
    orig_name_ = None
    desc_name_ = None
    exe_name_ = None
    dir_name_ = None

    print(tc.SELECTED + tc.GREEN)
    print(f'-----------------< METADATA >-----------------' + tc.END)
    print(tc.YELLOW)

    cmd = f'{sw_exiftool} -j {app_path}'
    try:
        out_cmd = run(cmd, shell=True, start_new_session=True, stdout=PIPE).stdout
    except OSError as e:
        print(e)
    else:
        try:
            metadata = json.loads(out_cmd)[0]
        except Exception as e:
            print(e)
            md_prod = None
        else:
            md_prod = get_meta_prod(metadata)

        if md_prod in ['BootstrapPackagedGame', None]:
            md_prod = get_meta_orig(app_name, app_path, metadata)
            if md_prod in ['BootstrapPackagedGame', None]:
                    md_prod = None

        ####___Filter product name metadata___.

        if md_prod is not None:
            md_prod = re.sub(r'[ЁёА-я]', '', md_prod)

            for word in exclude_double_words:
                md_prod = md_prod.replace(word[0], word[1])

            orig_name = ''.join(e for e in md_prod if e.isalnum())
            orig_name_ = ''.join(e for e in md_prod if e.isalnum() or e == ' ')
            orig_name_ = orig_name_.replace(' ', '_')

            if orig_name == '':
                orig_name = None
                orig_name_ = None
            else:
                orig_name = str_to_roman(orig_name)

            print(f'<< OriginalFileName: {orig_name} >>')

        ####___Check file description metadata___.

        md_desc = get_meta_desc(metadata)

        if md_desc in ['BootstrapPackagedGame', None]:
            md_desc = get_meta_orig(app_name, app_path, metadata)

            if md_desc in ['BootstrapPackagedGame', None]:
                    md_desc = None

        ####___Filter file description metadata___.

        if md_desc is not None:
            md_desc = re.sub(r'[ЁёА-я]', '', md_desc)

            for word in exclude_double_words:
                md_desc = md_desc.replace(word[0], word[1])

            desc_name = ''.join(e for e in md_desc if e.isalnum())
            desc_name_ = ''.join(e for e in md_desc if e.isalnum() or e == ' ')
            desc_name_ = desc_name_.replace(' ', '_')

            if desc_name == '':
                desc_name = None
                desc_name_ = None
            else:
                desc_name = str_to_roman(desc_name)

            print(f'<< FileDescription: {desc_name} >>')

    ####___Filter app name___.

    a_name = re.sub(r'[ЁёА-я]', '', app_name)

    for word in exclude_single_words:
        a_name = a_name.replace(word[0], word[1])

    exe_name = ''.join(e for e in a_name if e.isalnum())
    exe_name_ = ''.join(e for e in a_name if e.isalnum())
    exe_name_ = exe_name_.replace(' ', '_')

    if exe_name == '':
        exe_name = None
        exe_name_ = None
    else:
        exe_name = str_to_roman(a_name)

    print(f'<< ExeName: {exe_name} >>')

    ####___Filter directory name___.

    dirs = [x for x in Path(app_path).parent.parts if not x.upper() in str(exclude_names).upper()]

    for d in dirs:
        d = re.sub(r'[ЁёА-я]', '', d)

        for word in exclude_single_words:
            d = d.replace(word[0], word[1])

        dir_name = ''.join(e for e in d if e.isalnum())
        dir_name_ = ''.join(e for e in d if e.isalnum() or e == ' ')
        dir_name_ = dir_name_.replace(' ', '_')

        if dir_name != '':
            app_dir_list.append(dir_name)

    if len(app_dir_list) > 0:
        app_dir = str_to_roman(app_dir_list[-1])
    else:
        app_dir = None

    print(f'<< DirectoryName: {app_dir} >>')

    ####___Сomparison of filtered strings___.

    compare_name(
                orig_name, orig_name_, desc_name, desc_name_,
                app_dir, dir_name_, exe_name, exe_name_, app_name,
                ['OriginalName', 'Description', 'AppDirectory', 'ExeName']
                )

def check_exe_logo(app_name):
    '''___cecking and downloading wide screen logo for current application___'''

    for icon in  Path(f'{sw_app_hicons}').iterdir():
        app_name_isalnum = ''.join(e for e in app_name if e.isalnum())
        if app_name_isalnum == str(Path(icon).name).split('_')[0]:
            return True

    return False

def try_get_exe_logo():
    '''Try to get wide screen logo for current exe.'''

    app_path = get_app_path()
    app_name = get_out()

    if (app_name != 'StartWine'
        and check_exe_logo(app_name) is False):
            print(f'{tc.RED}Try to get exe logo...')
            p = mp.Process(target=get_exe_logo, args=(app_name, app_path))
            p.start()

def get_bookmark_list():

    bookmarks_list.clear()

    with open(sw_bookmarks, 'r') as f:
        l = f.read().splitlines()
        for s in l:
            bookmarks_list.append(s)
            f.close()

    return bookmarks_list

####___Echo_functon___.

def echo_func_name(func_name):
    '''___write and run function to function.sh___'''

    func = func_name + str(' \"$@\"')
    app_path = get_app_path()
    app_name = get_out()

    app_log = f"{sw_logs}/{app_name}.log"
    sys_stderr = open(app_log, 'w')

    count = -1
    try:
        for line in fshread:
            count += 1
            if count > 1:
                sw_fsh.write_text(sw_fsh.read_text().replace(fshread[count], ''))
    except IOError as e:
        print(e)
    else:
        print(tc.YELLOW)
        if (str(func) == str("ADD_SHORTCUT_TO_MENU \"$@\"")
            or str(func) == str("ADD_SHORTCUT_TO_DESKTOP \"$@\"")
                or str(func) == str("ADD_SHORTCUT_TO_STEAM \"$@\"")):
                    shortcut_name = f"export CUSTOME_GAME_NAME={getenv('CUSTOM_GAME_NAME')}"
                    shortcut_path = f"export SW_DESKTOP_DIR={getenv('CUSTOM_GAME_PATH')}"
                    sw_fsh.write_text(
                        fshread[0] + '\n' + fshread[1] + '\n'
                        + shortcut_name+ '\n' + shortcut_path + '\n' + func
                    )
                    run(f"{sw_fsh} {app_path}", shell=True)
        else:
            print(tc.YELLOW)
            sw_fsh.write_text(
                        fshread[0] + '\n' + fshread[1] + '\n' + func
            )
            run(
                f"{sw_fsh} {app_path}",
                shell=True,
                start_new_session=True,
                stderr=sys_stderr,
                encoding='UTF-8'
            )

def echo_cs_name(wine_name, wine_download, app_name, app_path):
    '''___write and run create shortcut function to function.sh___'''

    wine_ver = wine_name
    func_cs = f"CREATE_SHORTCUT \"$@\""

    g_log = f"{sw_logs}/{app_name}.log"
    sys_stderr = open(g_log, 'w')

    count = -1

    try:
        for line in fshread:
            count += 1
            if count > 1:
                sw_fsh.write_text(
                    sw_fsh.read_text().replace(fshread[count], ''))
    except IOError as e:
        print(e)
    else:
        if (not Path(f"{sw_wine}/{wine_name}/bin/wine").exists()
            and wine_download is not None):
                print(tc.YELLOW)
                wine_ok = f"export WINE_OK=1"
                func_download = f"{wine_download} \"$@\""
                sw_fsh.write_text(
                                fshread[0] + '\n' + fshread[1] + '\n' + wine_ok
                                + '\n' + func_download + '\n' + func_cs
                )
                run(
                    f"{sw_fsh} {app_path}",
                    shell=True,
                    start_new_session=True,
                    stderr=sys_stderr,
                    encoding='UTF-8'
                )
        else:
            print(tc.YELLOW)
            sw_fsh.write_text(
                fshread[0] + '\n' + fshread[1] + '\n' + func_cs
            )
            run(
                f"{sw_fsh} {app_path}",
                shell=True,
                start_new_session=True,
                stderr=sys_stderr,
                encoding='UTF-8'
            )

def echo_wine(wine_name, name_ver, wine_ver):
    '''___write and run download wine function to function.sh___'''

    export_wine_ver = f'export {name_ver}="{wine_ver}"'
    app_path = get_app_path()
    app_name = get_out()
    wine_num = wine_name + str(' \"$@\"')
    count = -1

    try:
        for line in fshread:
            count += 1
            if count > 1:
                sw_fsh.write_text(
                    sw_fsh.read_text().replace(fshread[count], '')
                )
    except IOError as e:
        print(e)
    else:
        sw_fsh.write_text(
            fshread[0] + '\n' + fshread[1] + '\n' + export_wine_ver + '\n'  + wine_num
        )
        proc_wine = run(
                        f"{sw_fsh} {app_path}",
                        shell=True,
                        #start_new_session=True,
                        #stdout=PIPE
        )

def cs_wine(wine_name, wine_download, app_name, app_path):
    '''___write the changed wine name and prefix to the application config___'''

    app_conf = Path(f"{sw_app_config}/{app_name}")

    try:
        for line in app_conf.read_text().splitlines():

            if f"SW_USE_WINE=" in line:
                app_conf.write_text(
                    app_conf.read_text().replace(
                        line, f'export SW_USE_WINE="{wine_name}"'))

            if f"SW_USE_PFX" in line:
                if app_name == 'StartWine':
                    app_conf.write_text(
                        app_conf.read_text().replace(
                            line, f'export SW_USE_PFX="pfx_default"'))

                else:
                    app_conf.write_text(
                        app_conf.read_text().replace(
                            line, f'export SW_USE_PFX="pfx_{app_name}"'))

    except:
        print('<< app_conf_not_found >>')
        pass

    echo_cs_name(wine_name, wine_download, app_name, app_path)

def cs_path(func_wine, app_name, app_path):
    '''___create shortcut with changed wine___'''

    if func_wine in wine_list:
        wine_download = wine_func_dict[func_wine]
    else:
        wine_download = None

    cs_wine(func_wine, wine_download, app_name, app_path)

def check_alive(thread, func, args, parent):
    '''___run the function when thread it completes___'''

    if thread.is_alive():
        return True
    else:
        if args is None:
            func()
        else:
            func(args)

        if parent is not None:
            parent.set_hide_on_close(True)

        return False

def vulkan_info(q):
    '''___get driver name from vulkaninfo___'''

    cmd = f"vulkaninfo | grep driverName | cut -d '=' -f2"

    proc = run(
            cmd, shell=True, stderr=DEVNULL,
            stdout=PIPE, encoding='UTF-8'
            )
    vulkan_dri = str(proc.stdout[0:]).splitlines()

    for dri in vulkan_dri:
        d = dri.replace(' ', '')
        q.append(d)

def check_wine():
    '''___check the existence of the path to wine___'''

    app_name = get_out()
    app_conf = Path(f"{sw_app_config}/{app_name}")
    app_dict = app_info(app_conf)
    wine = app_dict['export SW_USE_WINE'].strip('"')

    if not Path(f'{sw_wine}/{wine}/bin/wine').exists():
        return wine
    else:
        return None

def find_process(app_suffix):
    '''___Return a list of processes matching name___'''

    procs = psutil.Process(os.getpid()).children(recursive=True)
    for p in procs:
        try:
            ls = p.as_dict(attrs=['name'])
        except:
            pass
        else:
            n = ls['name']
            if app_suffix.lower() in n.lower():
                print(n)
                return True

    return False

def g_file_monitor(m, f, o, event_type):

    global f_mon_event
    f_mon_event.clear()

    if (event_type == Gio.FileMonitorEvent.MOVED_OUT
        or event_type == Gio.FileMonitorEvent.MOVED_IN
            or event_type == Gio.FileMonitorEvent.RENAMED
                or event_type == Gio.FileMonitorEvent.MOVED
                    or event_type == Gio.FileMonitorEvent.CREATED
                        or event_type == Gio.FileMonitorEvent.DELETED
                            or event_type == Gio.FileMonitorEvent.CHANGED
                                or event_type == Gio.FileMonitorEvent.ATTRIBUTE_CHANGED
                                    or event_type == Gio.FileMonitorEvent.CHANGES_DONE_HINT):
                                        f_mon_event = [f, event_type]

def get_samples_list(samples_dir):

    samples_dict = dict()
    samples_list = sorted(list(Path(samples_dir).iterdir()))
    for i, x in enumerate(samples_list):
        samples_dict[str(x)] = i

    return samples_dict

def media_play(media_file, samples, media_controls, volume, show):
    '''___playing system event sounds___'''

    if show is True:
        media_controls.get_parent().set_visible_child(media_controls)

    if type(samples) is str:
        media_file.set_filename(f'{samples}')
        media_file.set_volume(volume)
        media_file.play()
    else:
        s_list = list(samples)

        if media_file.get_file() is None:
            media_file.set_filename(f'{s_list[0]}')
            media_file.set_volume(volume)
            media_file.play()

        else:
            if media_file.get_ended():
                n = samples[media_file.get_file().get_path()]
                n = n + 1

                if n < len(s_list):
                    media_file.stream_unprepared()
                    media_file.clear()
                    media_file.set_filename(f'{s_list[n]}')
                    media_file.set_volume(volume)
                    media_file.play()

                elif n == len(s_list):
                    media_file.set_filename(f'{s_list[0]}')
                    media_file.pause()
    return True

def get_cpu_core_num():
    '''try get cpu core numbers'''
    try:
        cpu_core_num = len(psutil.Process().cpu_affinity())
    except:
        try:
            cpu_core_num = int(psutil.cpu_count())
        except:
            cpu_core_num = None
            raise ValueError('cpu core numbers not found')

    return cpu_core_num

####___Activate_startwine_menu___.

class StartWineGraphicalShell(Gtk.Application):

    def __init__(self, *args, **kwargs):
        super().__init__(*args,
                        application_id="ru.project.StartWine",
                        flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
                        **kwargs
        )
        GLib.set_prgname(sw_program_name)
        GLib.set_application_name(sw_program_name)

        self.get_default().register()
        set_print_id_info(self, True)

        self.width = 1280
        self.height = 720

        self.connection = self.get_dbus_connection()
        self.gdbus_node = Gio.DBusNodeInfo.new_for_xml(gdbus_node_sample)

        self.tray = start_tray()
        self.connect('activate', sw_activate)

        ####___send_notification___
        enable_notify = None
        if enable_notify is not None:
            try:
                Notify.init(sw_program_name)
            except Exception as e:
                pass
            else:
                message = msg.msg_dict['good_day_is']
                ntf = Notify.Notification.new(sw_program_name, message, sw_default_icon)
                ntf.show()
                Timer(3, ntf.close).start()

def sw_activate(swgs):
    '''___build and activate application___'''

    def gdbus_method_call(
                        connection, sender, object_path, interface_name,
                        method_name, params, invocation):

        if method_name == "Message":
            parm = params.unpack()[0]

            if parm == 'lnk_error':
                text_message = msg.msg_dict['lnk_error']
            else:
                text_message = None

            if text_message is not None:
                print(f'{sender} : {text_message}')
                dialog_info(text_message=text_message, message_type='ERROR').run()
                invocation.return_value(None)

        elif method_name == "Active":
            name = params.unpack()[0]
            print(f'{sender} : {name}')
            answer = GLib.Variant(
                "(s)", ("True",)
            )
            invocation.return_value(answer)

        elif method_name == "Run":
            if len(params.unpack()) > 0:
                arg = params.unpack()[0].strip('"')
                check_arg(arg)

            start_mode()
            on_start()
            invocation.return_value(None)

        elif method_name == "Terminal":
            open_window()
            on_terminal()
            terminal.feed_child(f'neofetch\n'.encode("UTF-8"))
            invocation.return_value(None)

        elif method_name == "Show":
            if len(params.unpack()) > 0:
                arg = params.unpack()[0].strip('"')
                check_arg(arg)

            startup_question()
            invocation.return_value(None)

        elif method_name == "ShowHide":
            window = swgs.get_active_window()

            if window.get_visible():
                hide_window()
            else:
                open_window()

            invocation.return_value(None)

        elif method_name == "Shutdown":
            Popen(f"{sw_scripts}/sw_stop", shell=True)
            swgs.connection.flush(callback=flush_connection, user_data=None)
            invocation.return_value(None)

    def flush_connection(self, res, data):
        '''___Async close dbus connection'''

        result = self.flush_finish(res)
        print(result)
        window = swgs.get_active_window()
        window.close()
        swgs.quit()

    def startup_question():
        '''___Startup dialog question___'''

        app_name = get_out()
        app_path = get_app_path()
        start_mode()

        if app_name != 'StartWine':
            if not Path(f'{sw_shortcuts}/{app_name}.swd').exists():
                on_files(Path(Path(app_path.strip('"')).parent))

                label_frame_create_shortcut.set_label(msg.msg_dict['cs'])
                response = [
                            msg.msg_dict['run'].title(),
                            msg.msg_dict['open'].title(),
                            msg.msg_dict['cs'].title(),
                            msg.msg_dict['cancel'].title(),
                ]
                title = msg.msg_dict['choose']
                message = [Path(app_path.strip('"')).name, '']
                func = [on_start, open_window, on_message_cs, None]
                dialog_question(swgs, title, message, response, func)
            else:
                if not Path(app_path.strip('"')).exists():
                    text_message = msg.msg_dict['lnk_error']
                    dialog_info(text_message=text_message, message_type='ERROR').run()
                else:
                    on_files(Path(Path(app_path.strip('"')).parent))

                    label_frame_create_shortcut.set_label(msg.msg_dict['cw'])
                    response = [
                                msg.msg_dict['run'].title(),
                                msg.msg_dict['open'].title(),
                                msg.msg_dict['cw'].title(),
                                msg.msg_dict['launch_settings'].title(),
                                msg.msg_dict['cancel'].title(),
                    ]
                    title = msg.msg_dict['choose']
                    message = [Path(app_path.strip('"')).name, '']
                    func = [on_start, open_window, on_message_cs, on_launch_settings, None]
                    dialog_question(swgs, title, message, response, func)
        else:
            commandline = getenv('SW_COMMANDLINE')
            if commandline != 'None':
                if Path(commandline.strip('"')).exists():
                    on_files(Path(Path(commandline.strip('"')).parent))
                    open_window()
                else:
                    dialog_info(text_message=f"{msg.msg_dict['lnk_error']}", message_type='ERROR').run()
            else:
                open_window()

    def open_window():

        window = swgs.get_active_window()
        window.set_hide_on_close(False)
        window.set_visible(True)
        window.unminimize()

    def hide_window():

        window = swgs.get_active_window()
        window.set_hide_on_close(True)
        window.close()

    def cb_ctrl_key_pressed(ctrl_key_press, keyval, keycode, state, parent):
        '''___key pressed events handler___'''

        all_mask = (Gdk.ModifierType.CONTROL_MASK
                        | Gdk.ModifierType.SHIFT_MASK
                            | Gdk.ModifierType.ALT_MASK
                                | Gdk.ModifierType.SUPER_MASK
        )
        ctrl_shift = (Gdk.ModifierType.CONTROL_MASK & Gdk.ModifierType.SHIFT_MASK)

        letters_list = [
            chr(x) for x in list(range(ord('A'), ord('z') + 1))
            ]
        numbers_list = [
            chr(x) for x in list(range(ord('0'), ord('9') + 1))
            ]

        key_name = Gdk.keyval_name(keyval)
        k_val = display.translate_key(keycode, state, 0)
        f_keys = (Gdk.KEY_F1, Gdk.KEY_F2, Gdk.KEY_F3, Gdk.KEY_F4,
                    Gdk.KEY_F5, Gdk.KEY_F6, Gdk.KEY_F7, Gdk.KEY_F8,
                    Gdk.KEY_F9, Gdk.KEY_F10, Gdk.KEY_F11, Gdk.KEY_F12
                    )

        if (not (state & Gdk.ModifierType.ALT_MASK)
            and not (state & Gdk.ModifierType.CONTROL_MASK)
                and not (state & Gdk.ModifierType.SHIFT_MASK)):
                    if keyval not in f_keys:

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
            if reveal_stack.get_visible_child() == files_view_grid:
                selected = get_selected_item_gfile()
                if len(selected) > 1:
                    return on_files_rename(selected)
                elif len(selected) == 1:
                    return on_file_rename(selected[0])

        if keyval == Gdk.KEY_F3:
            return on_paned_files_view()

        if keyval == Gdk.KEY_F4:
            return on_about()

        if keyval == Gdk.KEY_F5:
            if reveal_stack.get_visible_child() == files_view_grid:
                parent_file = get_parent_file()
                if parent_file.get_path() is None:
                    parent_uri = parent_file.get_uri()
                    update_grid_view_uri(parent_uri)
                else:
                    on_files(parent_file.get_path())

        if ((state & all_mask) == Gdk.ModifierType.SHIFT_MASK
            and keyval == Gdk.KEY_Delete):
                if reveal_stack.get_visible_child() == files_view_grid:
                    selected = get_selected_item_gfile()
                    return on_file_remove(selected)

        if keyval == Gdk.KEY_Delete:
            if reveal_stack.get_visible_child() == files_view_grid:
                selected = get_selected_item_gfile()
                return on_file_to_trash(selected)

        if ((state & all_mask) == Gdk.ModifierType.SHIFT_MASK
            and k_val[1] in (Gdk.KEY_l, Gdk.KEY_L)):
                if reveal_stack.get_visible_child() == files_view_grid:
                    data = get_selected_item_gfile()
                    return on_file_link(data)

        if ((state & all_mask) == Gdk.ModifierType.META_MASK
            and keyval == Gdk.KEY_BackSpace):
                entry_search.set_text('')
                stack_search_path.set_visible_child(box_side)

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
            and k_val[1] in (Gdk.KEY_t, Gdk.KEY_T)):
                if reveal_stack.get_visible_child() == files_view_grid:
                    return on_terminal()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
            and k_val[1] in (Gdk.KEY_d, Gdk.KEY_D)):
                if reveal_stack.get_visible_child() == files_view_grid:
                    return on_drive()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
            and k_val[1] in (Gdk.KEY_b, Gdk.KEY_B)):
                return on_bookmarks()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
            and k_val[1] in (Gdk.KEY_f, Gdk.KEY_F)):
                dict_ini = read_menu_conf()
                sw_default_dir = dict_ini['default_dir']
                return on_files(Path(sw_default_dir))

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
                return on_winetricks()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
            and k_val[1] in (Gdk.KEY_a, Gdk.KEY_A)):
                return on_shortcuts()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
            and k_val[1] in (Gdk.KEY_l, Gdk.KEY_L)):
                return on_install_launchers()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
            and k_val[1] in (Gdk.KEY_x, Gdk.KEY_X)):
                return on_launch_settings()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
            and k_val[1] in (Gdk.KEY_m, Gdk.KEY_M)):
                return on_mangohud_settings()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
            and k_val[1] in (Gdk.KEY_v, Gdk.KEY_V)):
                return on_vkbasalt_settings()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
            and k_val[1] in (Gdk.KEY_i, Gdk.KEY_I)):
                return on_global_settings()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
            and k_val[1] in (Gdk.KEY_j, Gdk.KEY_J)):
                return on_controller_settings()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
            and k_val[1] in (Gdk.KEY_u, Gdk.KEY_U)):
                on_webview(home_page)

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
            and k_val[1] in (Gdk.KEY_n, Gdk.KEY_N)):
                if reveal_stack.get_visible_child() == grid_web:
                    add_webview(home_page)

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
            and keyval == Gdk.KEY_Up):
                return back_up()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
            and k_val[1] in (Gdk.KEY_s, Gdk.KEY_S)):
                return on_sidebar()

        if keyval == Gdk.KEY_Escape:
            if btn_back_main.get_visible():
                return on_back_main()

            elif sidebar_revealer.get_reveal_child():
                return on_sidebar()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
            and k_val[1] == Gdk.KEY_Return):
                if reveal_stack.get_visible_child() == files_view_grid:
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
                on_shutdown()

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
            and k_val[1] in (Gdk.KEY_a, Gdk.KEY_A)):
                if reveal_stack.get_visible_child() == files_view_grid:
                    grid_view = get_list_view()
                    grid_view.get_model().select_all()

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
            and keyval == Gdk.KEY_KP_Add):
                if reveal_stack.get_visible_child() == files_view_grid:
                    if Path(entry_path.get_name()) == sw_shortcuts:
                        btn_scale_shortcuts.set_value(btn_scale_shortcuts.get_value() + scale_step)
                    else:
                        btn_scale_icons.set_value(btn_scale_icons.get_value() + scale_step)

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
            and keyval == Gdk.KEY_KP_Subtract):
                if reveal_stack.get_visible_child() == files_view_grid:
                    if Path(entry_path.get_name()) == sw_shortcuts:
                        btn_scale_shortcuts.set_value(btn_scale_shortcuts.get_value() - scale_step)
                    else:
                        btn_scale_icons.set_value(btn_scale_icons.get_value() - scale_step)

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
            and keyval == Gdk.KEY_equal):
                if reveal_stack.get_visible_child() == files_view_grid:
                    if Path(entry_path.get_name()) == sw_shortcuts:
                        btn_scale_shortcuts.set_value(btn_scale_shortcuts.get_value() + scale_step)
                    else:
                        btn_scale_icons.set_value(btn_scale_icons.get_value() + scale_step)

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
            and keyval == Gdk.KEY_minus):
                if reveal_stack.get_visible_child() == files_view_grid:
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
                if reveal_stack.get_visible_child() == files_view_grid:
                    return on_hidden_files()

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
            and k_val[1] in (Gdk.KEY_l, Gdk.KEY_L)):
                stack_search_path.set_visible_child(box_side)
                entry_path.grab_focus()

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
            and k_val[1] in (Gdk.KEY_n, Gdk.KEY_N)):
                if reveal_stack.get_visible_child() == files_view_grid:
                    parent_file = get_parent_file()
                    if parent_file.get_path() is not None:
                        return on_create_dir()

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
            and k_val[1] in (Gdk.KEY_c, Gdk.KEY_C)):
                if reveal_stack.get_visible_child() == files_view_grid:
                    data = get_selected_item_gfile()
                    return on_file_copy(data)

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
            and k_val[1] in (Gdk.KEY_v, Gdk.KEY_V)):
                if reveal_stack.get_visible_child() == files_view_grid:
                    return on_file_paste()

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
            and k_val[1] in (Gdk.KEY_x, Gdk.KEY_X)):
                if reveal_stack.get_visible_child() == files_view_grid:
                    data = get_selected_item_gfile()
                    return on_file_cut(data)

        if ((state & all_mask) == Gdk.ModifierType.CONTROL_MASK
            and k_val[1] in (Gdk.KEY_k, Gdk.KEY_K)):
                return on_show_hotkeys()

        if ((state & all_mask) == (
            Gdk.ModifierType.SHIFT_MASK | Gdk.ModifierType.CONTROL_MASK)
            and k_val[1] in (Gdk.KEY_k, Gdk.KEY_K)):
                return on_stop()

        if ((state & Gdk.MODIFIER_MASK) == Gdk.ModifierType.SUPER_MASK
            and keyval == Gdk.KEY_Escape):
                if (stack_search_path.get_visible_child() == box_search
                    or stack_search_path.get_visible_child() == box_side):
                        entry_search.set_text('')
                        stack_search_path.set_visible_child(box_path)

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
            and keyval == Gdk.KEY_Left):
                return on_prev()

        if ((state & all_mask) == Gdk.ModifierType.ALT_MASK
            and keyval == Gdk.KEY_Right):
                return on_next()

        if ((state & all_mask) == (
            Gdk.ModifierType.SHIFT_MASK | Gdk.ModifierType.CONTROL_MASK)
            and k_val[1] in (Gdk.KEY_f, Gdk.KEY_F)):
                return on_parent_fullscreen()

    def cb_ctrl_lclick_parent(self, n_press, x, y):
        '''___left click on parent window___'''

        pick = parent.pick(x, y, Gtk.PickFlags.DEFAULT)

        if (stack_search_path.get_visible_child() == box_search
            or stack_search_path.get_visible_child() == box_side
                or stack_search_path.get_visible_child() == box_web):
                    if (reveal_stack.get_visible_child() == files_view_grid
                        and not pick.get_name().isdigit()):
                            entry_search.set_text('')
                            stack_search_path.set_visible_child(box_path)

        if (terminal_revealer.get_reveal_child()
            and terminal_stack.get_visible_child() == terminal):
                terminal.set_visible(False)
                terminal_revealer.set_reveal_child(False)
                files_view_grid.set_position(-1)

    def cb_ctrl_swipe_panel(self, x, y, data):
        '''___swipe gesture on the bottom panel of the window___'''

        swap_x = x*1000
        swap_y = y*1000
        print(swap_x, swap_y)
        if swap_x != 0.0:
            if swap_x > swap_y:
                return on_next()
            elif swap_x < swap_y:
                return on_prev()

    def cb_ctrl_motion_headerbar(self, x, y, data):
        '''___  ___'''

        if getenv('SW_AUTO_HIDE_TOP_HEADER') == '1':
            if (y <= 42
                or stack_search_path.get_visible_child() == box_search
                    or stack_search_path.get_visible_child() == box_web):
                        top_headerbar_revealer.set_reveal_child(True)
            elif y > 42:
                top_headerbar_revealer.set_reveal_child(False)

        if getenv('SW_AUTO_HIDE_BOTTOM_HEADER') == '1':
            if (y >= (data.get_height() - 42)
                or progress_main.get_visible()):
                    bottom_headerbar_revealer.set_reveal_child(True)
            else:
                bottom_headerbar_revealer.set_reveal_child(False)

    def cb_ctrl_key_term(ctrl_key_press, keyval, keycode, state, terminal):
        '''___key press events in terminal___'''

        k_val = display.translate_key(keycode, state, 0)

        if ((state & Gdk.ModifierType.CONTROL_MASK | Gdk.ModifierType.SHIFT_MASK)
            and k_val[1] in (Gdk.KEY_v, Gdk.KEY_V)):
                terminal.paste_clipboard()

    def cb_ctrl_rclick_term(self, n_press, x, y):
        '''___vte terminal right click event___'''

        terminal.paste_clipboard()

    def cb_terminal_changed(self, pid, error, data):
        '''___vte terminal pid___'''
        pass

    ####___Overlay_info___.

    def overlay_info(overlay, title, message, response, timer):
        '''dialog info widget for text message in overlay widget'''

        def timer_finish(q):
            q.append('close')

        def close(grid_info):
            '''___remove overlay info message___'''

            grid_info.set_visible(False)

        def cb_btn_exit(self):
            '''___remove overlay info message___'''
            return close(grid_info)

        if title is None:
            title = f'{sw_program_name} INFO'

        title_label.set_label(title)
        message_label.set_label(str(message))
        btn_exit.connect('clicked', cb_btn_exit)
        grid_info.set_visible(True)

        if timer is not None:
            q = []
            t = Timer(timer, timer_finish, args=[q])
            t.start()
            GLib.timeout_add(1000, check_alive, t, close, grid_info, None)

    ####___Progress_function___.

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

            environ['FRAGMENT_NUM'] = getenv('FRAGMENT_INDEX')

            if stack_sidebar.get_visible_child() == frame_create_shortcut:
                stack_sidebar.set_visible_child(frame_main)

            if bar.get_name() == 'install_launchers':
                on_install_launchers()

            if bar.get_name() == 'install_wine':
                on_download_wine()
                on_wine_tools()

            if bar.get_name() == 'pfx_remove':
                environ['SW_EXEC'] = ''

            if info is not None:
                overlay_info(overlay, None, info, None, 3)

            start_mode()
            return False

    def cb_btn_search(self):
        '''___show search entry widget___'''

        stack_search_path.set_visible_child(box_search)

    def cb_entry_search_changed(self):
        '''___filter list items when search___'''

        wv_name = reveal_stack.get_visible_child().get_name()
        parent_file = get_parent_file()

        if wv_name == vw_dict['shortcuts']:
            if reveal_stack.get_visible_child() == files_view_grid:
                if parent_file.get_path() is not None:
                    on_view_search()
                else:
                    overlay_info(overlay, None, msg.msg_dict['action_not_supported'], None, 3)

        elif wv_name == vw_dict['files']:
            if reveal_stack.get_visible_child() == files_view_grid:
                if parent_file.get_path() is not None:
                    on_view_search()
                else:
                    overlay_info(overlay, None, msg.msg_dict['action_not_supported'], None, 3)

        elif wv_name == vw_dict['install_launchers']:
            if reveal_stack.get_visible_child() == scrolled_install_launchers:
                swgs.launchers_flow.set_filter_func(on_flowbox_search_filter, launchers_list)

        elif wv_name == vw_dict['launch_settings']:
            if reveal_stack.get_visible_child() == scrolled_launch_settings:
                ls_names = lp_title + switch_labels
                swgs.launch_flow.set_filter_func(on_flowbox_search_filter, ls_names)

        elif wv_name == vw_dict['mangohud_settings']:
            if reveal_stack.get_visible_child() == scrolled_mangohud_settings:
                swgs.mangohud_flow.set_filter_func(on_flowbox_search_filter, check_mh_labels)
                swgs.colors_flow_mh.set_filter_func(on_flowbox_search_filter, mh_colors_description)

        elif wv_name == vw_dict['vkbasalt_settings']:
            if reveal_stack.get_visible_child() == scrolled_vkbasalt_settings:
                swgs.vkbasalt_flow.set_filter_func(on_flowbox_search_filter, vkbasalt_dict)

        elif wv_name == vw_dict['winetricks']:
            if reveal_stack.get_visible_child() == scrolled_winetricks:
                if swgs.stack_tabs.get_visible_child() == swgs.scrolled_dll:
                    on_winetricks_search(swgs.list_store_dll_0, dll_dict)
                elif swgs.stack_tabs.get_visible_child() == swgs.scrolled_fonts:
                    on_winetricks_search(swgs.list_store_fonts, fonts_dict)

    def on_view_search():
        '''___recursive search for files in the current directory___'''

        find = entry_search.get_text().lower()
        found = []
        start_path = Path(entry_path.get_name())
        paned_store = get_list_store()
        dir_list = get_dir_list()

        def get_found():
            '''___append found files to list store___'''

            paned_store.remove_all()
            timeout_list_clear(None)
            count = 24
            for r, d, f in walk(start_path):
                if search_is_empty == []:
                    paned_store.remove_all()
                    timeout_list_clear(None)
                    break

                for x in d:
                    if find in x.lower():
                        count += 2
                        p = Path(join(r, x))
                        x_file = Gio.File.new_for_path(bytes(p))
                        x_info = x_file.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
                        timeout_info = GLib.timeout_add(count, get_file_info, paned_store, dir_list, x_file, x_info, None)
                        timeout_list.append(timeout_info)

                for x in f:
                    if find in x.lower():
                        count += 2
                        p = Path(join(r, x))
                        x_file = Gio.File.new_for_path(bytes(p))
                        x_info = x_file.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
                        timeout_info = GLib.timeout_add(count, get_file_info, paned_store, dir_list, x_file, x_info, None)
                        timeout_list.append(timeout_info)

        def clear():
            '''___terminate all when thread is dead and search is done___'''

            find = entry_search.get_text().lower()

            if len(find) <= 1:
                dict_ini = read_menu_conf()
                x_hidden_files = dict_ini['hidden_files']
                paned_store.remove_all()
                timeout_list_clear(None)
                count = 24
                g_file = Gio.File.new_for_path(bytes(start_path))
                g_enum = g_file.enumerate_children('*', Gio.FileQueryInfoFlags.NONE)
                sorted_list = sort_func(g_enum)

                for x in sorted_list:
                    count += 2
                    x_file = g_enum.get_child(x)
                    timeout_info = GLib.timeout_add(count, get_file_info, paned_store, dir_list, x_file, x, x_hidden_files)
                    timeout_list.append(timeout_info)

        if stack_search_path.get_visible_child() == box_search:

            if len(find) <= 1:
                search_is_empty.clear()
                clear()

            if len(find) > 1:
                search_is_empty.append(find)
                paned_store.remove_all()
                timeout_list_clear(None)

                if str(start_path) == str(sw_shortcuts):
                    count = 24
                    for x in scandir(path=start_path):
                        if find in x.name.lower():
                            count += 2
                            p = Path(join(start_path, x.name))
                            x_file = Gio.File.new_for_path(bytes(p))
                            x_info = x_file.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
                            timeout_info = GLib.timeout_add(count, get_file_info, paned_store, dir_list, x_file, x_info, None)
                            timeout_list.append(timeout_info)
                else:
                    thread_get_found = Thread(target=get_found)
                    thread_get_found.start()
                    progress_main.set_show_text(True)
                    progress_main.set_text(progress_dict['search'])
                    GLib.timeout_add(100, progress_on_thread, progress_main, thread_get_found, None)
                    #GLib.timeout_add(120, check_alive, thread_get_found, clear, None, None)

    def on_flowbox_search_filter(fb_child, data_labels):
        '''___filter item in flowbox___'''

        for line in data_labels:
            if fb_child.get_name() in str(line):
                fb_name = [line]

        find = entry_search.get_text()

        for line in fb_name:
            if find.lower() in line.lower():
                return True

    def on_winetricks_search(x_tab_store, x_dict):
        '''___search item in winetricks list___'''

        w_log = get_dll_info(get_pfx_path())
        find = entry_search.get_text()
        found = [ line for line in list(x_dict) if find.lower() in line.lower()]

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
        '''___append dll items to list store___'''

        if x_dll is not None:
            swgs.list_store_dll_0.append(x_dll)

        if y_dll is not None:
            swgs.list_store_dll_1.append(y_dll)

        if f_dll is not None:
            swgs.list_store_fonts.append(f_dll)

        return False

    def update_dll_store():
        '''update dlls and fonts list'''

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

    def cb_btn_path(self):
        '''___show path bar widget___'''

        stack_search_path.set_visible_child(box_path)

    def cb_btn_back_path(self):
        '''___show path bar widget___'''

        stack_search_path.set_visible_child(box_path)

    def cb_entry_path_activate(self):
        '''___activate found list items___'''

        path = Path(self.get_name())
        return on_files(path)

    def cb_ctrl_scroll_path(self, x, y):
        '''___mouse scroll event to scroll path bar___'''

        if self.get_unit() == Gdk.ScrollUnit.WHEEL:
            if y == -1.0:
                hadjustment_path.set_value(0)
            elif y == 1.0:
                hadjustment_path.set_value(1000)

    ####___Web_view___.

    def create_web_view():
        '''___Create new web page in web view___.'''

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

        num_pages = stack_web.get_n_pages()
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

        if stack_web.get_nth_page(0) is None:
            create_web_view()

        webview = stack_web.get_nth_page(0).get_child().get_child()
        webview.load_uri(url)

        stack_search_path.set_visible_child(box_web)
        entry_web.grab_focus()

        return set_settings_widget(
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

    def cb_web_resource_load_started(self, resource, request):
        '''___signal emmited when a new resource is going to be loaded___'''

        print('Request uri:', request.get_uri())

    def cb_web_permission_request(self, request):
        '''___signal is emitted when WebKit is requesting the client to decide 
        about a permission request___'''

        request.allow()

    def cb_authenticated(self, credential):
        '''___signal is emitted when the user authentication request succeeded___'''

        print('Authenticated succeeded:', credential)

    def cb_cancelled(self):
        '''___signal is emitted when the user authentication request cancelled___'''

        print('Authenticate cancelled')

    def cb_web_authenticate(self, request):
        '''___emitted when the user is challenged with HTTP authentication___'''

        credential = WebKit.Credential.new(
                                        username, password,
                                        WebKit.CredentialPersistence.SESSION
        )
        request.connect('authenticated', cb_authenticated)
        request.connect('authenticated', cb_cancelled)
        request.authenticate(credential)

    def cb_web_create(self, navigation_action):
        '''___emitted when the creation of a new WebKitWebView is requested___'''

        return add_webview(swgs.hit_test_uri)

    def cb_webview_context_menu(self, context_menu, hit_test_result):
        '''___emitted when a context menu is about to be displayed ___'''

        swgs.hit_test_uri = hit_test_result.get_link_uri()
        print(tc.YELLOW, hit_test_result.get_link_uri(), tc.END)

    def cb_entry_web_activate(self):

        buffer = self.get_buffer()
        url = buffer.get_text()
        if not '://' in url:
            url = 'https://www.google.com/search?q=' + url

            if url.endswith('/'):
                url = url.rstrip('/')

        update_web_page_tab(url, True, None)

    def cb_webview_load_changed(self, load_event):
        '''___handler for changing the loading state of a web page___'''

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

    def cb_favicon_get(self, res, data):
        '''___returns changed favicon from the database___'''
        try:
            result = self.get_favicon_finish(res)
        except Exception as e:
            print(e)
            result = None
        else:
            print(result)

    def cb_favicon_changed(self, page_uri, favicon_uri):
        '''___signal emitted when the favicon URI of page_uri has been changed
         to favicon_uri in the database___'''

        self.get_favicon(
                        page_uri=page_uri,
                        cancellable=Gio.Cancellable(),
                        callback=cb_favicon_get,
                        user_data=favicon_uri,
        )

    def cb_network_session_download_started(self, download):
        '''___signal emitted when download started___'''

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
        '''___signal emitted when download finished___'''

        current_image_path = Path(image_start_mode.get_name())
        parent_path = current_image_path.parent
        cache = self.get_destination()
        gfile = Gio.File.new_for_path(cache)
        ginfo = gfile.query_info('*', Gio.FileQueryInfoFlags.NONE)
        gtype = ginfo.get_content_type()

        if gtype in image_mime_types:
            app_name = get_out().replace('_', ' ')
            app_name_isalnum = ''.join(e for e in app_name if e.isalnum())
            app_id = Path(cache).stem
            length = len(app_name)
            is_lower_around = (lambda: app_name[i-1].islower() or 
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
            dict_ini = read_menu_conf()
            name = current_image_path.name

            if dict_ini['icon_position'] == 'vertical':
                name = name.replace('_horizontal_', '_vertical_')
                destination = f'{sw_app_vicons}/{name}'
                if Path(f'{sw_app_vicons}/{name}').exists():
                    shutil.move(f'{sw_app_vicons}/{name}', f'{sw_app_vicons}/old_{name}')
                else:
                    name = f'{app_name_isalnum}_vertical_{edited_name}_{app_id}.jpg'
                    destination = f'{sw_app_vicons}/{name}'
                try:
                    converted = convert_image(cache, destination, 480, 720)
                except:
                    shutil.move(cache, destination)
                    print(f'{tc.GREEN} Copy vertical icon: {tc.YELLOW}{destination} {tc.END}')
                else:
                    print(f'{tc.GREEN} Convert vertical icon: {tc.YELLOW}{destination} {tc.END}')
            else:
                name = name.replace('_vertical_', '_horizontal_')
                destination = f'{sw_app_hicons}/{name}'
                if Path(f'{sw_app_hicons}/{name}').exists():
                    shutil.move(f'{sw_app_hicons}/{name}', f'{sw_app_hicons}/old_{name}')
                else:
                    name = f'{app_name_isalnum}_horizontal_{edited_name}_{app_id}.jpg'
                    destination = f'{sw_app_hicons}/{name}'

                try:
                    converted = convert_image(cache, destination, 920, 430)
                except:
                    shutil.move(cache, destination)
                    print(f'{tc.GREEN} Copy horizontal icon: {tc.YELLOW}{destination} {tc.END}')
                else:
                    print(f'{tc.GREEN} Convert horizontal icon: {tc.YELLOW} {destination} {tc.END}')

            get_sm_icon(app_name)

        message = f'Download to {self.get_destination()} completed'
        return overlay_info(overlay, None, message, None, 5)

    def cb_download_failed(self, error):
        '''___signal is emitted when an error occurs during the download operation___'''

        if error:
            return overlay_info(overlay, None, error, None, 5)

    def cb_download_create_destination(self, destination):
        '''___Notify that destination file has been created successfully at destination___'''

        print(f'{tc.VIOLET}CREATE_DOWNLAOD_DESTINATION: {tc.GREEN}{destination}{tc.END}')

    def cb_download_received_data(self, data_length):
        '''___ signal is emitted after response is received, 
        every time new data has been written to the destination___'''

        fraction = self.get_estimated_progress()
        stack_progress_main.set_visible_child(progress_main_grid)
        progress_main.set_visible(True)
        progress_main.set_show_text(True)
        progress_main.set_fraction(fraction)
        if fraction >= 1:
            fraction = 0
            progress_main.set_fraction(0.0)
            progress_main.set_show_text(False)
            progress_main.set_visible(False)
            stack_progress_main.set_visible_child(stack_panel)

    def cb_decide_destination(self, res, webkit_download):
        '''___response callback to the selected destination___'''
        try:
            result = self.select_folder_finish(res)
        except GLib.GError as e:
            result = None
            dialog_info(text_message=str(e.message), message_type='ERROR').run()
        else:
            url_name = str(entry_web.get_text()).split('/')[-1]
            path = str(result.get_path()) + '/' + url_name
            webkit_download.set_destination(path)
            print(f'{tc.VIOLET}SET_DOWNLAOD_DESTINATION: {tc.GREEN}{path}{tc.END}')

    def cb_download_decide_destination(self, suggested_filename):
        '''___a response has been received to decide a destination for the download___'''

        title = 'Change Directory'
        dialog = dialog_directory(title)
        dialog.select_folder(
                    parent=parent,
                    cancellable=Gio.Cancellable(),
                    callback=cb_decide_destination,
                    user_data=self,
        )

    def cb_webview_decide_policy(self, decision, decision_type):
        '''___requesting the client to decide a policy decision___'''

        if decision_type == WebKit.PolicyDecisionType.RESPONSE:
            if not decision.is_mime_type_supported():
                decision.download()

    def cb_webview_mouse_target_changed(self, hit_test, modifiers):
        '''___when the mouse cursor moves over an web page element___'''

        if hit_test.get_link_uri() is not None:
            label_overlay.set_visible(True)
            label_overlay.set_label(hit_test.get_link_uri())
        else:
            label_overlay.set_visible(False)

    def cb_web_page_close(self, webview):
        '''___closing a web page tab___'''

        webview.terminate_web_process()
        webview.try_close()
        page_num = stack_web.get_current_page()
        stack_web.remove_page(page_num)

    ####___Files___.

    def cb_paned_cycle_child_focus(self, _reversed):
        '''___Emitted to cycle the focus between the children of the paned.___'''

        print(self.get_focus_child().get_name())

    def cb_paned_cycle_handle_focus(self):
        '''___Emitted to accept the current position of the handle.___'''

        print(self.get_position())

    def on_paned_files_view():
        '''___paned files grid view___'''

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
            action_copy = Gdk.DragAction.COPY
            action_move = Gdk.DragAction.MOVE
            action_ask = Gdk.DragAction.ASK

            ctrl_drop_target.set_gtypes(types)
            ctrl_drop_target.set_actions(action_move)
            ctrl_drop_target.set_preload(True)
            ctrl_drop_target.connect('drop', cb_ctrl_drop_target)

            ctrl_right_view_motion = Gtk.EventControllerMotion()
            ctrl_right_view_motion.connect('enter', cb_ctrl_right_view_motion)

            ctrl_right_view_focus = Gtk.EventControllerFocus()
            ctrl_right_view_focus.connect('enter', cb_ctrl_right_view_focus)
            #ctrl_left_view_focus.connect('leave', cb_ctrl_right_view_focus)

            right_grid_view.add_controller(ctrl_drag_source)
            right_grid_view.add_controller(ctrl_lclick_view)
            right_grid_view.add_controller(ctrl_rclick_view)
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

            set_view_parent_path(right_grid_view)
            return on_files(sw_default_dir)

    def on_files(path):
        '''___show files list view___'''

        timeout_list_clear(None)
        on_show_hidden_widgets(vw_dict['files'])

        if Path(path).is_dir():
            try:
                update_grid_view(path)
            except PermissionError as e:
                return overlay_info(overlay, None, e, None, 3)

            terminal.feed_child(
                f'cd "{str(path)}" && clear\n'.encode("UTF-8")
            )

        if (stack_sidebar.get_visible_child() != frame_main
            and stack_sidebar.get_visible_child() != frame_bookmarks):
                return on_back_main()

        reveal_stack.set_visible_child(files_view_grid)

        scrolled_left_files.set_min_content_width(width*0.2)
        scrolled_left_files.set_min_content_height(240)
        scrolled_right_files = paned_grid_view.get_end_child()
        if scrolled_right_files is not None:
            scrolled_right_files.set_min_content_width(width*0.2)
            scrolled_right_files.set_min_content_height(240)

        update_color_scheme()

    def on_hidden_files():
        '''___show or hide hidden files___'''

        timeout_list_clear(None)
        dict_ini = read_menu_conf()
        if dict_ini['hidden_files'] == 'True':
            dict_ini['hidden_files'] = 'False'
        else:
            dict_ini['hidden_files'] = 'True'

        write_menu_conf(dict_ini)
        parent_file = get_parent_file()
        if parent_file.get_path() is not None:
            try:
                update_grid_view(parent_file.get_path())
            except PermissionError as e:
                overlay_info(overlay, None, e, None, 3)
        else:
            try:
                update_grid_view_uri(parent_file.get_uri())
            except PermissionError as e:
                overlay_info(overlay, None, e, None, 3)

    def on_terminal():
        '''___show or hide terminal___'''

        if terminal_revealer.get_reveal_child():
            scrolled_gvol.set_visible(False)
            terminal.set_visible(False)
            terminal_revealer.set_reveal_child(False)
            files_view_grid.set_position(-1)
        else:
            terminal.set_visible(True)
            terminal_stack.set_visible_child(terminal)
            terminal_revealer.set_reveal_child(True)
            files_view_grid.set_position(0)

    def on_drive():
        '''___show or hide mounted volumes___'''

        if scrolled_gvol.get_child() is None:
            add_gvol_view()

        update_gvolume()

        if terminal_revealer.get_reveal_child():
            scrolled_gvol.set_visible(False)
            terminal.set_visible(False)
            terminal_revealer.set_reveal_child(False)
            files_view_grid.set_position(-1)
        else:
            scrolled_gvol.set_visible(True)
            terminal_stack.set_visible_child(scrolled_gvol)
            scrolled_gvol.set_min_content_width(swgs.width*0.2)
            scrolled_gvol.set_min_content_height(240)
            terminal_revealer.set_reveal_child(True)
            files_view_grid.set_position(swgs.height*0.5)
            update_color_scheme()

    def update_gvolume():
        '''___update mounted volumes list___'''

        swgs.list_gvol_store.remove_all()

        gvolume_list = swgs.gvolume_monitor.get_volumes()
        gmount_list = swgs.gvolume_monitor.get_mounts()
        gdrive_list = swgs.gvolume_monitor.get_connected_drives()

        if (gvolume_list is None or gvolume_list == []):
            partitions = psutil.disk_partitions()
            for x in sorted(partitions):
                for m in ['/mnt/', '/run/media/', '/home']:
                    if m in x.mountpoint:
                        mountpoint = x.mountpoint
                        if not '.Xauthority' in mountpoint:
                            string = Gtk.StringObject.new(f'{mountpoint}:{x.device}:{x.fstype}:{x.opts}')
                            swgs.list_gvol_store.append(string)
        else:
            for gvolume in gvolume_list:
                gvolume_name = gvolume.get_name()
                gvolume_icon = gvolume.get_icon()
                swgs.list_gvol_store.append(gvolume)

    def on_message_cs():
        '''___create shortcut on item activate___'''

        if scrolled_create_shortcut.get_child() is None:
            add_create_shortcut_menu()

        if sidebar_revealer.get_reveal_child() is False:
            on_sidebar()

        btn_back_main.set_visible(True)
        stack_sidebar.set_visible_child(frame_create_shortcut)

    def cb_item_activate(self, position):
        '''___activate view item by user___'''

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
                    return overlay_info(overlay, None, e, None, 3)
                else:
                    terminal.feed_child(f'cd "{symlink_target}" && clear\n'.encode("UTF-8"))
            else:
                try:
                    update_grid_view(item_path)
                except PermissionError as e:
                    return overlay_info(overlay, None, e, None, 3)
                else:
                    terminal.feed_child(f'cd "{item_path}" && clear\n'.encode("UTF-8"))

        elif f_type in exe_mime_types:

            environ['SW_EXEC'] = f'"{item_path}"'
            write_app_conf(Path(item_path))
            app_name = get_out()

            if Path(f'{sw_shortcuts}/{app_name}.swd').exists():
                app_dict = app_info(Path(f'{sw_shortcuts}/{app_name}.swd'))
                app_exec = app_dict['Exec'].replace(f'env "{sw_start}" ', '').strip('"')

                if str(item_path) == str(app_exec):
                    label_frame_create_shortcut.set_label(msg.msg_dict['cw'])
                    response = [
                                msg.msg_dict['run'].title(),
                                msg.msg_dict['cw'].title(),
                                msg.msg_dict['cancel'].title(),
                    ]
                    start_mode()
                    title = msg.msg_dict['choose']
                    func = [on_start, on_message_cs, None]
                    dialog_question(swgs, title, [Path(item_path).name, ''], response, func)
                else:
                    overlay_info(overlay, None, msg.msg_dict['same_name'], None, None)
            else:
                label_frame_create_shortcut.set_label(msg.msg_dict['cs'])
                response = [
                            msg.msg_dict['run'].title(),
                            msg.msg_dict['cs'].title(),
                            msg.msg_dict['cancel'].title(),
                ]
                start_mode()
                title = msg.msg_dict['choose']
                func = [on_start, on_message_cs, None]
                dialog_question(swgs, title, [Path(item_path).name, ''], response, func)

        elif f_type in app_mime_types:

            check_arg(str(item_path))
            if getenv('SW_EXEC') != 'StartWine':
                start_mode()
                cb_btn_start(btn_start)
            elif getenv('SW_COMMANDLINE') != 'None':
                cmd = getenv('SW_COMMANDLINE').strip('"').replace('env ', '')
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
                        return overlay_info(overlay, None, message, None, 3)
            else:
                fl = Gtk.FileLauncher()
                fl.set_file(item)
                try:
                    fl.launch()
                except Exception as e:
                    print(tc.RED, e, tc.END)
                    message = msg.msg_dict['launch_error'] + f': {e}'
                    return overlay_info(overlay, None, message, None, 3)

        elif Path(item_path).suffix in swd_mime_types:
#            check_arg(str(item_path))
#            if getenv('SW_EXEC') != 'StartWine':
#                start_mode()
#                on_startapp_page()
#            else:
#                return overlay_info(overlay, None, msg.msg_dict['lnk_error'], None, 3)

            check_arg(str(item_path))
            if getenv('SW_EXEC') != 'StartWine':
                start_mode()
                cb_btn_start(btn_start)
            elif getenv('SW_COMMANDLINE') != 'None':
                cmd = getenv('SW_COMMANDLINE').strip('"').replace('env ', '')
                run(cmd, shell=True)
            else:
                text_message = msg.msg_dict['lnk_error']
                return dialog_info(text_message=text_message, message_type='ERROR').run()

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
                return dialog_info(text_message=e.message, message_type='ERROR').run()
        else:
            fl = Gtk.FileLauncher()
            fl.set_file(item)
            try:
                fl.launch()
            except GLib.GError as e:
                print(tc.RED, e.message, tc.END)
                return dialog_info(text_message=e.message, message_type='ERROR').run()

    def get_dll_info(x_path):
        '''___get installed dll list from winetricks log___'''

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
        '''___get current path in file manger list view___'''

        parent_path = getenv('SW_FILES_PARENT_PATH')
        return parent_path

    def get_parent_file():
        '''___get current path in file manger list view___'''

        grid_view = get_list_view()
        dir_list = get_dir_list()

        if grid_view.get_model().get_item(0) is None:
            parent_file = dir_list.get_file()
        else:
            parent_file = dir_list.get_file().get_parent()

        return parent_file

    def get_parent_uri():
        '''___get current uri in file manger list view___'''

        grid_view = get_list_view()
        dir_list = get_dir_list()

        if grid_view.get_model().get_item(0) is None:
            parent_uri = dir_list.get_file().get_uri()
        else:
            parent_uri = dir_list.get_file().get_parent().get_uri()

        return parent_uri

    def get_selected_item_path():
        '''___get path list from selected item in list view___'''

        grid_view = get_list_view()
        model = grid_view.get_model()
        nums = model.get_n_items()
        paths = list()

        for n in range(nums):
            if model.is_selected(n):
                p = model.get_item(n).get_path()
                paths.append(p)

        return paths

    def get_selected_item_gfile():
        '''___get gio files list from selected item in list view___'''

        grid_view = get_list_view()
        model = grid_view.get_model()
        nums = model.get_n_items()
        files = list()

        for n in range(nums):
            if model.is_selected(n):
                f = model.get_item(n)
                files.append(f)

        return files

    def get_selected_item_info():
        '''___get gio file info list from selected item in list view___'''

        grid_view = get_list_view()
        model = grid_view.get_model()
        nums = model.get_n_items()
        infos = list()

        for n in range(nums):
            if model.is_selected(n):
                f = model.get_item(n)
                i = f.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
                infos.append(i)

        return infos

    def try_get_theme_icon(icon):
        '''___try get icon paintable from system icon theme by name___'''

        try:
            icon = icon_theme.lookup_icon(
                                icon_name=icon_name,
                                fallbacks=None,
                                size=256,
                                scale=1,
                                direction=Gtk.TextDirection.NONE,
                                flags=Gtk.IconLookupFlags.FORCE_REGULAR
                                )
        except:
            icon = None
            return icon
        else:
            return icon

    def sort_func(x_list):
        '''___file sorting function in the list___'''

        sorted_list = list()
        dict_ini = read_menu_conf()

        try:
            sorting_files = dict_ini['sorting_files']
        except KeyError as e:
            sorting_files = 'name'

        try:
            sorting_reverse = dict_ini['sorting_reverse']
        except KeyError as e:
            sorting_reverse = 'False'

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
            key=lambda x: (str(Path(x_list.get_child(x).get_path()).is_file()),
                        str(Path(x_list.get_child(x).get_path()).is_symlink())),
            reverse=False
        )
        return sorted_list

    def get_file_info(paned_store, dir_list, x_file, x_info, x_hidden_files):
        '''___getting file attributes to set name and images in list___'''

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
                    if not x_path.suffix in swd_mime_types:
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
        '''___update list view when path is changed___'''

        update_path(new_path)
        entry_path.set_text(str(new_path))
        entry_path.set_name(str(new_path))

        swgs.cur_dir = Gio.File.new_for_path(bytes(Path(new_path)))
        swgs.f_mon = swgs.cur_dir.monitor(Gio.FileMonitorFlags.WATCH_MOVES, None)
        swgs.f_mon.connect('changed', g_file_monitor)

        paned_store = get_list_store()
        grid_view = get_list_view()

        if Path(new_path).is_dir():
            os.chdir(new_path)
            paned_store.remove_all()
            dict_ini = read_menu_conf()
            x_hidden_files = dict_ini['hidden_files']
            g_file = Gio.File.new_for_path(bytes(Path(new_path)))
            t = Thread(target=update_view, args=[paned_store, g_file, x_hidden_files])
            t.start()
            timeout = GLib.timeout_add(100, check_alive, t, update_selection, grid_view, None)
            timeout_list.append(timeout)

    async def image_thumbnail():
        '''___generate image thumbnail___'''

        async def run_thumbnail(in_file, out_file, width, height):
            '''___generate thumbnail for image mime type files___'''

            start = perf_counter()
            in_type = 'image'
            file = Gio.File.new_for_commandline_arg(in_file)
            file_info = file.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
            size = width, height

            if file_info.get_content_type() == 'image/svg+xml':
                in_type = 'svg'

            if in_type == 'svg':
                image_cache = shutil.copy(in_file, out_file)
            else:
                try:
                    image = Image.open(in_file)
                except:
                    print(
                        f'{tc.RED}get_image_thumbnail'
                        + f'{tc.GREEN}{in_file}{tc.RED}failed{tc.END}'
                    )
                else:
                    try:
                        image.thumbnail(size, Image.Resampling.LANCZOS)
                    except:
                        print(
                            f'{tc.RED}get_image_thumbnail'
                            + f'{tc.GREEN}{in_file}{tc.RED}failed{tc.END}'
                        )
                    else:
                        try:
                            image.save(out_file, 'png')
                        except:
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
        '''___generate video thumbnail___'''

        async def run_thumbnail(in_file, out_file, width):
            '''___generate thumbnail for video mime type files___'''

            start = perf_counter()
            cmd = (f'ffmpeg -loglevel quiet -ss 00:00:01.00 -i "{in_file}" -vf \
                "scale={width}:{width}:force_original_aspect_ratio=decrease" \
                -vframes 1 -y "{out_file}"')
            try:
                run(cmd, shell=True)
            except:
                print(f'{tc.RED}Thumbnail {tc.GREEN}{in_file}{tc.RED}failed{tc.END}')
            else:
                end = perf_counter() - start
                print(f'-->Thumbnail {in_file} => {out_file} (took {end:0.2f} seconds)')
                print(f'{tc.GREEN}done{tc.END}')

        start = perf_counter()
        items = thumbnail_video_dict.items()
        args = (run_thumbnail(v.get_path(), k, 128) for k, v in items if not Path(k).exists())
        await asyncio.gather(*args)

        end = perf_counter() - start
        print(f"Thumbnailer finished in {end:0.2f} seconds.")

        thumbnail_video_dict.clear()
        print(f"Thumbnail list clear...")

    def update_selection(grid_view):
        '''___update list model item selection when list view is updated___'''

        #set_view_parent_path(grid_view)
        grid_view.grab_focus()

        if len(list(thumbnail_video_dict)) > 0:
            Thread(target=asyncio.run, args=[video_thumbnail()]).start()

        if len(list(thumbnail_image_dict)) > 0:
            Thread(target=asyncio.run, args=[image_thumbnail()]).start()

    def update_view(paned_store, g_file, x_hidden_files):
        '''___update list view when path is changed___'''

        dir_list = get_dir_list()
        count = 0
        if Path(g_file.get_path()).is_dir():
            g_enum = g_file.enumerate_children('*', Gio.FileQueryInfoFlags.NONE)
            sorted_list = sort_func(g_enum)
            start_time = time()
        else:
            sorted_list = [g_file.query_info('*', Gio.FileQueryInfoFlags.NONE, None)]

        if sorted_list == []:
            dir_list.set_file(g_file)
        else:
            for x_info in sorted_list:
                count += 1
                x_file = g_enum.get_child(x_info)
                timeout_info = GLib.timeout_add(count, get_file_info, paned_store, dir_list, x_file, x_info, x_hidden_files)
                timeout_list.append(timeout_info)

                if x_info.get_content_type() in video_mime_types:
                    out_file = f'{sw_fm_cache_thumbnail}/{x_file.get_path().replace("/", "")}.png'
                    thumbnail_video_dict[f'{out_file}'] = x_file

                if x_info.get_content_type() in image_mime_types:
                    out_file = f'{sw_fm_cache_thumbnail}/{x_file.get_path().replace("/", "")}'
                    thumbnail_image_dict[out_file] = x_file

    def cb_btn_back_up(self):
        '''___return to the parent directory when user activated___'''

        return back_up()

    def timeout_list_clear(args):
        '''___terminate all glib timeout process___'''

        if args is None:
            for t in timeout_list:
                GLib.Source.remove(t)
            else:
                timeout_list.clear()
        elif len(args) == 1:
                Glib.Source.remove(args)
                timeout_list.remove(args)
        elif len(args) > 1:
            for t in args:
                Glib.Source.remove(t)
                timeout_list.remove(t)
        else:
            pass

    def on_walk_path(self, x_path, x_type):

        g_file = Gio.File.new_for_commandline_arg(x_path)
        timeout_list_clear(None)

        if not reveal_stack.get_visible_child() == files_view_grid:
            on_files(x_path)

        elif x_type == 'uri':
            update_grid_view_uri(x_path)
        else:
            update_grid_view(g_file.get_path())

    def update_path(x_path):
        '''___update entry path button when path is chaged___'''

        len_cur_path = len(Path(entry_path.get_name()).parts)
        for p in range(len_cur_path*2):
            child = box_scrolled.get_last_child()
            try:
                box_scrolled.remove(child)
            except:
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

    def cb_btn_home(self):
        '''___return to the home directory when user activated___'''

        return on_home()

    def on_home():
        '''___go to the home directory___'''

        path = Path.home()
        on_files(path)

        terminal.feed_child(
                        f'cd "{str(path)}" && clear\n'.encode("UTF-8")
                        )

    def cb_btn_view_more(self):
        '''___activate headerbar context menu for current path___'''
        x = 0
        y = 32
        parent_path = get_parent_path()
        on_empty_context(x, y, self, parent_path)

    def cb_btn_view_header_menu(self):
        '''___activate headerbar context header menu___'''
        x = 0
        y = 32
        parent_path = get_parent_path()
        on_empty_context(x, y, self, parent_path)

    def on_btn_header_menu(action_name, parameter, data):
        '''___activate header menu button___'''

        if action_name.get_name() == (
                                ctx_dict['show_hidden_files'][0].replace(' ', '')
            ):
            return on_files_view_props('hidden_files', None)

        if action_name.get_name() == (
                                ctx_dict['sorting_by_type'][0].replace(' ', '')
            ):
            return on_files_view_props('sorting_files', 'type')

        if action_name.get_name() == (
                                ctx_dict['sorting_by_size'][0].replace(' ', '')
            ):
            return on_files_view_props('sorting_files', 'size')

        if action_name.get_name() == (
                                ctx_dict['sorting_by_date'][0].replace(' ', '')
            ):
            return on_files_view_props('sorting_files', 'date')

        if action_name.get_name() == (
                                ctx_dict['sorting_by_name'][0].replace(' ', '')
            ):
            return on_files_view_props('sorting_files', 'name')

        if action_name.get_name() == (
                                ctx_dict['sorting_reverse'][0].replace(' ', '')
            ):
            return on_files_view_props('sorting_reverse', None)

        if action_name.get_name() == (
                                    ctx_dict['global_settings'][0].replace(' ', '')
            ):
            return on_global_settings()

        if action_name.get_name() == (
                                    ctx_dict['show_hotkeys'][0].replace(' ', '')
            ):
            return on_show_hotkeys()

        if action_name.get_name() == (
                                    ctx_dict['about'][0].replace(' ', '')
            ):
            return on_about()

        if action_name.get_name() == (
                                    ctx_dict['help'][0].replace(' ', '')
            ):
            return on_webview(home_page + '/StartWine-Launcher')

        if action_name.get_name() == (
                                    ctx_dict['shutdown'][0].replace(' ', '')
                                    + f'{sw_program_name}'
            ):
            on_shutdown()

    def on_files_view_props(prop_name, prop_value):
        '''___set files view properties___'''

        dict_ini = read_menu_conf()

        if prop_value is None:
            if dict_ini[prop_name] == 'True':
                dict_ini[prop_name] = 'False'
            else:
                dict_ini[prop_name] = 'True'
        else:
            dict_ini[prop_name] = prop_value

        write_menu_conf(dict_ini)
        parent_file = get_parent_file()
        if parent_file.get_path() is not None:
            try:
                update_grid_view(parent_file.get_path())
            except PermissionError as e:
                overlay_info(overlay, None, e, None, 3)
        else:
            try:
                update_grid_view_uri(parent_file.get_uri())
            except PermissionError as e:
                overlay_info(overlay, None, e, None, 3)

    def back_up():
        '''___return to the parent directory when user activated___'''

        parent_file = get_parent_file()
        if parent_file.get_path() is None:
            if parent_file.get_parent() is not None:
                uri = parent_file.get_parent().get_uri()
                update_grid_view_uri(uri)
            else:
                on_files(sw_default_dir)
        else:
            if parent_file.get_parent() is not None:
                on_files(Path(parent_file.get_parent().get_path()))

    def cb_btn_back_main(self):
        '''___sidebar back to main menu___'''

        on_back_main()

    def on_back_main():
        '''___sidebar back to main menu___'''

        if main_stack.get_visible_child() == scrolled_startapp_page:
            main_stack.set_visible_child(reveal_stack)

        btn_back_main.set_visible(False)
        stack_sidebar.set_visible_child(frame_main)

        if reveal_stack.get_visible_child() != files_view_grid:
            current_path = get_parent_file().get_path()
            return on_files(current_path)

    def cb_btn_main(self):
        '''___main buttons signal handler___'''

        if self.get_name() == btn_dict['shortcuts']:
            return on_shortcuts()

        if self.get_name() == btn_dict['create_shortcut']:
            return on_create_shortcut()

        if self.get_name() == btn_dict['prefix_tools']:
            return on_prefix_tools()

        if self.get_name() == btn_dict['wine_tools']:
            return on_wine_tools()

        if self.get_name() == btn_dict['install_launchers']:
            return on_install_launchers()

        if self.get_name() == btn_dict['settings']:
            return on_settings()

        if self.get_name() == btn_dict['debug']:
            return on_debug()

        if self.get_name() == btn_dict['stop']:
            return on_stop()

        if self.get_name() == btn_dict['about']:
            return on_about()

    def cb_btn_start_settings(self):
        '''___show settings menu ___'''
        on_settings()

    def on_show_hidden_widgets(widget_name):
        '''___show hidden widgets when expand menu___'''

        if widget_name is not None:
            try:
                next_name = next_vw_dict[widget_name]
            except:
                next_name = 'launch_settings'
            try:
                prev_name = prev_vw_dict[widget_name]
            except:
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
                    btn_popover_scale.set_visible(True)
                    btn_icon_position.set_visible(True)

        #read_parent_state()
        stack_search_path.set_visible(True)
        image_next.set_visible(True)
        btn_sidebar.set_visible(True)
        btn_back_up.set_visible(True)
        btn_home.set_visible(True)
        btn_more.set_visible(True)
        stack_progress_main.set_visible_child(stack_panel)
        stack_panel.set_visible(True)
        scrolled_winetricks.set_visible(True)
        wc_maximize.set_visible(True)
        progress_main.set_size_request(480, 20)

    def on_set_px_size(self):
        '''___updating list when user resize icons___'''

        timeout_list_clear(None)
        t = GLib.timeout_add(100, on_spin_update, self)
        timeout_list.append(t)

    def on_spin_update(self):

        parent_file = get_parent_file()
        if parent_file.get_path() is not None:
            update_grid_view(parent_file.get_path())
        else:
            update_grid_view_uri(parent_file.get_uri())

    def update_color_scheme():
        '''___update new widgets color scheme___'''

        global scheme

        if scheme == 'dark':
            css_provider.load_from_file(Gio.File.new_for_path(bytes(sw_css_dark)))
            Gtk.StyleContext.add_provider_for_display(
                                        display,
                                        css_provider,
                                        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )
        elif scheme == 'light':
            css_provider.load_from_file(Gio.File.new_for_path(bytes(sw_css_light)))
            Gtk.StyleContext.add_provider_for_display(
                                        display,
                                        css_provider,
                                        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )
        else:
            css_provider.load_from_file(Gio.File.new_for_path(bytes(sw_css_custom)))
            Gtk.StyleContext.add_provider_for_display(
                                        display,
                                        css_provider,
                                        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )
        set_define_colors()

    def update_bookmarks():
        '''___update bookmarks list view___'''

        swgs.bookmarks_store.remove_all()
        bookmarks_list = get_bookmark_list()

        for b in bookmarks_list:
            gtk_str = Gtk.StringObject.new(b)
            swgs.bookmarks_store.append(gtk_str)

    def on_shortcuts():
        '''___show shortcuts list view___'''

        timeout_list_clear(None)
        on_show_hidden_widgets(vw_dict['shortcuts'])
        update_grid_view(sw_shortcuts)

        if stack_sidebar.get_visible_child() != frame_main:
            btn_back_main.set_visible(False)
            stack_sidebar.set_visible_child(frame_main)

        reveal_stack.set_visible_child(files_view_grid)

        scrolled_left_files.set_min_content_width(width*0.2)
        scrolled_left_files.set_min_content_height(240)
        scrolled_right_files = paned_grid_view.get_end_child()
        if scrolled_right_files is not None:
            scrolled_right_files.set_min_content_width(width*0.2)
            scrolled_right_files.set_min_content_height(240)

        update_color_scheme()

    def on_startapp_page():
        '''___show start app page___'''

        _image_btn_start = Gtk.Image(css_name='sw_image')
        _image_btn_start.set_from_file(IconPath.icon_playback)

        _image_start_settings = Gtk.Image(css_name='sw_image')
        _image_start_settings.set_from_file(IconPath.icon_settings)

        _image_stop = Gtk.Image(css_name='sw_image')
        _image_stop.set_from_file(IconPath.icon_clear)

        _label_btn_start = Gtk.Label(css_name='sw_label')
        _label_btn_start.set_label(btn_dict['start'])

        _box_btn_start = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        _box_btn_start.set_halign(Gtk.Align.CENTER)
        _box_btn_start.set_spacing(8)
        _box_btn_start.append(_label_btn_start)
        _box_btn_start.append(_image_btn_start)

        _btn_stop = Gtk.Button(
                                css_name='sw_button',
                                name=btn_dict['stop'],
                                tooltip_markup=msg.tt_dict['stop'],
                                valign=Gtk.Align.END,
                                child=_image_stop,
        )
        #btn_stop.connect('clicked', cb_btn_main)

        _btn_start = Gtk.Button(
                                css_name='sw_button',
                                width_request=240,
                                valign=Gtk.Align.END,
        )
        _btn_start.set_vexpand(True)
        _btn_start.set_child(_box_btn_start)
        #_btn_start.connect('clicked', cb_btn_start)

        _btn_settings = Gtk.Button(
                                css_name='sw_button',
                                name=btn_dict['settings'],
                                valign=Gtk.Align.END,
                                tooltip_markup=msg.tt_dict['settings'],
                                child=_image_start_settings
        )
        #btn_start_settings.connect('clicked', cb_btn_start_settings)

        label_startapp = Gtk.Label(
                                css_name='sw_label_title',
                                xalign=0.0,
                                margin_start=16,
                                margin_top=16,
                                valign=Gtk.Align.START,
        )
        label_startapp.add_css_class('font_size_18')

        image_title = Gtk.Picture(css_name='sw_picture')
        image_title.set_hexpand(True)
        image_title.set_vexpand(True)
        image_title.add_css_class('stub')
        image_title.set_size_request(-1,(swgs.width/96)*31)

#        image_subtitle = SwPicture(css_name='sw_picture')
#        image_subtitle.set_hexpand(True)
#        image_subtitle.set_vexpand(True)
#        image_subtitle.set_effects(['blur', 'reverse'])

        box_control = Gtk.Box(
                            css_name='sw_action_row', spacing=8,
                            hexpand=True, vexpand=True, valign=Gtk.Align.END,
                            orientation=Gtk.Orientation.HORIZONTAL
        )
        box_control.append(_btn_stop)
        box_control.append(_btn_start)
        box_control.append(_btn_settings)

        grid_title = Gtk.Grid(css_name='sw_grid', vexpand=True, hexpand=True)
        grid_title.set_row_spacing(8)
        grid_title.set_column_spacing(8)
        grid_title.attach(label_startapp,0,0,1,1)
        grid_title.attach(box_control, 0,1,1,1)
        grid_title.add_css_class('shadow')

        grid_button = Gtk.Grid(css_name='sw_grid', vexpand=True, hexpand=True,
                                margin_start=32, margin_end=32, margin_top=32, margin_bottom=32,
                                valign=Gtk.Align.CENTER, halign=Gtk.Align.CENTER,
                                row_spacing=8, column_spacing=32,
        )
        for i in range(4):
            btn0 = Gtk.Button(css_name='sw_button', label=f'button_{i}', hexpand=True, width_request=320)
            btn1 = Gtk.Button(css_name='sw_button', label=f'button_{i}', hexpand=True, width_request=320)
            grid_button.attach(btn0, 0,i,1,1)
            grid_button.attach(btn1, 1,i,1,1)

        box_text = Gtk.Box(
                        css_name='sw_box', orientation=Gtk.Orientation.VERTICAL,
                        halign=Gtk.Align.START, valign=Gtk.Align.START, vexpand=True, hexpand=True, spacing=4,
                        margin_start=16, margin_end=16, margin_top=48, margin_bottom=16,
        )
        for t in range(4):
            text = Gtk.Label(css_name='sw_label', label=f'если [ дважды два равно {t} ];\n\tтогда sudo rm -rf $мозг\nиначе')
            box_text.append(text)

        text_ = Gtk.Label(css_name='sw_label', label=f'дважды два равно 4\nexport мозг=1\nфи\nвернуть $мозг')
        box_text.append(text_)

        overlay_title = Gtk.Overlay()
        overlay_title.set_child(image_title)
        overlay_title.add_overlay(grid_title)
        overlay_title.add_overlay(box_text)

        box_button = Gtk.Box(css_name='sw_box', vexpand=True, hexpand=True)
        box_button.append(grid_button)
#        box_button.set_effects(['blur', 'reverse'])

        grid_content = Gtk.Grid(css_name='sw_grid', vexpand=True, hexpand=True)
        grid_content.attach(overlay_title, 0,0,1,1)
        grid_content.attach(box_button, 0,1,1,1)

        set_heroes_icon(get_out(), get_app_path(), image_title, label_startapp)
        #set_heroes_icon(get_out(), None, box_button, None)
        scrolled_startapp_page.set_child(grid_content)

        btn_back_main.set_visible(True)
        main_stack.set_visible_child(scrolled_startapp_page)

        #image_title.add_tick_callback(on_box_control_resize)

    def on_box_control_resize(self, frame_clock):
        self.set_size_request(-1, (swgs.width/96)*31)
        return True

    def context_connect(menu_x, context_x, data_x, count):
        '''___connect context menu items to a callback function___'''

        for a in context_x:
            count +=1
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
            except Exception as e:
                accel_for_action = None

            swgs.set_accels_for_action(
                f'app.{action_type}',
                [accel_for_action],
            )
            action_list.append(f'app.{action_type}')

        context_x.clear()

    def on_empty_context(x, y, widget, parent_path):
        '''___right click on empty place in list view___'''

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

        context_dir = [
            {
            'name': ctx_dict['create_dir'][0],
            'func': on_cb_empty_create_dir,
            'accel': ctx_dict['create_dir'][1],
            },
        ]
        context_edit = [
            {
            'name': ctx_dict['paste'][0],
            'func': on_cb_empty_paste,
            'accel': ctx_dict['paste'][1]
            },
            {
            'name': ctx_dict['select_all'][0],
            'func': on_cb_empty_select_all,
            'accel': ctx_dict['select_all'][1]
            },
        ]
        context_property = [
            {'name': ctx_dict['properties'][0], 'func': on_cb_empty_properties},
        ]
        context_create = [
            {'name': ctx_dict['txt'], 'func': on_cb_empty_create_file},
            {'name': ctx_dict['sh'], 'func': on_cb_empty_create_file},
            {'name': ctx_dict['py'], 'func': on_cb_empty_create_file},
            {'name': ctx_dict['desktop'], 'func': on_cb_empty_create_file},
        ]
        context_more = [
            {'name': ctx_dict['copy_path'], 'func': on_cb_empty_copy_path},
            {'name': ctx_dict['add_bookmark'], 'func': on_cb_empty_add_bookmark},
        ]
        context_file_props = [
            {
            'name': ctx_dict['show_hidden_files'][0],
            'accel': ctx_dict['show_hidden_files'][1],
            'func': on_btn_header_menu
            },
            {
            'name': ctx_dict['sorting_by_type'][0],
            'accel': ctx_dict['sorting_by_type'][1],
            'func': on_btn_header_menu
            },
            {
            'name': ctx_dict['sorting_by_size'][0],
            'accel': ctx_dict['sorting_by_size'][1],
            'func': on_btn_header_menu
            },
            {
            'name': ctx_dict['sorting_by_date'][0],
            'accel': ctx_dict['sorting_by_date'][1],
            'func': on_btn_header_menu
            },
            {
            'name': ctx_dict['sorting_by_name'][0],
            'accel': ctx_dict['sorting_by_name'][1],
            'func': on_btn_header_menu
            },
            {
            'name': ctx_dict['sorting_reverse'][0],
            'accel': ctx_dict['sorting_reverse'][1],
            'func': on_btn_header_menu
            },
        ]
        context_header_menu = [
            {
            'name': ctx_dict['global_settings'][0],
            'accel': ctx_dict['global_settings'][1],
            'func': on_btn_header_menu
            },
            {
            'name': ctx_dict['show_hotkeys'][0],
            'accel': ctx_dict['show_hotkeys'][1],
            'func': on_btn_header_menu
            },
            {
            'name': ctx_dict['about'][0],
            'accel': ctx_dict['about'][1],
            'func': on_btn_header_menu
            },
            {
            'name': ctx_dict['help'][0],
            'accel': ctx_dict['help'][1],
            'func': on_btn_header_menu
            },
        ]
        context_shutdown = [
            {
            'name': ctx_dict['shutdown'][0] + f' {sw_program_name}',
            'accel': ctx_dict['shutdown'][1],
            'func': on_btn_header_menu
            },
        ]
        rect = Gdk.Rectangle()
        rect.x = x
        rect.y = y
        rect.width = 0
        rect.height = 0

        menu_create = Gio.Menu()
        section_edit = Gio.Menu()
        section_property = Gio.Menu()
        section_more = Gio.Menu()
        section_file_props = Gio.Menu()
        section_header_menu = Gio.Menu()
        section_shutdown = Gio.Menu()

        context_menu = Gtk.PopoverMenu(css_name='sw_popovermenu')
        context_menu.set_has_arrow(False)
        context_menu.set_position(Gtk.PositionType.BOTTOM)
        context_menu.set_pointing_to(rect)
        context_menu.set_name('empty_context_menu')
        context_menu.set_parent(widget)

        if widget.get_name() == 'header_menu':
            gmenu = Gio.Menu()
            gmenu.insert_section(1, None, section_header_menu)
            gmenu.append_section(None, section_shutdown)

            context_connect(section_header_menu, context_header_menu, parent_path, 0)
            context_connect(section_shutdown, context_shutdown, parent_path, 0)
            context_menu.set_menu_model(gmenu)
        else:
            menu.append_section(None, section_more)
            context_connect(section_more, context_more, parent_path, 0)

            menu.insert_submenu(0, ctx_dict['sort'], section_file_props)
            context_connect(section_file_props, context_file_props, parent_path, 0)

            menu.insert_submenu(1, ctx_dict['create'], menu_create)
            menu.append_section(None, section_edit)
            menu.append_section(None, section_property)

            context_connect(menu, context_dir, parent_path, 1)
            context_connect(menu_create, context_create, parent_path, 0)
            context_connect(section_edit, context_edit, parent_path, 0)
            context_connect(section_property, context_property, parent_path, 0)

            context_menu.set_menu_model(menu)

        scrolled = context_menu.get_first_child().get_first_child()
        scrolled.set_propagate_natural_height(True)
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.NEVER)

        context_menu.popup()

        context_dir.clear()
        context_create.clear()
        context_edit.clear()
        context_property.clear()
        context_header_menu.clear()

        return context_menu

    def on_cb_empty_copy_path(action_name, parameter, data):
        '''___callback context button copy current path___'''

        x_file = Gio.File.new_for_commandline_arg(bytes(Path(data)))
        on_file_copy([x_file])

    def on_cb_empty_add_bookmark(action_name, parameter, data):
        '''___callback context button add current path to bookmark___'''

        return on_add_bookmark(data)

    def on_add_bookmark(data):
        '''___add new bookmark button in bookmarks menu___'''
        d = data
        try:
            r = sw_bookmarks.read_text()
            s = r.splitlines()
        except IOError as e:
            return overlay_info(overlay, None, e, None, 3)
        else:
            for x in s:
                if x == d:
                    d = None
            else:
                if d is not None:
                    try:
                        s.append(d)
                        sw_bookmarks.write_text('\n'.join(s))
                    except IOError as e:
                        return overlay_info(overlay, None, e, None, 3)
                    else:
                        update_bookmarks()
                        text_message = str_create_new_bookmark
                        print(f'{tc.VIOLET2}SW_BOOKMARKS: {tc.GREEN}write new bookmark: done' + tc.END)
                        return overlay_info(overlay, None, text_message, None, 3)
                else:
                    text_message = str_bookmark_exists
                    return overlay_info(overlay, None, text_message, None, 3)

    def cb_btn_remove_bookmark(self):
        '''___remove bookmark button from bookmarks menu___'''

        try:
            r = sw_bookmarks.read_text()
        except IOError as e:
            return overlay_info(overlay, None, e, None, 3)
        else:
            try:
                s = r.splitlines()
                s.remove(self.get_name())
                sw_bookmarks.write_text('\n'.join(s))
            except IOError as e:
                return overlay_info(overlay, None, e, None, 3)
            else:
                update_bookmarks()
                text_message = str_remove_bookmark
                print(f'{tc.VIOLET2}SW_BOOKMARKS: {tc.GREEN}remove bookmark: done' + tc.END)
                return overlay_info(overlay, None, text_message, None, 3)

    def on_cb_empty_create_file(action_name, parameter, data):
        '''___callback context button create file___'''

        if Path(data) == Path(sw_shortcuts):
            text_message = msg.msg_dict['impossible_create']
            return overlay_info(overlay, None, text_message, None, 3)

        elif Path(data) == Path(sw_launchers):
            text_message = msg.msg_dict['impossible_create']
            return overlay_info(overlay, None, text_message, None, 3)

        else:
            if action_name.props.name == ctx_dict['txt'].replace(' ', ''):
                on_create_file(f'{str_sample}', f'.txt', None)

            if action_name.props.name == ctx_dict['sh'].replace(' ', ''):
                on_create_file(f'{str_sample}', f'.sh', sample_bash)

            if action_name.props.name == ctx_dict['py'].replace(' ', ''):
                on_create_file(f'{str_sample}', f'.py', sample_python)

            if action_name.props.name == ctx_dict['desktop'].replace(' ', ''):
                on_create_file(f'{str_sample}', f'.desktop', sample_desktop)

    def on_create_file(name, ext, sample):
        '''___create new file___'''

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
            dialog_info(text_message=str(e.message), message_type='ERROR').run()
        else:
            if sample is not None:
                try:
                    with open(x_path, 'w') as x:
                        x.write(sample)
                        x.close()
                except IOError as e:
                    print(e)
                    strerr = msg.msg_dict['does_not_exist']
                    dialog_info(text_message=strerr, message_type='ERROR').run()

    def on_cb_empty_create_dir(action_name, parameter, parent_path):
        '''___callback on context button for create directory___'''

        if Path(parent_path) == Path(sw_shortcuts):
            text_message = msg.msg_dict['impossible_create']
            return overlay_info(overlay, None, text_message, None, 3)

        elif Path(parent_path) == Path(sw_launchers):
            text_message = msg.msg_dict['impossible_create']
            return overlay_info(overlay, None, text_message, None, 3)

        else:
            return on_create_dir()

    def on_create_dir():
        '''___create new directory___'''

        def create_dir(src):
            '''___create new directory___'''

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
                dialog_info(text_message=str(e.message), message_type='ERROR').run()

        parent_file = get_parent_file()
        if parent_file.get_path() is None:
            src = parent_file.get_uri()
        else:
            src = parent_file.get_path()

        title = msg.msg_dict['create_dir'].capitalize()
        text_message = [msg.msg_dict['new_dir'].capitalize()]
        button_name = msg.msg_dict['create'].capitalize()
        func = [(create_dir, (src,)), None]
        dialog = dialog_entry(swgs, title, text_message, button_name, func, 1, None)
        entry_name = dialog.get_child().get_first_child()

    def on_cb_empty_paste(action_name, parameter, data):
        '''___activate context menu button paste___'''

        return on_file_paste()

    def on_cb_empty_select_all(action_name, parameter, data):
        '''___callback context button select all___'''

        grid_view = get_list_view()
        grid_view.get_model().select_all()

    def on_cb_empty_properties(action_name, parameter, data):
        '''___get current directory properties___'''

        on_file_properties()

        if data is None:
            x_file = get_parent_uri()
        else:
            x_file = Gio.File.new_for_commandline_arg(bytes(Path(data)))

        get_file_props(x_file)

    def on_file_context(x, y, grid_view, x_files):
        '''___build and connect file context menu___'''

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
            {'name': ctx_dict['run'], 'func': on_cb_file_exe},
        ]
        context_open_location = [
            {'name': ctx_dict['open_location'], 'func': on_cb_file_open_location},
        ]
        context_open_with = [
            {'name': ctx_dict['open_with'], 'func': on_cb_file_open_with},
        ]
        context_run = [
            {'name': ctx_dict['run'], 'func': on_cb_file_run},
            {'name': ctx_dict['open'], 'func': on_cb_file_open},
        ]
        context_open = [
            {'name': ctx_dict['open'], 'func': on_cb_file_open},
        ]
        context_edit = [
            {'name': ctx_dict['cut'][0], 'func': on_cb_file_cut, 'accel': ctx_dict['cut'][1]},
            {'name': ctx_dict['copy'][0], 'func': on_cb_file_copy, 'accel': ctx_dict['copy'][1]},
            {'name': ctx_dict['rename'][0], 'func': on_cb_file_rename, 'accel': ctx_dict['rename'][1]},
            {'name': ctx_dict['link'][0], 'func': on_cb_file_link, 'accel': ctx_dict['link'][1]},
            {'name': ctx_dict['compress'], 'func': on_cb_file_compress},
        ]
        context_remove = [
            {'name': ctx_dict['trash'][0], 'func': on_cb_file_remove, 'accel': ctx_dict['trash'][1]},
            {'name': ctx_dict['remove'][0], 'func': on_cb_file_remove, 'accel': ctx_dict['remove'][1]},
        ]
        context_property = [
            {'name': ctx_dict['properties'][0], 'func': on_cb_file_properties},
        ]
        context_dir = [
            {'name': ctx_dict['open'], 'func': on_cb_dir_open},
        ]
        rect = Gdk.Rectangle()
        rect.x = x
        rect.y = y
        rect.width = 1
        rect.height = 1

        section_open = Gio.Menu()
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
        context_menu.set_name('file_context_menu')
        context_menu.set_parent(grid_view)

        file_info = x_files[0].query_info(
                                    '*',
                                    Gio.FileQueryInfoFlags.NONE,
                                    None,
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

    def on_content_changed(self, data):
        '''___paste content from clipboard___'''

        replace_source = list()
        copy_source = list()
        copy_target = list()
        cut_source = list()
        cut_target = list()
        parent_file = get_parent_file()

        if (parent_file.get_path() is not None and data[1].get_files()[0].get_path() is not None):
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
                        dialog_info(text_message=text_message, message_type='INFO').run()
                else:
                    if len(replace_source) > 0:
                        str_source = str('\n'.join(sorted(replace_source)))
                        title = msg.msg_dict['replace_file']
                        message = [msg.msg_dict['replace_override'], f'{str_source}']
                        func = [{move_replace : (parent_path, replace_source)}, None]
                        dialog_question(swgs, title, message, None, func)

                    if len(cut_source) > 0:
                        for s, t in zip(cut_source, cut_target):
                            Thread(target=run_move, args=(s, t,)).start()
                            GLib.timeout_add(100, on_copy_move_progress, s, t)

            elif data[0] == 'is_copy':
                for f in data[1].get_files():
                    source = Path(f.get_path())
                    target = Path(f'{parent_path}/{source.name}')

                    if (source != target
                        and source != Path(parent_path)):
                            if (target.exists()
                                and source.name == target.name):
                                    replace_source.append(str(source))
                            else:
                                copy_source.append(source)
                                copy_target.append(target)

                    elif (source == target
                        and source != Path(parent_path)):
                            target = Path(f'{parent_path}/{str_copy}_{source.name}')
                            count = int()
                            while target.exists():
                                count += 1
                                target = Path(f'{parent_path}/{str_copy}{count}_{source.name}')

                            copy_source.append(source)
                            copy_target.append(target)
                    else:
                        text_message = msg.msg_dict['equal_paths']
                        dialog_info(text_message=text_message, message_type='INFO').run()
                else:
                    if len(replace_source) > 0:
                        str_source = str('\n'.join(sorted(replace_source)))
                        title = msg.msg_dict['replace_file']
                        message = [msg.msg_dict['replace_override'], f'{str_source}']
                        func = [{copy_replace : (parent_path, replace_source)}, None]
                        dialog_question(swgs, title, message, None, func)

                    if len(copy_source) > 0:
                        for s, t in zip(copy_source, copy_target):
                            Thread(target=run_copy, args=[s, t]).start()
                            GLib.timeout_add(100, on_copy_move_progress, s, t)
            else:
                pass
        else:
            on_uri_changed(data)

    def get_dir_size(size, data):
        '''___get size of files in current directory___'''

        s_list = list()

        for root, dirs, files in walk(data):
            for f in files:
                try:
                    size += Stat(join(root, f)).st_size
                except:
                    pass
                else:
                    s_list.append(size)
        else:
            return s_list

    def run_copy(source, target):
        '''___run copy file in thread___'''

        if Path(source).is_file() or Path(source).is_symlink():
            if (target.exists() and source.name == target.name):
                Path(target).unlink()
                shutil.copy2(source, target, follow_symlinks=False)
            else:
                shutil.copy2(source, target, follow_symlinks=False)

        elif Path(source).is_dir():
            shutil.copytree(source, target, symlinks=True, dirs_exist_ok=True)
        else:
            raise ValueError(f'{tc.RED}file {source} is not a file or directory{tc.END}')

    def run_move(source, target):
        '''___run copy file in thread___'''

        if Path(source).is_symlink():
            shutil.move(source, target)

        elif Path(source).is_file():
            shutil.move(source, target)

        elif Path(source).is_dir():
            shutil.copytree(source, target, symlinks=True, dirs_exist_ok=True)
            shutil.rmtree(source)
        else:
            raise ValueError(f'{tc.RED}file {source} is not a file or directory{tc.END}')

    def move_replace(parent_path, replace_source):
        '''___replace files on dialog response___'''

        for r in replace_source:
            s = Path(r)
            t = Path(f'{parent_path}/{s.name}')
            Thread(target=run_move, args=(s, t,)).start()
            GLib.timeout_add(100, on_copy_move_progress, s, t)

    def copy_replace(parent_path, replace_source):
        '''___replace files on dialog response___'''

        for r in replace_source:
            s = Path(r)
            t = Path(f'{parent_path}/{s.name}')
            Thread(target=run_copy, args=[s, t]).start()
            GLib.timeout_add(100, on_copy_move_progress, s, t)

    def on_copy_move_progress(source, target):
        '''___progress copy file in thread___'''

        if Path(source).is_symlink():
            s_size = Stat(source).st_size
            try:
                t_size = Stat(target).st_size
            except:
                t_size = 0

        elif Path(source).is_file():
            s_size = Stat(source).st_size
            try:
                t_size = Stat(target).st_size
            except:
                t_size = 0

        elif (Path(source).is_dir()
            and len(list(Path(source).iterdir())) >= 1):
                s_size = get_dir_size(0, source)[-1]
                try:
                    t_size = get_dir_size(0, target)[-1]
                except:
                    t_size = 0
        else:
            raise ValueError(f'{tc.RED}file {source} is not a file or directory{tc.END}')

        if t_size < s_size:
            percent = round(t_size / s_size, 2)
            stack_progress_main.set_visible_child(progress_main_grid)
            progress_main.set_visible(True)
            progress_main.set_show_text(True)
            progress_main.set_text(f'{str_copying} {Path(source).name} {percent*100}%')
            progress_main.set_fraction(percent)
            environ['FRAGMENT_NUM'] = f'{len(fragments_list) - 1}'
            return True

        elif t_size >= s_size:
            progress_main.set_fraction(0.0)
            progress_main.set_show_text(False)
            progress_main.set_visible(False)
            stack_progress_main.set_visible_child(stack_panel)
            overlay_info(overlay, str_copying, msg.msg_dict['copy_completed'], None, 3)
            environ['FRAGMENT_NUM'] = getenv('FRAGMENT_INDEX')
            return False

    def on_delete_progress(start_size, source):
        '''___progress of deleting a files in a thread___'''

        if Path(source).exists():

            if Path(source).is_symlink():
                current_size = Stat(source).st_size

            elif Path(source).is_file():
                current_size = Stat(source).st_size

            elif (Path(source).is_dir()
                and len(list(Path(source).iterdir())) >= 1):
                    current_size = get_dir_size(0, source)[-1]
            else:
                raise ValueError(f'{tc.RED}file {source} is not a file or directory{tc.END}')

            if current_size > 0:
                percent = round(1 - (current_size / start_size), 2)
                stack_progress_main.set_visible_child(progress_main_grid)
                progress_main.set_visible(True)
                progress_main.set_show_text(True)
                progress_main.set_text(f'{str_deletion} {Path(source).name} {percent*100}%')
                progress_main.set_fraction(percent)
                return True

            elif current_size == 0:
                progress_main.set_fraction(0.0)
                progress_main.set_show_text(False)
                progress_main.set_visible(False)
                stack_progress_main.set_visible_child(stack_panel)
                overlay_info(overlay, str_deletion, msg.msg_dict['delete_completed'], None, 3)
                return False
        else:
            progress_main.set_fraction(0.0)
            progress_main.set_show_text(False)
            progress_main.set_visible(False)
            stack_progress_main.set_visible_child(stack_panel)
            overlay_info(overlay, str_deletion, msg.msg_dict['delete_completed'], None, 3)
            return False

    def on_file_run(g_file):
        '''___run a file from the context menu___'''

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
        '''___open a file from the context menu___'''

        fl = Gtk.FileLauncher()
        fl.set_file(g_file)
        try:
            fl.launch()
        except Exception as e:
            print(tc.RED, e , tc.END)

    def on_file_open_location(g_file):
        '''___open a file location from the context menu___'''

        path = g_file.get_path()
        if path is not None:
            on_files(Path(path).parent)

    def on_cb_file_exe(action_name, parameter, data):
        '''___run a x-ms-dos-executable file from the context menu___'''

        if data[0].get_path() is not None:
            environ['SW_EXEC'] = f'"{data[0].get_path()}"'
            write_app_conf(Path(data[0].get_path()))
            return on_start()
        else:
            return overlay_info(overlay, None, msg.msg_dict['action_not_supported'], None, 3)

    def on_cb_file_run(action_name, parameter, data):
        '''___run a x-executable file from the context menu___'''

        g_file = data[0]
        return on_file_run(g_file)

    def on_cb_file_open_location(action_name, parameter, data):
        '''___open a file from the context menu___'''

        g_file = data[0]
        on_file_open_location(g_file)

    def on_cb_file_open_with(action_name, parameter, data):
        '''___open a file with program from context menu___'''

        g_file = data[0]
        if g_file.get_path() is None:
            uri  = g_file.get_uri()
            on_uri_open_with(uri)
        else:
            on_file_open_with(g_file)

    def on_file_open_with(g_file):
        '''___open a file with program___'''

        fl = Gtk.FileLauncher()
        fl.set_always_ask(True)
        fl.set_file(g_file)
        try:
            fl.launch()
        except Exception as e:
            print(tc.RED, e , tc.END)

    def on_uri_open_with(uri):
        '''___open a file with program___'''

        ul = Gtk.UriLauncher()
        ul.set_uri(uri)
        try:
            ul.launch()
        except Exception as e:
            print(tc.RED, e , tc.END)

    def on_cb_file_open(action_name, parameter, data):
        '''___open a file from the context menu___'''

        g_file = data[0]
        if g_file.get_path() is None:
            uri  = g_file.get_uri()
            return on_uri_open_with(uri)
        else:
            return on_file_open(g_file)

    def on_cb_dir_open(action_name, parameter, data):
        '''___open a directory from the context menu___'''

        if data[0].get_path() is not None:
            file = Path(data[0].get_path()).name
            parent_file = get_parent_file()
            if parent_file.get_path() is not None:
                path = parent_file.get_path()
                on_files(Path(f'{path}/{file}'))
        else:
            item_uri = data[0].get_uri()
            update_grid_view_uri(item_uri)

    def on_cb_file_cut(action_name, parameter, data):
        '''___cut the selected file from the curent directory___'''

        if reveal_stack.get_visible_child() == files_view_grid:
            return on_file_cut(data)

    def on_file_cut(data):
        '''___cut the selected file from the curent directory___'''

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

    def on_cb_file_copy(action_name, parameter, data):
        '''___copy the selected file to the clipboard___'''

        if reveal_stack.get_visible_child() == files_view_grid:
            return on_file_copy(data)

    def on_file_copy(data):
        '''___copy the selected file to the clipboard___'''

        f_list = Gdk.FileList.new_from_list(data)
        clipboard.set(f_list)
        content = clipboard.get_content()
        content.connect('content-changed', on_content_changed, ['is_copy', f_list])

    def on_uri_changed(data):

        replace_source = list()
        replace_target = list()
        copy_source = list()
        copy_target = list()
        cut_source = list()
        cut_target = list()

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
                    '''___replace files on dialog response___'''

                    for s, t in zip(replace_source, replace_target):
                        try:
                            s.copy(t, Gio.FileCopyFlags.OVERWRITE,
                                    progress_callback=on_copy_uri_progress
                        )
                        except GLib.GError as e:
                            print(e.message)
                            dialog_info(text_message=str(e.message), message_type='ERROR').run()

                str_source = str(
                    '\n'.join(sorted([str(s.get_basename()) for s in replace_source])))
                title = msg.msg_dict['replace_file']
                message = [msg.msg_dict['replace_override'], f'\n{str_source}']
                func = [(paste_replace, [replace_source, replace_target]), None]
                dialog_question(swgs, title, message, None, func)

            if len(copy_source) > 0:
                for s, t in zip(copy_source, copy_target):
                    try:
                        s.copy(t, Gio.FileCopyFlags.NONE,
                                progress_callback=on_copy_uri_progress
                    )
                    except GLib.GError as e:
                        print(e.message)
                        dialog_info(text_message=str(e.message), message_type='ERROR').run()

    def on_copy_uri_progress(cur_bytes, total_bytes):
        print(cur_bytes/total_bytes)

    def on_file_paste():
        '''___get files for paste from clipboard___'''

        def read_text(self, res, data):
            '''___async reading non-local content from the clipboard___'''

            replace_source = list()
            copy_source = list()
            copy_target = list()
            result = self.read_text_finish(res)
            parent_file = get_parent_file()

            if parent_file.get_path() is not None:
                parent_path = parent_file.get_path()
                for r in result.splitlines():
                    source = Path(r)
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
                        func = [{copy_replace : (parent_path, replace_source)}, None]
                        dialog_question(swgs, title, message, None, func)

                    if len(copy_source) > 0:
                        for s, t in zip(copy_source, copy_target):
                            Thread(target=run_copy, args=[s, t]).start()
                            GLib.timeout_add(100, on_copy_move_progress, s, t)

        print(f'{tc.VIOLET2}CLIPBOARD: {tc.GREEN}is local {clipboard.is_local()}{tc.END}')

        if not clipboard.is_local():
            g_mimes = clipboard.get_formats().get_mime_types()
            clipboard.read_text_async(None, read_text, None)
        else:
            content = clipboard.get_content()
            content.content_changed()

    def on_cb_file_rename(action_name, parameter, data):
        '''___activate file rename button___'''

        if reveal_stack.get_visible_child() == files_view_grid:
            if len(data) > 1:
                return on_files_rename(data)
            else:
                return on_file_rename(data[0])

    def on_file_rename(x_file):
        '''___rename the selected file___'''

        def rename():
            '''___set new file name attribute___'''

            new_name = entry_rename.get_text()
            try:
                x_file.set_display_name(new_name)
            except GLib.GError as e:
                print(e.message)
                dialog_info(text_message=str(e.message), message_type='ERROR').run()

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
            dialog = dialog_entry(swgs, title, text_message, button_name, func, 1, None)
            entry_rename = dialog.get_child().get_first_child()

    def on_files_rename(x_files):
        '''___rename multiple files___'''

        def rename():
            '''___set a new name attribute for multiple files___'''

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

        title = (msg.msg_dict['rename'].capitalize()
                + f' {len(x_files)} '
                + msg.msg_dict['files'].lower()
                )
        text_message = [msg.msg_dict['original_name'].title() + '1, 2, 3...']
        button_name = msg.msg_dict['rename'].capitalize()
        func = [rename, None]
        dialog = dialog_entry(swgs, title, text_message, button_name, func, 1, None)
        entry_rename = dialog.get_child().get_first_child()

    def on_cb_file_link(action_name, parameter, data):
        '''___activate create link button___'''

        if reveal_stack.get_visible_child() == files_view_grid:
            return on_file_link(data)

    def on_file_link(x_path):
        '''___create file symbolic link___'''

        for x in x_path:
            if x.get_path() is not None:
                parent_path = Path(x.get_path()).parent
                link_path = Path(f'{parent_path}/{msg.msg_dict["file_link"]} {Path(x.get_path()).name}')
                x_file = Gio.File.new_for_path(bytes(link_path))
                x_file.make_symbolic_link(bytes(Path(x.get_path())))

    def on_cb_file_compress(action_name, parameter, data):
        '''___create a compressed archive from file or files___'''

        if reveal_stack.get_visible_child() == files_view_grid:
            return on_file_compress(data)

    def on_file_compress(data):
        '''___create a compressed archive___'''

        def create_archive():
            '''___create new file compressed archive___'''

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
        dialog = dialog_entry(swgs, title, text_message, button_name, func, 1, archive_formats)
        entry_name = dialog.get_child().get_first_child()
        dropdown = dialog.get_child().get_last_child()

    def zst_compress(x_path, data, archive_type):
        '''___create a zstd compressed archive___'''

        target = ' '.join([f'"{x.get_basename()}"' for x in data])

        if archive_type == 'zst':
            run(f"tar -I 'zstd -T0 -11 --progress' -cf '{x_path}.tar.zst' {target}", shell=True)
        else:
            run(f"tar -I 'zstd -T0 --ultra -22 --progress' -cf '{x_path}.tar.zst' {target}", shell=True)

    def tar_compress(x_path, data, archive_type):
        '''___create a gz, xz, bz2 compressed archive___'''

        with tarfile.open(f'{x_path}.tar.{archive_type}', f'w:{archive_type}') as tar:
            for file in data:
                tar.add(file.get_basename())
            else:
                tar.close()

    def zip_compress(x_path, data):
        '''___create a zip compressed archive___'''

        parent_path = x_path.parent
        with zipfile.ZipFile(f'{x_path}.zip','w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as fzip:
            for file in data:
                if Path(file.get_path()).is_dir():
                    for r, d, f in walk(file.get_path()):
                        for x in f:
                            fzip.write(f'{r}/{x}'.replace(f'{parent_path}/', ''))
                fzip.write(file.get_basename())
            else:
                fzip.close()

    def on_cb_file_remove(action_name, parameter, x_path):
        '''___activate context button and remove changed file___'''

        if action_name.props.name == ctx_dict['trash'][0].replace(' ', ''):
            if reveal_stack.get_visible_child() == files_view_grid:
                on_file_to_trash(x_path)

        elif action_name.props.name == ctx_dict['remove'][0].replace(' ', ''):
            if reveal_stack.get_visible_child() == files_view_grid:
                if x_path[0].get_path() is None:
                    on_uri_remove(x_path)
                else:
                    on_file_remove(x_path)

    def on_file_to_trash(x_path):
        '''___move selected file to trash___'''

        for x in x_path:
            try:
                x.trash()
            except GLib.GError as e:
                print(e.message)
                dialog_info(text_message=str(e.message), message_type='ERROR').run()
                break
        else:
            samples = f'{sw_sounds}/dialog/trash-empty.oga'
            if Path(samples).exists():
                try:
                    Thread(target=media_play, args=(media_file, samples,
                                                    media_controls, 0.35, False)
                                                    ).start()
                except:
                    pass

            return overlay_info(overlay, str_removal, msg.msg_dict['trash_completed'], None, 3)

    def on_file_remove(x_path):
        '''___delete selected files___'''

        def remove(x_path):
            '''___delete selected files on dialog response___'''

            for x in x_path:
                if (Path(x.get_path()).is_file()
                    or Path(x.get_path()).is_symlink()):
                        source = x.get_path()
                        try:
                            start_size = Stat(source).st_size
                        except Exception as e:
                            start_size = 0

                        Thread(target=x.delete).start()
                        GLib.timeout_add(100, on_delete_progress, start_size, source)

                elif Path(x.get_path()).is_dir():
                    source = Path(x.get_path())
                    if len(list(source.iterdir())) >= 1:
                        try:
                            start_size = get_dir_size(0, source)[-1]
                        except IndexError as e:
                            start_size = 0

                        Thread(target=shutil.rmtree, args=[source]).start()
                        GLib.timeout_add(100, on_delete_progress, start_size, source)
                    else:
                        start_size = 0
                        Thread(target=shutil.rmtree, args=[source]).start()
                        GLib.timeout_add(100, on_delete_progress, start_size, source)
            else:
                samples = f'{sw_sounds}/dialog/trash-empty.oga'
                if Path(samples).exists():
                    try:
                        Thread(target=media_play, args=(media_file, samples,
                                                        media_controls, 0.35, False
                                                        )).start()
                    except:
                        pass

        title = msg.msg_dict['remove']
        text_message = [
            msg.msg_dict['permanently_delete'],
            ' '.join([Path(x.get_path()).name for x in x_path]) + '?'
        ]
        func = [(remove, (x_path,)), None]
        dialog_question(swgs, title, text_message, None, func)

    def on_uri_remove(x_files):
        '''___delete selected files___'''

        for g_file in x_files:
            try:
                g_info = g_file.query_info('*', Gio.FileQueryInfoFlags.NONE)
            except GLib.GError as e:
                content_type = None
                print(e.message)
                return dialog_info(text_message=str(e.message), message_type='ERROR').run()
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
                        return dialog_info(text_message=str(e.message), message_type='ERROR').run()
                else:
                    try:
                        g_file.delete()
                    except GLib.GError as e:
                        print(e.message)
                        return dialog_info(text_message=str(e.message), message_type='ERROR').run()
            else:
                try:
                    g_file.delete()
                except GLib.GError as e:
                    print(e.message)
                    return dialog_info(text_message=str(e.message), message_type='ERROR').run()

    def on_cb_file_properties(action_name, parameter, data):
        '''___activate file properties button___'''

        on_file_properties()

        if len(data) > 1:
            get_file_props_list(data)
        else:
            get_file_props(data[0])

    def  on_switch_file_exec(self, state):
        '''___switch file execute property___'''

        p = Path(swgs.switch_file_execute.get_name())
        f = Gio.File.new_for_commandline_arg(bytes(p))
        i = f.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
        e = i.get_attribute_as_string('access::can-execute')

        if self.get_active():

            if e == 'FALSE':
                mode = p.stat().st_mode
                p.chmod(0o755)
        else:
            if e == 'TRUE':
                mode = p.stat().st_mode
                p.chmod(0o644)

    def get_allocated_size(size, data, label):
        '''___get size of files in current directory___'''

        size_list = list()
        t = GLib.timeout_add(100, set_allocated_size, size_list, label)

        for root, dirs, files in walk(data):
            for f in files:
                try:
                    size += Stat(join(root, f)).st_size
                except:
                    pass
                else:
                    size_list.append(size)

    def set_allocated_size(size_list, label):
        '''___set file size info to label___'''

        if len(size_list) >= 1:
            size = int(size_list[-1])

            if len(str(round(size, 2))) <= 6:
                str_size = f'{str(round(size/1024, 2))} Kib / {str(round(size/1000, 2))} Kb'

            elif 6 < len(str(round(size, 2))) <= 9:
                str_size = f'{str(round(size/1024**2, 2))} Mib / {str(round(size/1000**2, 2))} Mb'

            elif len(str(round(size, 2))) > 9:
                str_size = f'{str(round(size/1024**3, 2))} Gib / {str(round(size/1000**3, 2))} Gb'

            label.set_label(str_size)
            size_list.clear()
            return True

        return False

    def get_disk_usage(data):
        '''___get size of the current partition___'''

        partitions = psutil.disk_partitions()

        if data is not None:
            data_path = data.get_path()

            for x in sorted(partitions):
                if x.mountpoint in data_path:
                    mountpoint = x.mountpoint
            try:
                fs_size = psutil.disk_usage(mountpoint).total
            except Exception as e:
                fs_size = msg.msg_dict['unknown']
                fmt_size = msg.msg_dict['unknown']
            else:
                fmt_size = GLib.format_size(int(fs_size))
            try:
                fs_free = psutil.disk_usage(mountpoint).free
            except Exception as e:
                fs_free = msg.msg_dict['unknown']
                fmt_free = msg.msg_dict['unknown']
            else:
                fmt_free = GLib.format_size(int(fs_free))

            fmt_all = (
                        f"{msg.msg_dict['free']} {fmt_free} / "
                        +f"{msg.msg_dict['total']} {fmt_size}"
            )
            swgs.label_disk_size.set_label(fmt_all)

    def get_file_props_list(x_path):
        '''___get file list attributes___'''

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
        '''___get file attributes___'''

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
            file_info = x_file.query_info('*',
                                        Gio.FileQueryInfoFlags.NONE,
                                        None,
                                        )
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
            except:
                pass

            try:
                swgs.label_file_rw.set_label(f'{read} / {write}')
            except:
                pass

    def on_file_properties():
        '''___set visible file properties page___'''

        if scrolled_files_info.get_child() is None:
            add_files_info()

        if not sidebar_revealer.get_reveal_child():
            on_sidebar()

        btn_back_main.set_visible(True)
        stack_sidebar.set_visible_child(frame_files_info)
        update_color_scheme()

    def on_shortcut_context(x, y, grid_view, x_path):
        '''___popup context menu callback on right click___'''

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

        ####___write to run sh exec string___.

        file = Path(x_path).name
        parent_path = get_parent_path()
        shortcut_path = f'{parent_path}/{file}'
        check_arg(str(shortcut_path))
        start_mode()
        if getenv('SW_EXEC') == 'StartWine':
            return overlay_info(overlay, None, msg.msg_dict['lnk_error'], None, 3)

        ####___Context buttons___.

        rect = Gdk.Rectangle()
        rect.x = x
        rect.y = y
        rect.width = 0
        rect.height = 0

        shortcut_context = Gtk.PopoverMenu(css_name='sw_popovermenu')
        shortcut_context.set_has_arrow(False)
        shortcut_context.set_position(Gtk.PositionType.BOTTOM)
        shortcut_context.set_pointing_to(rect)
        shortcut_context.set_size_request(width*0.09, height*0.34)
        shortcut_context.set_parent(grid_view)
        shortcut_context.set_name(str(file))

        image_winehq = Gtk.Image(css_name='sw_image')
        image_winehq.set_halign(Gtk.Align.START)
        image_winehq.set_from_file(IconPath.icon_winehq)

        image_protondb = Gtk.Image(css_name='sw_image')
        image_protondb.set_halign(Gtk.Align.START)
        image_protondb.set_from_file(IconPath.icon_protondb)

        image_griddb = Gtk.Image(css_name='sw_image')
        image_griddb.set_halign(Gtk.Align.START)
        image_griddb.set_from_file(IconPath.icon_search)

        label_winehq = Gtk.Label(css_name='sw_label_popover', label=ctx_dict['winehq'])
        label_winehq.set_xalign(0)

        label_protondb = Gtk.Label(css_name='sw_label_popover', label=ctx_dict['protondb'])
        label_protondb.set_xalign(0)

        label_griddb = Gtk.Label(css_name='sw_label_popover', label=ctx_dict['griddb'])
        label_griddb.set_xalign(0)

        btn_winehq = Gtk.LinkButton(css_name='sw_link')
        btn_winehq.set_child(label_winehq)
        btn_winehq.connect("activate-link", cb_btn_winehq, file, shortcut_context)

        btn_protondb = Gtk.LinkButton(css_name='sw_link')
        btn_protondb.set_child(label_protondb)
        btn_protondb.connect("activate-link", cb_btn_protondb, file, shortcut_context)

        btn_griddb = Gtk.LinkButton(css_name='sw_link')
        btn_griddb.set_child(label_griddb)
        btn_griddb.connect("clicked", cb_btn_web_view_griddb, file, shortcut_context)
        #btn_griddb.connect("activate-link", cb_btn_griddb, file, shortcut_context)

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

        ####___Switch buttons___.

        switch_0 = Gtk.Switch(css_name='sw_switch')
        switch_1 = Gtk.Switch(css_name='sw_switch')
        switch_2 = Gtk.Switch(css_name='sw_switch')

        switch_0.set_valign(Gtk.Align.CENTER)
        switch_1.set_valign(Gtk.Align.CENTER)
        switch_2.set_valign(Gtk.Align.CENTER)

        switch_0.set_hexpand(True)
        switch_1.set_hexpand(True)
        switch_2.set_hexpand(True)

        switch_0.set_halign(Gtk.Align.END)
        switch_1.set_halign(Gtk.Align.END)
        switch_2.set_halign(Gtk.Align.END)

        switch_0.connect('state-set', cb_btn_switch_app_to_menu, file, shortcut_context)
        switch_1.connect('state-set', cb_btn_switch_app_to_desktop, file, shortcut_context)
        switch_2.connect('state-set', cb_btn_switch_app_to_steam, file, shortcut_context)

        img_path = image_start_mode.get_name()
        app_id = str(Path(img_path).stem).split('_')[-1]

        if app_id != 'x256':
            app_original_name = str(Path(img_path).stem).split('_')[-2]
        else:
            app_original_name = file.replace('.swd', '')

        local_dir = Path(f'{sw_local}/{app_original_name}.desktop')
        desktop_dir = Path(f'{dir_desktop}/{app_original_name}.desktop')

        if local_dir.exists():
            switch_0.set_active(True)

        if desktop_dir.exists():
            switch_1.set_active(True)

        ####___Swith images___.

        image_switch_0 = Gtk.Image(css_name='sw_image')
        image_switch_0.set_from_file(IconPath.icon_add)
        image_switch_1 = Gtk.Image(css_name='sw_image')
        image_switch_1.set_from_file(IconPath.icon_add)
        image_switch_2 = Gtk.Image(css_name='sw_image')
        image_switch_2.set_from_file(IconPath.icon_add)

        ####___Switch labels___.

        label_switch_0 = Gtk.Label(css_name='sw_label_popover', label=ctx_dict['app_to_menu'])
        label_switch_1 = Gtk.Label(css_name='sw_label_popover', label=ctx_dict['app_to_desktop'])
        label_switch_2 = Gtk.Label(css_name='sw_label_popover', label=ctx_dict['app_to_steam'])
        label_switch_0.set_xalign(0)
        label_switch_1.set_xalign(0)
        label_switch_2.set_xalign(0)

        ####___Switch boxes___.

        box_switch_0 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        box_switch_0.set_spacing(8)
        #box_switch_0.append(image_switch_0)
        box_switch_0.append(label_switch_0)
        box_switch_1 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        box_switch_1.set_spacing(8)
        #box_switch_1.append(image_switch_1)
        box_switch_1.append(label_switch_1)
        box_switch_2 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        box_switch_2.set_spacing(8)
        #box_switch_2.append(image_switch_1)
        box_switch_2.append(label_switch_2)

        ####___Grid context___.

        grid_context = Gtk.Grid(css_name='sw_grid')
        grid_context.set_row_spacing(8)
        grid_context.set_column_spacing(8)
        grid_context.attach(box_winehq, 0,0,1,1)
        grid_context.attach(box_protondb, 0,1,1,1)
        grid_context.attach(box_griddb, 0,2,1,1)
        grid_context.attach(box_switch_0, 0,3,1,1)
        grid_context.attach(box_switch_1, 0,4,1,1)
        grid_context.attach(box_switch_2, 0,5,1,1)
        grid_context.attach(switch_0, 1,3,1,1)
        grid_context.attach(switch_1, 1,4,1,1)
        grid_context.attach(switch_2, 1,5,1,1)

        ####___Custom context menu widgets___.

        builder_context = Gtk.Builder()
        builder_context.add_from_string(custom_context)
        custom_menu = builder_context.get_object('custom_context')

        ####___Binding context menu items to a callback function___.

        context_app_run = [
            {'name': ctx_dict['run'], 'func': on_cb_app_run},
            {'name': ctx_dict['open'], 'func': on_cb_app_open},
            {'name': ctx_dict['app_settings'], 'func': on_cb_app_settings},
        ]

        context_wine = [
            {'name': ctx_dict['change_wine'], 'func': cb_context_change_wine},
            ]

        context_remove = [
            {'name': ctx_dict['remove'][0], 'func': on_cb_app_remove},
        ]

        ####___Create submenu in context menu___.

        shortcut_menu = Gio.Menu()
        section_app_run = Gio.Menu()
        section_wine = Gio.Menu()
        section_remove = Gio.Menu()

        shortcut_menu.insert_section(0, None, section_app_run)
        shortcut_menu.insert_section(1, None, section_wine)
        shortcut_menu.insert_section(2, None, section_remove)
        shortcut_menu.append_section(None, custom_menu)

        context_connect(section_app_run, context_app_run, shortcut_context, 0)
        context_connect(section_wine, context_wine, shortcut_context, 1)
        context_connect(section_remove, context_remove, shortcut_context, 0)

        shortcut_context.set_menu_model(shortcut_menu)
        shortcut_context.add_child(grid_context, 'widget')

        scrolled = shortcut_context.get_first_child().get_first_child()
        scrolled.set_propagate_natural_height(True)
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.NEVER)

        shortcut_context.popup()

        context_app_run.clear()
        context_wine.clear()
        context_remove.clear()

    def on_cb_app_run(action_name, parameter, widget):
        '''___run application from context menu___'''

        file = widget.get_name()
        parent_path = get_parent_path()

        app_dict = app_info(f'{parent_path}/{file}')
        app_exec = app_dict['Exec'].replace(f'env "{sw_start}" ', '').strip('"')

        if Path(app_exec).exists():
            return on_start()
        else:
            return overlay_info(overlay, None, msg.msg_dict['lnk_error'], None, 3)

    def on_cb_app_open(action_name, parameter, widget):
        '''___open application directory from context menu___'''

        file = widget.get_name()
        parent_path = get_parent_path()

        app_dict = app_info(f'{parent_path}/{file}')
        app_exec = app_dict['Exec'].replace(f'env "{sw_start}" ', '').strip('"')

        if Path(app_exec).exists():
            on_files(Path(app_exec).parent)
        else:
            return overlay_info(overlay, None, msg.msg_dict['lnk_error'], None, 3)

    def on_cb_app_settings(action_name, parameter, widget):
        '''___open application settings menu from context menu___'''

        on_launch_settings()

    def on_cb_app_remove(action_name, parameter, widget):
        '''___remove application prefix from context menu___'''

        cb_btn_pfx_remove()

    def on_cb_menu_wine(action_name, parameter, widget):
        '''___change wine from context menu___'''

        wine_name = action_name.get_name()

        if wine_name == 'winestaging':
            changed_wine = 'wine_staging'
            write_changed_wine(changed_wine)
            start_mode()

        elif wine_name == 'winesteamproton':
            changed_wine = 'wine_steam_proton'
            write_changed_wine(changed_wine)
            start_mode()

        elif wine_name == 'wineprotonge':
            changed_wine = 'wine_proton_ge'
            write_changed_wine(changed_wine)
            start_mode()

        elif wine_name == 'winelutrisge':
            changed_wine = 'wine_lutris_ge'
            write_changed_wine(changed_wine)
            start_mode()

        elif wine_name == 'winelutris':
            changed_wine = 'wine_lutris'
            write_changed_wine(changed_wine)
            start_mode()

        else:
            changed_wine = str(wine_name).replace('__', '_')
            write_changed_wine(changed_wine)
            start_mode()

        update_grid_view(sw_shortcuts)

    def cb_btn_winehq(self, file, widget):

        name = file.replace('.swd', '')
        self.set_uri(f"{winehq_source}{name}")

    def cb_btn_protondb(self, file, widget):
        '''___search info on protondb web page by app name___'''

        img_path = image_start_mode.get_name()
        app_id = str(Path(img_path).stem).split('_')[-1]

        if app_id != 'x256':
            name = str(Path(img_path).stem).split('_')[-2]
            self.set_uri(f"{protondb_source}{name}")
        else:
            name = file.replace('.swd', '')
            self.set_uri(f"{protondb_source}{name}")

        widget.popdown()

    def cb_btn_griddb(self, file, widget):
        '''___search info on griddb web page by app name___'''

        img_path = image_start_mode.get_name()
        app_id = str(Path(img_path).stem).split('_')[-1]

        if app_id != 'x256':
            name = str(Path(img_path).stem).split('_')[-2]
            self.set_uri(f"{griddb_source}{name}")
        else:
            name = file.replace('.swd', '')
            self.set_uri(f"{griddb_source}{name}")

        widget.popdown()

    def cb_btn_web_view_griddb(self, file, widget):
        '''___search info on griddb web page by app name___'''

        img_path = image_start_mode.get_name()
        app_id = str(Path(img_path).stem).split('_')[-1]

        if app_id != 'x256':
            name = str(Path(img_path).stem).split('_')[-2]
            on_webview(f"{griddb_source}{name}")
        else:
            name = file.replace('.swd', '')
            on_webview(f"{griddb_source}{name}")

        widget.popdown()

    def cb_btn_switch_app_to_menu(self, state, file, widget):
        '''___add application shortcut to system menu___'''

        img_path = image_start_mode.get_name()
        app_id = str(Path(img_path).stem).split('_')[-1]

        if app_id != 'x256':
            app_original_name = str(Path(img_path).stem).split('_')[-2]
        else:
            app_original_name = file.replace('.swd', '')

        if self.get_active():
            if not Path(f'{sw_local}/{app_original_name}.desktop').exists():
                add_shortcut_to_menu(app_original_name)
        else:
            Path(f'{sw_local}/{app_original_name}.desktop').unlink()

        widget.popdown()

    def add_shortcut_to_menu(shortcut_name):
        '''___add application shortcut to system menu___'''

        if not Path(f'{sw_local}/{shortcut_name}').exists():
            environ['CUSTOM_GAME_NAME'] = f'"{shortcut_name}"'
            func_name = f"ADD_SHORTCUT_TO_MENU"
            echo_func_name(func_name)

    def cb_btn_switch_app_to_desktop(self, state, file, widget):
        '''___add application shortcut to desktop___'''

        img_path = image_start_mode.get_name()
        app_id = str(Path(img_path).stem).split('_')[-1]

        if app_id != 'x256':
            app_original_name = str(Path(img_path).stem).split('_')[-2]
        else:
            app_original_name = file.replace('.swd', '')

        if self.get_active():
            if not Path(f'{dir_desktop}/{app_original_name}.desktop').exists():
                add_shortcut_to_desktop(app_original_name, None)
        else:
            Path(f'{dir_desktop}/{app_original_name}.desktop').unlink()

        widget.popdown()

    def add_shortcut_to_desktop(custom_name, custom_path):
        '''___add application shortcut to desktop___'''

        if not Path(f'{dir_desktop}/{custom_name}').exists():
            environ['CUSTOM_GAME_NAME'] = f'"{custom_name}"'

            if custom_path is None:
                environ['CUSTOM_GAME_PATH'] = f'"{dir_desktop}"'
            else:
                environ['CUSTOM_GAME_PATH'] = f'"{custom_path}"'

            func_name = f"ADD_SHORTCUT_TO_DESKTOP"
            echo_func_name(func_name)

    def cb_btn_switch_app_to_steam(self, state, file, widget):
        '''___add application shortcut to steam library___'''

        img_path = image_start_mode.get_name()
        app_id = str(Path(img_path).stem).split('_')[-1]

        if app_id != 'x256':
            app_original_name = str(Path(img_path).stem).split('_')[-2]
        else:
            app_original_name = file.replace('.swd', '')

        if self.get_active():
            add_shortcut_to_steam(app_original_name)

        widget.popdown()

    def add_shortcut_to_steam(custom_name):
        '''___add application shortcut to steam library___'''

        if not Path(f'{dir_desktop}/{custom_name}').exists():
            environ['CUSTOM_GAME_NAME'] = f'"{custom_name}"'
            func_name = f"ADD_SHORTCUT_TO_STEAM"
            echo_func_name(func_name)

    def unparent_context_menu():
        '''___unparent unused context menu___'''

        grid_view = get_list_view()
        ctx = grid_view.get_last_child()

        for action_type in action_list:
            swgs.set_accels_for_action(
                action_type,
                []
            )
        else:
            action_list.clear()

        if ctx is not None:
            if 'GtkListItemWidget' in ctx:
                pass
            else:
                if ctx.get_name() == 'file_context_menu':
                    print(f'{tc.VIOLET2}{ctx} {tc.GREEN}unrealize{tc.END}')
                    ctx.get_menu_model().remove_all()
                    ctx.unparent()
                    ctx.unmap()
                    ctx.unrealize()

                elif ctx.get_name() == 'empty_context_menu':
                    print(f'{tc.VIOLET2}{ctx} {tc.GREEN}unrealize{tc.END}')
                    ctx.get_menu_model().remove_all()
                    ctx.unparent()
                    ctx.unmap()
                    ctx.unrealize()

                elif '.swd' in ctx.get_name():
                    print(f'{tc.VIOLET2}{ctx} {tc.GREEN}unrealize{tc.END}')
                    ctx.get_menu_model().remove_all()
                    ctx.unparent()
                    ctx.unmap()
                    ctx.unrealize()

    def cb_ctrl_lclick_view(self, n_press, x, y):
        '''___left click on empty place in list view___'''

        grid_view = self.get_widget()
        grid_view.grab_focus()
        set_view_parent_path(grid_view)

        unparent_context_menu()
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
                        shortcut_path = model.get_item(int(pos)).get_path()
                        check_arg(str(shortcut_path))
                        start_mode()
                        if getenv('SW_EXEC') == 'StartWine':
                            return overlay_info(overlay, None, msg.msg_dict['lnk_error'], None, 3)
                    else:
                        pass
                else:
                    pass

            elif str(pos) == grid_view.get_name():
                grid_view.get_model().unselect_all()
            else:
                pass

    def set_view_parent_path(grid_view):

        if (grid_view.get_name() == 'left_grid_view'
            or grid_view.get_name() == 'left_column_view'):

            if grid_view.get_model().get_item(0) is None:
                parent_path = left_dir_list.get_file().get_path()
                if parent_path is None:
                    parent_path = left_dir_list.get_file().get_uri()
            else:
                parent_path = left_dir_list.get_file().get_parent().get_path()
                if parent_path is None:
                    parent_path = left_dir_list.get_file().get_parent().get_uri()

        elif grid_view.get_name() == 'right_grid_view':
            if grid_view.get_model().get_item(0) is None:
                parent_path = right_dir_list.get_file().get_path()
                if parent_path is None:
                    parent_path = right_dir_list.get_file().get_uri()
            else:
                parent_path = right_dir_list.get_file().get_parent().get_path()
                if parent_path is None:
                    parent_path = right_dir_list.get_file().get_parent().get_uri()

        if (parent_path is not None and parent_path != entry_path.get_name()):
            update_path(parent_path)
            entry_path.set_text(str(parent_path))
            entry_path.set_name(str(parent_path))

        environ['SW_FILES_PARENT_PATH'] = parent_path
        environ['SW_FILES_VIEW_NAME'] = grid_view.get_name()

    def cb_ctrl_rclick_view(self, n_press, x, y):
        '''___right click in list view___'''

        grid_view = self.get_widget()
        grid_view.grab_focus()
        set_view_parent_path(grid_view)

        unparent_context_menu()
        pick = grid_view.pick(x, y, Gtk.PickFlags.DEFAULT)

        if pick is not None:
            pos = pick.get_name()
            parent_path = get_parent_path()

            if str(pos).isdigit():
                model = grid_view.get_model()
                if parent_path is not None:
                    if Path(parent_path) == Path(sw_shortcuts):
                        model.select_item(int(pos), True)
                        shortcut_path = model.get_item(int(pos)).get_path()
                        if Path(f'{shortcut_path}').is_file():
                            on_shortcut_context(x, y, grid_view, shortcut_path)
                    else:
                        nums = model.get_n_items()
                        selected = [i for i in range(nums) if model.is_selected(i)]
                        if len(selected) > 1:
                            model.select_item(int(pos), False)
                        else:
                            model.select_item(int(pos), True)

                        gio_files = get_selected_item_gfile()
                        on_file_context(x, y, grid_view, gio_files)
                else:
                    nums = model.get_n_items()
                    selected = [i for i in range(nums) if model.is_selected(i)]
                    if len(selected) > 1:
                        model.select_item(int(pos), False)
                    else:
                        model.select_item(int(pos), True)

                    gio_files = get_selected_item_gfile()
                    on_file_context(x, y, grid_view, gio_files)

            elif str(pos) == grid_view.get_name() or str(pos) == 'GtkColumnListView':
                    grid_view.get_model().unselect_all()
                    parent_path = get_parent_path()

                    if parent_path is not None:
                        if Path(parent_path) == Path(sw_shortcuts):
                            pass
                        else:
                            on_empty_context(x, y, grid_view, parent_path)
            else:
                pass

    def cb_model_selection_changed(self, position, n_items):
        '''______'''

        if str(get_parent_path()) == str(sw_shortcuts):
            item = self.get_item(position)
            #print(item.get_path())

    def cb_ctrl_left_view_focus(self):
        '''___Emitted whenever the focus enters into the widget or child___'''

        grid_view = self.get_widget()
        #set_view_parent_path(grid_view)

    def cb_ctrl_right_view_focus(self):
        '''___Emitted whenever the focus enters into the widget or child___'''

        grid_view = self.get_widget()
        #set_view_parent_path(grid_view)

    def cb_ctrl_left_view_motion(self, x, y):
        '''___Emmited when the pointer has entered the widget___'''

        grid_view = self.get_widget()
        #grid_view.grab_focus()

    def cb_ctrl_right_view_motion(self, x, y):
        '''___Emmited when the pointer has entered the widget___'''

        grid_view = self.get_widget()
        #grid_view.grab_focus()

    def cb_ctrl_drag_prepare(self, x, y):
        '''___return content for the drag file start___'''

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
                    src_name = (pick.get_parent()
                                        .get_parent()
                                            .get_last_child()
                                                .get_first_child()
                                                    .get_label()
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

                    if selected != []:
                        file_list = Gdk.FileList.new_from_list(selected)
                        content = Gdk.ContentProvider.new_for_value(GObject.Value(Gdk.FileList, file_list))
                        self.set_content(content)
                        selected.clear()
                        return content

    def cb_ctrl_drag_end(self, drag, delete_data):
        '''___signal on the drag source when a drag is finished___'''

    def cb_ctrl_drag_cancel(self, drag, reason):
        '''___emitted on the drag source when a drag has failed.___'''

        print(reason)

    def cb_ctrl_drop_target(self, value, x, y):
        '''___file drop in choose directory___'''

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
                                func = [{move_replace : (parent_path, replace_source)}, None]
                                dialog_question(swgs, title, message, None, func)

                            if len(copy_source) > 0:
                                for s, t in zip(copy_source, copy_target):
                                    Thread(target=run_move, args=(s, t,)).start()
                                    GLib.timeout_add(100, on_copy_move_progress, s, t)

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
                                    func = [{move_replace : (parent_path, replace_source)}, None]
                                    dialog_question(swgs, title, message, None, func)

                                if len(copy_source) > 0:
                                    for s, t in zip(copy_source, copy_target):
                                        Thread(target=run_move, args=(s, t,)).start()
                                        GLib.timeout_add(100, on_copy_move_progress, s, t)

    def cb_factory_setup(self, item_list, data):
        '''___setup items in grid view___'''
        cb_paned_factory_setup(item_list, data)

    def cb_paned_factory_setup(item_list, view):

        ft_size = btn_scale_icons.get_value()
        sc_size = btn_scale_shortcuts.get_value()

        file_overlay = Gtk.Overlay()

        ####___setup_shortcut_widgets___.
        if (get_parent_file().get_path() is not None
            and Path(get_parent_file().get_path()) == Path(sw_shortcuts)):
                #view.set_single_click_activate(True)

                file_image = Gtk.Picture(
                                    css_name='sw_picture',
                                    content_fit=Gtk.ContentFit.COVER,
                )
                file_image.add_css_class('gridview')

                prefix_label = Gtk.Label(
                                        css_name='sw_label_sub',
                                        xalign=0,
                                        yalign=0,
                                        width_chars=12,
                                        ellipsize=Pango.EllipsizeMode.END,
                                        lines=2,
                                        wrap=True,
                                        wrap_mode=Pango.WrapMode.WORD,
                )
                wine_label = Gtk.Label(
                                        css_name='sw_label_sub',
                                        xalign=0,
                                        yalign=0,
                                        width_chars=12,
                                        ellipsize=Pango.EllipsizeMode.END,
                                        lines=2,
                                        wrap=True,
                                        wrap_mode=Pango.WrapMode.WORD,
                )
                for i in range(9, 26):
                    prefix_label.remove_css_class(f'font_size_{i}')
                    wine_label.remove_css_class(f'font_size_{i}')

                prefix_label.add_css_class(f'font_size_{int(sc_size/12)+1}')
                wine_label.add_css_class(f'font_size_{int(sc_size/12)+1}')

                label_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
                label_box.append(prefix_label)
                label_box.append(wine_label)

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
                    for i in range(9, 26):
                        file_label.remove_css_class(f'font_size_{i}')

                    file_label.add_css_class(f'font_size_{int(sc_size/12)+1}')

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
                    for i in range(9, 26):
                        file_label.remove_css_class(f'font_size_{i}')

                    file_label.add_css_class(f'font_size_{int(sc_size/12)+1}')

                    file_box = Gtk.Box(
                                    css_name='sw_box',
                                    orientation=Gtk.Orientation.VERTICAL,
                                    spacing=4,
                    )
                    overlay_box.append(file_label)
                    overlay_box.append(label_revealer)
                    ctrl_motion_overlay = Gtk.EventControllerMotion()
                    ctrl_motion_overlay.connect('enter', cb_ctrl_enter_overlay, label_revealer, file_image)
                    ctrl_motion_overlay.connect('leave', cb_ctrl_leave_overlay, label_revealer, file_image)
                    file_overlay.add_controller(ctrl_motion_overlay)

                    dict_ini = read_menu_conf()

                    if dict_ini['icon_position'] == 'horizontal':
                        file_image.set_size_request(sc_size * (21/10), sc_size)
                        overlay_box.set_size_request(sc_size * (21/10), -1)

                    elif dict_ini['icon_position'] == 'vertical':
                        file_image.set_size_request(sc_size, sc_size * (18/10))
                        overlay_box.set_size_request(sc_size, -1)

                file_box.append(file_image)
                file_overlay.set_child(file_box)
                file_overlay.add_overlay(overlay_box)
                item_list.set_child(file_overlay)

                if not view.has_css_class('shortcuts'):
                    view.add_css_class('shortcuts')

        ####___setup_file_widgets___.
        else:
            #view.set_single_click_activate(False)
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
                for i in range(9, 26):
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
                for i in range(9, 26):
                    file_label.remove_css_class(f'font_size_{i}')

                file_box = Gtk.Box(
                                css_name='sw_box',
                                orientation=Gtk.Orientation.VERTICAL,
                                spacing=4,
                )

            file_label.add_css_class(f'font_size_{int(ft_size/12)+7}')
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

    def cb_right_factory_bind(self, item_list, data):
        '''___bind items in list view___'''

        cb_paned_factory_bind(item_list, data)

    def cb_factory_bind(self, item_list, data):
        '''___bind items in list view___'''

        cb_paned_factory_bind(item_list, data)

    def cb_paned_factory_bind(item_list, view):
        '''___bind items in list view___'''

        overlay = item_list.get_child()
        box = overlay.get_first_child()
        image = box.get_first_child()
        symlink_image = overlay.get_last_child()
        item = item_list.get_item()
        position = item_list.get_position()

        try:
            info = item.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
        except Exception as e:
            info = None

        if info is not None:
            if not info.has_attribute(attrs['content_type']):
                pass
            else:
                content_type = info.get_content_type()
                if info.has_attribute('standard::is-symlink'):
                    symbolic_link = info.get_is_symlink()

                    ####___Set_symbolic_links___.
                    if symbolic_link:
                        try:
                            symlink_image.set_from_file(IconPath.icon_symlink)
                        except:
                            pass
                        else:
                            symlink_image.set_visible(True)

                ####___Set_uri_items___.
                if item.get_path() is None:
                    uri_factory_bind(overlay, item, box, image, position, info)
                else:
                    ####___Set_shortcuts___.
                    if Path(item.get_path()).parent == Path(sw_shortcuts):
                        if Path(item.get_path()).suffix in swd_mime_types:
                            shortcut_factory_bind(view, overlay, item, image, position)

                    ####___Set_files___.
                    else:
                        file_factory_bind(view, item, image, content_type, info)

                    if label is not None:
                        label.set_name(str(position))

                    if image is not None:
                        image.set_name(str(position))

                    if box is not None:
                        box.set_name(str(position))

                    if overlay is not None:
                        overlay.set_name(str(position))

    def uri_factory_bind(overlay, item, box, image, position, info):

        label = image.get_next_sibling()
        label.set_label(info.get_name())
        label.set_name(info.get_name())
        image.set_from_gicon(info.get_icon())
        image.set_name(str(position))
        box.set_name(str(position))
        overlay.set_name(str(position))

    def shortcut_factory_bind(view, overlay, item, image, position):

        dict_ini = read_menu_conf()
        app_name = str(Path(item.get_path()).stem)
        app_strip = app_name.strip('"').replace(' ', '_')
        app_config_path = f"{sw_app_config}/{app_strip}"

        if not Path(app_config_path).exists():
            write_app_conf(item.get_path())

        overlay_box = overlay.get_last_child()
        overlay_box.set_name(str(position))
        label = overlay_box.get_first_child()

        if view.get_name() == 'left_column_view':
            swgs.column_view_file.set_title(msg.msg_dict['file_name'])
            set_horizontal_icon(app_name, item, image, label)
        else:
            app_conf_dict = app_info(app_config_path)

            ####___prefix label___.
            prefix_label = (label.get_next_sibling().get_child().get_first_child())
            prefix_label.set_name(str(position))
            prefix_name = str_prefix + ' ' + app_conf_dict['export SW_USE_PFX'][1:-1]
            prefix_label.set_label(prefix_name.replace('pfx_',''))

            ####___wine label___.
            wine_label = prefix_label.get_next_sibling()
            wine_label.set_name(str(position))
            wine_name = (str('Wine: ') + app_conf_dict['export SW_USE_WINE'][1:-1])
            wine_label.set_label(wine_name.replace('wine_',''))

            ####___horizontal_icons___.
            if dict_ini['icon_position'] == 'horizontal':
                set_horizontal_icon(app_name, item, image, label)

            ####___vertical_icons___.
            elif dict_ini['icon_position'] == 'vertical':
                set_vertical_icon(app_name, item, image, label)

    def set_horizontal_icon(app_name, item , image, label):

        for icon in sw_app_hicons.iterdir():
            an_isalnum = ''.join(e for e in app_name if e.isalnum())
            if an_isalnum == str(Path(icon).name).split('_')[0]:
                image.set_filename(f'{icon}')
                image.set_content_fit(Gtk.ContentFit.COVER)
                if label is not None:
                    label.set_label(str(Path(icon).name).split('_')[-2])
                    label.set_tooltip_markup(str(Path(icon).name).split('_')[-2])
                break
        else:
            try:
                image.set_filename(f'{sw_gui_icons}/sw.svg')
            except:
                pass
            else:
                image.set_content_fit(Gtk.ContentFit.SCALE_DOWN)

            if label is not None:
                try:
                    label.set_label(
                        str(Path(item.get_path()).stem))
                except:
                    pass
                else:
                    label.set_tooltip_markup(
                        str(Path(item.get_path()).stem))

    def set_vertical_icon(app_name, item, image, label):

        for icon in sw_app_vicons.iterdir():
            an_isalnum = ''.join(e for e in app_name if e.isalnum())
            if an_isalnum == str(Path(icon).name).split('_')[0]:
                image.set_filename(f'{icon}')
                label.set_label(str(Path(icon).name).split('_')[-2])
                label.set_tooltip_markup(str(Path(icon).name).split('_')[-2])
                break
        else:
            try:
                label.set_label(str(Path(item.get_path()).stem))
            except:
                pass
            else:
                label.set_tooltip_markup(str(Path(item.get_path()).stem))
            try:
                image.set_filename(f'{sw_gui_icons}/sw.svg')
            except:
                pass
            else:
                image.set_content_fit(Gtk.ContentFit.SCALE_DOWN)

    def set_heroes_icon(app_name, app_path , image, label):

        for icon in sw_app_heroes_icons.iterdir():
            an_isalnum = ''.join(e for e in app_name if e.isalnum())
            if an_isalnum == str(Path(icon).name).split('_')[0]:
                image.set_filename(f'{icon}')
                image.set_content_fit(Gtk.ContentFit.COVER)
                if label is not None:
                    label.set_label(str(Path(icon).name).split('_')[-2])
                    label.set_tooltip_markup(str(Path(icon).name).split('_')[-2])
                break
        else:
            try:
                image.set_filename(f'{sw_gui_icons}/{sw_logo_light}')
            except:
                pass
            else:
                image.set_content_fit(Gtk.ContentFit.SCALE_DOWN)

            if label is not None:
                try:
                    label.set_label(
                        str(Path(app_path).stem))
                except:
                    pass
                else:
                    label.set_tooltip_markup(
                        str(Path(app_path).stem))

    def file_factory_bind(view, item, image, content_type, info):

        label = image.get_next_sibling()

        if view.get_name() == 'left_column_view':
            swgs.column_view_file.set_title(msg.msg_dict['file_name'])
            label.set_size_request(140, -1)

        if content_type in app_mime_types:
            app_dict = app_info(item.get_path())
            try:
                app_dict["Icon"]
            except:
                try:
                    image.set_from_gicon(
                        info.get_attribute_object("standard::icon"))
                except:
                    print(f'{tc.VIOLET2} app_mime_type icon not found for: {tc.GREEN}'
                        + item.get_path() + tc.END)
            else:
                try:
                    image.set_from_file(app_dict["Icon"])
                except:
                    try:
                        image.set_from_gicon(
                            info.get_attribute_object("standard::icon"))
                    except:
                        print(f'{tc.VIOLET2} app_mime_type icon not found for: {tc.GREEN}'
                            + item.get_path() + tc.END)

        ####___Image_mime_type___.
        elif content_type in image_mime_types:
            thumb = f'{sw_fm_cache_thumbnail}/{item.get_path().replace("/", "")}'
            if Path(thumb).exists():
                file_icon = Gtk.IconPaintable.new_for_file(
                                Gio.File.new_for_path(thumb),
                                btn_scale_icons.get_value(), 1)
                try:
                    image.set_from_paintable(file_icon)
                except:
                    try:
                        image.set_paintable(file_icon)
                    except:
                        try:
                            image.set_from_gicon(
                                info.get_attribute_object("standard::icon"))
                        except:
                            try:
                                icon = try_get_theme_icon('image')
                                image.set_from_paintable(icon)
                            except:
                                print(f'{tc.VIOLET2} image_mime_type icon not found for: {tc.GREEN}'
                                                + item.get_path() + tc.END)
            else:
                try:
                    image.set_from_gicon(
                        info.get_attribute_object("standard::icon"))
                except:
                    try:
                        icon = try_get_theme_icon('image')
                        image.set_from_paintable(icon)
                    except:
                        print(f'{tc.VIOLET2} image_mime_type icon not found for: {tc.GREEN}'
                                        + item.get_path() + tc.END)
        ####___Video_mime_type___.
        elif content_type in video_mime_types:
            thumb = f'{sw_fm_cache_thumbnail}/{item.get_path().replace("/", "")}.png'
            if Path(thumb).exists():
                file_icon = Gtk.IconPaintable.new_for_file(
                                Gio.File.new_for_path(f'{thumb}'),
                                btn_scale_icons.get_value(), 1,)
                try:
                    image.set_from_paintable(file_icon)
                except:
                    try:
                        image.set_paintable(file_icon)
                    except:
                        try:
                            image.set_from_gicon(
                                info.get_attribute_object("standard::icon"))
                        except:
                            print(f'{tc.VIOLET2} video_mime_type icon not found for: {tc.GREEN}'
                                            + item.get_path() + tc.END)
            else:
                try:
                    image.set_from_gicon(
                        info.get_attribute_object("standard::icon"))
                except:
                    print(f'{tc.VIOLET2} video_mime_type icon not found for: {tc.GREEN}'
                                    + item.get_path() + tc.END)
        ####___Other_mime_type___.
        else:
            try:
                image.set_from_gicon(
                    info.get_attribute_object("standard::icon"))
            except:
                try:
                    icon = try_get_theme_icon('text')
                    image.set_from_paintable(icon)
                except:
                    print(f'{tc.VIOLET2} other_mime_type gicon not found for: {tc.GREEN}'
                            + item.get_path() + tc.END)
        try:
            label.set_label(
                info.get_attribute_string("standard::display-name"))
        except:
            print(f'{tc.VIOLET2} label not set for: {tc.GREEN}'
                + item.get_path() + tc.END)
        try:
            label.set_tooltip_markup(
                info.get_attribute_string("standard::display-name"))
        except:
            print(f'{tc.VIOLET2} tooltip not set for: {tc.GREEN}'
                + item.get_path() + tc.END)

    def cb_grid_factory_teardown(self, item_list):
        '''___prepare remove objects from list view___'''
        return True

    def cb_grid_factory_unbind(self, item_list):
        '''___remove objects from list view___'''
        return True

    def cb_column_factory_type_setup(self, item_list):
        '''___setup items in column size view___'''

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

        file_label.set_size_request(140, -1)
        item_list.set_child(box)

    def cb_column_factory_size_setup(self, item_list):
        '''___setup items in column size view___'''

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

    def cb_column_factory_uid_setup(self, item_list):
        '''___setup items in column size view___'''

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

    def cb_column_factory_created_setup(self, item_list):
        '''___setup items in column file created time view___'''

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

    def cb_column_factory_type_bind(self, item_list):
        '''___bind items in list view___'''

        box = item_list.get_child()
        file_label = box.get_first_child()
        item = item_list.get_item()

        try:
            file_info = item.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
        except Exception as e:
            file_info = None

        if file_info is not None:
            if str(item.get_parent().get_path()) == str(sw_shortcuts):
                swgs.column_view_type.set_title(msg.msg_dict['startup_mode'])

                stat_dict = app_info(item.get_path())
                app_path = stat_dict['Exec'].strip('"').replace(' ', '_')
                stat_name = app_path.replace('/', '_').replace('.', '_')
                stat_path = f'{sw_fm_cache_stats}/{stat_name}'

                app_name = str(Path(item.get_path()).stem)
                app_strip = app_name.strip('"').replace(' ', '_')
                app_config_path = f"{sw_app_config}/{app_strip}"
                app_conf_dict = app_info(app_config_path)

                prefix = app_conf_dict['export SW_USE_PFX'][1:-1].replace('pfx_','')
                wine = app_conf_dict['export SW_USE_WINE'][1:-1].replace('wine_','')

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

    def cb_column_factory_size_bind(self, item_list):
        '''___bind items in list view___'''

        file_label = item_list.get_child()
        item = item_list.get_item()

        try:
            file_info = item.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
        except Exception as e:
            file_info = None

        if file_info is not None:
            if str(item.get_parent().get_path()) == str(sw_shortcuts):
                swgs.column_view_size.set_title(msg.msg_dict['directory_size'])
                app_dict = app_info(f'{item.get_path()}')
                app_exec = app_dict['Exec'].replace(f'env "{sw_start}" ', '').strip('"')
                size = 0
                if Path(app_exec).exists():
                    data = Path(Path(app_exec).parent)
                    Thread(target=get_allocated_size, args=[size, data, file_label]).start()
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

    def cb_column_factory_uid_bind(self, item_list):
        '''___bind items in list view___'''

        file_label = item_list.get_child()
        item = item_list.get_item()

        try:
            file_info = item.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
        except Exception as e:
            file_info = None

        if file_info is not None:
            if str(item.get_parent().get_path()) == str(sw_shortcuts):
                swgs.column_view_uid.set_title(msg.msg_dict['path'])
                app_dict = app_info(f'{item.get_path()}')
                app_exec = app_dict['Exec'].replace(f'env "{sw_start}" ', '').strip('"')
                file_label.set_label(app_exec)
                file_label.set_tooltip_markup(app_exec)
            else:
                swgs.column_view_uid.set_title(msg.msg_dict['user_group'])
                f_uid = file_info.get_attribute_as_string("owner::user")
                f_gid = file_info.get_attribute_as_string("owner::group")
                try:
                    st = os.stat(item.get_path())
                except:
                    permission = ''
                else:
                    permission = oct(st.st_mode)
                    permission = list(permission[:-4:-1])
                    permission.reverse()
                    permission = ' '.join([access_dict[int(p)] for p in permission])

                file_label.set_label(f'{f_uid} {f_gid}\n{msg.msg_dict["access"]}: {permission}')

    def cb_column_factory_created_bind(self, item_list):
        '''___bind items in list view___'''

        file_label = item_list.get_child()
        item = item_list.get_item()
        try:
            file_info = item.query_info('*', Gio.FileQueryInfoFlags.NONE, None)
        except Exception as e:
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

    def cb_volume_ops(self, volume):
        '''___mount unmount volume changed___'''

        if scrolled_gvol.get_child() is None:
            add_gvol_view()

        return update_gvolume()

    def cb_gvol_activate(self, position):
        '''___activate mount and unmount operation by the user___'''

        gvol = self.get_model().get_item(position)

        if isinstance(gvol, Gtk.StringObject):
            mount_path = Path(gvol.get_string().split(':')[0])
            gmount_path = Gio.File.new_for_path(bytes(mount_path))
            if (gmount_path is not None
                and mount_path.exists()):
                    try:
                        update_grid_view(mount_path)
                    except PermissionError as e:
                        overlay_info(overlay, None, e, None, 3)
        else:
            gmnt = gvol.get_mount()

            if (gmnt is None and gvol.can_mount()):
                gvol.mount(Gio.MountMountFlags.NONE, swgs.gmount_ops, callback=gvol_mount)

            elif gmnt is not None:
                mount_path = gvol.get_mount().get_default_location().get_path()

                if (mount_path is not None
                    and Path(mount_path).exists()):
                        try:
                            update_grid_view(mount_path)
                        except PermissionError as e:
                            overlay_info(overlay, None, e, None, 3)

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

        #os.chdir(new_uri)
        swgs.cur_dir = Gio.File.new_for_uri(new_uri)
        swgs.f_mon = swgs.cur_dir.monitor(Gio.FileMonitorFlags.WATCH_MOVES, None)
        swgs.f_mon.connect('changed', g_file_monitor)

        gfile = Gio.File.new_for_uri(new_uri)

        try:
            ginfo = gfile.query_info('*', Gio.FileQueryInfoFlags.NONE)
        except GLib.GError as e:
            content_type = None
        else:
            content_type = ginfo.get_content_type()

        if content_type is None:
            on_files(sw_default_dir)

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
                return dialog_info(text_message=str(e.message), message_type='ERROR').run()
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
                    return dialog_info(text_message=str(e.message), message_type='ERROR').run()

    def cb_eject_btn(self, gmount):

        dict_ini =  read_menu_conf()
        gmount.unmount_with_operation(Gio.MountUnmountFlags.NONE, swgs.gmount_ops, callback=gmount_unmount)

    def gvol_mount(self, res):
        '''___mount operation finish___'''
        try:
            result = self.mount_finish(res)
        except GLib.GError as e:
            print(e)
            dialog_info(text_message=str(e.message), message_type='ERROR').run()
        else:
            mount_path = self.get_mount().get_default_location().get_path()

            if (mount_path is not None
                and Path(mount_path).exists()):
                    try:
                        update_grid_view(mount_path)
                    except PermissionError as e:
                        return overlay_info(overlay, None, e, None, 3)

            elif mount_path is None:
                uri = self.get_mount().get_default_location().get_uri()
                if uri is not None:
                    try:
                        update_grid_view_uri(uri)
                    except PermissionError as e:
                        return overlay_info(overlay, None, e, None, 3)
            else:
                raise ValueError(f'{tc.RED}{self.get_name()} mount error{tc.END}')

    def gmount_unmount(self, res):
        '''___unmount operation finish___'''
        try:
            result = self.unmount_with_operation_finish(res)
        except GLib.GError as e:
            result = None
            return dialog_info(text_message=str(e.message), message_type='ERROR').run()
        else:
            unmount_path = dict_ini['default_dir']
            if (unmount_path is not None
                and Path(unmount_path).exists()):
                    try:
                        update_grid_view(unmount_path)
                    except PermissionError as e:
                        return overlay_info(overlay, None, e, None, 3)

    def cb_gvol_factory_setup(self, list_item):
        '''___bind items in column view___'''

        label = Gtk.Label(
                        css_name='sw_label_desc',
                        wrap=True,
                        natural_wrap_mode=True,
                        xalign=0,
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

    def cb_gvol_id_factory_setup(self, list_item):
        '''___bind items in column view___'''

        label = Gtk.Label(
                        css_name='sw_label_desc',
                        wrap=True,
                        natural_wrap_mode=True,
                        xalign=0,
                        margin_start=8,
                        margin_end=8,
                        )
        list_item.set_child(label)

    def cb_gvol_uuid_factory_setup(self, list_item):
        '''___bind items in column view___'''

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

    def cb_gvol_drive_factory_setup(self, list_item):
        '''___bind items in column view___'''

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

    def cb_gvol_size_factory_setup(self, list_item):
        '''___bind items in column view___'''

        bar = Gtk.ProgressBar(
                            css_name='sw_progressbar',
                            valign=Gtk.Align.CENTER,
                            margin_start=16,
                            margin_end=16,
                            )
        list_item.set_child(bar)

    def cb_gvol_factory_bind(self, list_item):
        '''___bind items in column view___'''

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
            if (data.get_mount() is not None
                and data.get_mount().can_unmount()):
                    eject_btn.connect('clicked', cb_eject_btn, data.get_mount())
                    eject_btn.set_name(data.get_name())
                    eject_btn.set_visible(True)
            else:
                eject_btn.set_name(data.get_name())
                eject_btn.set_visible(False)

    def cb_gvol_id_factory_bind(self, list_item):
        '''___bind items in column view___'''

        label = list_item.get_child()
        data = list_item.get_item()

        if isinstance(data, Gtk.StringObject):
            devid = data.get_string().split(':')[1]
            label.set_label(devid)
        else:
            dev_id = data.get_identifier('unix-device')
            if dev_id is not None:
                label.set_label(dev_id)

    def cb_gvol_uuid_factory_bind(self, list_item):
        '''___bind items in column view___'''

        label = list_item.get_child()
        data = list_item.get_item()

        if isinstance(data, Gtk.StringObject):
            pass
        else:
            if data.get_uuid() is not None:
                label.set_label(data.get_uuid())

    def cb_gvol_drive_factory_bind(self, list_item):
        '''___bind items in column view___'''

        label = list_item.get_child()
        data = list_item.get_item()

        if isinstance(data, Gtk.StringObject):
            mount_options = data.get_string().split(':')[3]
            label.set_label(mount_options)
        else:
            if not data.get_drive() is None:
                label.set_label(data.get_drive().get_name())

    def cb_gvol_size_factory_bind(self, list_item):
        '''___bind items in column view___'''

        size_bar = list_item.get_child()
        data = list_item.get_item()

        if isinstance(data, Gtk.StringObject):
            mountpoint = data.get_string().split(':')[0]
            fs_size = psutil.disk_usage(mountpoint).total
            fs_used = psutil.disk_usage(mountpoint).used
            fs_free = psutil.disk_usage(mountpoint).free
            fs_type = data.get_string().split(':')[2]
            percent = psutil.disk_usage(mountpoint).percent
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
                except:
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
                        fs_used = 0
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

    def cb_bookmarks_factory_setup(self, item_list):
        '''___setup items in bookmarks list view___'''

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

    def cb_bookmarks_factory_bind(self, item_list):
        '''___bind items in bookmarks list view___'''

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
            if bookmarks_dict[str_item][1] is not None:
                label.set_label(bookmarks_dict[str_item][1])
            else:
                label.set_label(Path(str_item).name.capitalize())
        except:
            image.set_from_file(IconPath.icon_folder)
            label.set_label(Path(str_item).name.capitalize())

    def cb_factory_dll_0_setup(self, item_list):
        '''___setup items in dll column view___'''

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

    def cb_factory_dll_1_setup(self, item_list):
        '''___setup items in dll column view___'''

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

    def cb_factory_dll_0_bind(self, item_list):
        '''___bind items in dll column view___'''

        btn_check = item_list.get_child().get_first_child()
        label_dll = btn_check.get_next_sibling()
        item = item_list.get_item()
        pos = item_list.get_position()
        label_dll.set_label(item.get_label())
        pic_dll = btn_check.get_child()

        if 'installed_' in str(item.get_name()):
            pic_dll.set_filename(IconPath.icon_checked)
            btn_check.set_active(True)
            btn_check.set_sensitive(False)

        btn_check.connect('toggled', on_dll_toggled, label_dll, pic_dll)

    def cb_factory_dll_1_bind(self, item_list):
        '''___bind items in dll column view___'''

        btn_check = item_list.get_child().get_first_child()
        label_dll = btn_check.get_next_sibling()
        item = item_list.get_item()
        pos = item_list.get_position()
        label_dll.set_label(item.get_label())
        pic_dll = btn_check.get_child()

        if 'installed_' in str(item.get_name()):
            pic_dll.set_filename(IconPath.icon_checked)
            btn_check.set_active(True)
            btn_check.set_sensitive(False)

        btn_check.connect('toggled', on_dll_toggled, label_dll, pic_dll)

    def cb_factory_dll_0_desc_setup(self, item_list):
        '''___setup items in dll column view___'''

        label_desc = Gtk.Label(css_name='sw_label_desc')
        label_desc.set_xalign(0)
        label_desc.set_wrap(True)
        label_desc.set_wrap_mode(Pango.WrapMode.CHAR)
        item_list.set_child(label_desc)

    def cb_factory_dll_0_desc_bind(self, item_list):
        '''___bind items in dll column view___'''

        label_dll = item_list.get_child()
        item = item_list.get_item()
        pos = item_list.get_position()
        label_dll.set_label(dll_dict[item.get_label()])

    def cb_factory_dll_1_desc_setup(self, item_list):
        '''___setup items in dll column view___'''

        label_desc = Gtk.Label(css_name='sw_label_desc')
        label_desc.set_xalign(0)
        label_desc.set_wrap(True)
        label_desc.set_wrap_mode(Pango.WrapMode.CHAR)
        item_list.set_child(label_desc)

    def cb_factory_dll_1_desc_bind(self, item_list):
        '''___bind items in dll column view___'''

        label_dll = item_list.get_child()
        item = item_list.get_item()
        pos = item_list.get_position()
        label_dll.set_label(dll_dict[item.get_label()])

    def cb_factory_fonts_setup(self, item_list):
        '''___setup items in fonts column view___'''

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

    def cb_factory_fonts_bind(self, item_list):
        '''___bind items in fonts column view___'''

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

    def cb_factory_fonts_desc_setup(self, item_list):
        '''___setup items in fonts column view___'''

        item = item_list.get_item()
        label_desc = Gtk.Label(css_name='sw_label_desc')
        label_desc.set_xalign(0)
        label_desc.set_wrap(True)
        label_desc.set_wrap_mode(Pango.WrapMode.WORD)
        item_list.set_child(label_desc)

    def cb_factory_fonts_desc_bind(self, item_list):
        '''___bind items in fonts column view___'''

        label_fonts = item_list.get_child()
        item = item_list.get_item()
        label_fonts.set_label(fonts_dict[item.get_label()])

    def cb_factory_dll_templates_setup(self, item_list):
        '''___setup dll templates in dropdown list___'''

        label = Gtk.Label(css_name='sw_label_desc', xalign=0)
        item_list.set_child(label)

    def cb_factory_dll_templates_bind(self, item_list):
        '''___bind dll templates in dropdown list___'''

        item = item_list.get_item()
        label = item_list.get_child()
        label.set_label(item.get_label())
        label.set_name(item.get_name())
        label.set_tooltip_markup(item.get_name())

####___Start_application___.

    def run_vulkan():
        '''___run application in vulkan mode___'''

        func_name = f"RUN_VULKAN"
        echo_func_name(func_name)

    def run_opengl():
        '''___run application in opengl mode___'''

        func_name = f"SW_USE_OPENGL='1' RUN_VULKAN"
        echo_func_name(func_name)

    def request_wine(wine):
        '''___wine download request___'''

        def on_thread_wine():

            t = Thread(target=echo_func_name, args=(func_name,))
            t.start()

            winedevice = []
            thread_check_winedevice = Thread(target=check_winedevice, args=[winedevice])
            thread_check_winedevice.start()

            app_path = get_app_path()
            app_name = get_out()
            s_time = time()
            parent.set_hide_on_close(True)

            GLib.timeout_add(1000, check_alive, thread_check_winedevice, parent_back, (app_path, s_time), None)

        wine_ver = wine.replace('-amd64', '').replace('-x86_64', '')
        wine_ver = ''.join([e for e in wine_ver if not e.isalpha()]).strip('-')

        try:
            func_wine = wine_download_dict[wine]
        except KeyError as e:
            text_message = [f'{wine} ' + msg.msg_dict['is_not_installed'], '']
            dialog_question(swgs, f'{sw_program_name} Info', text_message, [msg.msg_dict['cancel'],], [on_stop,])
        else:
            if func_wine == 'WINE_1':
                name_ver = 'STAG_VER'

            if func_wine == 'WINE_2':
                name_ver = 'SP_VER'

            if func_wine == 'WINE_3':
                name_ver = 'GE_VER'

            if func_wine == 'WINE_4':
                name_ver = 'STAG_VER'

            func_name = f'{name_ver}="{wine_ver}" WINE_OK=1 {func_wine} && RUN_VULKAN'
            text_message = [f"{wine} {msg.msg_dict['not_exists']}", '']
            func = [on_thread_wine, on_stop]
            dialog_question(swgs, None, text_message, None, func)

    def parent_back(args):
        '''___restore the menu after exiting a running application___'''

        app_path, s_time = args
        dict_ini = read_menu_conf()

        if dict_ini['auto_stop'] == 'on':
            on_stop()

        if dict_ini['restore_menu'] == 'on':
            parent.set_visible(True)
            parent.set_hide_on_close(False)

        time_in = round(time() - s_time, 2)
        time_val = 'seconds'

        cache_name = (app_path.strip('"').replace(' ', '_').replace('/', '_')
                    .replace('.', '_')
        )
        app_name = get_out()
        app_stat_cache = f'{sw_fm_cache_stats}/{cache_name}'
        fps_in = read_overlay_output(app_name)

        if not Path(app_stat_cache).exists():
            open(app_stat_cache, 'w').close()

        write_app_stat(app_stat_cache, 'Time', time_in)
        print(f'{tc.VIOLET2}TIME_IN_THE_APP: {tc.GREEN}{time_in}{tc.END}')

        if fps_in is not None:
            write_app_stat(app_stat_cache, 'Fps', fps_in)
            print(f'{tc.VIOLET2}AVERAGE_FPS: {tc.GREEN}{fps_in}{tc.END}')

    def check_winedevice(winedevice):
        '''___Check winedevice process___'''

        found = None
        while found is None:
            winedevice = ([p.info['name'] for p in psutil.process_iter(['pid', 'name'])
                if 'winedevice' in p.info['name']]
            )
            if winedevice == []:
                sleep(1)
            else:
                found = 1
        else:
            while winedevice != []:
                winedevice = ([p.info['name'] for p in psutil.process_iter(['pid', 'name'])
                    if 'winedevice' in p.info['name']]
                )
                print(winedevice)
                sleep(1)

    def cb_btn_start(self):
        '''___run application in vulkan or opengl mode___'''

        return on_start()

    def on_start():
        '''___Running application in vulkan or opengl mode___'''

        app_path = get_app_path()
        app_name = get_out()
        app_suffix = get_suffix()

        if app_name == 'StartWine':
            text_message = str_oops
            samples = f'{sw_sounds}/dialog/dialog-warning.oga'
            if Path(samples).exists():
                Thread(target=media_play, args=(media_file, samples,
                                                media_controls, 1.0, False
                                                )).start()
            return overlay_info(overlay, None, text_message, None, 3)
        else:
            def run_(q):
                '''___Running the executable in vulkan or opengl mode___'''

                if len(q) > 0:
                    try:
                        vulkan_dri = q[0]
                    except Exception as e:
                        vulkan_dri = None
                    else:
                        if vulkan_dri == '' or vulkan_dri == 'llvmpipe':
                            vulkan_dri = None
                    try:
                        vulkan_dri2 = q[1]
                    except Exception as e:
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

                if app_suffix == '.lnk':
                    app_name, app_suffix, app_lnk_path = get_lnk_data(app_path)
                    write_lnk_data(app_name, app_path, app_suffix, app_lnk_path)

                app_conf = Path(f"{sw_app_config}/" + str(app_name))
                app_conf_dict = app_conf_info(app_conf, switch_labels)
                debug = app_conf_dict['WINEDBG_DISABLE'].split('=')[1]

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
                GLib.timeout_add(1000, check_alive, thread_check_winedevice, parent_back, (app_path, s_time), None)

            def wait_exe_proc(bar, app_suffix):
                '''___Waiting for the executing process to close the menu___'''

                environ['FRAGMENT_NUM'] = f'{len(fragments_list) - 1}'
                found = find_process(app_suffix)
                if found:
                    bar.set_show_text(False)
                    bar.set_fraction(0.0)
                    bar.set_visible(False)
                    parent.close()
                    environ['FRAGMENT_NUM'] = getenv('FRAGMENT_INDEX')
                    return False

                stack_progress_main.set_visible_child(progress_main_grid)
                bar.set_visible(True)
                bar.set_show_text(True)
                bar.set_text(progress_dict['app_loading'])
                bar.pulse()
                return True

            wine = check_wine()
            if wine is not None:
                if app_suffix == '.lnk':
                    app_name, app_suffix, app_lnk_path = get_lnk_data(app_path)
                    write_lnk_data(app_name, app_path, app_suffix, app_lnk_path)

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

####___Create_shortcut___.

    def on_create_shortcut():
        '''___show files to create shortcut___'''

        dict_ini = read_menu_conf()
        sw_default_dir = dict_ini['default_dir']
        on_files(Path(sw_default_dir))

    def write_changed_wine(changed_wine):
        '''___write changed wine to application config___'''

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

        if not check_exe_logo(app_name):
            ctx = mp.get_context('spawn')
            p = ctx.Process(target=get_exe_logo, args=(app_name, app_path))
            p.start()
            GLib.timeout_add(100, check_alive, p, get_sm_icon, app_name, None)

        if (Path(f'{sw_shortcuts}/{app_name}.swd').exists()
            and Path(f'{get_pfx_path()}').exists()):
                app_dict = app_info(Path(f'{sw_shortcuts}/{app_name}.swd'))
                app_exec = app_dict['Exec'].replace(f'env "{sw_start}" ', '').strip('"')

                if app_exec == app_path.strip('"'):
                    write_changed_wine(func_wine)
                    start_mode()
                    if stack_sidebar.get_visible_child() == frame_create_shortcut:
                        on_back_main()
                else:
                    btn_back_main.set_visible(False)
                    t = Thread(target=cs_path, args=(func_wine, app_name, app_path))
                    t.start()
                    progress_main.set_name(func_wine)
                    GLib.timeout_add(100, progress_on_thread, progress_main, t, None)
        else:
            btn_back_main.set_visible(False)
            t = Thread(target=cs_path, args=(func_wine, app_name, app_path))
            t.start()
            progress_main.set_name(func_wine)
            GLib.timeout_add(100, progress_on_thread, progress_main, t, None)

    def cb_btn_cs_wine(self):
        '''___create shortcut with changed wine___'''

        app_path = get_app_path()
        app_name = get_out()
        func_wine = latest_wine_dict[self.get_name()]

        if func_wine is None:
            message = msg.msg_dict['wine_not_found']
            dialog_info(text_message=message, message_type='ERROR').run()
        else:
            on_cs_wine(app_name, app_path, func_wine)

    def cb_btn_cs_wine_custom(self, position):
        '''___create shortcut with changed custom wine___'''

        app_path = get_app_path()
        app_name = get_out()

        func_wine = self.get_model().get_item(position).get_name()
        wc_label = self.get_model().get_item(position).get_label()

        on_cs_wine(app_name, app_path, func_wine)
        swgs.popover_wines.popdown()

    def cb_factory_wine_custom_setup(self, item_list):

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

    def cb_factory_wine_custom_bind(self, item_list):

        item = item_list.get_item()
        box = item_list.get_child()

        image = box.get_first_child()
        label = image.get_next_sibling()

        image.set_from_file(IconPath.icon_wine)
        label.set_label(item.get_label())
        label.set_name(item.get_name())

    def update_wine_custom_store():

        swgs.list_store_wine_custom.remove_all()

        cw_file = []

        def check_wine_path(cw_file):

            for r, d, f in walk(sw_wine):
                for w in f:
                    if w == 'wine':
                        cw_file.append(f'{r}/{w}')
                        break
            else:
                for w in wine_list:
                    wine_dir = latest_wine_dict[w]
                    try:
                        cw_file.remove(f'{sw_wine}/{wine_dir}/files/bin/wine')
                    except:
                        pass
                    try:
                        cw_file.remove(f'{sw_wine}/{wine_dir}/bin/wine')
                    except:
                        pass

        def update_wine_path(q):

            cw_file = q

            if len(cw_file) > 0:
                for cw in cw_file:
                    cn = (str(Path(cw).parent.parent)
                            .replace(f'{sw_wine}/', '')
                                .replace('/files', '')
                                    .replace('/dist', '')
                    )
                    cw = str(Path(cw).parent.parent).replace(f'{sw_wine}/', '')
                    label = Gtk.Label(label=cn, name=Path(cw))
                    swgs.list_store_wine_custom.append(label)

        t = Thread(target=check_wine_path, args=[cw_file])
        t.start()
        f = update_wine_path
        q = cw_file
        GLib.timeout_add(25, check_alive, t, f, q, None)

    def cb_btn_menu_wine_custom(self):
        '''___show pop up wine custom menu___'''

        swgs.scrolled_wine_custom.set_max_content_height(parent.get_height() / 2)
        update_wine_custom_store()
        swgs.popover_wines.popup()

####___Prefix_tools___.

    def on_prefix_tools():
        '''___show prefix tools menu___'''

        if scrolled_prefix_tools.get_child() is None:
            add_prefix_tools_menu()

        btn_back_main.set_visible(True)
        stack_sidebar.set_visible_child(frame_prefix_tools)
        on_pfx_dropdown()

    def on_change_pfx_setup(self, item_list):
        '''___setup change wine items___'''

        item = item_list.get_item()
        label = Gtk.Label(css_name='sw_label_desc')
        label.set_xalign(0)
        item_list.set_child(label)

    def on_change_pfx_bind(self, item_list):
        '''___bind change wine items___'''

        item = item_list.get_item()
        label = item_list.get_child()
        label.set_label(item.get_string())

    def on_change_pfx_activate(self, gparam):
        '''___activate changed wine___'''

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

        start_mode()

    def on_pfx_dropdown():

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_dict = app_conf_info(app_conf, ['SW_USE_PFX'])

        if not '="pfx_default"' in app_conf_dict[swgs.dropdown_change_pfx.get_name()]:
            swgs.dropdown_change_pfx.set_selected(1)
        else:
            swgs.dropdown_change_pfx.set_selected(0)

    def cb_btn_prefix_tools(self):
        '''___prefix tools buttons signal handler___'''

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

        elif self.get_name() == prefix_tools_dict['pfx_full_backup']:
            cb_btn_pfx_full_backup()

        elif self.get_name() == prefix_tools_dict['pfx_full_restore']:
            cb_btn_pfx_full_restore()

    def cb_btn_pfx_remove():
        '''___remove current prefix___'''

        bar = progress_main
        bar.set_name('pfx_remove')
        t = Thread(target=on_pfx_remove)
        t.start()
        timeout_info = GLib.timeout_add(100, progress_on_thread, bar, t, None)
        timeout_list.append(timeout_info)

    def on_pfx_remove():
        '''___remove current prefix___'''

        func_name = f"REMOVE_PFX"
        echo_func_name(func_name)

    def cb_btn_pfx_clear():
        '''___clear current prefix___'''

        bar = progress_main
        bar.set_name('pfx_clear')
        t = Thread(target=on_pfx_clear)
        t.start()
        timeout_info = GLib.timeout_add(100, progress_on_thread, bar, t, None)
        timeout_list.append(timeout_info)

    def on_pfx_clear():
        '''___clear current prefix___'''

        func_name = f"SW_CLEAR_PFX"
        echo_func_name(func_name)

    def cb_btn_pfx_reinstall():
        '''___reinstall current prefix___'''

        bar = progress_main
        bar.set_name('pfx_reinstall')
        t = Thread(target=on_pfx_reinstall)
        t.start()
        timeout_info = GLib.timeout_add(100, progress_on_thread, bar, t, None)
        timeout_list.append(timeout_info)

    def on_pfx_reinstall():
        '''___reinstall current prefix___'''

        func_name = f"REINSTALL_PFX"
        echo_func_name(func_name)

    def cb_btn_pfx_backup():
        '''___backup current prefix___'''

        bar = progress_main
        bar.set_name('pfx_backup')

        t = Thread(target=on_pfx_backup)
        t.start()
        timeout_info = GLib.timeout_add(100, progress_on_thread, bar, t, None)
        timeout_list.append(timeout_info)

    def on_pfx_backup():
        '''___backup current prefix___'''

        func_name = f"SW_PFX_BACKUP"
        echo_func_name(func_name)

    def cb_btn_pfx_restore():
        '''___restore current prefix___'''

        bar = progress_main
        bar.set_name('pfx_restore')
        t = Thread(target=on_pfx_restore)
        t.start()
        timeout_info = GLib.timeout_add(100, progress_on_thread, bar, t, None)
        timeout_list.append(timeout_info)

    def on_pfx_restore():
        '''___restore current prefix___'''

        func_name = f"SW_PFX_RESTORE"
        echo_func_name(func_name)

    def cb_btn_pfx_full_backup():
        '''___backup all prefixes___'''

        bar = progress_main
        bar.set_name('pfx_full_backup')
        t = Thread(target=on_pfx_full_backup)
        t.start()
        timeout_info = GLib.timeout_add(100, progress_on_thread, bar, t, None)
        timeout_list.append(timeout_info)

    def on_pfx_full_backup():
        '''___backup all prefixes___'''

        func_name = f"SW_PFX_FULL_BACKUP"
        echo_func_name(func_name)

    def cb_btn_pfx_full_restore():
        '''___restore all prefixes___'''

        bar = progress_main
        bar.set_name('pfx_full_restore')

        t = Thread(target=on_pfx_full_restore)
        t.start()
        timeout_info = GLib.timeout_add(100, progress_on_thread, bar, t, None)
        timeout_list.append(timeout_info)

    def on_pfx_full_restore():
        '''___restore all prefixes___'''

        func_name = f"SW_PFX_FULL_RESTORE"
        echo_func_name(func_name)

####___Wine_tools___.

    def on_wine_tools():
        '''___show wine tools menu___'''

        if scrolled_wine_tools.get_child() is None:
            add_wine_tools_menu()

        btn_back_main.set_visible(True)
        stack_sidebar.set_visible_child(frame_wine_tools)
        Thread(target=update_wine_list).start()

    def on_change_wine_setup(self, item_list):
        '''___setup change wine items___'''

        item = item_list.get_item()
        label = Gtk.Label(
                        css_name='sw_label_desc',
                        ellipsize=Pango.EllipsizeMode.END,
                        xalign=0,
        )
        item_list.set_child(label)

    def on_change_wine_bind(self, item_list):
        '''___bind change wine items___'''

        item = item_list.get_item()
        label = item_list.get_child()
        label.set_name(item.get_name())
        label.set_label(item.get_label())

    def update_wine_list():
        '''___udate wine list in dropdown model___'''

        winever_data, latest_wine_dict, wine_download_dict = get_wine_dicts()
        swgs.change_wine_store.remove_all()

        cw_file = []
        for r, d, f in walk(sw_wine):
            for w in f:
                if w == 'wine':
                    cw_file.append(f'{r}/{w}')
                    break
        else:
            for w in wine_list:
                wine_dir = latest_wine_dict[w]
                try:
                    cw_file.remove(f'{sw_wine}/{wine_dir}/files/bin/wine')
                except:
                    pass
                try:
                    cw_file.remove(f'{sw_wine}/{wine_dir}/bin/wine')
                except:
                    pass

        for w in wine_list:
            wine_dir = latest_wine_dict[w]
            if wine_dir is not None:
                label = Gtk.Label(label=wine_dir, name=f'{wine_dir}')
                swgs.change_wine_store.append(label)

        if len(cw_file) > 0:
            for cw in cw_file:
                cn = (str(Path(cw).parent.parent)
                        .replace(f'{sw_wine}/', '')
                            .replace('/files', '')
                                .replace('/dist', '')
                )
                label = Gtk.Label(label=cn, name=Path(cn))
                swgs.change_wine_store.append(label)

        set_selected_wine()

    def cb_context_change_wine(action_name, parameter, data):
        '''___show change wine menu___'''

        label_frame_create_shortcut.set_label(msg.msg_dict['cw'])
        on_message_cs()

    def cb_change_wine_activate(self, position):
        '''___activate changed wine___'''

        if self.get_model().get_item(position) is not None:
            item = self.get_model().get_item(position).get_name()

            try:
                changed_wine = wine_list_dict[item]
            except:
                changed_wine = item

            write_changed_wine(changed_wine)
            set_label_wine_mode(None)

    def set_selected_wine():

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_dict = app_conf_info(app_conf, ['SW_USE_WINE'])
        exported_wine = app_conf_dict['SW_USE_WINE'].split('=')[-1]

        for n, x in enumerate(swgs.change_wine_store):
            if f'="{x.get_name()}"' == f'={exported_wine}':
                swgs.dropdown_change_wine.set_selected(n)
                print(f'{tc.VIOLET2}SELECTED_WINE:', tc.GREEN, x.get_name(), tc.END)

    def cb_btn_wine_tools(self):
        '''___wine tools buttons signal handler___'''

        if self.get_name() == wine_tools_dict['download_wine']:
            on_download_wine()

        elif self.get_name() == wine_tools_dict['wine_settings']:
            cb_btn_winecfg()

        elif self.get_name() == wine_tools_dict['wine_console']:
            cb_btn_wineconsole()

        elif self.get_name() == wine_tools_dict['regedit']:
            cb_btn_regedit()

        elif self.get_name() == wine_tools_dict['file_explorer']:
            cb_btn_file_explorer()

        elif self.get_name() == wine_tools_dict['uninstaller']:
            cb_btn_uninstaller()

        elif self.get_name() == wine_tools_dict['winetricks']:
            cb_btn_winetricks()

    def cb_btn_winecfg():
        '''___run wine settings___'''

        bar = progress_main
        bar.set_name('winecfg')

        thread = Thread(target=on_winecfg)
        thread.start()
        GLib.timeout_add(100, progress_on_thread, bar, thread, None)

    def on_winecfg():
        '''___run wine settings___'''

        func_name = f"WINECFG"
        echo_func_name(func_name)

    def cb_btn_wineconsole():
        '''___run wine console___'''

        bar = progress_main
        bar.set_name('wineconsole')
        thread = Thread(target=on_wineconsole)
        thread.start()
        GLib.timeout_add(100, progress_on_thread, bar, thread, None)

    def on_wineconsole():
        '''___run wine console___'''

        func_name = f"WINECONSOLE"
        echo_func_name(func_name)

    def cb_btn_regedit():
        '''___run wine regedit___'''

        bar = progress_main
        bar.set_name('regedit')
        thread = Thread(target=on_regedit)
        thread.start()
        GLib.timeout_add(100, progress_on_thread, bar, thread, None)

    def on_regedit():
        '''___run wine regedit___'''

        func_name = f"REGEDIT"
        echo_func_name(func_name)

    def cb_btn_file_explorer():
        '''___run wine file explorer___'''

        bar = progress_main
        bar.set_name('winefile')

        thread = Thread(target=on_explorer)
        thread.start()
        GLib.timeout_add(100, progress_on_thread, bar, thread, None)

    def on_explorer():
        '''___run wine file explorer___'''

        func_name = f"WINEFILE"
        echo_func_name(func_name)

    def cb_btn_uninstaller():
        '''___run wine uninstaller___'''

        bar = progress_main
        bar.set_name('uninstaller')
        thread = Thread(target=on_uninstaller)
        thread.start()
        GLib.timeout_add(100, progress_on_thread, bar, thread, None)

    def on_uninstaller():
        '''___run wine uninstaller___'''

        func_name = f"UNINSTALLER"
        echo_func_name(func_name)

    def cb_btn_winetricks():
        '''___show winetricks list view___'''

        return on_winetricks()

    def on_winetricks():
        '''___show winetricks list___'''

        if reveal_stack.get_visible_child() == scrolled_winetricks:
            pass
        else:
            add_winetricks_view()
            update_dll_store()

            pfx_path = get_pfx_path()
            pfx_label = get_pfx_name()[1]
            swgs.winetricks_title.set_label(vl_dict['winetricks'] + f' ({pfx_label})')

            on_show_hidden_widgets(vw_dict['winetricks'])

            reveal_stack.set_visible_child(scrolled_winetricks)
            swgs.scrolled_dll.set_min_content_width(width*0.2)
            swgs.scrolled_fonts.set_min_content_width(width*0.2)

            update_color_scheme()

    def on_tab_dll(self):
        swgs.stack_tabs.set_visible_child(swgs.scrolled_dll)

    def on_tab_fonts(self):
        swgs.stack_tabs.set_visible_child(swgs.scrolled_fonts)

    def on_dll_toggled(self, label, pic):
        '''___check_dll_list_on_toggle_button___'''

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
        '''___check_fonts_list_on_toggle_button___'''

        if self.get_sensitive():
            if self.get_active():
                pic.set_filename(IconPath.icon_checked)
                install_dll_list.append(label.get_label())
            else:
                pic.set_filename(None)
                install_dll_list.remove(label.get_label())

        elif not self.get_sensitive():
            install_dll_list.remove(label.get_label())

    def cb_btn_install_dll(self):
        '''___install changed dll from winetricks list___'''

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

            samples = f'{sw_sounds}/dialog/dialog-warning.oga'
            if Path(samples).exists():
                try:
                    Thread(target=media_play, args=(media_file, samples,
                                                    media_controls, 1.0, False
                                                    )).start()
                except:
                    pass
            return overlay_info(overlay, None, text_message, None, 3)
        else:
            t = Thread(target=install_dll, args=[dll_list])
            t.start()
            GLib.timeout_add(100, progress_on_thread, bar, t, None)

    def install_dll(dll_list):
        '''___install changed dll from winetricks list___'''

        pfx_path = get_pfx_path()
        app_path = get_app_path()
        read_w_log = get_dll_info(pfx_path)

        func_name = f"SW_WINETRICKS \"$@\""
        export_dll = f"export DLL=\"{' '.join(dll_list)}\""
        count = 1
        print(f'{tc.VIOLET2}setup_list: {tc.GREEN}{" ".join(dll_list)}{tc.END}')

        try:
            for line in fshread:
                count += 1
                sw_fsh.write_text(sw_fsh.read_text().replace(fshread[count], ''))

        except IndexError as e:
            print(tc.YELLOW)
            sw_fsh.write_text(fshread[0] + '\n' + fshread[1] + '\n' + export_dll + '\n' + func_name)
            run(f"{sw_fsh} {app_path}", shell=True)
            install_dll_list.clear()

####___Download_wine___.

    def on_download_wine():
        '''___show wine download list___'''

        if (stack_sidebar.get_visible_child() != frame_main
            and stack_sidebar.get_visible_child() != frame_wine_tools):
                on_back_main()
        else:
            btn_back_main.set_visible(True)

        if scrolled_install_wine.get_child() is not None:
            if reveal_stack.get_visible_child_name() != vw_dict['install_wine']:
                set_settings_widget(vw_dict['install_wine'], None)
                update_wine_view()
            else:
                activate_install_wine_settings()
                update_wine_view()
        else:
            add_wine_view()
            update_wine_view()
            activate_install_wine_settings()

    def cb_btn_update_wine_view(self):
        '''Check and update wine list from sources'''
        return on_update_wine_view()

    def on_update_wine_view():
        '''Check and update wine list from sources'''

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

    def cb_factory_dropdown_wine_setup(self, item_list):

        label = Gtk.Label(css_name='sw_label_desc', xalign=0)
        item_list.set_child(label)

    def cb_factory_dropdown_wine_bind(self, item_list):

        item = item_list.get_item()
        label = item_list.get_child()
        label.set_label(item.get_string())
        label.set_name(item.get_string())

    def cb_dropdown_download_wine(self, position):
        '''___dropdown changed wine version to download___'''

        return activate_install_wine_settings()

    def cb_btn_download_wine(self, dropdown):
        '''___download changed wine___'''

        bar = progress_main
        bar.set_name('install_wine')
        wine_ver = dropdown.get_selected_item().get_string()
        wine_ver = wine_ver.replace('-amd64', '').replace('-x86_64', '')
        wine_ver = ''.join([e for e in wine_ver if not e.isalpha()]).strip('-')

        if self.get_name() == 'WINE_1' :
            t = Thread(target=cb_btn_wine_1, args=[wine_ver])
            t.start()
            GLib.timeout_add(100, progress_on_thread, bar, t, None)
            self.get_parent().set_visible_child_name('RM_WINE_1')

        elif self.get_name() == 'WINE_2' :
            t = Thread(target=cb_btn_wine_2, args=[wine_ver])
            t.start()
            GLib.timeout_add(100, progress_on_thread, bar, t, None)

        elif self.get_name() == 'WINE_3' :
            t = Thread(target=cb_btn_wine_3, args=[wine_ver])
            t.start()
            GLib.timeout_add(100, progress_on_thread, bar, t, None)

        elif self.get_name() == 'WINE_4' :
            t = Thread(target=cb_btn_wine_4, args=[wine_ver])
            t.start()
            GLib.timeout_add(100, progress_on_thread, bar, t, None)

    def cb_btn_remove_wine(self, dropdown):
        '''___remove changed wine___'''

        bar = progress_main
        bar.set_name('install_wine')
        wine_ver = dropdown.get_selected_item().get_string()
        wine_ver = wine_ver.replace('-amd64', '').replace('-x86_64', '')
        wine_ver = ''.join([e for e in wine_ver if not e.isalpha()]).strip('-')
        print(wine_ver)

        if self.get_name() == 'RM_WINE_1' :
            t = Thread(target=cb_btn_rm_wine_1, args=[wine_ver])
            t.start()
            GLib.timeout_add(100, progress_on_thread, bar, t, None)

        elif self.get_name() == 'RM_WINE_2' :
            t = Thread(target=cb_btn_rm_wine_2, args=[wine_ver])
            t.start()
            GLib.timeout_add(100, progress_on_thread, bar, t, None)

        elif self.get_name() == 'RM_WINE_3' :
            t = Thread(target=cb_btn_rm_wine_3, args=[wine_ver])
            t.start()
            GLib.timeout_add(100, progress_on_thread, bar, t, None)

        elif self.get_name() == 'RM_WINE_4' :
            t = Thread(target=cb_btn_rm_wine_4, args=[wine_ver])
            t.start()
            GLib.timeout_add(100, progress_on_thread, bar, t, None)

    def cb_btn_wine_1(wine_ver):

        name_ver="STAG_VER"
        wine_name = f"WINE_1"
        echo_wine(wine_name, name_ver, wine_ver)

    def cb_btn_rm_wine_1(wine_ver):

        name_ver="STAG_VER"
        wine_name = f"RM_WINE_1"
        echo_wine(wine_name, name_ver, wine_ver)

    def cb_btn_wine_2(wine_ver):

        name_ver="SP_VER"
        wine_name = f"WINE_2"
        echo_wine(wine_name, name_ver, wine_ver)

    def cb_btn_rm_wine_2(wine_ver):

        name_ver="SP_VER"
        wine_name = f"RM_WINE_2"
        echo_wine(wine_name, name_ver, wine_ver)

    def cb_btn_wine_3(wine_ver):

        name_ver="GE_VER"
        wine_name = f"WINE_3"
        echo_wine(wine_name, name_ver, wine_ver)

    def cb_btn_rm_wine_3(wine_ver):

        name_ver="GE_VER"
        wine_name = f"RM_WINE_3"
        echo_wine(wine_name, name_ver, wine_ver)

    def cb_btn_wine_4(wine_ver):

        name_ver="STAG_VER"
        wine_name = f"WINE_4"
        echo_wine(wine_name, name_ver, wine_ver)

    def cb_btn_rm_wine_4(wine_ver):

        name_ver="STAG_VER"
        wine_name = f"RM_WINE_4"
        echo_wine(wine_name, name_ver, wine_ver)

    def cb_btn_source_wine(self):

        if self.get_name() == 'wine_staging':
            self.set_uri(wine_source_dict['wine_staging'])

        if self.get_name() == 'wine_steam_proton':
            self.set_uri(wine_source_dict['wine_steam_proton'])

        if self.get_name() == 'wine_proton_ge':
            self.set_uri(wine_source_dict['wine_proton_ge'])

        if self.get_name() == 'wine_lutris_ge':
            self.set_uri(wine_source_dict['wine_lutris_ge'])

        if self.get_name() == 'wine_lutris':
            self.set_uri(wine_source_dict['wine_lutris'])

####___Install_launchers___.

    def on_install_launchers():
        '''___show launchers grid view___'''

        if stack_sidebar.get_visible_child() != frame_main:
            on_back_main()
        else:
            btn_back_main.set_visible(True)

        if scrolled_install_launchers.get_child() is not None:
            if reveal_stack.get_visible_child_name() != vw_dict['install_launchers']:
                return set_settings_widget(vw_dict['install_launchers'], None)
            else:
                activate_install_launchers_settings()
        else:
            add_install_launchers_view()
            activate_install_launchers_settings()

    def cb_btn_install_launchers(self):

        self.remove_css_class('install')
        self.add_css_class('installing')
        bar = progress_main
        bar.set_name('install_launchers')
        bar.set_show_text(True)
        bar.set_text(f"{self.get_name()} {progress_dict['install_launchers']}")
        t = Thread(target=run_install_launchers, args=[self.get_name()])
        t.start()
        GLib.timeout_add(100, progress_on_thread, bar, t, None)

    def on_launchers_flow_activated(self, child, button):
        '''___run install launchers function___'''

        if button.get_name() == child.get_name():
            cb_btn_install_launchers(button)

    def run_install_launchers(x_name):
        '''___run install launchers function___'''

        launcher_name = str(x_name).upper()
        func = f'INSTALL_{launcher_name}'
        echo_func_name(func)

####___Settings___.

    def on_settings():
        '''___show settings menu___'''

        if scrolled_settings.get_child() is None:
            add_settings_menu()

        btn_back_main.set_visible(True)
        stack_sidebar.set_visible_child(frame_settings)

    def cb_btn_settings(self):
        '''___show settings submenu___'''

        if self.get_name() == settings_dict['launch_settings']:
            image_next.unparent()
            self.get_child().append(image_next)
            return on_launch_settings()

        if self.get_name() == settings_dict['mangohud_settings']:
            image_next.unparent()
            self.get_child().append(image_next)
            return on_mangohud_settings()

        if self.get_name() == settings_dict['vkbasalt_settings']:
            image_next.unparent()
            self.get_child().append(image_next)
            return on_vkbasalt_settings()

        if self.get_name() == settings_dict['set_app_default']:
            return cb_btn_app_conf_default()

        if self.get_name() == settings_dict['clear_shader_cache']:
            return cb_btn_clear_shader_cache()

    def set_settings_widget(view_widget, title):
        '''___activate settings submenu___'''

        app_name = get_out()
        try:
            on_app_conf_activate(view_widget)
        except Exception as e:
            print(e)
            if reveal_stack.get_visible_child().get_name() == 'launch_settings':
                text_message = [
                                msg.msg_dict['app_conf_incorrect'] + f' {app_name}.',
                                msg.msg_dict['app_conf_reset']
                ]
                func = [{app_conf_reset_request : (view_widget, title)}, None]
                dialog_question(swgs, None, text_message, None, func)
        else:
            if reveal_stack.get_visible_child().get_name() != view_widget:
                set_settings_page(view_widget, title)

    def app_conf_reset_request(view_widget, title):
        '''___Request for reset application settings___'''

        on_app_conf_default()
        set_settings_page(view_widget, title)

    def set_settings_page(view_widget, title):
        '''___show settings submenu___'''

        app_name = get_out()
        on_show_hidden_widgets(view_widget)
        widget = reveal_stack.get_child_by_name(view_widget)

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

        visible_name = str(reveal_stack.get_visible_child().get_name())

        if visible_name in view_widgets and visible_name != view_widget:
            reveal_stack.set_visible_child(widget)
            if type(widget) == Gtk.ScrolledWindow:
                widget.set_min_content_width(width*0.2)

        update_color_scheme()

    def on_app_conf_default():
        '''___reset application config to default___'''

        app_path = get_app_path()
        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        launcher_conf = Path(f"{sw_app_config}/.default/" + str(app_name))

        if not launcher_conf.exists():
            try:
                app_conf.write_text(sw_default_config.read_text())
            except IOError as e:
                print('<< app_conf_not_found >>')
            else:
                on_app_conf_activate(vw_dict['launch_settings'])
                on_app_conf_activate(vw_dict['mangohud_settings'])
                on_app_conf_activate(vw_dict['vkbasalt_settings'])
                start_mode()
        else:
            try:
                app_conf.write_text(launcher_conf.read_text())
            except IOError as e:
                print('<< app_conf_not_found >>')
            else:
                on_app_conf_activate(vw_dict['launch_settings'])
                on_app_conf_activate(vw_dict['mangohud_settings'])
                on_app_conf_activate(vw_dict['vkbasalt_settings'])
                start_mode()

    def cb_btn_app_conf_default():
        '''___request reset apllication config to default___'''

        text_message = [msg.msg_dict['reset_settings'], '']
        func = [on_app_conf_default, None]
        dialog_question(swgs, None, text_message, None, func)

    def cb_btn_menu_json_default(self):
        '''___request reset menu config to default___'''

        text_message = [msg.msg_dict['reset_settings'], '']
        func = [on_menu_conf_default, None]
        dialog_question(swgs, None, text_message, None, func)

    def on_menu_conf_default():
        '''___request reset menu configuration to default___'''

        set_menu_json_default()
        clear_cache_dir()
        check_bookmarks()
        check_css_custom()
        on_app_conf_activate(vw_dict['global_settings'])
        activate_global_settings()
        #clear_app_icons()

    def activate_global_settings():

        dict_ini = read_menu_conf()
        global scheme
        scheme = dict_ini.get('color_scheme')
        update_color_scheme()
        btn_scale_icons.set_value(int(dict_ini.get('icon_size')))
        btn_scale_shortcuts.set_value(int(dict_ini.get('shortcut_size')))
        sw_current_dir = dict_ini.get('current_dir')

        if dict_ini.get('autostart') == '1':
            swgs.switch_autostart.set_active(True)
        else:
            swgs.switch_autostart.set_active(False)

        if dict_ini.get('opengl_bg') == 'True':
            swgs.switch_opengl.set_active(True)
            swgs.dropdown_shaders.set_sensitive(True)
        else:
            swgs.switch_opengl.set_active(False)
            swgs.dropdown_shaders.set_sensitive(False)

        count = -1
        for lang in lang_labels:
            count += 1
            if dict_ini.get('language') in lang:
                swgs.dropdown_lang.set_selected(count)

        if dict_ini.get('icons') == 'custom':
            swgs.switch_icons.set_active(True)
        else:
            swgs.switch_icons.set_active(False)
            gtk_settings.props.gtk_icon_theme_name = "SWSuru++"

        if dict_ini.get('restore_menu') == 'on':
            swgs.switch_restore_menu.set_active(True)
        else:
            swgs.switch_restore_menu.set_active(False)

        if dict_ini.get('auto_stop') == 'on':
            swgs.switch_auto_stop.set_active(True)
        else:
            swgs.switch_auto_stop.set_active(False)

        if dict_ini.get('auto_hide_top_header') == 'on':
            swgs.switch_auto_hide_top.set_active(True)
        else:
            swgs.switch_auto_hide_top.set_active(False)
            top_headerbar_revealer.set_reveal_child(True)

        if dict_ini.get('auto_hide_bottom_header') == 'on':
            swgs.switch_auto_hide_bottom.set_active(True)
        else:
            swgs.switch_auto_hide_bottom.set_active(False)
            bottom_headerbar_revealer.set_reveal_child(True)

        swgs.entry_def_dir.set_placeholder_text(dict_ini.get('default_dir'))
        swgs.dropdown_shaders.set_selected(int(dict_ini.get('shader_src')))
        parent.set_default_size(int(dict_ini.get('width')), int(dict_ini.get('height')))

    def cb_btn_clear_shader_cache():
        '''___request clear shader cache___'''

        text_message = [msg.msg_dict['clear_shader_cache'], '']
        func = [on_clear_shader_cache, None]
        dialog_question(swgs, None, text_message, None, func)

    def on_clear_shader_cache():
        '''___clear shader cache___'''

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

        if sw_vkd3d_shader_cache.exists():
            for cache in sw_vkd3d_shader_cache.iterdir():
                if cache.is_dir():
                    shutil.rmtree(cache)
                if cache.is_file():
                    cache.unlink()

        if sw_dxvk_shader_cache.exists():
            for cache in sw_dxvk_shader_cache.iterdir():
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

        if sw_gst_cache.exists():
            for cache in sw_gst_cache.iterdir():
                if cache.is_dir():
                    shutil.rmtree(cache)
                if cache.is_file():
                    cache.unlink()

        print(f'{tc.RED}Clear shader cache...')

####___Launch_settings___.

    def on_launch_settings():
        '''___open application settings menu___'''

        on_settings()
        if scrolled_launch_settings.get_child() is not None:
            if reveal_stack.get_visible_child().get_name() != vw_dict['launch_settings']:
                set_settings_widget(
                                vw_dict['launch_settings'],
                                swgs.pref_group_title
                )
            else:
                pass
        else:
            add_launch_settings_view()

    def app_conf_chooser(data):
        '''___application configuration chooser window___'''

        def factory_apps_setup(self, items):
            '''___setup application config list___'''

            image = Gtk.Picture(
                        css_name='sw_picture',
                        hexpand=True,
                        halign=Gtk.Align.FILL,
                        content_fit=Gtk.ContentFit.COVER,
            )
            image.set_size_request(196, 96)

            pic = Gtk.Picture(
                        css_name='sw_uncheck',
                        hexpand=True,
                        halign=Gtk.Align.START,
                        content_fit=Gtk.ContentFit.SCALE_DOWN,
                        vexpand=True,
                        valign=Gtk.Align.END,
            )
            pic.set_size_request(32, 32)

            label = Gtk.Label(
                        css_name='sw_label_view',
                        xalign=0,
                        ellipsize=Pango.EllipsizeMode.END,
                        lines=2,
                        wrap=True,
                        natural_wrap_mode=True,
                        hexpand=True,
                        halign=Gtk.Align.FILL,
                        vexpand=True,
                        valign=Gtk.Align.CENTER,
            )
            check = Gtk.CheckButton(
                        css_name='sw_checkbutton',
                        halign=Gtk.Align.START,
                        vexpand=True,
                        valign=Gtk.Align.CENTER,
            )
            check.get_first_child().set_visible(False)
            check.set_child(pic)

            box = Gtk.Box(
                        css_name='sw_box_overlay',
                        orientation=Gtk.Orientation.HORIZONTAL,
                        spacing=8,
                        hexpand=True,
                        vexpand=True,
                        valign=Gtk.Align.END,
            )
            box.append(check)
            box.append(label)

            overlay = Gtk.Overlay(
                        css_name='sw_box_view',
                        margin_start=8,
                        margin_end=8,
                        margin_top=8,
                        margin_bottom=8,
            )
            overlay.set_child(image)
            overlay.add_overlay(box)

            items.set_child(overlay)

        def factory_apps_bind(self, items):
            '''___bind application config list___'''

            item = items.get_item()
            overlay = items.get_child()
            image = overlay.get_first_child()
            box = overlay.get_last_child()
            check = box.get_first_child()
            label = check.get_next_sibling()
            pic = check.get_child()
            path = item.get_path()

            n = ''.join([x for x in Path(path).stem if x.isalnum()])
            p = f'{sw_app_hicons}/{n}'
            app_dict = app_info(path)

            try:
                image.set_filename(f'{sw_img}/' + Path(path).stem + '_x256.png')
            except:
                pass
            else:
                label.set_label(Path(path).stem)

            for x in sw_app_hicons.iterdir():
                if p in str(x):
                    image.set_filename(str(x))
                    label.set_label(str(x.stem.split('_')[-2]))
                    break

            check.set_name(item.get_path())
            check.connect('toggled', cb_check, pic)

            if check_header.get_active():
                pic.set_filename(IconPath.icon_checked)
                check.set_active(True)
            else:
                pic.set_filename(None)
                data.clear()

        def update_apps_view():
            '''___update application config list store___'''

            list_apps_store.remove_all()
            for s in sw_shortcuts.iterdir():
                for c in sw_app_config.iterdir():
                    if c.stem == s.stem:
                        f = Gio.File.new_for_path(f'{c}')
                        list_apps_store.append(f)

        def cb_check(self, pic):
            '''___toggle choosed item in view___'''

            if self.get_active():
                pic.set_filename(IconPath.icon_checked)
                data.append(self.get_name())
            else:
                pic.set_filename(None)
                data.remove(self.get_name())

        def cb_check_all(self, pic):
            '''___toggle all item in view___'''

            if self.get_active():
                pic.set_filename(IconPath.icon_checked)
            else:
                pic.set_filename(None)

            return update_apps_view()

        list_apps_store = Gio.ListStore()
        apps_model = Gtk.SingleSelection.new(list_apps_store)

        apps_factory = Gtk.SignalListItemFactory()
        apps_factory.connect('setup', factory_apps_setup)
        apps_factory.connect('bind', factory_apps_bind)

        apps_view = Gtk.GridView(
                        css_name='sw_pref_box',
                        hexpand=True,
                        halign=Gtk.Align.CENTER,
        )
        apps_view.set_model(apps_model)
        apps_view.set_factory(apps_factory)

        label_header = Gtk.Label(
                        css_name='sw_label',
                        label=ctx_dict['select_all'][0],
        )
        pic_header = Gtk.Picture(
                        css_name='sw_uncheck',
                        hexpand=True,
                        halign=Gtk.Align.FILL,
                        content_fit=Gtk.ContentFit.COVER,
        )
        pic_header.set_size_request(32, 32)

        check_header = Gtk.CheckButton(
                        css_name='sw_checkbutton',
                        child=pic_header,
        )
        check_header.get_first_child().set_visible(False)
        check_header.connect('toggled', cb_check_all, pic_header)

        apps_header = Gtk.Box(
                        css_name='sw_box_view',
                        orientation=Gtk.Orientation.HORIZONTAL,
                        hexpand=True,
        )
        apps_header.append(check_header)
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
        apps_grid.attach(apps_header, 0,0,1,1)
        apps_grid.attach(scrolled, 0,1,1,1)

        ok = Gtk.Button(
                        css_name='sw_button_accept',
                        valign=Gtk.Align.CENTER,
                        label=msg.msg_dict['ok'],
        )
        ok.set_size_request(160,-1)

        cancel = Gtk.Button(
                        css_name='sw_button_cancel',
                        valign=Gtk.Align.CENTER,
                        label=msg.msg_dict['cancel'],
        )
        cancel.set_size_request(160,-1)

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
        win = Gtk.Window(
                        css_name='sw_window',
                        application=swgs,
                        titlebar=headerbar,
                        modal=True,
                        child=apps_grid,
                        transient_for=parent,
        )
        win.remove_css_class('background')
        win.add_css_class('sw_background')
        win.set_default_size(1164, 640)
        ok.connect('clicked', cb_btn_ok_choose, win, data)
        cancel.connect('clicked', cb_btn_close, win)
        update_apps_view()
        win.present()

    def cb_btn_ls_move(self):
        '''___Show application configuration chooser window___'''

        data = list()
        return app_conf_chooser(data)

    def cb_btn_ok_choose(self, win, data):
        '''___Moving settings after confirmation from the user___'''

        if data is not None:
            if len(data) > 0:
                data = list(set(data))
                for x in data:
                    on_move_settings(x)
                else:
                    win.close()
            else:
                win.close()
        else:
            win.close()

    def on_move_settings(x_conf):
        '''___Moving current settings to other prefix'''

        app_name = get_out()
        src_conf = Path(f'{sw_app_config}/{app_name}')
        dst_conf = Path(x_conf)
        src_lst = src_conf.read_text().splitlines()
        dst_lst = dst_conf.read_text().splitlines()
        lst = list()
        print(dst_conf)
        for s, d in zip(src_lst, dst_lst):
            if (not f'{str_sw_use_pfx}=' in s
                and not f'{str_sw_use_wine}=' in s):
                    dst = dst_conf.read_text()
                    dst_conf.write_text(dst.replace(d, s))

    def on_app_conf_activate(x_settings):
        '''___activate application config in settings menu___'''

        ####___Activate download wine settings___.

        if x_settings == vw_dict['install_wine']:
            activate_install_wine_settings()

        ####___Activate launcher_settings___.

        if x_settings == vw_dict['install_launchers']:
            activate_install_launchers_settings()

        ####___Activate launch_settings___.

        if x_settings == vw_dict['launch_settings']:
            activate_launch_settings()

        ####___Activate mangohud settings___.

        if x_settings == vw_dict['mangohud_settings']:
            activate_mangohud_settings()
            activate_colors_settings()

        ####___Activate vkbasalt settings___.

        if x_settings == vw_dict['vkbasalt_settings']:
            activate_vkbasalt_settings()

        ####___Activate colors settings___.

        if x_settings == vw_dict['global_settings']:
            activate_colors_settings()

    def activate_install_wine_settings():
        '''___disable button if launchers is installed___'''

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
        '''___disable button if launchers is installed___'''

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
        '''___set launch_settings from application config___'''

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

        cpu_value = cpu_dict[export_cpu_topology].split('=')[1].split(':')[0].strip('"')
        if cpu_value == "":
            cpu_value = 0.0

        swgs.btn_spin_cpu.set_value(float(cpu_value))

    def activate_mangohud_settings():
        '''___set mangohud settings from application config___'''

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
        '''___set vkbasalt settings from application config___'''

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_vk_dict = app_conf_info(app_conf, [export_vkbasalt_effects])

        for v in check_btn_vk_list:
            if f'{v.get_name()}' in app_conf_vk_dict[export_vkbasalt_effects]:
                v.set_active(True)
            else:
                v.set_active(False)

    def activate_colors_settings():
        '''___set colors settings from application config___'''

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_mh_dict = app_conf_info(app_conf, [export_mangohud_config])

        export_string = app_conf_mh_dict[export_mangohud_config]
        export_name = export_string.split('=')[0]
        export_value = export_string.removeprefix(f'{export_name}=').strip('"')
        value_list = export_value.split(',')
        css_string_list = sw_css_custom.read_text().splitlines()

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

    def on_row_entry_icon_press(self, position):
        '''___writing a value from entry widget to the application config
        when user click the edit button___'''

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_dict = app_conf_info(app_conf, [self.get_name()])

        app_conf.write_text(
            app_conf.read_text().replace(
                app_conf_dict[self.get_name()],
                app_conf_dict[self.get_name()].split('=')[0] + f'="{self.get_text()}"'
            )
        )

    def on_row_entry_enter(self):
        '''___writing a value from entry widget to the application config
        when user press the Enter key___'''

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_dict = app_conf_info(app_conf, [self.get_name()])

        app_conf.write_text(
            app_conf.read_text().replace(
                app_conf_dict[self.get_name()],
                app_conf_dict[self.get_name()].split('=')[0] + f'="{self.get_text()}"'
            )
        )

    def on_launch_flow_activated(self, child, switch_ls):
        '''___activate flowbox child in launch settings___'''

        if switch_ls.get_name() == child.get_name():
            if not switch_ls.get_active():
                switch_ls.set_active(True)
            else:
                switch_ls.set_active(False)

    def on_combo_setup(self, item_list):
        '''___setup item in combobox item list___'''

        item = item_list.get_item()
        label = Gtk.Label(css_name='sw_label_desc')
        label.set_xalign(0)
        item_list.set_child(label)

    def on_combo_bind(self, item_list):
        '''___bind item in combobox item list___'''

        item = item_list.get_item()
        label = item_list.get_child()
        label.set_label(item.get_string())

    def on_row_combo_activate(self, gparam):
        '''___write selected item in application config___'''

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_dict = app_conf_info(app_conf, lp_title)

        i = self.get_selected_item().get_string()

        ####___windows version___.

        try:
            v = winver_dict[i]
        except:
            pass
        else:
            app_conf.write_text(
                app_conf.read_text().replace(
                    app_conf_dict[self.get_name()],
                    app_conf_dict[self.get_name()].split('=')[0] + f'="{v}"'
                )
            )

        ####___windows architecture___.

        try:
            a = winarch_dict[i]
        except:
            pass
        else:
            app_conf.write_text(
                app_conf.read_text().replace(
                    app_conf_dict[self.get_name()],
                    app_conf_dict[self.get_name()].split('=')[0] + f'="{a}"'
                )
            )

        ####___registry patches___.

        if 'REGEDIT' in self.get_name():
            if i in reg_patches:
                app_conf.write_text(
                    app_conf.read_text().replace(
                        app_conf_dict[self.get_name()],
                        app_conf_dict[self.get_name()].split('=')[0] + f'="{i}"'
                    )
                )

        ####___dxvk version___.

        if 'DXVK' in self.get_name():
            if i in dxvk_ver:
                app_conf.write_text(
                    app_conf.read_text().replace(
                        app_conf_dict[self.get_name()],
                        app_conf_dict[self.get_name()].split('=')[0] + f'="{i}"'
                    )
                )

        ####___vkd3d version___.

        if 'VKD3D' in self.get_name():
            if i in vkd3d_ver:
                app_conf.write_text(
                    app_conf.read_text().replace(
                        app_conf_dict[self.get_name()],
                        app_conf_dict[self.get_name()].split('=')[0] + f'="{i}"'
                    )
                )

        ####___fsr mode___.

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

    def on_row_theme_activate(self, param):
        '''___write selected item in custom css___'''
        color = self.get_selected_item().get_string()
        sample = default_themes[color]

        with open(sw_css_custom, 'w') as f:
            f.write(sample)
            f.close()
            activate_colors_settings()

    def cb_btn_regedit_patch(self, combo):
        '''___activate registry patch for current prefix___'''

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
        '''___registry patch for current prefix___'''

        echo_func_name('TRY_REGEDIT_PATCH')

    def on_fps_adjustment(self):
        '''___write fps value in application config___'''

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
        '''___write cpu core value in application config___'''

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        cpu_dict = app_conf_info(app_conf, [export_cpu_topology])
        cpu = int(self.get_value())

        if cpu == 0:
            str_cpu = ''
        else:
            str_cpu = f'{cpu}:'

        cpu_idx = []
        for i in range(int(cpu)):
            cpu_idx.append(i)

        idx = str(cpu_idx)[1:-1].replace(' ', '')

        app_conf.write_text(
            app_conf.read_text().replace(
                cpu_dict[export_cpu_topology],
                cpu_dict[export_cpu_topology].split('=')[0] + f'="{str_cpu}{idx}"'
            )
        )

    def cb_btn_switch_ls(self, state):
        '''___update switch list when changed switch state___'''

        app_name = get_out()
        app_conf = Path(f"{sw_app_config}/" + str(app_name))
        app_conf_dict = app_conf_info(app_conf, switch_labels)

        if self.get_active():
            app_conf.write_text(
                app_conf.read_text().replace(
                    app_conf_dict[self.get_name()],
                    app_conf_dict[self.get_name()].replace('0','1')
                )
            )

        elif not self.get_active():
            app_conf.write_text(
                app_conf.read_text().replace(
                    app_conf_dict[self.get_name()],
                    app_conf_dict[self.get_name()].replace('1','0')
                )
            )

####___Mangohud_settings___.

    def on_mangohud_settings():

        on_settings()
        if scrolled_mangohud_settings.get_child() is not None:
            if reveal_stack.get_visible_child_name() != vw_dict['mangohud_settings']:
                return set_settings_widget(
                                    vw_dict['mangohud_settings'],
                                    swgs.pref_group_mh_title,
                )
            else:
                pass
        else:
            add_mangohud_settings_view()

    def on_mango_flow_activated(self, child, btn_switch_mh):
        '''___activate flowbox child in mangohud settings___'''

        if btn_switch_mh.get_name() == child.get_name():
            if not btn_switch_mh.get_active():
                btn_switch_mh.set_active(True)
            else:
                btn_switch_mh.set_active(False)

    def cb_btn_switch_mh(self, state):
        '''___write mangohud config when toggle check button___'''

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

    def on_reload_cfg(key_reload):
        '''___reload mangohud config___'''

        def kDown():
            Popen(
                f"xdotool keydown {key_reload}",
                shell=True
                )

        def kUp():
            Popen(
                f"xdotool keyup {key_reload}",
                shell=True
                )

        Timer(0.01, kDown).start()
        Timer(0.2, kUp,).start()

    def cb_btn_mh_preview(self):
        '''___preview opengl cube with mangohud overlay___'''

        def unlock_button(button):
            button.set_sensitive(True)

        self.set_sensitive(False)
        thread_preview = Thread(target=on_btn_mh_preview)
        thread_preview.start()
        GLib.timeout_add(1000, check_alive, thread_preview, unlock_button, self, None)

    def on_btn_mh_preview():

        get_mangohud_config()
        on_reload_cfg(key_reload)
        Popen(f"mangohud --dlsym {sw_cube} -v", shell=True)

    def get_mangohud_config():
        '''___get mangohud config from application config'''

        global gl_x, gl_y, mh_config, key_reload

        key_reload = 'Control_L+Shift_L+r'
        gl_x = '-12'
        gl_y = '12'

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

        font_size = (int(height)/55)
        mhud_conf = (f'reload_cfg={key_reload},offset_x={gl_x},offset_y={gl_y},\
                    {default_mangohud},font_size={font_size},{mh_config}'
        )
        environ["MANGOHUD_CONFIG"] = pathsep + mhud_conf

    def on_mh_color_set(self, entry):
        '''___set custom mangohud indicator colors___'''

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

    def on_theme_color_set(self, gparam, entry):
        '''___set custom color scheme colors___'''

        entry.set_text(self.get_rgba().to_string())

    def on_row_entry_color(self, position):
        '''___save custom color from entry string___'''

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

    def cb_btn_save_theme(self):
        '''___apply custom color scheme___'''

        css_change_list.clear()
        avg_colors = dict()
        css_string_list = sw_css_custom.read_text().splitlines()
        count = 0
        for entry, invert in zip(entry_theme_color_list, invert_dcolors):
            color = f" {entry.get_text()};"
            split_color = entry.get_text().replace('rgba', '').replace('rgb', '')[1:-1].split(',')
            avg_color = (int(split_color[0]) + int(split_color[1]) + int(split_color[2])) / 3
            r = int(split_color[0])
            g = int(split_color[1])
            b = int(split_color[2])

            if avg_color < 64:
                avg_color = avg_color + 192

            elif 64 <= avg_color < 96:
                avg_color = avg_color + 128

            elif 96 <= avg_color < 128:
                avg_color = avg_color + 96

            elif 128 <= avg_color < 160:
                avg_color = avg_color - 96

            elif 160 <= avg_color < 192:
                avg_color = avg_color - 128

            elif 192 <= avg_color <= 255:
                avg_color = avg_color - 192

            avg_colors[f'{invert}'] = f' rgba({int(avg_color)},{int(avg_color)},{int(avg_color)}, 1.0);'

            print(entry.get_name())
            if entry.get_name() == '@define-color sw_accent_fg_color':
                define_ipc = '@define-color sw_invert_progress_color'
                invert_progress_color = f' rgba({255 - r},{255 - g},{255 - b},1.0);'
                for string in css_string_list:
                    if define_ipc in string:
                        sw_css_custom.write_text(
                            sw_css_custom.read_text().replace(
                                string,
                                define_ipc + invert_progress_color
                            )
                        )

            change = entry.get_name() + color
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

        on_toggled_custom(btn_custom, pic_custom)
        btn_custom.set_active(True)

####___VkBasalt_settings___.

    def on_vkbasalt_settings():

        on_settings()
        if scrolled_vkbasalt_settings.get_child() is not None:
            if reveal_stack.get_visible_child_name() != vw_dict['vkbasalt_settings']:
                return set_settings_widget(
                                    vw_dict['vkbasalt_settings'],
                                    swgs.pref_group_vk_title,
                )
            else:
                pass
        else:
            add_vkbasalt_settings_view()

    def on_vk_flow_activated(self, child, btn_switch_vk):

        if btn_switch_vk.get_name() == child.get_name():
            if not btn_switch_vk.get_active():
                btn_switch_vk.set_active(True)
            else:
                btn_switch_vk.set_active(False)

    def cb_btn_switch_vk(self, state):

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
        '''___set_vkbasalt_effect_entensity___'''

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

        if stack_sidebar.get_visible_child() != frame_main:
            on_back_main()
            btn_back_main.set_visible(True)
        else:
            btn_back_main.set_visible(True)

        if scrolled_global_settings.get_child() is not None:
            if reveal_stack.get_visible_child_name() != vw_dict['global_settings']:
                return set_settings_widget(
                                    vw_dict['global_settings'],
                                    None,
                )
            else:
                pass
        else:
            add_global_settings_view()

    def get_folder(self, res, window):

        try:
            result = self.select_folder_finish(res)
        except GLib.GError as e:
            result = None
        else:
            swgs.entry_def_dir.set_text(str(result.get_path()))
            on_def_dir()

        return result

    def cb_btn_def_dir(self):

        title = 'Change Directory'
        dialog = dialog_directory(title)
        dialog.select_folder(
                    parent=parent,
                    cancellable=Gio.Cancellable(),
                    callback=get_folder,
                    user_data=parent,
                    )

    def cb_entry_def_dir(self, position):
        '''___set the default directory to open files___'''

        return on_def_dir()

    def on_def_dir():
        '''___set the default directory to open files___'''

        string = swgs.entry_def_dir.get_text()
        if (string != ''
            and Path(string).exists()):
                dict_ini = read_menu_conf()
                dict_ini['default_dir'] = f'{string}'
                write_menu_conf(dict_ini)
        else:
            text_message = str_wrong_path
            samples = f'{sw_sounds}/dialog/dialog-warning.oga'
            if Path(samples).exists():
                try:
                    Thread(target=media_play, args=(media_file, samples,
                                                    media_controls, 1.0, False
                                                    )).start()
                except:
                    pass
            return overlay_info(overlay, None, text_message, None, 3)

    def on_lang_setup(self, item_list):
        '''___setup language item list___'''

        item = item_list.get_item()
        label = Gtk.Label(css_name='sw_label_desc')
        label.set_xalign(0)
        item_list.set_child(label)

    def on_lang_bind(self, item_list):
        '''___bind language item list___'''

        item = item_list.get_item()
        label = item_list.get_child()
        label.set_label(item.get_string())

    def on_lang_activate(self, gparam):
        '''___set the locale of the selected language___'''

        str_lang = self.get_selected_item().get_string()

        for lang in lang_labels:
            if str_lang in lang:
                dict_ini = read_menu_conf()
                dict_ini['language'] = f'{lang}'
                write_menu_conf(dict_ini)

    def on_shaders_setup(self, item_list):
        '''___setup shaders item list___'''

        item = item_list.get_item()
        label = Gtk.Label(css_name='sw_label_desc')
        label.set_xalign(0)
        item_list.set_child(label)

    def on_shaders_bind(self, item_list):
        '''___bind shaders item list___'''

        item = item_list.get_item()
        label = item_list.get_child()
        label.set_label(item.get_string())

    def on_shaders_activate(self, gparam):
        '''___activate changed shaders for opengl background___'''

        str_shader = self.get_selected_item().get_string()

        count = -1
        for f, l in zip(fragments_list, fragments_labels):
            count += 1
            if str_shader == l:
                environ['FRAGMENT_NUM'] = str(count)
                environ['FRAGMENT_INDEX'] = str(count)
                write_changed_shaders(count)
                break

    def write_changed_shaders(count):
        '''___write changed shaders for opengl background___'''

        dict_ini = read_menu_conf()
        dict_ini['shader_src'] = f'{count}'
        write_menu_conf(dict_ini)

    def on_switch_opengl_bg(self, state):
        '''___enable or disable opengl background___'''

        dict_ini = read_menu_conf()

        if self.get_active():
            environ['SW_OPENGL'] = '1'
            dict_ini['opengl_bg'] = 'True'
            swgs.dropdown_shaders.set_sensitive(True)

        elif not self.get_active():
            environ['SW_OPENGL'] = '0'
            dict_ini['opengl_bg'] = 'False'
            swgs.dropdown_shaders.set_sensitive(False)

        write_menu_conf(dict_ini)

    def on_switch_autostart(self, state):
        '''___create or delete autostart tray shortcut___'''

        dict_ini = read_menu_conf()

        if self.get_active():
            dict_ini['autostart'] = '1'
            if not sw_tray_autostart.parent.exists():
                sw_tray_autostart.parent.mkdir(parents=True, exist_ok=True)
                sw_tray_autostart.write_text(sample_tray_desktop)
                sw_tray_autostart.chmod(0o755)
            else:
                if not sw_tray_autostart.exists():
                    sw_tray_autostart.write_text(sample_tray_desktop)
                    sw_tray_autostart.chmod(0o755)

        if not self.get_active():
            dict_ini['autostart'] = '0'
            if sw_tray_autostart.exists():
                sw_tray_autostart.unlink()

        write_menu_conf(dict_ini)

    def get_sys_icons():
        '''___try get system icons theme___'''

        sys_icons = getenv('SW_GTK_ICON_THEME')
        if sys_icons is None:
            gtk_ini = f'{Path.home()}/.config/gtk-3.0/settings.ini'
            if Path(gtk_ini).exists():
                sys_icons = [x.split('=')[1] for x in Path(gtk_ini).read_text().splitlines() if 'gtk-icon-theme-name=' in x]
                if sys_icons != []:
                    sys_icons = sys_icons[0]
                else:
                    sys_icons = 'SWSuru++'
            else:
                sys_icons = 'SWSuru++'
        else:
            sys_icons = 'SWSuru++'

        return sys_icons

    def on_switch_icons(self, state):
        '''___switch icons theme___'''

        gtk_settings = Gtk.Settings.get_for_display(display)
        sys_icons = get_sys_icons()
        dict_ini = read_menu_conf()

        if self.get_active():
            dict_ini['icons'] = 'custom'
            gtk_settings.props.gtk_icon_theme_name = f"{sys_icons}"
            print(f'{tc.VIOLET}SYSTEM_ICONS: {tc.BLUE}{sys_icons}')

        if not self.get_active():
            dict_ini['icons'] = 'builtin'
            gtk_settings.props.gtk_icon_theme_name = "SWSuru++"
            print(f'{tc.VIOLET}BUILTIN_ICONS: {tc.BLUE}SWSuru++')

        write_menu_conf(dict_ini)

    def on_switch_restore_menu(self, state):
        '''___switch restore menu mode___'''

        dict_ini = read_menu_conf()

        if self.get_active():
            dict_ini['restore_menu'] = 'on'

        if not self.get_active():
            dict_ini['restore_menu'] = 'off'

        write_menu_conf(dict_ini)

    def on_switch_auto_stop(self, state):
        '''___switch auto stop mode___'''

        dict_ini = read_menu_conf()

        if self.get_active():
            dict_ini['auto_stop'] = 'on'

        if not self.get_active():
            dict_ini['auto_stop'] = 'off'

        write_menu_conf(dict_ini)

    def on_switch_auto_hide_top_header(self, state):
        '''___switch auto hide headers mode___'''

        dict_ini = read_menu_conf()

        if self.get_active():
            dict_ini['auto_hide_top_header'] = 'on'
            environ['SW_AUTO_HIDE_TOP_HEADER'] = '1'
            top_headerbar_revealer.set_reveal_child(False)

        if not self.get_active():
            dict_ini['auto_hide_top_header'] = 'off'
            environ['SW_AUTO_HIDE_TOP_HEADER'] = '0'
            top_headerbar_revealer.set_reveal_child(True)

        write_menu_conf(dict_ini)

    def on_switch_auto_hide_bottom_header(self, state):
        '''___switch auto hide headers mode___'''

        dict_ini = read_menu_conf()

        if self.get_active():
            dict_ini['auto_hide_bottom_header'] = 'on'
            environ['SW_AUTO_HIDE_BOTTOM_HEADER'] = '1'
            bottom_headerbar_revealer.set_reveal_child(False)

        if not self.get_active():
            dict_ini['auto_hide_bottom_header'] = 'off'
            environ['SW_AUTO_HIDE_BOTTOM_HEADER'] = '0'
            bottom_headerbar_revealer.set_reveal_child(True)

        write_menu_conf(dict_ini)

    def on_switch_tray():
        '''___enable or disable tray at startup___'''

        dict_ini = read_menu_conf()
        if dict_ini['on_tray'] == 'True':
            dict_ini['on_tray'] = 'False'
        else:
            dict_ini['on_tray'] = 'True'

        write_menu_conf(dict_ini)

    def on_controller_settings():
        '''______'''
        pass

####___About___.

    def check_sw_update():

        func_name = f"try_update_sw"
        echo_func_name(func_name)

    def cb_btn_about(self):
        '''___show_about_submenu___'''

        if self.get_name() == 'about_update':
            t = Thread(target=check_sw_update)
            t.start()
        else:
            stack_sidebar.set_visible_child(frame_stack)
            grid = swgs.stack_about.get_child_by_name(self.get_name())
            swgs.btn_back_about.unparent()
            swgs.label_back_about.set_label(about_dict[self.get_name()])
            grid.attach(swgs.btn_back_about,0,0,1,1)
            swgs.stack_about.set_visible_child_name(self.get_name())

    def cb_btn_back_about(self):
        '''___back to main about submenu page___'''

        stack_sidebar.set_visible_child(frame_about)

    def on_about():
        '''___show_about_menu___'''

        if scrolled_about.get_child() is None:
            add_about()

        str_sw_version = check_sw_version()
        swgs.title_news.set_label(sw_program_name + ' ' + str_sw_version,)
        swgs.about_version.set_label(str_sw_version)

        if not sidebar_revealer.get_reveal_child():
            on_sidebar()

        if stack_sidebar.get_visible_child() != frame_main:
            on_back_main()
        else:
            btn_back_main.set_visible(True)
            stack_sidebar.set_visible_child(frame_about)

        update_color_scheme()

    def cb_btn_website(self):
        '''___open source page on github___'''
        self.set_uri(website_source)

    def cb_btn_github(self):
        '''___open source page on github___'''
        self.set_uri(github_source)

    def cb_btn_discord(self):
        '''___open web page invite to discord___'''
        self.set_uri(discord_source)

    def cb_btn_telegram(self):
        '''___open web page invite to telegram___'''
        self.set_uri(telegram_source)

    def cb_btn_license(self):
        '''___open web page about license___'''
        self.set_uri(license_source)

    def cb_btn_donation(self):
        '''___open web page about donation___'''

        if self.get_name() != '':
            if (self.get_name().startswith('https://')
                or self.get_name().startswith('http://')):
                    self.set_uri(self.get_name())
            else:
                clipboard.set(str(self.get_name()))
                text_message = msg.msg_dict['copied_to_clipboard']
                return overlay_info(overlay, None, text_message, None, 3)

####___Debug___.

    def cb_btn_debug(self):
        '''___activate button debug mode___'''

        return on_debug()

    def on_debug():
        '''___run application in debug mode___'''

        on_start()

    def debug_vulkan():
        '''___run application in vulkan debug mode___'''

        func_name = f"DEBUG_VULKAN"
        echo_func_name(func_name)

    def debug_opengl():
        '''___run application in opengl debug mode___'''

        func_name = f"SW_USE_OPENGL='1' DEBUG_VULKAN"
        echo_func_name(func_name)

    def on_terminate(proc):
        print("process {} terminated with exit code {}".format(proc, proc.returncode))

    def on_stop():
        '''___terminate all wine process and stop progress___'''

        winedevices = ([p.info['pid'] for p in psutil.process_iter(['pid', 'name'])
                                if 'winedevice' in p.info['name']]
        )
        for proc in winedevices:
            psutil.Process(proc).kill()

        webkits = ([p.info['pid'] for p in psutil.process_iter(['pid', 'name'])
                                if 'WebKitNetworkProcess' in p.info['name']]
        )
        for proc in webkits:
            psutil.Process(proc).kill()

        timeout_list_clear(None)

        image_btn_start.set_visible(True)
        label_btn_start.set_visible(True)
        progress_main.set_fraction(0.0)
        progress_main.set_show_text(False)
        progress_main.set_visible(False)
        stack_progress_main.set_visible_child(stack_panel)
        spinner.stop()

        overlay_info(overlay, None, msg.msg_dict['termination'], None, 3)
        cmd = f"{sw_scripts}/sw_stop"
        Popen(cmd, shell=True)

    def cb_btn_popover_colors(self):
        '''___popup cloor scheme chooser menu___'''

        popover_colors.popup()

    def cb_btn_popover_scale(self):
        '''___popup icon scale button___'''

        path = Path(entry_path.get_name())

        if path == sw_shortcuts:
            popover_scale_sc.popup()
        else:
            popover_scale.popup()

    def on_toggled_dark(self, pic):
        '''___toggle color scheme___'''

        if self.get_active():
            pic.add_css_class('checked')
        else:
            pic.remove_css_class('checked')

        popover_colors.popdown()
        return on_dark_color_scheme()

    def on_dark_color_scheme():
        '''___set dark color scheme___'''

        global scheme
        scheme = 'dark'
        dict_ini = read_menu_conf()
        dict_ini['color_scheme'] = 'dark'
        write_menu_conf(dict_ini)

        css_provider.load_from_file(Gio.File.new_for_path(bytes(sw_css_dark)))
        Gtk.StyleContext.add_provider_for_display(
                                        display,
                                        css_provider,
                                        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )
        set_define_colors()
        start_mode()

    def on_toggled_light(self, pic):
        '''___toggle color scheme___'''

        if self.get_active():
            pic.add_css_class('checked')
        else:
            pic.remove_css_class('checked')

        popover_colors.popdown()
        return on_light_color_scheme()

    def on_light_color_scheme():
        '''___set light color scheme___'''

        global scheme
        scheme = 'light'
        dict_ini = read_menu_conf()
        dict_ini['color_scheme'] = 'light'
        write_menu_conf(dict_ini)

        css_provider.load_from_file(Gio.File.new_for_path(bytes(sw_css_light)))
        Gtk.StyleContext.add_provider_for_display(
                                        display,
                                        css_provider,
                                        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )
        set_define_colors()
        start_mode()

    def on_toggled_custom(self, pic):
        '''___toggle color scheme___'''

        if self.get_active():
            pic.add_css_class('checked')
        else:
            pic.remove_css_class('checked')

        popover_colors.popdown()
        return on_custom_color_scheme()

    def on_custom_color_scheme():
        '''___set custom color scheme___'''

        global scheme
        scheme = 'custom'
        dict_ini = read_menu_conf()
        dict_ini['color_scheme'] = 'custom'
        write_menu_conf(dict_ini)

        css_provider.load_from_file(Gio.File.new_for_path(bytes(sw_css_custom)))
        Gtk.StyleContext.add_provider_for_display(
                                        display,
                                        css_provider,
                                        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )
        set_define_colors()
        start_mode()

    def cb_btn_icon_position(self):
        '''___change shortcut icons position in view___'''

        dict_ini = read_menu_conf()

        if dict_ini['icon_position'] == 'horizontal':
            dict_ini['icon_position'] = 'vertical'
            write_menu_conf(dict_ini)

        elif dict_ini['icon_position'] == 'vertical':
            dict_ini['icon_position'] = 'horizontal'
            write_menu_conf(dict_ini)

        parent_file = get_parent_file()
        if parent_file.get_path() is not None:
            update_grid_view(parent_file.get_path())
        else:
            update_grid_view_uri(parent_file.get_uri())

    def cb_ctrl_enter_overlay(self, x, y, label_revealer, image):
        '''___cursor position signal handler___'''

        label_revealer.set_reveal_child(True)

    def cb_ctrl_leave_overlay(self, label_revealer, image):
        '''___cursor position signal handler___'''

        label_revealer.set_reveal_child(False)

    def cb_ctrl_enter_bookmarks(self, x, y, btn_remove):
        '''___cursor position signal handler___'''

        btn_remove.set_visible(True)

    def cb_ctrl_leave_bookmarks(self, btn_remove):
        '''___cursor position signal handler___'''

        btn_remove.set_visible(False)

    def cb_ctrl_enter_start_mode(self, x, y):
        '''___activate, when cursor enter in widget___'''

        return GLib.timeout_add(150, enter_start_mode)

    def enter_start_mode():
        '''___cursor position signal handler___'''

        reveal_start_mode.set_reveal_child(True)
        image_start_mode.add_css_class('sw_blur')

    def cb_ctrl_leave_start_mode(self):
        '''___activate, when cursor leave widget___'''

        return GLib.timeout_add(150, leave_start_mode)

    def leave_start_mode():
        '''___cursor position signal handler___'''

        reveal_start_mode.set_reveal_child(False)
        image_start_mode.remove_css_class('sw_blur')

    def cb_btn_sidebar(self):
        '''___reveal show or hide main menu___'''

        return on_sidebar()

    def on_sidebar():

        global flap_locked

        if parent.get_width() < 960:
            if not sidebar_revealer.get_reveal_child():
                flap_locked = True
                sidebar_revealer.set_reveal_child(True)
            else:
                sidebar_revealer.set_reveal_child(False)
        else:
            if flap_locked:
                flap_locked = False
            else:
                flap_locked = True

            if sidebar_revealer.get_reveal_child():
                sidebar_revealer.set_reveal_child(False)
                btn_back_main.set_visible(False)
            else:
                sidebar_revealer.set_reveal_child(True)
                if stack_sidebar.get_visible_child() != frame_main:
                    btn_back_main.set_visible(True)

    def cb_btn_drive(self):
        '''___show or hide mounted volumes___'''

        return on_drive()

    def cb_btn_bookmarks(self):
        '''___show or hide bookmarks list___'''

        return on_bookmarks()

    def on_bookmarks():
        '''___show or hide bookmarks list___'''

        if scrolled_bookmarks.get_child() is None:
            add_bookmarks_menu()

        if not sidebar_revealer.get_reveal_child():
            sidebar_revealer.set_reveal_child(True)
            update_bookmarks()
            stack_sidebar.set_visible_child(frame_bookmarks)
            update_color_scheme()
            btn_back_main.set_visible(True)

        elif stack_sidebar.get_visible_child() == frame_bookmarks:
            on_back_main()
        else:
            update_bookmarks()
            stack_sidebar.set_visible_child(frame_bookmarks)
            update_color_scheme()
            btn_back_main.set_visible(True)

    def cb_btn_overlay(self):
        '''___main buttons signal handler___'''

        if self.get_name() == 'btn_next':
            return cb_btn_next(self)

        if self.get_name() == 'btn_prev':
            return cb_btn_prev(self)

    def cb_ctrl_scroll_view(self, x, y, data):
        '''___mouse scroll event to scroll gridview___'''

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
        '''___activate next view list___'''

        self.set_sensitive(False)
        self.set_can_focus(False)
        self.set_focusable(False)
        GLib.timeout_add(250, set_btn_sensitive, self)
        return on_next()

    def on_next():
        '''___show next view page___'''

        w_name = str(reveal_stack.get_visible_child().get_name())
        if w_name == 'files' or w_name == 'web_view' or w_name == 'winetricks':
            w_name = 'shortcuts'

        w_next = next_vw_dict[w_name]

        if w_next == 'launch_settings':
            return on_launch_settings()
        if w_next == 'mangohud_settings':
            return on_mangohud_settings()
        if w_next == 'vkbasalt_settings':
            return on_vkbasalt_settings()
        if w_next == 'global_settings':
            return on_global_settings()
        if w_next == 'install_wine':
            return on_download_wine()
        if w_next == 'install_launchers':
            return on_install_launchers()
        if w_next == 'shortcuts':
            return on_shortcuts()

    def cb_btn_prev(self):
        '''___show previous view page___'''

        self.set_sensitive(False)
        self.set_can_focus(False)
        self.set_focusable(False)
        GLib.timeout_add(250, set_btn_sensitive, self)
        return on_prev()

    def on_prev():
        '''___show previous view page___'''

        w_name = str(reveal_stack.get_visible_child().get_name())
        if w_name == 'files' or w_name == 'web_view' or w_name == 'winetricks':
            w_name = 'shortcuts'

        w_prev = prev_vw_dict[w_name]

        if w_prev == 'install_launchers':
            return on_install_launchers()
        if w_prev == 'shortcuts':
            return on_shortcuts()
        if w_prev == 'launch_settings':
            return on_launch_settings()
        if w_prev == 'mangohud_settings':
            return on_mangohud_settings()
        if w_prev == 'vkbasalt_settings':
            return on_vkbasalt_settings()
        if w_prev == 'global_settings':
            return on_global_settings()
        if w_prev == 'install_wine':
            return on_download_wine()

    def set_btn_sensitive(btn_widget):
        '''___set sensitive button in overlay control panel___'''

        btn_widget.set_sensitive(True)
        btn_widget.set_can_focus(True)
        btn_widget.set_focusable(True)
        #btn_widget.grab_focus()

    def get_sm_icon(app_name):
        '''___get application icon for start mode in sidebar___'''

        global scheme
        if scheme == 'dark':
            sw_logo = sw_logo_light
        elif scheme == 'light':
            sw_logo = sw_logo_dark
        else:
            sw_logo = sw_logo_light

        if app_name == 'StartWine':
            app_icon = f'{sw_gui_icons}/{sw_logo}'
        else:
            if getenv('SW_SIDEBAR_IMAGE') == 'horizontal':
                for icon in  Path(f'{sw_app_hicons}').iterdir():
                    app_name_isalnum = ''.join(e for e in app_name if e.isalnum())
                    if app_name_isalnum == str(Path(icon).name).split('_')[0]:
                        app_icon = f'{icon}'
                        break
                else:
                    if Path(f'{sw_img}/{app_name}_x256.png').exists():
                        app_icon = f'{sw_img}/{app_name}_x256.png'
                    else:
                        app_icon = f'{sw_gui_icons}/{sw_logo}'

            elif getenv('SW_SIDEBAR_IMAGE') == 'vertical':
                for icon in  Path(f'{sw_app_vicons}').iterdir():
                    app_name_isalnum = ''.join(e for e in app_name if e.isalnum())
                    if app_name_isalnum == str(Path(icon).name).split('_')[0]:
                        app_icon = f'{icon}'
                        break
                else:
                    for icon in  Path(f'{sw_app_hicons}').iterdir():
                        app_name_isalnum = ''.join(e for e in app_name if e.isalnum())
                        if app_name_isalnum == str(Path(icon).name).split('_')[0]:
                            app_icon = f'{icon}'
                            break
                    else:
                        if Path(f'{sw_img}/{app_name}_x256.png').exists():
                            app_icon = f'{sw_img}/{app_name}_x256.png'
                        else:
                            app_icon = f'{sw_gui_icons}/{sw_logo}'
            else:
                app_icon = f'{sw_gui_icons}/{sw_logo}'

        image_start_mode.set_file(Gio.File.new_for_path(app_icon))
        image_start_mode.set_name(f'{app_icon}')

        if str(sw_logo) in str(app_icon):
            image_start_mode.set_content_fit(Gtk.ContentFit.SCALE_DOWN)
        else:
            image_start_mode.set_content_fit(Gtk.ContentFit.COVER)

        return app_icon

    def set_label_wine_mode(app_dict):

        if app_dict is None:
            app_name = get_out()
            app_conf = f"{sw_app_config}/{app_name}"
            app_dict = app_info(app_conf)

        str_wine_name = str(app_dict['export SW_USE_WINE'])[1:-1].replace('/files', '')

        if Path(f'{sw_wine}/{str_wine_name}/version').exists():
            for w in wine_list:
                if str_wine_name == w:
                    str_wine_ver = '-' + Path(f'{sw_wine}/{str_wine_name}/version').read_text().splitlines()[-1]
                    label_wine_mode.set_label(str(str_wine_name + str_wine_ver).lower())
                    break
            else:
                label_wine_mode.set_label(str(str_wine_name).lower())
        else:
            label_wine_mode.set_label(str(str_wine_name).lower())

    def start_mode():
        '''___set application icon, prefix, wine___'''

        app_name = get_out()
        app_conf = f"{sw_app_config}/{app_name}"
        app_dict = app_info(app_conf)

        str_prefix_name = str(app_dict['export SW_USE_PFX'])[1:-1].removeprefix('pfx_')
        label_prefix_mode.set_label(str(str_prefix_name).lower())

        app_icon = get_sm_icon(app_name)
        set_label_wine_mode(app_dict)
        #set_selected_wine()
        #vk_adjustment.set_value(float(app_dict['export SW_USE_VKBASALT_CAS'][1:-1])*100)

        return set_print_start_info(app_name, app_icon, app_dict, True)

    def check_parent_state():
        '''___check_parent_window_state___'''

        clear_tmp()
        dict_ini = read_menu_conf()

        if dict_ini['view_widget'] == vw_dict['shortcuts']:
            on_shortcuts()

        elif dict_ini['view_widget'] == vw_dict['install_launchers']:
            on_install_launchers()

        elif dict_ini['view_widget'] == vw_dict['files']:
            sw_current_dir = dict_ini['current_dir']

            if Path(sw_current_dir).exists():
                on_files(Path(sw_current_dir))
            else:
                sw_default_dir = dict_ini['default_dir']
                on_files(Path(sw_default_dir))
        else:
            sw_default_dir = dict_ini['default_dir']
            on_files(Path(sw_default_dir))

        if dict_ini['view_mode'] == 'column':
            if scrolled_left_files.get_child().get_name() != 'left_column_view':
                add_column_view()
            else:
                scrolled_left_files.set_child(left_grid_view)

        if dict_ini['control_panel'] == 'hide':
            sidebar_revealer.set_reveal_child(False)

        elif dict_ini['control_panel'] == 'show':
            sidebar_revealer.set_reveal_child(True)

        if dict_ini['color_scheme'] == 'dark':
            btn_dark.set_active(True)

        if dict_ini['color_scheme'] == 'light':
            btn_light.set_active(True)

        if dict_ini['color_scheme'] == 'custom':
            btn_custom.set_active(True)

        if dict_ini['icons'] == 'custom':
            sys_icons = get_sys_icons()
            gtk_settings.props.gtk_icon_theme_name = f"{sys_icons}"
            print(f'{tc.VIOLET}SYSTEM_ICONS: {tc.BLUE}{sys_icons}')
        else:
            gtk_settings.props.gtk_icon_theme_name = "SWSuru++"
            print(f'{tc.VIOLET}BUILTIN_ICONS: {tc.BLUE}SWSuru++')

        if dict_ini['auto_hide_top_header'] == 'on':
            environ['SW_AUTO_HIDE_TOP_HEADER'] = '1'
            top_headerbar_revealer.set_reveal_child(False)
        else:
            environ['SW_AUTO_HIDE_TOP_HEADER'] = '0'
            top_headerbar_revealer.set_reveal_child(True)

        if dict_ini['auto_hide_bottom_header'] == 'on':
            environ['SW_AUTO_HIDE_BOTTOM_HEADER'] = '1'
            bottom_headerbar_revealer.set_reveal_child(False)
        else:
            environ['SW_AUTO_HIDE_BOTTOM_HEADER'] = '0'
            bottom_headerbar_revealer.set_reveal_child(True)

        #"WenQuanYi Micro Hei 12" #"Sans 12"
        gtk_settings.props.gtk_font_name = "Noto Sans 12"
        gtk_settings.props.gtk_application_prefer_dark_theme = True
        gtk_settings.props.gtk_theme_name = "Sw-dark"

    def read_parent_state():
        '''___read parent window state from config___'''

        dict_ini = read_menu_conf()
        sw_width = int(dict_ini['width'])
        sw_height = int(dict_ini['height'])

        return sw_width, sw_height

    def on_write_parent_state(self):
        '''___write parent window state in config___'''

        parent.set_hide_on_close(True)
        return write_parent_state()

    def write_parent_state():
        '''___write parent window state in config___'''

        clear_tmp()
        dict_ini = read_menu_conf()

        h = parent.get_height()
        w = parent.get_width()
        w_name = str(reveal_stack.get_visible_child().get_name())

        if Path(entry_path.get_name()) == sw_shortcuts:
            dict_ini['view_widget'] = vw_dict['shortcuts']
            dict_ini['current_dir'] = entry_path.get_name()
        else:
            dict_ini['view_widget'] = vw_dict['files']
            dict_ini['current_dir'] = entry_path.get_name()

        if scrolled_left_files.get_child().get_name() == 'left_column_view':
            dict_ini['view_mode'] = 'column'
        else:
            dict_ini['view_mode'] = 'grid'

        if not sidebar_revealer.get_reveal_child():
            dict_ini['control_panel'] = 'hide'
        else:
            dict_ini['control_panel'] = 'show'

        if w != 0:
            dict_ini['width'] = w

        if h !=0:
            dict_ini['height'] = h

        if getenv('SW_OPENGL') == '1':
            dict_ini['opengl_bg'] = 'True'
        else:
            dict_ini['opengl_bg'] = 'False'

        dict_ini['icon_size'] = round(btn_scale_icons.get_value())
        dict_ini['shortcut_size'] = round(btn_scale_shortcuts.get_value())
        dict_ini['sound'] = 'off'

        return write_menu_conf(dict_ini)

    def check_file_monitor_event():
        '''___update file grid view on file monitor events___'''

        event_list = [
            Gio.FileMonitorEvent.MOVED_OUT,
            Gio.FileMonitorEvent.MOVED_IN,
            Gio.FileMonitorEvent.RENAMED,
            Gio.FileMonitorEvent.MOVED,
            Gio.FileMonitorEvent.CREATED,
            Gio.FileMonitorEvent.DELETED,
            Gio.FileMonitorEvent.CHANGED,
            Gio.FileMonitorEvent.ATTRIBUTE_CHANGED,
            Gio.FileMonitorEvent.CHANGES_DONE_HINT,
        ]

        global f_mon_event

        if f_mon_event != []:
            print(f_mon_event)

            if f_mon_event[0].get_parent() is not None:
                if f_mon_event[0].get_parent().get_path() is not None:
                    event_path = f_mon_event[0].get_parent().get_path()
                    path_type = 'file'
                elif f_mon_event[0].get_parent().get_uri() is not None:
                    event_path = f_mon_event[0].get_parent().get_uri()
                    path_type = 'uri'
                else:
                    event_path = None
            else:
                event_path = None

            if f_mon_event[1] == Gio.FileMonitorEvent.CHANGED:
                f_mon_event.clear()

            elif (f_mon_event[1] == Gio.FileMonitorEvent.ATTRIBUTE_CHANGED
                or f_mon_event[1] == Gio.FileMonitorEvent.CHANGES_DONE_HINT):
                    if event_path is not None:
                        paned_store = get_list_store()
                        for n, x in enumerate(paned_store):
                            if str(x.get_path()) == str(event_path):
                                paned_store.remove(n)
                                dict_ini = read_menu_conf()
                                x_hidden_files = dict_ini['hidden_files']
                                update_view(paned_store, x, x_hidden_files)
                                f_mon_event.clear()
                                break
                        else:
                            f_mon_event.clear()
                            if path_type == 'file':
                                update_grid_view(event_path)
                            else:
                                update_grid_view_uri(event_path)
            else:
                if event_path is not None:
                    f_mon_event.clear()
                    if path_type == 'file':
                        update_grid_view(event_path)
                    else:
                        update_grid_view_uri(event_path)
                else:
                    pass

            if scrolled_gvol.get_child() is not None:
                update_gvolume()

            f_mon_event.clear()

        return True

    def check_reveal_flap():
        '''___Сhecking the size and position status of sidebar widgets___'''

        if reveal_stack.get_visible_child() == files_view_grid:
            btn_gmount.set_visible(True)
            btn_bookmarks.set_visible(True)
            btn_popover_scale.set_visible(True)
            if Path(entry_path.get_name()) == sw_shortcuts:
                btn_icon_position.set_visible(True)
            else:
                btn_icon_position.set_visible(False)
        else:
            btn_gmount.set_visible(False)
            btn_bookmarks.set_visible(False)
            btn_popover_scale.set_visible(False)
            btn_icon_position.set_visible(False)

        swgs.width = parent.get_width()
        swgs.height = parent.get_height()

        if swgs.height >= 720:
            environ['SW_SIDEBAR_IMAGE'] = 'vertical'
            if stack_sidebar.get_visible_child() == frame_main:
                app_name =get_out()
                if (not sw_program_name in app_name
                    and not f'{app_name}_x256' in str(image_start_mode.get_name())
                        and not f'{sw_logo_dark}' in str(image_start_mode.get_name())
                            and not f'{sw_logo_light}' in str(image_start_mode.get_name())):
                                img = Path(image_start_mode.get_name().replace('_horizontal', '_vertical'))
                                if (not str(sw_app_vicons) in str(img)
                                    and Path(f'{sw_app_vicons}/{img.name}').exists()):
                                        get_sm_icon(app_name)
        elif swgs.height < 720:
            environ['SW_SIDEBAR_IMAGE'] = 'horizontal'
            if stack_sidebar.get_visible_child() == frame_main:
                app_name = get_out()
                if (not sw_program_name in app_name
                    and not f'{app_name}_x256' in str(image_start_mode.get_name())
                        and not f'{sw_logo_dark}' in str(image_start_mode.get_name())
                            and not f'{sw_logo_light}' in str(image_start_mode.get_name())):
                                img = Path(image_start_mode.get_name().replace('_vertical', '_horizontal'))
                                if (not str(sw_app_hicons) in str(image_start_mode.get_name())
                                    and Path(f'{sw_app_hicons}/{img.name}').exists()):
                                        get_sm_icon(app_name)
        return True

    def get_sidebar_position(self, widget, allocation):
        '''___get overlay child position___'''

        global flap_locked
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
            if not flap_locked:
                widget.set_reveal_child(False)
            empty_box.set_size_request(0,-1)
            empty_box.set_visible(False)

        elif allocation.width > 960:
            if not flap_locked:
                widget.set_reveal_child(True)
            if sidebar_revealer.get_reveal_child():
                flap_locked = False
                empty_box.set_size_request(sidebar_width, -1)
                empty_box.set_visible(True)
            else:
                empty_box.set_size_request(0,-1)
                empty_box.set_visible(False)

    def on_parent_close(self):
        '''___window_close___'''

        parent.close()

    def on_parent_minimize(self):
        '''___window_minimize___'''

        parent.minimize()

    def on_parent_maximize(self):
        '''___window_maximize___'''

        if parent.is_maximized():
            parent.unmaximize()
        else:
            parent.maximize()

    def on_parent_fullscreen():
        '''___window_fullscreen___'''

        if parent.is_fullscreen():
            parent.unfullscreen()
        else:
            #parent.fullscreen()
            parent.fullscreen_on_monitor(monitor)

    def on_show_hotkeys():
        '''___show hotkeys settings window___'''

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
            key_mod.set_size_request(72,-1)
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
                key_y.set_size_request(72,-1)
                key_y.set_sensitive(False)
                key_y.set_child(label_y)

            if k[1] == '':
                plus_x = Gtk.Label(css_name='sw_label', label='')
                key_x = Gtk.Label(css_name='sw_label', label='')
            else:
                plus_x = Gtk.Label(css_name='sw_label', label='+')
                key_x = Gtk.Button(css_name='sw_action_row')
                key_x.add_css_class('key')
                key_x.set_size_request(72,-1)
                key_x.set_sensitive(False)
                key_x.set_child(label_x)

            if count < len(hotkey_list) / 2:
                grid_keys_0.attach(key_mod, 0,count,1,1)
                grid_keys_0.attach(plus_x, 1, count,1,1)
                grid_keys_0.attach(key_x, 2, count,1,1)
                grid_keys_0.attach(plus_y, 3, count,1,1)
                grid_keys_0.attach(key_y, 4, count,1,1)
                grid_keys_0.attach(label_desc_x, 5, count,1,1)
            else:
                grid_keys_1.attach(key_mod, 0,count,1,1)
                grid_keys_1.attach(plus_x, 1, count,1,1)
                grid_keys_1.attach(key_x, 2, count,1,1)
                grid_keys_1.attach(plus_y, 3, count,1,1)
                grid_keys_1.attach(key_y, 4, count,1,1)
                grid_keys_1.attach(label_desc_x, 5, count,1,1)

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

        scrolled = Gtk.ScrolledWindow(css_name='sw_scrolled_view')

        close = Gtk.Button(
                        css_name='sw_wc_close',
                        valign=Gtk.Align.CENTER
                        )
        headerbar = Gtk.HeaderBar(
                        css_name='sw_header_top',
                        show_title_buttons=False
                        )
        win = Gtk.Window(
                        css_name='sw_window',
                        application=swgs,
                        )
        win.remove_css_class('background')
        win.add_css_class('sw_background')
        scrolled.set_child(group_hotkeys)
        headerbar.pack_end(close)
        win.set_titlebar(headerbar)
        win.set_default_size(1280, 720)
        win.set_transient_for(parent)
        win.set_modal(True)
        win.set_child(scrolled)
        close.connect('clicked', cb_btn_close, win)
        win.present()

    def cb_btn_close(self, win):
        '''___close hotkeys settings window___'''

        win.close()

    def cb_bookmark_activate(self, position):
        '''___open bookmark directory in file manager'''

        string_path = self.get_model().get_item(position).get_string()
        file = Gio.File.new_for_commandline_arg(string_path)

        if file.get_path() is None:
            uri = file.get_uri()
            update_grid_view_uri(file.get_uri())
        else:
            on_files(file.get_path())

    def get_gl_image():
        '''___Get opengl background image___'''
        gl_image = None
        if sw_background.exists():
            for x in sw_background.iterdir():
                if x.is_file():
                    for s in ['.jpeg', '.jpg', '.png', '.tiff']:
                        if x.suffix == s:
                            gl_image = GdkPixbuf.Pixbuf.new_from_file(f'{x}')
        return gl_image

    def on_shutdown():
        '''___Shutdown all process and close application'''

        Popen(f"{sw_scripts}/sw_stop", shell=True)

        p = Popen(['ps', '-AF'], stdout=PIPE, encoding='UTF-8')
        out, err = p.communicate()

        for line in out.splitlines():
            if str('sw_tray.py') in line:
                pid = int(line.split()[1])
                kill(pid, 9)

        swgs.connection.flush(callback=flush_connection, user_data=None)

    def add_create_shortcut_menu():
        '''___build wine create chortcut_menu___.'''

        swgs.grid_create_shortcut = Gtk.Grid()
        swgs.grid_create_shortcut.set_vexpand(True)
        swgs.grid_create_shortcut.set_row_spacing(10)
        swgs.grid_create_shortcut.set_margin_top(16)
        swgs.grid_create_shortcut.set_margin_bottom(16)
        swgs.grid_create_shortcut.set_margin_start(16)
        swgs.grid_create_shortcut.set_margin_end(16)
        swgs.grid_create_shortcut.set_halign(Gtk.Align.CENTER)

        swgs.grid_menu_wine_custom = Gtk.Grid()
        swgs.grid_menu_wine_custom.set_column_spacing(10)

        image_create = Gtk.Picture(css_name='sw_picture')
        image_create.set_margin_start(32)
        image_create.set_margin_end(32)
        image_create.set_margin_bottom(16)

        paintable_icon_create = Gtk.IconPaintable.new_for_file(
                                Gio.File.new_for_path(IconPath.icon_create), 256, 1
        )
        image_create.set_paintable(paintable_icon_create)

        count = 0
        for w, l in zip(wine_list, wine_labels):
            count += 1

            image_wine = Gtk.Image(css_name='sw_image')
            image_wine.set_from_file(IconPath.icon_wine)

            label_wine = Gtk.Label(css_name='sw_label', label=l)

            box_wine = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
            box_wine.set_spacing(8)
            box_wine.append(image_wine)
            box_wine.append(label_wine)

            btn_wine = Gtk.Button(css_name='sw_button')
            btn_wine.set_hexpand(True)
            btn_wine.set_name(w)
            btn_wine.set_child(box_wine)
            btn_wine.connect('clicked', cb_btn_cs_wine)

            swgs.grid_create_shortcut.attach(btn_wine,0,count,1,1)

        ###_Cutom_wines___.

        swgs.list_store_wine_custom = Gio.ListStore()
        swgs.model_wine_custom = Gtk.SingleSelection.new(swgs.list_store_wine_custom)

        swgs.factory_wine_custom = Gtk.SignalListItemFactory()
        swgs.factory_wine_custom.connect('setup', cb_factory_wine_custom_setup)
        swgs.factory_wine_custom.connect('bind', cb_factory_wine_custom_bind)

        swgs.list_view_wine_custom = Gtk.ListView(
                                    css_name='sw_listview',
                                    single_click_activate=True,
                                    show_separators=True,
                                    margin_top = 16,
        )
        swgs.list_view_wine_custom.set_factory(swgs.factory_wine_custom)
        swgs.list_view_wine_custom.set_model(swgs.model_wine_custom)
        swgs.list_view_wine_custom.connect('activate', cb_btn_cs_wine_custom)

        swgs.scrolled_wine_custom = Gtk.ScrolledWindow(
                                                css_name='sw_scrolledwindow',
                                                vexpand=True,
                                                hexpand=False,
                                                propagate_natural_height=True,
                                                min_content_width=(280),
                                                child=swgs.list_view_wine_custom,
        )
        swgs.image_menu_wine_custom = Gtk.Image(css_name='sw_image')
        swgs.image_menu_wine_custom.set_from_file(IconPath.icon_wine)

        swgs.label_menu_wine_custom = Gtk.Label(css_name='sw_label')
        swgs.label_menu_wine_custom.set_label('Wine Custom')

        swgs.btn_menu_wine_custom = Gtk.Button(css_name='sw_button')
        swgs.btn_menu_wine_custom.set_child(swgs.grid_menu_wine_custom)
        swgs.btn_menu_wine_custom.connect('clicked', cb_btn_menu_wine_custom)

        swgs.popover_wines = Gtk.Popover(css_name='sw_popover')
        swgs.popover_wines.set_child(swgs.scrolled_wine_custom)
        swgs.popover_wines.set_autohide(True)
        swgs.popover_wines.set_has_arrow(False)
        swgs.popover_wines.set_position(Gtk.PositionType.TOP)
        swgs.popover_wines.set_parent(swgs.btn_menu_wine_custom)

        swgs.grid_create_shortcut.attach(image_create, 0,0,1,1)
        swgs.grid_create_shortcut.attach(swgs.btn_menu_wine_custom,0,6,1,1)

        swgs.grid_menu_wine_custom.attach(swgs.image_menu_wine_custom,0,0,1,1)
        swgs.grid_menu_wine_custom.attach(swgs.label_menu_wine_custom,1,0,1,1)

        scrolled_create_shortcut.set_child(swgs.grid_create_shortcut)

    def add_prefix_tools_menu():
        '''___build prefix tools menu___.'''

        grid_prefix_tools = Gtk.Grid()
        grid_prefix_tools.set_vexpand(True)
        grid_prefix_tools.set_row_spacing(10)
        grid_prefix_tools.set_margin_top(16)
        grid_prefix_tools.set_margin_bottom(16)
        grid_prefix_tools.set_margin_start(16)
        grid_prefix_tools.set_margin_end(16)
        grid_prefix_tools.set_halign(Gtk.Align.CENTER)

        image_ptools = Gtk.Picture(css_name='sw_picture')
        image_ptools.set_margin_start(32)
        image_ptools.set_margin_end(32)
        image_ptools.set_margin_bottom(16)

        paintable_icon_tools = Gtk.IconPaintable.new_for_file(
                                Gio.File.new_for_path(IconPath.icon_toolbox),256,1,
        )
        image_ptools.set_paintable(paintable_icon_tools)
        grid_prefix_tools.attach(image_ptools,0,0,1,1)

        change_pfx_list_model = Gtk.StringList()

        for l in prefix_labels:
            change_pfx_list_model.append(l)

        change_pfx_factory = Gtk.SignalListItemFactory()
        change_pfx_factory.connect('setup', on_change_pfx_setup)
        change_pfx_factory.connect('bind', on_change_pfx_bind)

        swgs.dropdown_change_pfx = Gtk.DropDown(css_name='sw_dropdown')
        swgs.dropdown_change_pfx.set_valign(Gtk.Align.CENTER)
        swgs.dropdown_change_pfx.set_model(change_pfx_list_model)
        swgs.dropdown_change_pfx.set_name(str_sw_use_pfx)
        swgs.dropdown_change_pfx.connect('notify::selected-item', on_change_pfx_activate)

        grid_prefix_tools.attach(swgs.dropdown_change_pfx,0,1,1,1)

        count = 1
        for l, i in zip(prefix_tools_labels, prefix_tools_icons):
            count +=1

            image_pfx_tools = Gtk.Image(css_name='sw_image')
            image_pfx_tools.set_from_file(i)
            label_pfx_tools = Gtk.Label(css_name='sw_label', label=l)

            box_pfx_tools = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
            box_pfx_tools.set_spacing(8)
            box_pfx_tools.append(image_pfx_tools)
            box_pfx_tools.append(label_pfx_tools)

            btn_pfx_tools = Gtk.Button(css_name='sw_button')
            btn_pfx_tools.set_size_request(280,-1)
            btn_pfx_tools.set_name(l)
            btn_pfx_tools.set_child(box_pfx_tools)
            btn_pfx_tools.connect('clicked', cb_btn_prefix_tools)

            grid_prefix_tools.attach(btn_pfx_tools,0,count,1,1)

        scrolled_prefix_tools.set_child(grid_prefix_tools)

####___Wine_tools_buttons___.

    def add_wine_tools_menu():
        '''___build wine tools menu___'''
        swgs.grid_wine_tools = Gtk.Grid()
        swgs.grid_wine_tools.set_vexpand(True)
        swgs.grid_wine_tools.set_row_spacing(10)
        swgs.grid_wine_tools.set_margin_top(16)
        swgs.grid_wine_tools.set_margin_bottom(16)
        swgs.grid_wine_tools.set_margin_start(16)
        swgs.grid_wine_tools.set_margin_end(16)
        swgs.grid_wine_tools.set_halign(Gtk.Align.CENTER)

        swgs.change_wine_store = Gio.ListStore()
        swgs.change_wine_model = Gtk.SingleSelection.new(swgs.change_wine_store)

        swgs.change_wine_factory = Gtk.SignalListItemFactory()
        swgs.change_wine_factory.connect('setup', on_change_wine_setup)
        swgs.change_wine_factory.connect('bind', on_change_wine_bind)

        swgs.dropdown_change_wine = Gtk.DropDown(css_name='sw_dropdown')
        swgs.dropdown_change_wine.set_size_request(160, -1)
        swgs.dropdown_change_wine.set_hexpand(False)
        swgs.dropdown_change_wine.set_valign(Gtk.Align.CENTER)
        swgs.dropdown_change_wine.set_model(swgs.change_wine_model)
        swgs.dropdown_change_wine.set_factory(swgs.change_wine_factory)
        swgs.dropdown_change_wine.set_name(str_sw_use_wine)
        #swgs.dropdown_change_wine.connect('notify::selected-item', cb_change_wine_activate)

        swgs.drop_list_view = (swgs.dropdown_change_wine
                            .get_last_child()
                                .get_first_child()
                                    .get_first_child()
                                        .get_first_child()
                                            .get_next_sibling()
                                                .get_first_child()
        )
        swgs.drop_list_view.connect('activate', cb_change_wine_activate)
        swgs.grid_wine_tools.attach(swgs.dropdown_change_wine,0,1,1,1)

        count = 1
        for l, i in zip(wine_tools_labels, wine_tools_icons):
            count +=1

            image_wine_tools = Gtk.Image(css_name='sw_image')
            image_wine_tools.set_from_file(i)
            label_wine_tools = Gtk.Label(css_name='sw_label', label=l)

            box_wine_tools = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
            box_wine_tools.set_spacing(8)
            box_wine_tools.append(image_wine_tools)
            box_wine_tools.append(label_wine_tools)

            btn_wine_tools = Gtk.Button(css_name='sw_button')
            btn_wine_tools.set_size_request(280,-1)
            btn_wine_tools.set_name(l)
            btn_wine_tools.set_child(box_wine_tools)
            btn_wine_tools.connect('clicked', cb_btn_wine_tools)

            swgs.grid_wine_tools.attach(btn_wine_tools,0,count,1,1)

        swgs.image_wtools = Gtk.Picture(css_name='sw_picture')
        swgs.image_wtools.set_margin_start(32)
        swgs.image_wtools.set_margin_end(32)
        swgs.image_wtools.set_margin_bottom(16)

        paintable_icon_wtools = Gtk.IconPaintable.new_for_file(
                                Gio.File.new_for_path(IconPath.icon_toolbars),256, 1,
                                )
        swgs.image_wtools.set_paintable(paintable_icon_wtools)

        swgs.grid_wine_tools.attach(swgs.image_wtools,0,0,1,1)
        scrolled_wine_tools.set_child(swgs.grid_wine_tools)

####___Files_info___.

    def add_files_info():
        '''___build files info widgets___'''

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
                                css_name='sw_action_row',
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

        ####___file path info___.

        swgs.box_file_path = Gtk.Box(
                                css_name='sw_action_row',
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

        ####___file user, group, time info___.

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
                                css_name='sw_action_row',
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

        ####___file executable info___.

        swgs.box_file_execute = Gtk.Box(
                                css_name='sw_action_row',
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

        swgs.grid_files_info.attach(swgs.box_header_info, 0,0,1,1)
        swgs.grid_files_info.attach(swgs.box_file_path, 0,1,1,1)
        swgs.grid_files_info.attach(swgs.box_file_info, 0,2,1,1)
        swgs.grid_files_info.attach(swgs.box_file_execute, 0,3,1,1)

        scrolled_files_info.set_child(swgs.grid_files_info)

####___Settings___.

    def add_settings_menu():
        '''___build settings menu widgets___'''

        grid_settings = Gtk.Grid()
        grid_settings.set_vexpand(True)
        grid_settings.set_row_spacing(10)
        grid_settings.set_margin_top(16)
        grid_settings.set_margin_bottom(16)
        grid_settings.set_margin_start(16)
        grid_settings.set_margin_end(16)
        grid_settings.set_halign(Gtk.Align.CENTER)

        image_settings_tools = Gtk.Picture(css_name='sw_picture')
        image_settings_tools.set_margin_start(32)
        image_settings_tools.set_margin_end(32)
        image_settings_tools.set_margin_bottom(16)

        paintable_icon_settings = Gtk.IconPaintable.new_for_file(
                                Gio.File.new_for_path(IconPath.icon_settings), 256, 1,
                                )
        image_settings_tools.set_paintable(paintable_icon_settings)

        count = 0
        for l, i in zip(settings_labels, settings_icons):
            count += 1

            image_settings = Gtk.Image(css_name='sw_image')
            image_settings.set_from_file(i)
            label_settings = Gtk.Label(css_name='sw_label', label=l)

            box_settings = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
            box_settings.set_spacing(8)
            box_settings.append(image_settings)
            box_settings.append(label_settings)

            btn_settings = Gtk.Button(css_name='sw_button')
            btn_settings.set_size_request(280,-1)
            btn_settings.set_name(l)
            btn_settings.set_child(box_settings)
            btn_settings.connect('clicked', cb_btn_settings)

            grid_settings.attach(btn_settings,0,count,1,1)

        grid_settings.attach(image_settings_tools,0,0,1,1)
        scrolled_settings.set_child(grid_settings)

####___About___.

    def add_about():
        '''___build about menu widgets___'''

        paintable_about = Gtk.IconPaintable.new_for_file(
                                            Gio.File.new_for_path(IconPath.icon_app),256,1,
                                            )
        about_picture = Gtk.Picture(css_name='sw_picture')
        about_picture.set_margin_start(32)
        about_picture.set_margin_end(32)
        about_picture.set_size_request(-1,32)
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
        pref_group_about.set_size_request(280,-1)

        grid_about = Gtk.Grid()
        grid_about.set_vexpand(True)
        grid_about.set_row_spacing(10)
        grid_about.set_margin_top(16)
        grid_about.set_margin_bottom(16)
        grid_about.set_margin_start(16)
        grid_about.set_margin_end(16)
        grid_about.set_halign(Gtk.Align.CENTER)
        grid_about.attach(box_about_version,0,0,1,1)
        grid_about.attach(pref_group_about,0,1,1,1)

        ####___About_menu_stack___.

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
        swgs.btn_back_about.set_size_request(280,-1)
        swgs.btn_back_about.set_child(box_btn_back_about)
        swgs.btn_back_about.connect('clicked', cb_btn_back_about)

        count = 0
        for l, w in zip(about_labels, about_widgets):
            count += 1

            if count < 7:

                label_a = Gtk.Label(
                                    css_name='sw_label',
                                    label=l,
                                    xalign=0.0
                                    )
                btn_a = Gtk.Button(css_name='sw_button')
                btn_a.set_child(label_a)
                btn_a.set_name(w)
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
                grid_about_content.set_name(w)

                swgs.stack_about.add_named(grid_about_content, w)

        grid_about_news = swgs.stack_about.get_child_by_name(list(about_dict)[0])
        grid_about_details = swgs.stack_about.get_child_by_name(list(about_dict)[1])
        grid_about_authors = swgs.stack_about.get_child_by_name(list(about_dict)[2])
        grid_about_license = swgs.stack_about.get_child_by_name(list(about_dict)[3])
        grid_about_donation = swgs.stack_about.get_child_by_name(list(about_dict)[4])
        grid_about_update = swgs.stack_about.get_child_by_name(list(about_dict)[5])

        ####___About_news___.

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
                                        css_name='sw_action_row',
                                        orientation=Gtk.Orientation.VERTICAL
                                        )
        pref_group_about_news.set_size_request(280,-1)
        pref_group_about_news.append(swgs.title_news)
        pref_group_about_news.append(label_news)

        grid_about_news.attach(pref_group_about_news, 0,1,1,1)

        ####___About_details___.

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
                                        css_name='sw_action_row',
                                        orientation=Gtk.Orientation.VERTICAL
                                        )
        pref_group_about_details.set_size_request(280,-1)
        pref_group_about_details.append(title_details)
        pref_group_about_details.append(label_details)

        grid_about_details.attach(pref_group_about_details, 0, 1, 1, 1)
        grid_about_details.attach(btn_website, 0, 2, 1, 1)
        grid_about_details.attach(btn_github, 0, 3, 1, 1)
        grid_about_details.attach(btn_discord, 0, 4, 1, 1)
        grid_about_details.attach(btn_telegram, 0, 5, 1, 1)

        ####___About_autors___.

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
                                        css_name='sw_action_row',
                                        orientation=Gtk.Orientation.VERTICAL
                                        )
        pref_group_about_authors.set_size_request(280,-1)
        pref_group_about_authors.append(title_authors)
        pref_group_about_authors.append(label_authors)

        pref_group_about_coders = Gtk.Box(
                                        css_name='sw_action_row',
                                        orientation=Gtk.Orientation.VERTICAL
                                        )
        pref_group_about_coders.set_size_request(280,-1)
        pref_group_about_coders.append(title_coders)
        pref_group_about_coders.append(label_coders)

        pref_group_about_members = Gtk.Box(
                                        css_name='sw_action_row',
                                        orientation=Gtk.Orientation.VERTICAL
                                        )
        pref_group_about_members.set_size_request(280,-1)
        pref_group_about_members.append(title_members)
        pref_group_about_members.append(label_members)

        pref_group_about_projects = Gtk.Box(
                                        css_name='sw_action_row',
                                        orientation=Gtk.Orientation.VERTICAL
                                        )
        pref_group_about_projects.set_size_request(280,-1)
        pref_group_about_projects.append(title_projects)
        pref_group_about_projects.append(label_projects)

        pref_group_about_design = Gtk.Box(
                                        css_name='sw_action_row',
                                        orientation=Gtk.Orientation.VERTICAL
                                        )
        pref_group_about_design.set_size_request(280,-1)
        pref_group_about_design.append(title_design)
        pref_group_about_design.append(label_design)

        grid_about_authors.attach(pref_group_about_authors, 0,1,1,1)
        grid_about_authors.attach(pref_group_about_coders, 0,2,1,1)
        grid_about_authors.attach(pref_group_about_members, 0,3,1,1)
        grid_about_authors.attach(pref_group_about_projects, 0,4,1,1)
        grid_about_authors.attach(pref_group_about_design, 0,5,1,1)

        ####___About_license___.

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
                                        css_name='sw_action_row',
                                        orientation=Gtk.Orientation.VERTICAL
                                        )
        pref_group_about_license.set_size_request(280,-1)
        pref_group_about_license.append(title_license)
        pref_group_about_license.append(label_license)

        grid_about_license.attach(pref_group_about_license, 0, 1, 1, 1)
        grid_about_license.attach(btn_license, 0, 2, 1, 1)

        ####___About_donation___.
        count = 1
        for k, v in donation_source.items():
            count += 1

            label_link_donation = Gtk.Label(
                                        css_name='sw_label',
                                        label=v,
                                        xalign=0,
                                        wrap=True,
                                        max_width_chars=4,
                                        natural_wrap_mode=True,
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
                                        css_name='sw_action_row',
                                        orientation=Gtk.Orientation.VERTICAL
        )
        pref_group_about_donation.set_size_request(280,-1)
        pref_group_about_donation.append(title_donation)
        pref_group_about_donation.append(label_donation)

        grid_about_donation.attach(pref_group_about_donation, 0, 1, 1, 1)

        scrolled_about.set_child(grid_about)
        scrolled_stack.set_child(swgs.stack_about)


    def add_launch_settings_view():
        '''___build lauch settings view page'''

        swgs.label_ls_move = Gtk.Label(css_name='sw_label', label=str_move_settings)

        swgs.btn_ls_move = Gtk.Button(css_name='sw_button')
        swgs.btn_ls_move.set_hexpand(True)
        swgs.btn_ls_move.set_halign(Gtk.Align.END)
        swgs.btn_ls_move.set_valign(Gtk.Align.START)
        swgs.btn_ls_move.set_child(swgs.label_ls_move)
        swgs.btn_ls_move.set_tooltip_markup(msg.tt_dict['choose_app'])
        swgs.btn_ls_move.connect('clicked', cb_btn_ls_move)

        swgs.launch_settings = Gtk.Box(
                                        css_name='sw_flowbox',
                                        orientation=Gtk.Orientation.VERTICAL
        )
        swgs.pref_group_title = Gtk.Label(
                                        css_name='sw_label_title',
                                        label=vl_dict['launch_settings'],
                                        xalign=0.0
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

        swgs.pref_group_ls_title_grid = Gtk.Grid(css_name='sw_box')
        swgs.pref_group_ls_title_grid.attach(swgs.pref_group_ls_title_box, 0,0,1,1)
        swgs.pref_group_ls_title_grid.attach(swgs.btn_ls_move, 1,0,1,1)

        swgs.launch_flow = Gtk.FlowBox(css_name='sw_preferencesgroup')
        swgs.launch_flow.set_margin_top(16)
        swgs.launch_flow.set_homogeneous(True)
        swgs.launch_flow.set_min_children_per_line(1)
        swgs.launch_flow.set_max_children_per_line(8)

        swgs.pref_group_flow = Gtk.Box(
                                css_name='sw_pref_box',
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

        ####___Entry_launch_parameters___.

#        row_entry_list = list()
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

        ####___Combobox_launch_parameters___.

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
                row_combo.set_size_request(240,-1)
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
                                                tooltip_markup=(msg.tt_dict['apply']
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

                    row_grid.attach(row_combo_desc,0,count,1,1)
                    row_grid.attach(box_reg_combo,1,count,1,1)

                else:
                    row_grid.attach(row_combo_desc,0,count,1,1)
                    row_grid.attach(row_combo,1,count,1,1)

                try:
                    if count < 9:
                        row_combo.set_model(swgs.combo_list_model[count-2])
                        #row_combo.set_factory(lp_combo_list_factory)
                        row_combo.connect('notify::selected-item', on_row_combo_activate)
                except:
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

        ####___Fps_limit_parameters___.

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
        swgs.btn_spin_fps.set_size_request(160,-1)
        swgs.btn_spin_fps.set_valign(Gtk.Align.CENTER)
        swgs.btn_spin_fps.set_halign(Gtk.Align.END)
        swgs.btn_spin_fps.set_adjustment(swgs.fps_adjustment)
        swgs.btn_spin_fps.connect('value-changed', on_fps_adjustment)

        swgs.grid_lp_fps = Gtk.Grid(css_name='sw_grid')
        swgs.grid_lp_fps.set_hexpand(True)
        swgs.grid_lp_fps.attach(swgs.lp_fps_desc,0,0,1,1)
        swgs.grid_lp_fps.attach(swgs.btn_spin_fps,1,0,1,1)

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

        ####___CPU_topology_parameters___.

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
        swgs.btn_spin_cpu.set_size_request(160,-1)
        swgs.btn_spin_cpu.set_valign(Gtk.Align.CENTER)
        swgs.btn_spin_cpu.set_halign(Gtk.Align.END)
        swgs.btn_spin_cpu.set_adjustment(swgs.cpu_adjustment)
        swgs.btn_spin_cpu.connect('value-changed', on_cpu_adjustment)

        swgs.grid_lp_cpu = Gtk.Grid(css_name='sw_grid')
        swgs.grid_lp_cpu.set_hexpand(True)
        swgs.grid_lp_cpu.attach(swgs.lp_cpu_topology_desc,0,0,1,1)
        swgs.grid_lp_cpu.attach(swgs.btn_spin_cpu,1,0,1,1)

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

        ####___Switch_launch_parameters___.

#        switch_ls_list = list()
        count = -1
        for l, d in zip(switch_labels, switch_descriptions):
            count += 1
            switch_ls = Gtk.Switch(css_name='sw_switch')
            switch_ls.set_margin_start(16)
            switch_ls.set_name(l)
            switch_ls.set_valign(Gtk.Align.CENTER)
            switch_ls.set_halign(Gtk.Align.START)
            switch_ls.connect('state-set', cb_btn_switch_ls)
            switch_ls_list.append(switch_ls)

            ls_title = Gtk.Label(css_name='sw_label', label=l)
            ls_title.set_hexpand(True)
            ls_title.set_halign(Gtk.Align.START)
            ls_title.set_xalign(0)

            ls_desc = Gtk.Label(css_name='sw_label_desc', label=d)
            ls_desc.set_size_request(180,-1)
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
            launch_child.set_name(l)
            launch_child.set_child(ls_box)
            swgs.launch_flow.append(launch_child)
            swgs.launch_flow.connect('child-activated', on_launch_flow_activated, switch_ls)

        scrolled_launch_settings.set_child(swgs.launch_settings)

        return set_settings_widget(
                            vw_dict['launch_settings'],
                            swgs.pref_group_title,
        )

####___Install_launchers___.

    def add_install_launchers_view():
        '''___build install launchers view page___'''

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
        swgs.pref_group_launchers_title_grid.attach(swgs.pref_group_launchers_box, 0,0,1,1)

        swgs.launchers_flow = Gtk.FlowBox(css_name='sw_preferencesgroup')
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
        for l in sorted(launchers_list):
            count += 1
            image_il = Gtk.Picture(css_name='sw_image')
            image_il.add_css_class('sw_shadow')
            paintable_launcher_icon = Gtk.IconPaintable.new_for_file(
                                    Gio.File.new_for_path(bytes(Path(l))), 288, 1,
            )
            image_il.set_paintable(paintable_launcher_icon)
            image_il.set_content_fit(Gtk.ContentFit.COVER)
            image_il.set_size_request(320, 180)
            image_il.set_halign(Gtk.Align.START)

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
                                name=Path(l).stem,
                                valign=Gtk.Align.START,
                                halign=Gtk.Align.END,
                                child=box_btn_il
            )
            btn_il.set_size_request(160, -1)
            btn_il.add_css_class('install')
            btn_il.connect('clicked', cb_btn_install_launchers)
            btn_il_list.append(btn_il)

            il_name = Path(l).stem.replace('_', ' ')
            il_title = Gtk.Label(css_name='sw_label_title', label=il_name)
            il_title.set_hexpand(True)
            il_title.set_halign(Gtk.Align.START)
            il_title.set_valign(Gtk.Align.START)
            il_title.set_xalign(0)

            il_desc = Gtk.Label(
                                css_name='sw_label_desc',
                                label=str(launchers_descriptions[Path(l).stem]),
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
            launchers_child.set_name(Path(l).stem)
            launchers_child.set_child(grid_il)
            swgs.launchers_flow.append(launchers_child)
            #launchers_flow.connect('child-activated', on_launchers_flow_activated, btn_il)

        scrolled_install_launchers.set_child(swgs.launchers_menu)

        return set_settings_widget(
                            vw_dict['install_launchers'],
                            None,
        )

####___Install_wine___.

    def add_wine_view():
        '''___build wine list view page___'''

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
                                halign=Gtk.Align.CENTER
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
        swgs.pref_group_wine_title_grid.attach(swgs.pref_group_wine_box, 0,0,1,1)
        swgs.pref_group_wine_title_grid.attach(swgs.btn_update_wine_list, 1,0,1,1)

        swgs.wine_flow = Gtk.FlowBox(css_name='sw_preferencesgroup')
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
            drop_wine_list_view = (dropdown_download_wine
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
            iw_desc.set_size_request(260,-1)

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
        return set_settings_widget(vw_dict['install_wine'], None)

#####___Mangohud_settings___.

    def add_mangohud_settings_view():
        '''___build mangohud settings view page___'''

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
        swgs.pref_group_mh_title_grid.attach(swgs.pref_group_mh_label_box, 0,0,1,1)
        swgs.pref_group_mh_title_grid.attach(swgs.btn_mh_preview_0, 1,0,1,1)

        swgs.mangohud_flow = Gtk.FlowBox(css_name='sw_preferencesgroup')
        swgs.mangohud_flow.set_margin_top(16)
        swgs.mangohud_flow.set_homogeneous(True)
        swgs.mangohud_flow.set_min_children_per_line(1)
        swgs.mangohud_flow.set_max_children_per_line(8)

        swgs.pref_group_mh_flow = Gtk.Box(
                                    css_name='sw_pref_box',
                                    orientation=Gtk.Orientation.VERTICAL
                                    )
        swgs.pref_group_mh_flow.append(swgs.pref_group_mh_title_grid)
        swgs.pref_group_mh_flow.append(swgs.mangohud_flow)

        swgs.mangohud_settings = Gtk.Box(
                                    css_name='sw_flowbox',
                                    orientation=Gtk.Orientation.VERTICAL
                                    )
        swgs.mangohud_settings.append(swgs.pref_group_mh_flow)

        count = -1
        for l, d in sorted(zip(check_mh_labels, check_mh_description)):
            count += 1
            btn_switch_mh = Gtk.Switch(
                                    css_name='sw_switch',
                                    valign=Gtk.Align.CENTER,
                                    halign=Gtk.Align.START,
                                    name=l,
            )
            btn_switch_mh.connect('state-set', cb_btn_switch_mh)
            check_btn_mh_list.append(btn_switch_mh)

            title_mh = Gtk.Label(
                                css_name='sw_label',
                                label=l.upper(),
                                hexpand=True,
                                halign=Gtk.Align.START,
                                xalign=0,
            )
            desc_mh = Gtk.Label(
                                css_name='sw_label_desc',
                                label=d,
                                hexpand=True,
                                valign=Gtk.Align.CENTER,
                                xalign=0,
                                max_width_chars=0,
                                wrap=True,
                                natural_wrap_mode=True,
                                wrap_mode=Pango.WrapMode.WORD,
            )
            desc_mh.set_size_request(280,-1)
            grid_mh = Gtk.Grid(css_name='sw_grid')
            grid_mh.attach(title_mh,0,count,1,1)
            grid_mh.attach(btn_switch_mh,1,count,1,1)

            pref_group_mh = Gtk.Box(
                                    css_name='sw_box_view',
                                    orientation=Gtk.Orientation.VERTICAL
            )
            pref_group_mh.append(grid_mh)
            pref_group_mh.append(desc_mh)

            mangohud_child = Gtk.FlowBoxChild(
                                    css_name='sw_flowboxchild',
                                    name=l,
            )
            mangohud_child.set_child(pref_group_mh)
            swgs.mangohud_flow.append(mangohud_child)
            swgs.mangohud_flow.connect('child-activated', on_mango_flow_activated, btn_switch_mh)

    ####___Colors_settings___.

        swgs.label_preview = Gtk.Label(css_name='sw_label', label=preview_label)

        swgs.btn_mh_preview = Gtk.Button(css_name='sw_button')
        swgs.btn_mh_preview.set_hexpand(True)
        swgs.btn_mh_preview.set_valign(Gtk.Align.START)
        swgs.btn_mh_preview.set_halign(Gtk.Align.END)
        swgs.btn_mh_preview.set_margin_bottom(16)
        swgs.btn_mh_preview.set_child(swgs.label_preview)
        swgs.btn_mh_preview.connect('clicked', cb_btn_mh_preview)

        ####___Mangohud_colors___.

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
        swgs.colors_mh_title_grid.attach(swgs.colors_mh_label_box, 0,0,1,1)
        swgs.colors_mh_title_grid.attach(swgs.btn_mh_preview, 1,0,1,1)

        swgs.colors_pref_mh = Gtk.Box(
                                css_name='sw_pref_box',
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
            title_mh_color.set_size_request(200,-1)
            title_mh_color.set_hexpand(True)
            title_mh_color.set_halign(Gtk.Align.START)
            title_mh_color.set_xalign(0)

            grid_mh_color = Gtk.Grid(css_name='sw_grid')
            grid_mh_color.attach(entry_mh_color,0,count,1,1)
            grid_mh_color.attach(btn_mh_color,1,count,1,1)

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
                            vw_dict['mangohud_settings'],
                            swgs.pref_group_mh_title,
        )

#####___Vkbasalt_settings___.

    def add_vkbasalt_settings_view():
        '''___build vkbasalt settings view page___'''

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
        swgs.btn_vk_scale.set_size_request(140,-1)
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
        swgs.pref_group_vk_title_grid.attach(swgs.pref_group_vk_label_box, 0,0,1,1)
        swgs.pref_group_vk_title_grid.attach(swgs.vk_scale_box, 1,0,1,1)

        swgs.vkbasalt_flow = Gtk.FlowBox(css_name='sw_preferencesgroup')
        swgs.vkbasalt_flow.set_homogeneous(True)
        swgs.vkbasalt_flow.set_min_children_per_line(1)
        swgs.vkbasalt_flow.set_max_children_per_line(8)

        swgs.pref_group_vk_flow = Gtk.Box(
                                    css_name='sw_pref_box',
                                    orientation=Gtk.Orientation.VERTICAL
                                    )
        swgs.pref_group_vk_flow.append(swgs.pref_group_vk_title_grid)
        swgs.pref_group_vk_flow.append(swgs.vkbasalt_flow)

        swgs.vkbasalt_settings = Gtk.Box(
                                    css_name='sw_flowbox',
                                    orientation=Gtk.Orientation.VERTICAL
                                    )
        swgs.vkbasalt_settings.append(swgs.pref_group_vk_flow)

        count = -1
        for l, d in sorted(vkbasalt_dict.items()):
            count += 1

            btn_switch_vk = Gtk.Switch(css_name='sw_switch')
            btn_switch_vk.set_name(l)
            btn_switch_vk.set_valign(Gtk.Align.CENTER)
            btn_switch_vk.set_halign(Gtk.Align.START)
            btn_switch_vk.connect('state-set', cb_btn_switch_vk)
            check_btn_vk_list.append(btn_switch_vk)

            title_vk = Gtk.Label(css_name='sw_label', label=l.upper())
            title_vk.set_hexpand(True)
            title_vk.set_halign(Gtk.Align.START)
            title_vk.set_xalign(0)

            desc_vk = Gtk.Label(css_name='sw_label_desc', label=d)
            desc_vk.set_size_request(280,-1)
            desc_vk.set_hexpand(True)
            desc_vk.set_valign(Gtk.Align.CENTER)
            desc_vk.set_xalign(0)
            desc_vk.set_max_width_chars(0)
            desc_vk.set_wrap(True)
            desc_vk.set_natural_wrap_mode(True)

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
            vkbasalt_child.set_name(l)
            vkbasalt_child.set_child(pref_group_vk)
            swgs.vkbasalt_flow.insert(vkbasalt_child, position=count)
            swgs.vkbasalt_flow.connect('child-activated', on_vk_flow_activated, btn_switch_vk)

        scrolled_vkbasalt_settings.set_child(swgs.vkbasalt_settings)

        app_name = get_out()
        app_conf = f"{sw_app_config}/{app_name}"
        app_dict = app_info(app_conf)
        swgs.vk_adjustment.set_value(float(app_dict['export SW_USE_VKBASALT_CAS'][1:-1])*100)

        return set_settings_widget(
                                vw_dict['vkbasalt_settings'],
                                swgs.pref_group_vk_title
                                )

#####___Global_settings___.

    def add_global_settings_view():
        '''___build global settings view page___'''

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
        swgs.global_settings_title_grid.attach(swgs.global_settings_label_box,0,0,1,1)
        swgs.global_settings_title_grid.attach(swgs.btn_global_settings_reset,1,0,1,1)

        ####___autostart_row___.

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
        swgs.grid_autostart_labels.attach(swgs.title_autostart,0,0,1,1)
        swgs.grid_autostart_labels.attach(swgs.subtitle_autostart,0,1,1,1)

        swgs.switch_autostart = Gtk.Switch(css_name='sw_switch', margin_end=4)
        swgs.switch_autostart.set_valign(Gtk.Align.CENTER)
        swgs.switch_autostart.set_halign(Gtk.Align.END)
        swgs.switch_autostart.connect('state-set', on_switch_autostart)

        swgs.row_autostart = Gtk.Box(
                        css_name='sw_action_row',
                        orientation=Gtk.Orientation.HORIZONTAL,
                        spacing=4
                        )
        swgs.row_autostart.set_size_request(-1, 48)
        swgs.row_autostart.append(swgs.grid_autostart_labels)
        swgs.row_autostart.append(swgs.switch_autostart)

        ####___language_row___.

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
        swgs.lang_list_factory.connect('setup', on_lang_setup)
        swgs.lang_list_factory.connect('bind', on_lang_bind)

        swgs.dropdown_lang = Gtk.DropDown(css_name='sw_dropdown')
        swgs.dropdown_lang.set_valign(Gtk.Align.CENTER)
        swgs.dropdown_lang.set_halign(Gtk.Align.END)
        swgs.dropdown_lang.set_model(swgs.lang_list_model)
        swgs.dropdown_lang.connect('notify::selected-item', on_lang_activate)

        swgs.row_lang = Gtk.Box(
                        css_name='sw_action_row',
                        orientation=Gtk.Orientation.HORIZONTAL,
                        spacing=4
                        )
        swgs.row_lang.set_size_request(-1,48)
        swgs.row_lang.append(swgs.grid_lang_labels)
        swgs.row_lang.append(swgs.dropdown_lang)

        ####___icon_mode_row___.

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
        swgs.grid_icons_labels.attach(swgs.title_icons,0,0,1,1)
        swgs.grid_icons_labels.attach(swgs.subtitle_icons,0,1,1,1)

        swgs.switch_icons = Gtk.Switch(css_name='sw_switch', margin_end=4)
        swgs.switch_icons.set_valign(Gtk.Align.CENTER)
        swgs.switch_icons.set_halign(Gtk.Align.END)
        swgs.switch_icons.connect('state-set', on_switch_icons)

        swgs.row_icons = Gtk.Box(
                        css_name='sw_action_row',
                        orientation=Gtk.Orientation.HORIZONTAL,
                        spacing=4
                        )
        swgs.row_icons.set_size_request(-1, 48)
        swgs.row_icons.append(swgs.grid_icons_labels)
        swgs.row_icons.append(swgs.switch_icons)

        ####___restore_menu_mode_row___.

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
        swgs.grid_restore_menu_labels.attach(swgs.title_restore_menu,0,0,1,1)
        swgs.grid_restore_menu_labels.attach(swgs.subtitle_restore_menu,0,1,1,1)

        swgs.switch_restore_menu = Gtk.Switch(css_name='sw_switch', margin_end=4)
        swgs.switch_restore_menu.set_valign(Gtk.Align.CENTER)
        swgs.switch_restore_menu.set_halign(Gtk.Align.END)
        swgs.switch_restore_menu.connect('state-set', on_switch_restore_menu)

        swgs.row_restore_menu = Gtk.Box(
                        css_name='sw_action_row',
                        orientation=Gtk.Orientation.HORIZONTAL,
                        spacing=4
                        )
        swgs.row_restore_menu.set_size_request(-1, 48)
        swgs.row_restore_menu.append(swgs.grid_restore_menu_labels)
        swgs.row_restore_menu.append(swgs.switch_restore_menu)

        ####___auto_stop_mode___.

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

        swgs.row_auto_stop = Gtk.Box(
                        css_name='sw_action_row',
                        orientation=Gtk.Orientation.HORIZONTAL,
                        spacing=4
        )
        swgs.row_auto_stop.set_size_request(-1, 48)
        swgs.row_auto_stop.append(swgs.grid_auto_stop_labels)
        swgs.row_auto_stop.append(swgs.switch_auto_stop)

        ####___auto_hide_top_header_mode___.

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

        swgs.row_auto_hide_top = Gtk.Box(
                        css_name='sw_action_row',
                        orientation=Gtk.Orientation.HORIZONTAL,
                        spacing=4
        )
        swgs.row_auto_hide_top.set_size_request(-1, 48)
        swgs.row_auto_hide_top.append(swgs.grid_auto_hide_top)
        swgs.row_auto_hide_top.append(swgs.switch_auto_hide_top)

        ####___auto_hide_bottom_header_mode___.

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

        swgs.row_auto_hide_bottom = Gtk.Box(
                        css_name='sw_action_row',
                        orientation=Gtk.Orientation.HORIZONTAL,
                        spacing=4,
        )
        swgs.row_auto_hide_bottom.set_size_request(-1, 48)
        swgs.row_auto_hide_bottom.append(swgs.grid_auto_hide_bottom)
        swgs.row_auto_hide_bottom.append(swgs.switch_auto_hide_bottom)

        ####___default_file_manager_directory_row___.

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
        swgs.grid_def_dir_labels.attach(swgs.title_def_dir,0,0,1,1)
        swgs.grid_def_dir_labels.attach(swgs.subtitle_def_dir,0,1,1,1)

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
        swgs.row_def_dir.set_size_request(-1, 48)
        swgs.row_def_dir.append(swgs.entry_def_dir)
        swgs.row_def_dir.append(swgs.btn_def_dir)

        ####___opengl_background_row___.

        swgs.title_opengl = Gtk.Label(
                            css_name='sw_label_title',
                            label=str_title_opengl,
                            xalign=0,
                            margin_start=4,
                            hexpand=True
                            )

        swgs.subtitle_opengl = Gtk.Label(
                            css_name='sw_label_warning',
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

        swgs.grid_opengl_labels = Gtk.Grid(css_name='sw_grid')
        swgs.grid_opengl_labels.attach(swgs.title_opengl,0,0,1,1)
        swgs.grid_opengl_labels.attach(swgs.subtitle_opengl,0,1,1,1)
        swgs.grid_opengl_labels.attach(swgs.switch_opengl,1,0,1,1)

        swgs.grid_shader_labels = Gtk.Grid(css_name='sw_grid')
        swgs.grid_shader_labels.set_hexpand(True)
        swgs.grid_shader_labels.attach(swgs.title_shaders,0,0,1,1)
        swgs.grid_shader_labels.attach(swgs.subtitle_shaders,0,1,1,1)

        swgs.shaders_list_model = Gtk.StringList()

        for l in fragments_labels:
            swgs.shaders_list_model.append(l)

        swgs.shaders_list_factory = Gtk.SignalListItemFactory()
        swgs.shaders_list_factory.connect('setup', on_shaders_setup)
        swgs.shaders_list_factory.connect('bind', on_shaders_bind)

        swgs.dropdown_shaders = Gtk.DropDown(css_name='sw_dropdown')
        swgs.dropdown_shaders.set_valign(Gtk.Align.CENTER)
        swgs.dropdown_shaders.set_halign(Gtk.Align.END)
        swgs.dropdown_shaders.set_model(swgs.shaders_list_model)
        swgs.dropdown_shaders.connect('notify::selected-item', on_shaders_activate)

        swgs.row_shaders = Gtk.Box(
                            css_name='sw_action_row',
                            orientation=Gtk.Orientation.HORIZONTAL,
                            spacing=4
                            )
        swgs.row_shaders.set_size_request(-1, 48)
        swgs.row_shaders.append(swgs.grid_shader_labels)
        swgs.row_shaders.append(swgs.dropdown_shaders)

        ###___groups___.

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
        swgs.title_startup_grid.attach(swgs.title_startup,0,0,1,1)
        swgs.title_startup_grid.attach(swgs.subtitle_startup,0,1,1,1)

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

        swgs.group_opengl = Gtk.Box(
                            css_name='sw_preferencesgroup',
                            orientation=Gtk.Orientation.VERTICAL,
                            spacing=4,
                            margin_start=16,
                            margin_end=16,
        )
        swgs.group_opengl.append(swgs.grid_opengl_labels)
        swgs.group_opengl.append(swgs.row_shaders)

        ####___Custom_theme_colors___.

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
        for t in list(default_themes):
            swgs.themes_model.append(t)

        swgs.themes_list_factory = Gtk.SignalListItemFactory()
        swgs.themes_list_factory.connect('setup', on_combo_setup)
        swgs.themes_list_factory.connect('bind', on_combo_bind)

        #dropdown_theme.set_factory(themes_list_factory)
        swgs.dropdown_theme.set_model(swgs.themes_model)
        swgs.dropdown_theme.connect('notify::selected-item', on_row_theme_activate)

        swgs.label_sample = Gtk.Label(
                            css_name='sw_label',
                            xalign=0,
                            label=str_sample.capitalize(),
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
        swgs.colors_theme_title_grid.attach(swgs.colors_theme_label_box, 0,0,1,1)
        swgs.colors_theme_title_grid.attach(swgs.btn_save_theme, 1,0,1,1)
        swgs.colors_theme_title_grid.attach(swgs.box_theme, 0,1,1,1)

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
        for n, l in zip(dcolor_names, dcolor_labels):
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
            entry_theme_color.set_name(n)
            entry_theme_color_list.append(entry_theme_color)

            color_dialog = Gtk.ColorDialog()

            btn_theme_color = Gtk.ColorDialogButton(css_name='sw_buttoncolor')
            btn_theme_color.set_vexpand(True)
            btn_theme_color.set_hexpand(True)
            btn_theme_color.set_valign(Gtk.Align.CENTER)
            btn_theme_color.set_halign(Gtk.Align.END)
            btn_theme_color.set_size_request(32, 32)
            btn_theme_color.set_name(n)
            btn_theme_color.set_tooltip_markup(msg.tt_dict['color'])
            btn_theme_color.set_dialog(color_dialog)
            btn_theme_color.connect('notify::rgba', on_theme_color_set, entry_theme_color)
            btn_theme_color_list.append(btn_theme_color)

            btn_theme_color.get_first_child().remove_css_class('color')
            btn_theme_color.get_first_child().add_css_class('sw_color')

            title_theme_color = Gtk.Label(css_name='sw_label', label=l)
            title_theme_color.set_size_request(200,-1)
            title_theme_color.set_hexpand(True)
            title_theme_color.set_halign(Gtk.Align.START)
            title_theme_color.set_xalign(0)

            grid_theme_color = Gtk.Grid(css_name='sw_grid')
            grid_theme_color.attach(entry_theme_color,0,count,1,1)
            grid_theme_color.attach(btn_theme_color,1,count,1,1)

            pref_box_theme_color = Gtk.Box(
                                        css_name='sw_box_view',
                                        orientation=Gtk.Orientation.VERTICAL
            )
            pref_box_theme_color.append(title_theme_color)
            pref_box_theme_color.append(grid_theme_color)

            colors_flow_theme_child = Gtk.FlowBoxChild(css_name='sw_flowboxchild')
            colors_flow_theme_child.set_name(l)
            colors_flow_theme_child.set_child(pref_box_theme_color)
            swgs.colors_flow_theme.append(colors_flow_theme_child)

        swgs.global_box = Gtk.Box(
                            css_name='sw_pref_box',
                            orientation=Gtk.Orientation.VERTICAL,
                            spacing=16,
                            halign=Gtk.Align.CENTER
        )
        swgs.global_box.append(swgs.global_settings_title_grid)
        swgs.global_box.append(swgs.group_startup)
        swgs.global_box.append(swgs.group_fm)
        swgs.global_box.append(swgs.group_opengl)
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
                                vw_dict['global_settings'],
                                None
        )

    ####___Winetricks_dll_column_view___.

    def add_winetricks_view():
        '''___build winetricks view page___'''

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

        ####___Winetricks fonts_column_view___.

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
            l = Gtk.Label(name=v, label=k)
            swgs.model_templates_dll.append(l)

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
                                    label=str_sample.capitalize(),
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
        swgs.winetricks_title_grid.attach(swgs.winetricks_label_box, 0,0,1,1)
        swgs.winetricks_title_grid.attach(swgs.btn_install_dll, 1,0,1,1)

        swgs.pref_group_winetricks = Gtk.Box(
                                    css_name='sw_pref_box',
                                    orientation=Gtk.Orientation.VERTICAL
        )
        swgs.pref_group_winetricks.append(swgs.winetricks_title_grid)
        swgs.pref_group_winetricks.append(swgs.box_tabs)
        swgs.pref_group_winetricks.append(swgs.stack_tabs)

        scrolled_winetricks.set_child(swgs.pref_group_winetricks)

    def add_column_view():
        '''___build files_column_view___'''

        swgs.column_view = Gtk.ColumnView(
                                    name='left_column_view',
                                    css_name='sw_columnview_view',
                                    show_row_separators=True,
                                    show_column_separators=True,
        )
        #swgs.column_view.remove_css_class('view')
        #swgs.column_view.add_css_class('sw_view')

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

    ####___Gvolume_column_view___

    def add_gvol_view():
        '''___build gio volumes view___'''

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

        ####___Get_volume_info___

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

        gvolume_list = swgs.gvolume_monitor.get_volumes()
        gmount_list = swgs.gvolume_monitor.get_mounts()
        gdrive_list = swgs.gvolume_monitor.get_connected_drives()

        scrolled_gvol.set_child(column_gvol_view)

    ####___Bookmarks_list_view___.

    def add_bookmarks_menu():
        '''___build bookmarks menu___'''

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


####___Game_controller_settings___.

    def add_controller_settings_view():
        ''''''
        pass

    def get_define_colors():
        '''Get current define colors from css provider'''

        css_list = css_provider.to_string().splitlines()
        define_colors = dict()
        for x in css_list:
            if '@define-color sw_' in x:
                if len([x.split(' ')[2].strip(';') ]) > 0:
                    define_colors[x.split(' ')[1]] = [x.split(' ')[2].strip(';') ][0]

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
        '''Set parent window surface as a background layer.'''

        LayerShell.init_for_window(window)
        LayerShell.set_layer(window, LayerShell.Layer.BACKGROUND)
        #LayerShell.set_anchor(window, LayerShell.Edge.TOP, True)
        LayerShell.set_monitor(window, monitor)

        LayerShell.set_margin(window, LayerShell.Edge.BOTTOM, 0)
        LayerShell.set_margin(window, LayerShell.Edge.TOP, 0)
        LayerShell.auto_exclusive_zone_enable(window)

####___Build_main_menu___.

    display = Gdk.Display().get_default()

    try:
        monitor = display.get_monitors()[0]
    except:
        width = 1280
        height = 720
        print(tc.RED, f'MONITOR_SIZE: not found, set {width}x{height}{tc.END}')
    else:
        width = monitor.get_geometry().width
        height = monitor.get_geometry().height
        env_dict['SW_HUD_SIZE'] = f'{int(height / 55)}'
        print(tc.VIOLET, f'MONITOR_SIZE: {tc.YELLOW}{width}x{height}{tc.END}')

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
    parent.set_default_size(sw_width, sw_height)
    parent.set_resizable(True)
    parent.set_default_icon_name(sw_program_name)

    swgs.connection.register_object(
                            "/ru/project/StartWine",
                            swgs.gdbus_node.interfaces[0],
                            gdbus_method_call,
                            None,
                            None
    )

####___Headerbars___.

    ####___Search_entry___.

    entry_search = Gtk.SearchEntry(
                                css_name='sw_entry',
                                placeholder_text='search...',
                                valign=Gtk.Align.CENTER,
                                hexpand=True,
                                search_delay=500,
    )
    entry_search.connect('search-changed', cb_entry_search_changed)

    entry_web = Gtk.Entry(
                        css_name='sw_entry',
                        placeholder_text='url...',
                        valign=Gtk.Align.CENTER,
                        hexpand=True,
    )
    entry_web.connect('activate', cb_entry_web_activate)

    entry_path = Gtk.Entry(
                        name = str(sw_default_dir),
                        css_name='sw_entry',
                        text=str(sw_default_dir),
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
                        min_content_width=width*0.25,
                        max_content_width=width*0.66,
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

    image_home =Gtk.Image(css_name='sw_image')
    image_home.set_from_file(IconPath.icon_home)

    image_back =Gtk.Image(css_name='sw_image')
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
                                valign=Gtk.Align.CENTER,
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

    wc_close = Gtk.Button(css_name='sw_wc_close')
    wc_close.connect('clicked', on_parent_close)

    wc_minimize = Gtk.Button(css_name='sw_wc_minimize')
    wc_minimize.connect('clicked', on_parent_minimize)

    wc_maximize = Gtk.Button(css_name='sw_wc_maximize')
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
    top_headerbar.set_size_request(-1,46)
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

    ####___Bottom_headerbar stack panel___.

    progress_main = SwProgressBar(
                        css_name='sw_progressbar',
                        valign=Gtk.Align.CENTER,
                        halign=Gtk.Align.CENTER,
                        hexpand=True,
                        vexpand=True,
    )
    progress_main.set_size_request(320, 20)
    progress_main.set_visible(False)

    spinner = Gtk.Spinner(css_name='sw_spinner')

    progress_main_grid = Gtk.Grid(css_name='sw_grid')
    progress_main_grid.attach(progress_main,0,0,1,1)
    progress_main_grid.attach(spinner,1,0,1,1)

    media_file = Gtk.MediaFile.new()
    media_controls = Gtk.MediaControls(css_name="sw_media_controls")
    media_controls.set_media_stream(media_file)
    media_controls.set_size_request(200,-1)

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
    stack_progress_main.add_child(media_controls)

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
    btn_scale_icons.set_increments(scale_step,1)
    btn_scale_icons.set_numeric(True)
    btn_scale_icons.set_range(24, 216)
    btn_scale_icons.set_snap_to_ticks(True)
    btn_scale_icons.set_update_policy(Gtk.SpinButtonUpdatePolicy.IF_VALID)
    btn_scale_icons.set_value(sw_icon_size)
    btn_scale_icons.connect('value-changed', on_set_px_size)

    btn_scale_shortcuts = Gtk.SpinButton(css_name='sw_spinbutton')
    btn_scale_shortcuts.set_hexpand(True)
    btn_scale_shortcuts.set_halign(Gtk.Align.FILL)
    btn_scale_shortcuts.set_climb_rate(0)
    btn_scale_shortcuts.set_digits(0)
    btn_scale_shortcuts.set_increments(scale_step,1)
    btn_scale_shortcuts.set_numeric(True)
    btn_scale_shortcuts.set_range(96, 288)
    btn_scale_shortcuts.set_snap_to_ticks(True)
    btn_scale_shortcuts.set_update_policy(Gtk.SpinButtonUpdatePolicy.IF_VALID)
    btn_scale_shortcuts.set_value(sw_sc_size)
    btn_scale_shortcuts.connect('value-changed', on_set_px_size)

    menu_box = Gtk.Grid()
    menu_box.set_size_request(width*0.1, height*0.01)
    menu_box.set_hexpand(True)
    menu_box.set_halign(Gtk.Align.FILL)
    menu_box.attach(btn_scale_icons, 0,0,1,1)

    menu_box_sc = Gtk.Grid()
    menu_box_sc.set_size_request(width*0.1, height*0.01)
    menu_box_sc.set_hexpand(True)
    menu_box_sc.set_halign(Gtk.Align.FILL)
    menu_box_sc.attach(btn_scale_shortcuts, 0,0,1,1)

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
    colors_box.attach(btn_dark, 0,0,1,1)
    colors_box.attach(label_dark, 1,0,1,1)
    colors_box.attach(btn_light, 2,0,1,1)
    colors_box.attach(label_light, 3,0,1,1)
    colors_box.attach(btn_custom, 4,0,1,1)
    colors_box.attach(label_custom, 5,0,1,1)

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

    bottom_headerbar_center_box.append(stack_progress_main)

    bottom_headerbar_end_box.append(btn_popover_scale)
    bottom_headerbar_end_box.append(btn_popover_colors)
    bottom_headerbar_end_box.append(btn_icon_position)

    bottom_headerbar = Gtk.HeaderBar(
                                    css_name='sw_header_bottom',
                                    title_widget=bottom_headerbar_center_box,
                                    show_title_buttons=False,
                                    
                                    )
    bottom_headerbar.set_size_request(-1,46)
    bottom_headerbar.pack_start(bottom_headerbar_start_box)
    bottom_headerbar.pack_end(bottom_headerbar_end_box)

####___Sidebar main grids___.

    grid_main = Gtk.Grid()
    grid_main.set_hexpand(True)
    grid_main.set_vexpand(True)

    grid_start_mode = Gtk.Grid(css_name='sw_grid')
    grid_start_mode.set_vexpand(True)
    grid_start_mode.set_valign(Gtk.Align.START)
    grid_start_mode.set_row_spacing(10)

    grid_main_btn = Gtk.Grid()
    grid_main_btn.set_vexpand(True)
    grid_main_btn.set_row_spacing(10)
    grid_main_btn.set_margin_start(16)
    grid_main_btn.set_margin_end(16)
    grid_main_btn.set_margin_top(16)
    grid_main_btn.set_margin_bottom(16)
    grid_main_btn.set_halign(Gtk.Align.CENTER)

####___Image next___.

    image_next = Gtk.Image(css_name='sw_image')
    image_next.set_from_file(IconPath.icon_next)
    image_next.set_halign(Gtk.Align.END)

####___Sidebar_widgets___.

    ####___Start_mode___.

    image_start_mode = Gtk.Picture(css_name='sw_picture')
    image_start_mode.set_hexpand(True)
    image_start_mode.set_vexpand(True)
    image_start_mode.set_valign(Gtk.Align.START)
    image_start_mode.set_size_request(-1, 128)

    image_shortcuts = Gtk.Image(css_name='sw_image')
    image_shortcuts.set_from_file(IconPath.icon_shortcuts)

    image_create_shortcut = Gtk.Image(css_name='sw_image')
    image_create_shortcut.set_from_file(IconPath.icon_folder)

    label_shortcuts = Gtk.Label(
                                css_name='sw_label',
                                label=msg.msg_dict['shortcuts']
    )
    label_create_shortcut = Gtk.Label(
                                    css_name='sw_label',
                                    label=vl_dict['files']
    )
    label_prefix_mode = Gtk.Label(
                                css_name='sw_label_desc',
                                ellipsize=Pango.EllipsizeMode.END,
                                xalign=0,
    )
    label_wine_mode = Gtk.Label(
                                css_name='sw_label_desc',
                                ellipsize=Pango.EllipsizeMode.END,
                                xalign=0,
    )
    box_btn_shortcuts = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
    box_btn_shortcuts.set_spacing(8)
    box_btn_shortcuts.append(image_shortcuts)
    box_btn_shortcuts.append(label_shortcuts)

    box_btn_files = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
    box_btn_files.set_spacing(8)
    box_btn_files.append(image_create_shortcut)
    box_btn_files.append(label_create_shortcut)

    btn_shortcuts = Gtk.Button(css_name='sw_button_custom')
    btn_shortcuts.set_name(btn_dict['shortcuts'])
    btn_shortcuts.set_vexpand(True)
    btn_shortcuts.set_valign(Gtk.Align.END)
    btn_shortcuts.set_child(box_btn_shortcuts)
    btn_shortcuts.connect('clicked', cb_btn_main)

    btn_files = Gtk.Button(css_name='sw_button_custom')
    btn_files.set_name(btn_dict['create_shortcut'])
    btn_files.set_child(box_btn_files)
    btn_files.connect('clicked', cb_btn_main)

    box_btn_start_mode = Gtk.Box(css_name='sw_box', orientation=Gtk.Orientation.VERTICAL)
    box_btn_start_mode.set_margin_start(8)
    box_btn_start_mode.set_margin_end(8)
    box_btn_start_mode.set_margin_bottom(8)
    box_btn_start_mode.set_spacing(8)
    box_btn_start_mode.set_vexpand(True)
    box_btn_start_mode.set_valign(Gtk.Align.END)
    box_btn_start_mode.append(btn_shortcuts)
    box_btn_start_mode.append(btn_files)

    reveal_start_mode = Gtk.Revealer()
    reveal_start_mode.set_child(box_btn_start_mode)
    reveal_start_mode.set_transition_duration(250)
    reveal_start_mode.set_transition_type(Gtk.RevealerTransitionType.CROSSFADE)
    reveal_start_mode.set_reveal_child(False)

    ctrl_moition_start_mode = Gtk.EventControllerMotion()
    ctrl_moition_start_mode.connect('enter', cb_ctrl_enter_start_mode)
    ctrl_moition_start_mode.connect('leave', cb_ctrl_leave_start_mode)

    overlay_start_mode = Gtk.Overlay(css_name='sw_overlay')
    overlay_start_mode.set_child(image_start_mode)
    overlay_start_mode.add_overlay(reveal_start_mode)
    overlay_start_mode.set_valign(Gtk.Align.CENTER)
    overlay_start_mode.add_controller(ctrl_moition_start_mode)

    grid_start_mode.attach(overlay_start_mode, 0,0,1,1)

    ####___Start___.

    image_btn_start = Gtk.Image(css_name='sw_image')
    image_btn_start.set_from_file(IconPath.icon_playback)

    image_btn_debug = Gtk.Image(css_name='sw_image')
    image_btn_debug.set_from_file(IconPath.icon_debug)

    image_start_settings = Gtk.Image(css_name='sw_image')
    image_start_settings.set_from_file(IconPath.icon_settings)

    image_stop = Gtk.Image(css_name='sw_image')
    image_stop.set_from_file(IconPath.icon_clear)

    label_btn_start = Gtk.Label(css_name='sw_label')
    label_btn_start.set_label(btn_dict['start'])

    box_btn_start = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
    box_btn_start.set_halign(Gtk.Align.CENTER)
    box_btn_start.set_spacing(8)
    box_btn_start.append(label_btn_start)
    box_btn_start.append(image_btn_start)

    btn_stop = Gtk.Button(css_name='sw_button')
    btn_stop.set_tooltip_markup(msg.tt_dict['stop'])

    btn_stop.set_halign(Gtk.Align.START)
    btn_stop.set_name(btn_dict['stop'])
    btn_stop.set_child(image_stop)
    btn_stop.connect('clicked', cb_btn_main)

    btn_start = Gtk.Button(css_name='sw_button')
    btn_start.set_vexpand(True)
    btn_start.set_hexpand(True)
    btn_start.set_halign(Gtk.Align.FILL)
    btn_start.set_child(box_btn_start)
    btn_start.connect('clicked', cb_btn_start)

    btn_start_settings = Gtk.Button(css_name='sw_button')
    btn_start_settings.set_tooltip_markup(msg.tt_dict['settings'])
    btn_start_settings.set_name(btn_dict['settings'])
    btn_start_settings.set_vexpand(True)
    btn_start_settings.set_halign(Gtk.Align.END)
    btn_start_settings.set_child(image_start_settings)
    btn_start_settings.connect('clicked', cb_btn_start_settings)

    box_start_main = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
    box_start_main.set_spacing(8)
    box_start_main.append(btn_stop)
    box_start_main.append(btn_start)
    box_start_main.append(btn_start_settings)

    grid_start_mode.attach(box_start_main,0,1,1,1)
    grid_main_btn.attach(grid_start_mode,0,0,1,1)

    ####___Sidebar_menu_buttons___.

    image_btn_wine_tools = Gtk.Image(css_name='sw_image')
    image_btn_wine_tools.set_from_file(IconPath.icon_wine)

    image_btn_prefix_tools = Gtk.Image(css_name='sw_image')
    image_btn_prefix_tools.set_from_file(IconPath.icon_toolbox)

    label_btn_wine_tools = Gtk.Label(
                                    css_name='sw_label',
                                    label=btn_dict['wine_tools']
                                    )
    label_btn_wine_tools.set_xalign(0)

    label_btn_prefix_tools = Gtk.Label(
                                    css_name='sw_label',
                                    label=btn_dict['prefix_tools']
                                    )
    label_btn_prefix_tools.set_xalign(0)

    btn_wine_menu = Gtk.Button(css_name='sw_button')
    btn_wine_menu.set_name(btn_dict['wine_tools'])
    btn_wine_menu.set_hexpand(True)

    btn_prefix_tools = Gtk.Button(css_name='sw_button')
    btn_prefix_tools.set_name(btn_dict['prefix_tools'])
    btn_prefix_tools.set_hexpand(True)

    grid_btn_wine_tools = Gtk.Grid()
    grid_btn_wine_tools.set_column_spacing(8)
    grid_btn_wine_tools.attach(image_btn_wine_tools,0,0,1,1)
    grid_btn_wine_tools.attach(label_btn_wine_tools,1,0,1,1)
    grid_btn_wine_tools.attach(label_wine_mode,1,1,1,1)

    grid_btn_prefix_tools = Gtk.Grid()
    grid_btn_prefix_tools.set_column_spacing(8)
    grid_btn_prefix_tools.attach(image_btn_prefix_tools,0,0,1,1)
    grid_btn_prefix_tools.attach(label_btn_prefix_tools,1,0,1,1)
    grid_btn_prefix_tools.attach(label_prefix_mode,1,1,1,1)

    btn_wine_menu.set_child(grid_btn_wine_tools)
    btn_wine_menu.connect('clicked', cb_btn_main)

    btn_prefix_tools.set_child(grid_btn_prefix_tools)
    btn_prefix_tools.connect('clicked', cb_btn_main)

    grid_btn_tools = Gtk.Grid()
    grid_btn_tools.set_row_spacing(12)
    grid_btn_tools.attach(btn_wine_menu,0,0,1,1)
    grid_btn_tools.attach(btn_prefix_tools,0,1,1,1)

    grid_btn_tools.set_vexpand(True)
    grid_btn_tools.set_hexpand(True)
    grid_btn_tools.set_valign(Gtk.Align.CENTER)
    grid_btn_tools.set_halign(Gtk.Align.FILL)

    image_install = Gtk.Image(css_name='sw_image')
    image_install.set_from_file(IconPath.icon_install)

    label_install = Gtk.Label(
                            css_name='sw_label',
                            label=msg.msg_dict['install_title'],
                            xalign=0,
    )
    label_install_desc = Gtk.Label(
                                css_name='sw_label_desc',
                                label=msg.msg_dict['install_desc'],
                                xalign=0,
    )
    grid_label_install = Gtk.Grid(
                                css_name='sw_box',
                                orientation=Gtk.Orientation.VERTICAL,
                                column_spacing=4,
    )
    grid_label_install.attach(image_install, 0, 0, 1, 1)
    grid_label_install.attach(label_install, 1, 0, 1, 1)
    grid_label_install.attach(label_install_desc, 1, 1, 1, 1)

    btn_install = Gtk.Button(css_name='sw_button')
    btn_install.set_hexpand(True)
    btn_install.set_name(btn_dict['install_launchers'])
    btn_install.set_child(grid_label_install)
    btn_install.connect('clicked', cb_btn_main)

    grid_btn_tools.attach(btn_install,0,2,1,1)
    grid_start_mode.attach(grid_btn_tools,0,2,1,1)

####___Vte_terminal___.

    terminal_stack = Gtk.Stack()
    terminal_stack.set_transition_duration(350)
    terminal_stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)

    terminal_revealer = Gtk.Revealer()
    terminal_revealer.set_transition_duration(250)
    terminal_revealer.set_transition_type(Gtk.RevealerTransitionType.SLIDE_UP)
    terminal_revealer.set_reveal_child(False)

    try:
        terminal = Vte.Terminal(css_name='sw_vte')
    except:
        pass
    else:
        shell = '/bin/sh'

        terminal.spawn_async(
                            Vte.PtyFlags.DEFAULT,
                            None,
                            [shell],
                            None,
                            GLib.SpawnFlags.DEFAULT,
                            None, None,
                            -1,
                            None,
                            cb_terminal_changed,
                            Path.cwd(),
                            )

        ctrl_rclick_term = Gtk.GestureClick()
        ctrl_rclick_term.connect('pressed', cb_ctrl_rclick_term)
        ctrl_rclick_term.set_button(3)

        ctrl_key_term = Gtk.EventControllerKey()
        ctrl_key_term.connect('key_pressed', cb_ctrl_key_term, terminal)

        terminal.set_scrollback_lines(8192)
        term_font = Pango.FontDescription("Normal 11")
        terminal.set_font(term_font)
        terminal.set_clear_background(True)

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

####___file_view_lists___.

    list_store = Gio.ListStore()
    left_dir_list = Gtk.DirectoryList()
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
    action_copy = Gdk.DragAction.COPY
    action_move = Gdk.DragAction.MOVE
    action_ask = Gdk.DragAction.ASK

    ctrl_drop_target.set_gtypes(types)
    ctrl_drop_target.set_actions(action_move)
    ctrl_drop_target.set_preload(True)
    ctrl_drop_target.connect('drop', cb_ctrl_drop_target)

    ctrl_left_view_motion = Gtk.EventControllerMotion()
    ctrl_left_view_motion.connect('enter', cb_ctrl_left_view_motion)

    ctrl_left_view_focus = Gtk.EventControllerFocus()
    ctrl_left_view_focus.connect('enter', cb_ctrl_left_view_focus)
    #ctrl_left_view_focus.connect('leave', cb_ctrl_left_view_focus)

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
                                    min_content_height=(height*0.2),
                                    child=grid_main_btn,
    )
    scrolled_create_shortcut = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    vexpand=True,
                                    valign=Gtk.Align.FILL,
                                    halign=Gtk.Align.FILL,
                                    #child=grid_create_shortcut,
    )
    scrolled_prefix_tools = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    vexpand=True,
                                    valign=Gtk.Align.FILL,
                                    halign=Gtk.Align.FILL,
                                    #child=grid_prefix_tools,
    )
    scrolled_wine_tools = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    vexpand=True,
                                    valign=Gtk.Align.FILL,
                                    halign=Gtk.Align.FILL,
                                    #child=grid_wine_tools,
    )
    scrolled_settings = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    vexpand=True,
                                    valign=Gtk.Align.FILL,
                                    halign=Gtk.Align.FILL,
                                    #child=grid_settings,
    )
    scrolled_about = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    vexpand=True,
                                    valign=Gtk.Align.FILL,
                                    halign=Gtk.Align.FILL,
                                    #child=grid_about,
    )
    scrolled_stack = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    vexpand=True,
                                    valign=Gtk.Align.FILL,
                                    halign=Gtk.Align.FILL,
                                    #child=stack_about,
    )
    scrolled_files_info = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    vexpand=True,
                                    valign=Gtk.Align.FILL,
                                    halign=Gtk.Align.FILL,
                                    #child=grid_files_info,
    )
    scrolled_bookmarks = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    vexpand=True,
                                    valign=Gtk.Align.FILL,
                                    halign=Gtk.Align.FILL,
                                    #child=list_view_bookmarks,
    )
    scrolled_gvol = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    propagate_natural_height=True,
                                    propagate_natural_width=True,
                                    halign=Gtk.Align.FILL,
                                    valign=Gtk.Align.FILL,
                                    #child=column_gvol_view,
    )
    terminal_stack.add_child(scrolled_gvol)
    terminal_stack.add_child(terminal)
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

    files_view_grid = Gtk.Paned(name='files', css_name='sw_grid', orientation=Gtk.Orientation.VERTICAL)
    files_view_grid.set_start_child(paned_grid_view)
    files_view_grid.set_end_child(terminal_revealer)

    scrolled_startapp_page = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    vexpand=True,
                                    hexpand=True,
                                    valign=Gtk.Align.FILL,
                                    halign=Gtk.Align.FILL,
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
    scrolled_launch_settings = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    name=vw_dict['launch_settings'],
                                    vexpand=True,
                                    hexpand=True,
                                    valign=Gtk.Align.FILL,
                                    halign=Gtk.Align.FILL,
    )
    scrolled_mangohud_settings = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    name=vw_dict['mangohud_settings'],
                                    vexpand=True,
                                    hexpand=True,
                                    valign=Gtk.Align.FILL,
                                    halign=Gtk.Align.FILL,
    )
    scrolled_vkbasalt_settings = Gtk.ScrolledWindow(
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
                                        min_content_width=width*0.25,
                                        max_content_width=width*0.66,
                                        propagate_natural_width=True,
                                        child=box_web_bar,
    )
    scrolled_web_bar.set_policy(Gtk.PolicyType.EXTERNAL, Gtk.PolicyType.NEVER)
    stack_web = Gtk.Notebook(css_name='sw_stack', scrollable=True)
    overlay_web = Gtk.Overlay(css_name='sw_overlay')
    overlay_web.set_child(stack_web)
    label_overlay = Gtk.Label(
                            css_name='sw_row',
                            visible=False,
                            valign=Gtk.Align.END,
                            halign=Gtk.Align.START,
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
    label_frame_create_shortcut = Gtk.Label(
                                    css_name='sw_label_title',
                                    label=btn_dict['create_shortcut'],
                                    margin_top=12,
    )
    frame_create_shortcut = Gtk.Frame(
                                    css_name='sw_frame',
                                    label_widget=label_frame_create_shortcut,
                                    child=scrolled_create_shortcut,
    )
    frame_create_shortcut.set_label_align(0.5)

    label_frame_prefix_tools = Gtk.Label(
                                    css_name='sw_label_title',
                                    label=btn_dict['prefix_tools'],
                                    margin_top=12,
    )
    frame_prefix_tools = Gtk.Frame(
                                    css_name='sw_frame',
                                    label_widget=label_frame_prefix_tools,
                                    child=scrolled_prefix_tools,
    )
    frame_prefix_tools.set_label_align(0.5)

    label_frame_wine_tools = Gtk.Label(
                                    css_name='sw_label_title',
                                    label=btn_dict['wine_tools'],
                                    margin_top=12,
    )
    frame_wine_tools = Gtk.Frame(
                                css_name='sw_frame',
                                label_widget=label_frame_wine_tools,
                                child=scrolled_wine_tools,
    )
    frame_wine_tools.set_label_align(0.5)

    label_frame_settings = Gtk.Label(
                                    css_name='sw_label_title',
                                    label=btn_dict['settings'],
                                    margin_top=12,
    )
    frame_settings = Gtk.Frame(
                            css_name='sw_frame',
                            label_widget=label_frame_settings,
                            child=scrolled_settings,
    )
    frame_settings.set_label_align(0.5)

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

    ####___Add_widgets_to_stack___.

    stack_sidebar = Gtk.Stack(css_name='sw_stack')
    stack_sidebar.set_transition_duration(200)
    stack_sidebar.set_transition_type(Gtk.StackTransitionType.ROTATE_LEFT_RIGHT)
    stack_sidebar.add_child(frame_main)
    stack_sidebar.add_child(frame_create_shortcut)
    stack_sidebar.add_child(frame_prefix_tools)
    stack_sidebar.add_child(frame_wine_tools)
    stack_sidebar.add_child(frame_settings)
    stack_sidebar.add_child(frame_about)
    stack_sidebar.add_child(frame_stack)
    stack_sidebar.add_child(frame_files_info)
    stack_sidebar.add_child(frame_bookmarks)

    ####___Add_view_pages_to_stack___.

    reveal_stack = Gtk.Stack(css_name='sw_stack')
    reveal_stack.set_transition_duration(250)
    reveal_stack.set_transition_type(Gtk.StackTransitionType.ROTATE_LEFT_RIGHT)
    reveal_stack.add_named(files_view_grid, vw_dict['files'])
    reveal_stack.add_named(scrolled_launch_settings, vw_dict['launch_settings'])
    reveal_stack.add_named(scrolled_mangohud_settings, vw_dict['mangohud_settings'])
    reveal_stack.add_named(scrolled_vkbasalt_settings, vw_dict['vkbasalt_settings'])
    reveal_stack.add_named(scrolled_global_settings, vw_dict['global_settings'])
    reveal_stack.add_named(scrolled_install_launchers, vw_dict['install_launchers'])
    reveal_stack.add_named(scrolled_install_wine, vw_dict['install_wine'])
    reveal_stack.add_named(scrolled_winetricks, vw_dict['winetricks'])
    reveal_stack.add_named(grid_web, vw_dict['web_view'])
    reveal_stack.add_named(scrolled_gc_settings, vw_dict['gc_settings'])

    main_stack = Gtk.Stack(css_name='sw_stack')
    main_stack.set_transition_duration(250)
    main_stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
    main_stack.add_named(reveal_stack, 'main_page')
    main_stack.add_named(scrolled_startapp_page, 'startapp_page')

    ####___Overlay___.

    overlay = Gtk.Overlay(css_name='sw_overlay')
    overlay.set_name('launch_settings')
    overlay.set_child(main_stack)

    ####___Grid_info___.

    title_label = Gtk.Label(
                    css_name='sw_label',
                    xalign=0,
                    wrap=True,
                    natural_wrap_mode=True,
                    hexpand=True,
                    vexpand=True,
                    halign=Gtk.Align.FILL,
                    valign=Gtk.Align.CENTER,
    )
    message_label = Gtk.Label(
                    css_name='sw_label_desc',
                    xalign=0,
                    wrap=True,
                    natural_wrap_mode=True,
                    hexpand=True,
                    vexpand=True,
                    halign=Gtk.Align.FILL,
                    valign=Gtk.Align.CENTER,
    )
    btn_box = Gtk.Box(
                    css_name='sw_box',
                    orientation=Gtk.Orientation.HORIZONTAL,
                    spacing=4,
                    hexpand=True,
                    vexpand=True,
                    halign=Gtk.Align.FILL,
                    valign=Gtk.Align.CENTER,
    )
    btn_exit = Gtk.Button(
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
    grid_info.set_size_request(280,-1)
    grid_info.attach(title_label,0,0,1,1)
    grid_info.attach(message_label,0,1,1,1)
    grid_info.attach(btn_box,1,1,1,1)
    grid_info.attach(btn_exit,1,0,1,1)
    grid_info.set_visible(False)

    overlay.add_overlay(grid_info)

    ####___Revealer___.

    sidebar_revealer = Gtk.Revealer(css_name='sw_revealer')
    sidebar_revealer.set_name('sidebar')
    sidebar_revealer.set_hexpand(True)
    sidebar_revealer.set_halign(Gtk.Align.START)
    sidebar_revealer.set_transition_duration(250)
    sidebar_revealer.set_transition_type(Gtk.RevealerTransitionType.SLIDE_RIGHT)
    sidebar_revealer.set_child(stack_sidebar)

    empty_box = Gtk.Box(css_name="sw_shade_box")
    empty_box.set_size_request(320,-1)

    flap_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
    flap_box.append(empty_box)
    flap_box.append(overlay)

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

    grid_main.attach(top_headerbar_revealer, 0,0,1,1)
    grid_main.attach(flap_overlay, 0,1,1,1)
    grid_main.attach(bottom_headerbar_revealer, 0,2,1,1)

    ####___Event_controllers___.
    ctrl_key = Gtk.EventControllerKey()
    ctrl_key.connect('key_pressed', cb_ctrl_key_pressed, parent)

    ctrl_lclick = Gtk.GestureClick()
    ctrl_lclick.connect('pressed', cb_ctrl_lclick_parent)
    ctrl_lclick.set_button(1)

    ctrl_motion = Gtk.EventControllerMotion()
    ctrl_motion.connect('motion', cb_ctrl_motion_headerbar, parent)

    ####___GL_Area_overlay___.
    gl_image = get_gl_image()
    gl_cover = Gtk.Overlay()
    gl_cover.add_overlay(grid_main)
    gl_cover.set_child(RenderArea(parent, gl_image))
    gl_cover.set_size_request(768,508)

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

    if not '--silent' in argv:
        #parent.set_default_size(width+16, height+64)
        #set_parent_layer(parent, monitor)
        parent.present()

    ####___Reveal flap sidebar handler___.
    GLib.timeout_add(200, check_reveal_flap)
    GLib.timeout_add(350, check_file_monitor_event)

    ####___Sound_check___.
    dict_ini = read_menu_conf()
    if dict_ini['sound'] == 'on':
        if Path(sw_startup_sounds).exists():
            samples = get_samples_list(sw_startup_sounds)
            if len(samples) > 0:
                Thread(target=media_play, args=(media_file,
                            samples, media_controls, 0.7, False,)).start()

    set_print_run_time(True)

####___Run_application___.

if __name__ == '__main__':

    if len(argv) < 3:
        check_arg(None)

    elif len(argv) == 3:
        check_arg(argv[2])

    create_app_conf()
    get_exe_icon()

    if not sw_appid_json.exists():
        mp.Process(target=try_get_appid_json).start()

    try_get_exe_logo()

    sw = StartWineGraphicalShell()
    try:
        sw.run()
    except KeyboardInterrupt as e:
        exit(0)

    set_print_mem_info(False)
    exit(0)
