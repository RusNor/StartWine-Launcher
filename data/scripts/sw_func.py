#!/usr/bin/env python3
"""
StartWine funtion module
"""
import os
from os import environ, getenv, scandir
from os.path import join
from sys import argv, exit
from subprocess import Popen, run, PIPE, DEVNULL
from pathlib import Path
from threading import Thread
import mimetypes
import urllib.request
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import re
import json
import codecs
import shutil
# from markdown import markdown

from PIL import Image
import psutil
from psutil import Process
from sw_data import *
from sw_data import Msg as msg
from sw_data import TermColors as tc


def get_arg_mimetype():
    """___get exe path from system commandline arg___"""

    try:
        exc_type = tuple(mimetypes.guess_type(f'{argv[2]}', strict=True))[0]
    except (Exception,):
        exc_type = tuple(mimetypes.guess_type(f'{argv[0]}', strict=True))[0]
    else:
        if Path(argv[2]).suffix in swd_mime_types:
            exc_type = 'application-x-swd'

    return exc_type


def set_print_mem_info(mapped):
    """___print used memory info___"""

    mem_info = Process().memory_full_info()
    mem_map = Process().memory_maps(grouped=True)
    rss_memory = round(mem_info.rss / (1024**2), 2)
    shared_memory = round(mem_info.shared / (1024**2), 2)

    print(
        tc.SELECTED + tc.YELLOW
        + "\n----------------< MEMORY_INFO >----------------\n"
        + tc.END, "\n",
        tc.VIOLET2 + 'SW MEMORY:     ' + tc.GREEN
        + str(rss_memory - shared_memory) + tc.END, "\n",
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
            except (Exception,):
                pass
    else:
        return None


def get_app_path():
    """___get application path___"""

    app_path = getenv('SW_EXEC')
    if app_path == '' or app_path is None:
        app_path = 'StartWine'
    else:
        app_suffix = str(Path(app_path).suffix).strip('"')
        if app_suffix == '.lnk':
            app_name, app_suffix, app_lnk_path = get_lnk_data(app_path)
            get_lnk_exec(app_name, app_path, app_suffix, app_lnk_path)
            app_path = getenv('SW_EXEC')
            print(f'{tc.VIOLET2}LNK_APP_PATH:{tc.END}', app_path)

    return app_path


def get_out():
    """___get application name___"""

    app_path = get_app_path()

    if app_path == str('StartWine'):
        app_name = app_path
    else:
        app_name = str(Path(app_path).stem).strip('"').replace(' ', '_')

    return app_name


def get_suffix():
    """___get application suffix___"""

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
    except (Exception,):
        return None, None, None
    else:
        if len(decode_string) > 0:
            decode_exe = decode_string[-1].replace('\\', '/')
            re_suffix = '.exe'
        else:
            try:
                decode_string = [x for x in text.split(':') if '.bat' in x.lower()]
            except (Exception,):
                return None, None, None
            else:
                if len(decode_string) > 0:
                    decode_exe = decode_string[-1].replace('\\', '/')
                    re_suffix = '.bat'
                else:
                    try:
                        decode_string = [x for x in text.split(':') if '.msi' in x.lower()]
                    except (Exception,):
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

            format_name = Path(decode_exe).stem.strip('\0')
            suffix = Path(decode_exe).suffix
            suffix = '.' + ''.join([e for e in suffix if e.isalpha()])
            trash_symbols = re.sub(f'(?i){re_suffix}', '', suffix)
            format_suffix = suffix.replace(trash_symbols, '').strip('\0')
            format_path = f'{parent_path}/{format_name}{format_suffix}'.strip('\0')

            print(
                tc.SELECTED + tc.GREEN,
                f'-----------------< LNK DATA >-----------------\n' + tc.END
                + f'APP_NAME={format_name}\n'
                + f'APP_SUFFIX={format_suffix}\n'
                + f'APP_PATH={format_path}'
            )
            return format_name, format_suffix, format_path
        else:
            return None, None, None


def get_lnk_exec(app_name, app_path, app_suffix, app_lnk_path):
    """___get executable file path from x-ms-shortcut___"""

    if app_lnk_path is not None:
        partitions = psutil.disk_partitions()
        exist_path = ''
        format_app_name = app_name.replace(' ', '_')
        for x in sorted(partitions):
            for m in ['/mnt/', '/run/media/', '/home', '/var/']:
                if m in x.mountpoint:
                    prefix = x.mountpoint
                    path = Path(f'{prefix}', f'{app_lnk_path}')
                    if path.parent.exists():
                        exist_path = Path(path)
                        if not path.exists():
                            exist_list = [
                                x for x in Path(path).parent.glob('*.exe')
                                    if app_name.lower() in str(x.stem).lower()
                            ]
                            if len(exist_list) > 0:
                                exist_path = exist_list[0]

                        environ['SW_EXEC'] = f'"{exist_path}"'
                        print(f'{tc.BLUE}FOUND_EXEC:{tc.END}', f'"{exist_path}"')
                        break

        if exist_path == '':

            if Path(f'{sw_path}/{app_lnk_path}').exists():
                exist_path = Path(f'{sw_path}/{app_lnk_path}')
                environ['SW_EXEC'] = f'"{exist_path}"'
                print(f'{tc.BLUE}FOUND_EXEC:{tc.END}', f'"{exist_path}"')

            elif Path(f'{sw_pfx_default}/drive_c/{app_lnk_path}').exists():
                exist_path = Path(f'{sw_pfx_default}/drive_c/{app_lnk_path}')
                environ['SW_EXEC'] = f'"{exist_path}"'
                print(f'{tc.BLUE}FOUND_EXEC:{tc.END}', f'"{exist_path}"')

            elif Path(f'{sw_pfx}/pfx_{format_app_name}/drive_c/{app_lnk_path}').exists():
                exist_path = Path(f'{sw_pfx}/pfx_{format_app_name}/drive_c/{app_lnk_path}')
                environ['SW_EXEC'] = f'"{exist_path}"'
                print(f'{tc.BLUE}FOUND_EXEC:{tc.END}', f'"{exist_path}"')

            else:
                print(f'{tc.RED}LNK_ERROR: executable not found for {app_path}')
                environ['SW_EXEC'] = 'StartWine'


def create_app_conf():
    """___create application config___"""

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
    """___remove shortcuts from tmp directory___"""

    if sw_tmp.exists():
        for x in scandir(path=sw_tmp):
            x_path = Path(join(sw_tmp, x.name))
            if x_path.is_file():
                if '.desktop' in str(x_path):
                    x_path.unlink()


def start_tray():
    """___run menu in system tray___"""

    if sw_cfg.get('on_tray') == 'True':
        app_path = get_app_path()
        p = Popen(['ps', '-AF'], stdout=PIPE, encoding='UTF-8')
        out, err = p.communicate()

        is_active = []
        for line in out.splitlines():
            if str('sw_tray.py') in line:
                is_active.append('1')

        if not is_active:
            try:
                Popen([sw_tray, app_path])
            except KeyboardInterrupt:
                exit(0)
            print(f'{tc.VIOLET2} SW_TRAY: {tc.GREEN}done', tc.END)


def get_pfx_path():
    """___get current prefix path___"""

    try:
        dpath = Path(f"{sw_app_config}/" + get_out())
        pfx = dpath.read_text().splitlines()
    except (Exception,):
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
    """___get application prefix name___"""

    pfx_path = get_pfx_path()
    pfx_name = str(Path(pfx_path).stem)
    pfx_label = pfx_name.replace('pfx_', '')
    pfx_names = [pfx_name, pfx_label]

    return pfx_names


def write_app_conf(x_path):
    """___create application config when create shortcut___"""

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
    """___Writing total time in the app___"""

    if Path(stat_path).exists():
        text = Path(stat_path).read_text()
        lines = text.splitlines()
        line = [x for x in lines if f'{var}=' in x]
        if len(line) > 0:
            cur_val = line[0].split('=')[1]
            new_val = 'None'

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
    """___Reading total time in the app___"""

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
    """___Getting average fps from output log___"""

    fps_tmp = f'{sw_tmp}/stats/{app_name}.txt'

    if Path(fps_tmp).exists():
        with open(fps_tmp, 'r') as f:
            lines = f.read().splitlines()
            f.close()

        if len(lines) != 0:
            count = 0
            val = 0
            for line in lines:
                count += 1
                try:
                    val += float(line.split(', ')[2])
                except (Exception,):
                    pass
            else:
                fps = float(val / count)
                return fps
        else:
            return None
    else:
        return None


def app_info(x_path):
    """___get application settings dictionary___"""

    app_dict = {}
    if Path(x_path).exists():
        x_path = x_path
    elif str(sw_app_config) in str(x_path):
        x_path = f'{sw_app_config}/StartWine'
    else:
        x_path = None

    if x_path:
        read_text = Path(x_path).read_text().splitlines()
        text_list = [x for x in read_text if '=' in x]
        count = range(len(text_list))

        for i in count:
            app_dict[(text_list[i].split('=')[0])] = text_list[i].split('=')[1]

    return app_dict


def app_conf_info(x_path, x_list):
    """___get application config dictionary___"""

    app_conf_dict = {}

    if Path(x_path).exists():
        x_path = x_path
    elif str(sw_app_config) in str(x_path):
        x_path = f'{sw_app_config}/StartWine'
    else:
        x_path = None

    if x_path is not None:
        read_text = Path(x_path).read_text().splitlines()
        text_list = [x for x in read_text if 'export' in x]

        for x in x_list:
            for t in text_list:
                if x + '=' in t:
                    app_conf_dict[x] = t

    return app_conf_dict


def preload_runlib(enable_env: bool):
    """___preload runlib functions___"""

    app_name = get_out()

    if enable_env:
        for k, v in env_dict.items():
            print(tc.BLUE, f'{k}={tc.GREEN}{v}')
            environ[f'{k}'] = f'{v}'

    cmd = f"{sw_scripts}/sw_runlib {app_name}"
    run(cmd, shell=True, check=False)

    print(tc.VIOLET2, f'PRELOAD_RUNLIB: {tc.YELLOW}done{tc.END}')


def get_exe_icon():
    """___get icon from exe file___"""

    app_name = get_out()
    app_name_isalnum = ''.join(e for e in app_name if e.isalnum())
    app_def_icon = list(sw_app_default_icons.rglob(f'{app_name_isalnum}_*x256.png'))
    if len(app_def_icon) > 0:
        print(f'{tc.VIOLET} SW_DEFAULT_ICON: {tc.BLUE}{app_def_icon}{tc.END}')
        print(f'{tc.VIOLET} SW_DEFAULT_ICON: {tc.BLUE}icon for {app_name} exists, skip...{tc.END}')
    else:
        print(f'{tc.VIOLET} SW_DEFAULT_ICON: {tc.BLUE} try to get icon from {app_name}{tc.END}')
        func = f"CREATE_ICON \"$@\""
        app_path = get_app_path()
        app_suffix = get_suffix()

        if app_suffix:
            count = 1
            try:
                for _line in fshread:
                    count += 1
                    sw_fsh.write_text(sw_fsh.read_text().replace(fshread[count], ''))
            except IndexError:
                sw_fsh.write_text(fshread[0] + '\n' + fshread[1] + '\n' + func)
                run(f"{sw_fsh} {app_path}", shell=True)


def try_get_appid_json():
    """___get json data file from url___"""

    try:
        response = Request(url_app_id, headers=request_headers)
    except HTTPError as e:
        print(e)
    else:
        page = urlopen(response)
        id_list = page.read().decode('utf-8')

        with codecs.open(f'{sw_appid_source}', mode='w', encoding='utf-8') as f:
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
                    for letter in exclude_letters:
                        x['name'] = x['name'].replace(letter[0], letter[1])
                else:
                    filter_data = [x for x in filter_data if x['name'] != '']
                    f.close()

        with open(sw_appid_json, 'w', encoding='utf-8') as f:
            f.write(json.dumps(filter_data, indent=0))
            f.close()

            print(f'{tc.RED}Write app id json data...{tc.END}')


def convert_image(in_file, out_file, width, height):
    """___generate thumbnail for image mime type files___"""

    size = width, height
    try:
        image = Image.open(in_file)
    except IOError as e:
        print(e)
        return False
    else:
        try:
            imc = image.convert('RGB')
        except IOError as e:
            print(e)
            return False
        else:
            try:
                imc.thumbnail(size, Image.Resampling.LANCZOS)
            except IOError as e:
                print(e)
                return False
            else:
                imc.save(out_file, 'JPEG')
                return True


def request_urlopen(url, dest, auth):
    """___download content from open URL___"""

    key = f'9bd57c167c0f9b466539d0c8f9bdbd70'

    if auth:
        request_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 \
            (KHTML, like Gecko) Chrome/30.0.1599.101 Safari/537.36",
            "Accept-Language": "fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive",
            "Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
            "Authorization": f"Bearer {key}",
        }
    else:
        request_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 \
            (KHTML, like Gecko) Chrome/30.0.1599.101 Safari/537.36",
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
            urllib.request.urlretrieve(url, dest)
        except HTTPError as e:
            print(e)
    else:
        with response as res, open(dest, 'wb') as out:
            shutil.copyfileobj(res, out)
            res.close()


def try_download_logo(app_id, app_name, original_name, orientation):
    """___try download application logo by id___"""

    image_type = Path('') 
    image_dir = Path('')

    if orientation == 'heroes':
        image_type = 'library_hero'
        image_dir = sw_app_heroes_icons

    elif orientation == 'horizontal':
        image_type = 'header'
        image_dir = sw_app_hicons

    elif orientation == 'vertical':
        image_type = 'library_600x900_2x'
        image_dir = sw_app_vicons

    if not str(app_id) in str([x.name for x in list(image_dir.iterdir())]):
        app_name_isalnum = ''.join(e for e in app_name if e.isalnum())
        out_file = f'{image_dir}/{app_name_isalnum}_{orientation}_{original_name}_s{app_id}.jpg'
        url_app_logo = f'https://cdn.cloudflare.steamstatic.com/steam/apps/{app_id}/{image_type}.jpg'

        try:
            urllib.request.urlretrieve(url_app_logo, out_file)
            #request_urlopen(url_app_logo, file_hicon)
        except Exception as e:
            print(f'{tc.RED} Download: {e} {tc.END}')
            return False
        else:
            print(
                f'{tc.GREEN} Download {orientation} image complete: '
                + f'{tc.YELLOW} {app_id} {tc.RED} {original_name} {tc.END}')
            return True
    else:
        print(f'{tc.RED} Download {orientation} image: Skip {tc.END}')
        return True


def get_steam_appid_dict(orig_name, desc_name, dir_name, exe_name, info_list):
    """___get application id dictionary from json data___"""

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
            key_name = ''.join(e for e in key_name.upper() if e.isalnum())
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

    return app_id_dict, name_dict


def compare_name(
        orig_name, orig_name_, desc_name, desc_name_, dir_name, dir_name_,
        exe_name, exe_name_, app_name, info_list):
    """___compare application metadata info with application id data___"""

    match_vert = compare_sgdb_vertical(orig_name_, desc_name_, dir_name_, exe_name_, app_name, 'exact_match')
    if match_vert is None:
        app_id_dict, name_dict = get_steam_appid_dict(orig_name, desc_name, dir_name, exe_name, info_list)
        if len(app_id_dict) > 0:
            steamdb_vert = check_download_steamdb(app_id_dict, app_name, name_dict, 'vertical')
            steamdb_hero = check_download_steamdb(app_id_dict, app_name, name_dict, 'heroes')
            if not steamdb_vert or not steamdb_hero:
                compare_sgdb_vertical(orig_name_, desc_name_, dir_name_, exe_name_, app_name, 'inaccurate_match')
        else:
            compare_sgdb_vertical(orig_name_, desc_name_, dir_name_, exe_name_, app_name, 'inaccurate_match')

    match_horiz = compare_sgdb_horizontal(orig_name_, desc_name_, dir_name_, exe_name_, app_name, 'exact_match')
    if match_horiz is None:
        app_id_dict, name_dict = get_steam_appid_dict(orig_name, desc_name, dir_name, exe_name, info_list)
        if len(app_id_dict) > 0:
            steamdb_horiz = check_download_steamdb(app_id_dict, app_name, name_dict, 'horizontal')
            steamdb_hero = check_download_steamdb(app_id_dict, app_name, name_dict, 'heroes')
            if not steamdb_horiz or not steamdb_hero:
                compare_sgdb_horizontal(orig_name_, desc_name_, dir_name_, exe_name_, app_name, 'inaccurate_match')
        else:
            compare_sgdb_horizontal(orig_name_, desc_name_, dir_name_, exe_name_, app_name, 'inaccurate_match')


def compare_sgdb_vertical(orig_name_, desc_name_, dir_name_, exe_name_, app_name, match_type):
    """___compare application metadata info with application id data___"""

    check_db_vert = None
    compare_dict = {
        orig_name_: 'Original name',
        desc_name_: 'Description name',
        dir_name_: 'Directory name',
        exe_name_: 'Exe name',
        app_name: 'App name',
    }
    print(compare_dict)
    for name, desc in compare_dict.items():
        if name is not None:
            print(f'{tc.GREEN}Check and try download by {desc}: {tc.RED}{name} {tc.GREEN}vertical sgdb image{tc.END}')
            check_db_vert = check_download_sgdb(name, app_name, '600', '900', 'vertical', match_type)
            if check_db_vert is None:
                check_db_vert = check_download_sgdb(name, app_name, '660', '930', 'vertical', match_type)
                if check_db_vert is not None:
                    break
            else:
                break
        else:
            continue

    if check_db_vert is None:
        return None
    else:
        return 0


def compare_sgdb_horizontal(orig_name_, desc_name_, dir_name_, exe_name_, app_name, match_type):
    """___compare application metadata info with application id data___"""

    check_db_horiz = None
    compare_dict = {
        orig_name_: 'Original name',
        desc_name_: 'Description name',
        dir_name_: 'Directory name',
        exe_name_: 'Exe name',
        app_name: 'App name',
    }
    print(compare_dict)
    for name, desc in compare_dict.items():
        if name is not None:
            print(f'{tc.GREEN}Check and try download by {desc}: {tc.RED}{name}{tc.GREEN} horizontal sgdb image {tc.END}')
            check_db_horiz = check_download_sgdb(name, app_name, '460', '215', 'horizontal', match_type)
            if check_db_horiz is None:
                check_db_horiz = check_download_sgdb(name, app_name, '920', '430', 'horizontal', match_type)
                if check_db_horiz is not None:
                    break
            else:
                break
        else:
            continue

    if check_db_horiz is None:
        return None
    else:
        return 0


def edit_cur_name(cur_name):
    """___edit application name for searching steamgriddb content___"""

    length = len(cur_name)
    count = 0
    parts = []

    is_alpha_around = (lambda: not cur_name[i-1].isdigit() or 
                        length > (i + 1) and cur_name[i + 1].isdigit())

    is_lower_around = (lambda: not cur_name[i-1].isupper() or 
                        length > (i + 1) and cur_name[i + 1].islower())

    for i, e in enumerate(list(cur_name)):
        if e.isdigit() and is_alpha_around() or e.isupper() and is_lower_around():
            for x in cur_name[count: i]:
                part = ''.join(c for c in cur_name[count: i])
                parts.append(part)
                break

            count = i

    parts.append(cur_name[count:])
    edit_name = '_'.join(parts).strip('_')

    return edit_name


def get_sgdb_match(data, cur_name, match_type):

    app_id_list = list()
    name_list = list()

    for app in data:
        key_name = str(app['name'].encode('ascii','ignore'), encoding='utf-8')
        key_name = re.sub(r'[ЁёА-я]', '', key_name)

        for letter in exclude_letters:
            key_name = key_name.replace(letter[0], letter[1])

        for word in exclude_single_words:
            key_name = key_name.replace(word[0], word[1])

        for word in exclude_double_words:
            if word[0] in key_name:
                key_name = key_name.replace(word[0], word[1])

        key_name = ''.join(e for e in key_name.upper() if e.isalnum())
        key_name = str_to_roman(key_name)

        cur_name = ''.join(e for e in cur_name.upper() if e.isalnum())
        cur_name = str_to_roman(cur_name)

        if match_type == 'inaccurate_match':
            if len(cur_name) > len(key_name):
                if key_name != '':
                    split_cur_name = cur_name.split(key_name)
                    if len(split_cur_name) > 1:
                        for num in range(len(split_cur_name)):
                            cur_name = cur_name.replace(split_cur_name[num], '')

            elif len(key_name) > len(cur_name):
                if cur_name != '':
                    split_key_name = key_name.split(cur_name)
                    if len(split_key_name) > 1:
                        for num in range(len(split_key_name)):
                            key_name = key_name.replace(split_key_name[num], '')

        print(f'{tc.VIOLET2}COMPARE NAMES:{tc.END}', cur_name, key_name)
        if cur_name == key_name:
            app_id_list.append(app['id'])
            name_list.append(app['name'])

    return app_id_list, name_list


def check_download_sgdb(cur_name, app_name, width, height, orientation, match_type):
    """___search and download content from steamgriddb___"""

    if cur_name is not None:
        app_name_isalnum = ''.join(e for e in app_name if e.isalnum())
        edited_name = edit_cur_name(cur_name)
        print(f'{tc.VIOLET}Search by Edited name: {tc.RED}{edited_name}{tc.END}')
        url_search = f'https://www.steamgriddb.com/api/v2/search/autocomplete/{edited_name}'

        try:
            request_urlopen(url_search, f'{sw_fm_cache_database}/{edited_name}.json', True)
        except (Exception,) as e:
            print(e)
            return None
        else:
            data = []
            if Path(f'{sw_fm_cache_database}/{edited_name}.json').exists():
                with open(f'{sw_fm_cache_database}/{edited_name}.json', mode='r', encoding='utf-8') as f:
                    json_data = json.load(f)
                    data = json_data['data']
                    f.close()

            if len(data) > 0:
                app_id_list, name_list = get_sgdb_match(data, cur_name, match_type)
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

            if app_id is not None:
                url_app_id = f'https://www.steamgriddb.com/api/v2/grids/game/{app_id}?dimentions={width}x{height}'
                check_sgdb_heroes(app_name_isalnum, app_id, data_name)
                json_cache = f'{sw_fm_cache_database}/{app_name_isalnum}_{orientation}_{app_id}.json'

                try:
                    request_urlopen(url_app_id, json_cache, True)
                except Exception as e:
                    print(e)
                    return None
                else:
                    with open(json_cache, mode='r', encoding='utf-8') as f:
                        json_data = json.load(f)
                        f.close()

                    url_icon = []
                    if len(json_data['data']) > 0:
                        for value in json_data['data']:
                            if int(value['width']) == int(width):
                                url_icon.append(value['url'])
                                break

                    if len(url_icon) > 0:
                        print(url_icon)

                        jpg_cache = f'{sw_fm_cache_database}/{app_name_isalnum}_{orientation}_{data_name}_{app_id}.jpg'
                        hicon = f'{sw_app_hicons}/{app_name_isalnum}_horizontal_{data_name}_{app_id}.jpg'
                        vicon = f'{sw_app_vicons}/{app_name_isalnum}_vertical_{data_name}_{app_id}.jpg'

                        try:
                            request_urlopen(url_icon[0], jpg_cache, False)
                        except Exception as e:
                            print(e)
                            return None
                        else:
                            if orientation == 'horizontal':
                                try:
                                    convert_image(jpg_cache, hicon, 644, 301)
                                except (Exception,):
                                    shutil.copy2(jpg_cache, hicon)
                                    print(
                                        f'{tc.GREEN} Copy horizontal image: '
                                        + f'{tc.YELLOW} {app_id} {tc.RED} {data_name} {tc.END}')
                                else:
                                    print(
                                        f'{tc.GREEN} Convert horizontal image: '
                                        + f'{tc.YELLOW} {app_id} {tc.RED} {data_name} {tc.END}')

                            elif orientation == 'vertical':
                                try:
                                    convert_image(jpg_cache, vicon, 400, 600)
                                except (Exception,):
                                    shutil.copy2(jpg_cache, vicon)
                                    print(
                                        f'{tc.GREEN} Copy vertical image: '
                                        + f'{tc.YELLOW} {app_id} {tc.RED} {data_name} {tc.END}')
                                else:
                                    print(
                                        f'{tc.GREEN} Convert vertical image: '
                                        + f'{tc.YELLOW} {app_id} {tc.RED} {data_name} {tc.END}')
                            else:
                                print(
                                    f'{tc.GREEN} content not found {tc.YELLOW} '
                                    + f'{app_id} {tc.RED} {data_name} {tc.END}')

                            if Path(f'{jpg_cache}').exists():
                                for path in Path(f'{sw_fm_cache_database}').iterdir():
                                    if path.is_file():
                                        path.unlink()

                            print(f'{tc.GREEN}Done{tc.END}')
                            return 0
                    else:
                        print(f'{tc.RED}URL data is empty, content not found...{tc.END}')
                        return None
            else:
                print(f'{tc.RED}App ID is None, content not found...{tc.END}')
                return None
    else:
        print(f'{tc.RED}Current app name is None, content not found...{tc.END}')
        return None


def get_app_id_dict():
    """___get dictionary of app IDs from icon names___"""

    id_dict = dict()
    for icon in sw_app_vicons.iterdir():
        app_nm = str(icon.stem).split('_')[0]
        app_id = str(icon.stem).split('_')[-1]
        if not 's' in app_id and not 'x' in app_id:
            id_dict[app_nm] = app_id

    return id_dict


def request_external_data():
    """___get external JSON data using ID dictionary___"""

    id_dict = get_app_id_dict()
    ext_data_dict = read_json_data(sw_external_json)
    for k, v in id_dict.items():
        if ext_data_dict.get(k) is None:
            check_external_data(k, v)


def check_external_data(app_name_isalnum, app_id):
    """___get external steam platform data for application by app id___"""

    url_stm_id = f'https://www.steamgriddb.com/api/v2/games/id/{app_id}?platformdata=steam'
    external_json_cache = f'{sw_fm_cache_database}/{app_name_isalnum}_{app_id}.json'

    try:
        request_urlopen(url_stm_id, external_json_cache, True)
    except Exception as e:
        print(e)
    else:
        if Path(external_json_cache).exists():
            with open(external_json_cache, mode='r', encoding='utf-8') as f:
                external_json = json.load(f)
                f.close()

            if external_json.get('data'):
                ext_data = external_json.get('data')
                if ext_data.get('external_platform_data'):
                    ext_plat_data = ext_data.get('external_platform_data')
                    if ext_plat_data.get('steam'):
                        stm_id = ext_plat_data['steam'][0]['id']
                        stm_nm = ext_data['name']
                        if ext_data_dict.get(f'{app_name_isalnum}') is None:
                            ext_data_dict[f'{app_name_isalnum}'] = {
                                "app_id": f'{app_id}', "steam_id": f'{stm_id}', "name": f'{stm_nm}', "exe_name": f'{app_name_isalnum}'
                            }
                            with open(sw_external_json, mode='w', encoding='utf-8') as f:
                                f.write(json.dumps(ext_data_dict))
                                f.close()
                        print(ext_data_dict)
                        print(f'{tc.VIOLET}External {app_name_isalnum} data {stm_nm}: {stm_id} {tc.END}')
                    else:
                        print(f'{tc.RED}External {app_name_isalnum} data not found{tc.END}')
                else:
                    print(f'{tc.RED}External {app_name_isalnum} data not found{tc.END}')
            else:
                print(f'{tc.RED}External {app_name_isalnum} data not found{tc.END}')


def check_sgdb_heroes(app_name_isalnum, app_id, data_name):

    if not f'{sw_app_heroes_icons}/{app_name_isalnum}_heroes_' in str([x for x in list(sw_app_heroes_icons.iterdir())]):

        size_dict = {3840: 1240, 1920: 620, 1600: 650}
        url_heroes_icon = []

        for width, height in size_dict.items():
            url_heroes = f'https://www.steamgriddb.com/api/v2/heroes/game/{app_id}?dimentions={width}x{height}'
            try:
                request_urlopen(url_heroes, f'{sw_fm_cache_database}/{app_name_isalnum}_heroes_{app_id}.json', True)
            except Exception as e:
                print(e)
                return None
            else:
                cache_json = f'{sw_fm_cache_database}/{app_name_isalnum}_heroes_{app_id}.json'
                with open(cache_json, mode='r', encoding='utf-8') as f:
                    json_data = json.load(f)
                    if len(json_data['data']) > 0:
                        for value in json_data['data']:
                            if (str(value['style']) in ['alternate', 'blurred']
                                    and int(value['width']) == int(width)):
                                url_heroes_icon.append(value['url'])
                                break
                    f.close()
        else:
            if len(url_heroes_icon) > 0:
                print(url_heroes_icon)
                jpg_cache = f'{sw_fm_cache_database}/{app_name_isalnum}_heroes_{data_name}_{app_id}.jpg'
                try:
                    request_urlopen(url_heroes_icon[0], jpg_cache, False)
                except Exception as e:
                    print(e)
                    return None
                else:
                    heroes = f'{sw_app_heroes_icons}/{app_name_isalnum}_heroes_{data_name}_{app_id}.jpg'
                    try:
                        convert_image(jpg_cache, heroes, 3840, 1240)
                    except (Exception,):
                        shutil.copy2(jpg_cache, heroes)
                        print(f'{tc.GREEN} Copy heroes icon: {tc.YELLOW} {app_id} {tc.RED} {data_name} {tc.END}')
                    else:
                        print(f'{tc.GREEN} Convert heroes icon: {tc.YELLOW} {app_id} {tc.RED} {data_name} {tc.END}')
                    return 0
            else:
                print(f'{tc.RED}Heroes image not found...{tc.END}')
                return None
    else:
        print(f'{tc.GREEN} Heroes image {tc.RED}{app_name_isalnum}{tc.YELLOW} exists: {tc.YELLOW} skip... {tc.END}')
        return None


def check_download_steamdb(app_id_dict, app_name, name_dict, orientation):

    check_io = False

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
                        print(
                            tc.VIOLET2
                            + f'Try download by Description: '
                            + f'{app_id_dict[key]} {name_dict[name]}'
                            + tc.END
                        )
                        check_io = try_download_logo(app_id_dict[key], app_name, name_dict[name], orientation)
                        if check_io:
                            break
                    else:
                        check_io = False
                else:
                    if not check_io:
                        for key, name in zip(list(app_id_dict), list(name_dict)):
                            if 'directory' in key:
                                print(
                                    tc.VIOLET2
                                    + f'Try download by DirectoryName: '
                                    + f'{app_id_dict[key]} {name_dict[name]}'
                                    + tc.END
                                )
                                check_io = try_download_logo(app_id_dict[key], app_name, name_dict[name], orientation)
                                if check_io:
                                    break
                            else:
                                check_io = False
                        else:
                            if not check_io:
                                for key, name in zip(list(app_id_dict), list(name_dict)):
                                    if 'exe' in key:
                                        print(
                                            tc.VIOLET2
                                            + f'Try download by ExeName: '
                                            + f'{app_id_dict[key]} {name_dict[name]}'
                                            + tc.END
                                        )
                                        check_io = try_download_logo(
                                            app_id_dict[key], app_name,
                                            name_dict[name], orientation
                                        )
                                        if check_io:
                                            break
                                    else:
                                        pass
                                else:
                                    print(tc.RED + f'application id not found' + tc.END)
                                    return False
        return check_io
    else:
        print(tc.RED + f'application id not found' + tc.END)
        return False


def get_meta_prod(metadata):
    """___get exe product name info from metadata___"""

    try:
        md_prod = metadata['ProductName']
    except (Exception,):
        print(f'{tc.YELLOW}ProductName: {tc.RED}metadata not found{tc.END}')
        return None
    else:
        return md_prod


def get_meta_orig(app_name, app_path, metadata):
    """___get exe original name info from metadata___"""

    cmd = str()
    out_cmd = None
    metadata_original = None

    original_path = [
        x for x in list(Path(Path(app_path.strip('"')).parent).rglob('*.exe'))
        if '-Win64-Shipping.exe' in str(x)
    ]

    if len(original_path) == 0:
        original_path = [
            x for x in list(Path(Path(app_path.strip('"')).parent).rglob('*.exe'))
            if f'{app_name}' in str(x)
        ]

    if len(original_path) != 0:
        if len(original_path) == 1:
            cmd = f'{sw_exiftool} -j "{original_path[0]}"'
        elif len(original_path) > 1:
            cmd = f'{sw_exiftool} -j "{original_path[1]}"'

        out_cmd = run(cmd, shell=True, stdout=PIPE).stdout
        try:
            metadata_original = json.loads(out_cmd)[0]
        except (Exception,):
            print(f'<< OriginalFileName: metadata not found... >>')
            return None
        else:
            try:
                md_orig_prod = metadata_original['ProductName']
            except (Exception,):
                print(f'<< ProductName of OriginalFileName: metadata not found >>')
                return None
            else:
                return md_orig_prod

    return None


def get_meta_desc(metadata):
    """___get exe description info from metadata___"""

    try:
        md_desc = metadata['FileDescription']
    except (Exception,):
        print(f'{tc.YELLOW}FileDescription: {tc.RED}metadata not found{tc.END}')
        return None
    else:
        return md_desc


def get_exe_metadata(app_name, app_path, event):
    """___get exe logo id from json data___"""

    dir_list = list()
    metadata = None
    orig_name = None
    desc_name = None
    orig_name_ = None
    desc_name_ = None
    dir_name_ = None
    md_prod = None
    md_desc = None

    print_metadata = (lambda:
        print(
            tc.SELECTED + tc.GREEN,
            f'-----------------< METADATA >-----------------' + tc.END
        )
    )
    cmd = f'{sw_exiftool} -j {app_path}'
    out_cmd = run(cmd, shell=True, stdout=PIPE).stdout

    try:
        metadata = json.loads(out_cmd)[0]
    except (Exception,):
        print_metadata()
        print(f'{tc.RED}Exe metadata not found...{tc.END}')
    else:
        md_prod = get_meta_prod(metadata)
        md_desc = get_meta_desc(metadata)

        if md_prod in ['BootstrapPackagedGame', None]:
            md_prod = get_meta_orig(app_name, app_path, metadata)
            if md_prod in ['BootstrapPackagedGame', None]:
                md_prod = None

        if md_prod is not None:
            md_prod = re.sub(r'[ЁёА-я]', '', md_prod)

            for word in exclude_single_words:
                md_prod = md_prod.replace(word[0], word[1])

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

            print_metadata()
            print(f'<< OriginalName: {orig_name} >>')

        if md_desc in ['BootstrapPackagedGame', None]:
            md_desc = get_meta_orig(app_name, app_path, metadata)
            if md_desc in ['BootstrapPackagedGame', None]:
                md_desc = None

        if md_desc is not None:
            md_desc = re.sub(r'[ЁёА-я]', '', md_desc)

            for word in exclude_single_words:
                md_desc = md_desc.replace(word[0], word[1])

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

            print_metadata()
            print(f'<< FileDescription: {desc_name} >>')

    a_name = re.sub(r'[ЁёА-я]', '', app_name)
    for e in a_name:
        if not e.isalnum():
            a_name = a_name.replace(e, ' ')

    for word in exclude_single_words:
        a_name = a_name.replace(word[0], word[1])

    for word in exclude_double_words:
        a_name = a_name.replace(word[0], word[1])

    exe_name = ''.join(e for e in a_name if e.isalnum())
    exe_name_ = ''.join(e for e in a_name if e.isalnum())
    exe_name_ = exe_name_.replace(' ', '_')

    if exe_name == '':
        exe_name = None
        exe_name_ = None
    else:
        exe_name = str_to_roman(a_name)

    print_metadata()
    print(f'<< ExeName: {exe_name} >>')

    dirs = [x for x in Path(app_path.strip('"')).parent.parts if not x.upper() in str(exclude_names).upper()]
    for d in dirs:
        d = re.sub(r'[ЁёА-я]', '', d)

        for e in d:
            if not e.isalnum():
                d = d.replace(e, ' ')

        for word in exclude_single_words:
            d = d.replace(word[0], word[1])

        for word in exclude_double_words:
            d = d.replace(word[0], word[1])

        dir_name = ''.join(e for e in d if e.isalnum())
        dir_name_ = ''.join(e for e in d if e.isalnum() or e == ' ')
        dir_name_ = dir_name_.replace(' ', '_')

        if dir_name != '':
            dir_list.append(dir_name)

    if len(dir_list) > 0:
        dir_name = str_to_roman(dir_list[-1])
    else:
        dir_name_ = None
        dir_name = None

    print_metadata()
    print(f'<< DirectoryName: {dir_name} {dir_name_} >>')

    compare_name(
                orig_name, orig_name_, desc_name, desc_name_,
                dir_name, dir_name_, exe_name, exe_name_, app_name,
                ['OriginalName', 'Description', 'AppDirectory', 'ExeName']
    )
    if event:
        event.set()


def check_exe_logo(app_name):
    """___check if image exists for current application___"""

    hicons = False
    vicons = False
    heroes = False
    app_name_isalnum = ''.join(e for e in app_name if e.isalnum())

#    data = exe_data.get_(app_name)
#    if data:
#        hicon = data.get('horizontal')
#        vicon = data.get('vertical')
#        heroes = data.get('heroes')

    for icon in Path(f'{sw_app_hicons}').iterdir():
        app_name_isalnum = ''.join(e for e in app_name if e.isalnum())
        if app_name_isalnum == str(Path(icon).name).split('_')[0]:
            hicons = True

    for icon in Path(f'{sw_app_vicons}').iterdir():
        app_name_isalnum = ''.join(e for e in app_name if e.isalnum())
        if app_name_isalnum == str(Path(icon).name).split('_')[0]:
            vicons = True

    for icon in Path(f'{sw_app_heroes_icons}').iterdir():
        app_name_isalnum = ''.join(e for e in app_name if e.isalnum())
        if app_name_isalnum == str(Path(icon).name).split('_')[0]:
            heroes = True

    if hicons and vicons and heroes:
        return True
    else:
        return False


def get_bookmark_list():
    """___get bookmarks list from cache file___"""

    bookmarks_list.clear()
    with open(sw_bookmarks, 'r') as f:
        lines = f.read().splitlines()
        for s in lines:
            bookmarks_list.append(s)
            f.close()

    return bookmarks_list


def get_playlist():
    """___get playlist from cache file___"""

    playlist.clear()
    with open(sw_playlist, 'r') as f:
        lines = f.read().splitlines()
        for s in lines:
            playlist.append(s)
            f.close()

    return playlist


def get_media_metadata(media_path):
    """___get media info from metadata___"""

    md_media = {}
    cmd = f'{sw_exiftool} -j "{media_path}"'
    out_cmd = run(cmd, shell=True, stdout=PIPE).stdout
    try:
        media_metadata = json.loads(out_cmd)[0]
    except (Exception,):
        print(f'<< MediaFile: metadata not found... >>')
    else:
        for md in ['Album', 'Title', 'Artist', 'Year']:
            if media_metadata.get(md):
                data = media_metadata.get(md)
                md_media[md] = data
            else:
                md_media[md] = msg.msg_dict['unknown']
    return md_media


def get_media_info(x_file):
    """___get media info from metadata___"""

    media_data = msg.msg_dict['unknown']
    if x_file is not None:
        path = x_file.get_path()
        md_media = get_media_metadata(f'{path}')
        md_info = str()
        if len(md_media) > 0:
            for k, v in md_media.items():
                md_info += f'{msg.msg_dict[k.lower()]}:\t{v}\n'
            media_data = md_info

    return media_data


def volume_control(volume, step):
    """___volume control dictionary for gstreamer media controls___"""

    value = volume.get('volume') if volume.get('volume') else 1.0
    if value < 0.0:
        value = 0.0
    if value > 1.0:
        value = 1.0
    volume['volume'] = value + float(step)
    message = round((value + float(step))*100, 0)
    notify_send(f'SwMedia volume {message}%')


def notify_send(data):
    """___send notify to desktop___"""
    Popen(f'notify-send -t 1500 "{data}"', shell=True)


def echo_func_name(func_name):
    """___write and run function to function.sh___"""

    func = func_name + str(' \"$@\"')
    app_path = get_app_path()
    app_name = get_out()

    app_log = f"{sw_logs}/{app_name}.log"
    stderr_log = open(app_log, 'w')

    count = -1
    try:
        for _line in fshread:
            count += 1
            if count > 1:
                sw_fsh.write_text(sw_fsh.read_text().replace(fshread[count], ''))
    except IOError as e:
        print(e)
    else:
        if (str(func) == str("ADD_SHORTCUT_TO_MENU \"$@\"")
                or str(func) == str("ADD_SHORTCUT_TO_DESKTOP \"$@\"")
                or str(func) == str("ADD_SHORTCUT_TO_STEAM \"$@\"")):

            shortcut_name = f"export CUSTOME_GAME_NAME={getenv('CUSTOM_GAME_NAME')}"
            shortcut_path = f"export SW_DESKTOP_DIR={getenv('CUSTOM_GAME_PATH')}"

            sw_fsh.write_text(
                fshread[0] + '\n' + fshread[1] + '\n' + shortcut_name + '\n'
                + shortcut_path + '\n' + func
            )
            run(f"{sw_fsh} {app_path}", shell=True)
        else:
            sw_fsh.write_text(fshread[0] + '\n' + fshread[1] + '\n' + func)
            run(
                f"{sw_fsh} {app_path}", shell=True, start_new_session=True,
                stderr=stderr_log, encoding='UTF-8'
            )


def cs_wine(wine_name, app_name, app_path):
    """___write and run create shortcut function to function.sh___"""

    wine_download = wine_func_dict.get(wine_name) if wine_func_dict.get(wine_name) else None
    func_cs = f"CREATE_SHORTCUT \"$@\""
    count = -1
    try:
        for _line in fshread:
            count += 1
            if count > 1:
                sw_fsh.write_text(sw_fsh.read_text().replace(fshread[count], ''))
    except IOError as e:
        print(e)
    else:
        if (not Path(f"{sw_wine}/{wine_name}/bin/wine").exists()
                and wine_download is not None):

            wine_ok = f"export WINE_OK=1"
            func_download = f"{wine_download} \"$@\""

            sw_fsh.write_text(
                fshread[0] + '\n' + fshread[1] + '\n' + wine_ok + '\n'
                + func_download + '\n' + func_cs
            )
            run(
                f"{sw_fsh} {app_path}", shell=True, start_new_session=True,
                encoding='UTF-8'
            )
        else:
            sw_fsh.write_text(fshread[0] + '\n' + fshread[1] + '\n' + func_cs)
            run(
                f"{sw_fsh} {app_path}", shell=True, start_new_session=True,
                encoding='UTF-8'
            )


def echo_wine(wine_name, name_ver, wine_ver):
    """___write and run download wine function to function.sh___"""

    export_wine_ver = f'export {name_ver}="{wine_ver}"'
    app_path = get_app_path()
    wine_num = wine_name + str(' \"$@\"')
    count = -1

    try:
        for _line in fshread:
            count += 1
            if count > 1:
                sw_fsh.write_text(
                    sw_fsh.read_text().replace(fshread[count], '')
                )
    except IOError as e:
        print(e)
    else:
        sw_fsh.write_text(
            fshread[0] + '\n' + fshread[1] + '\n' + export_wine_ver + '\n' + wine_num
        )
        run(f"{sw_fsh} {app_path}", shell=True)


def check_alive(thread, func, args, parent):
    """___run the function when thread it completes___"""

    if thread.is_alive():
        return True
    else:
        if args is None:
            func()
        elif isinstance(args, tuple):
            func(*args)
        else:
            func(args)

        if parent is not None:
            parent.set_hide_on_close(True)

        return False


def vulkan_info(q):
    """___get driver name from vulkaninfo___"""

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
    """___check the existence of the path to wine___"""

    app_name = get_out()
    app_conf = Path(f"{sw_app_config}/{app_name}")
    app_dict = app_info(app_conf)
    wine = app_dict['export SW_USE_WINE'].strip('"')

    if not Path(f'{sw_wine}/{wine}/bin/wine').exists():
        return wine, False
    else:
        return wine, True


def find_process(app_suffix):
    """___Return a list of processes matching name___"""

    procs = psutil.Process(os.getpid()).children(recursive=True)
    for p in procs:
        try:
            ls = p.as_dict(attrs=['name'])
        except (Exception,):
            pass
        else:
            n = ls['name']
            if app_suffix.lower() in n.lower():
                print(n)
                return True

    return False


def get_samples_list(samples_dir):
    """___get a list of sound samples from a directory___"""

    samples_dict = dict()
    samples_list = sorted(list(Path(samples_dir).iterdir()))
    for i, x in enumerate(samples_list):
        samples_dict[str(x)] = i

    return samples_dict


def get_cpu_core_num():
    """___try get cpu core numbers___"""

    cpu_core_num = None
    try:
        cpu_affinity = psutil.Process().cpu_affinity()
    except (Exception,):
        try:
            cpu_core_num = int(psutil.cpu_count())
        except (Exception,):
            pass
    else:
        if cpu_affinity is not None:
            cpu_core_num = len(cpu_affinity)

    return cpu_core_num


def run_vulkan():
    """___run application in vulkan mode___"""

    func_name = f"RUN_VULKAN"
    echo_func_name(func_name)


def run_opengl():
    """___run application in opengl mode___"""

    func_name = f"SW_USE_OPENGL='1' RUN_VULKAN"
    echo_func_name(func_name)


def debug_vulkan():
    """___run application in vulkan debug mode___"""

    func_name = f"DEBUG_VULKAN"
    echo_func_name(func_name)


def debug_opengl():
    """___run application in opengl debug mode___"""

    func_name = f"SW_USE_OPENGL='1' DEBUG_VULKAN"
    echo_func_name(func_name)


def run_screencast():
    """
    ___run screencast session___

    for p in psutil.process_iter():
        cmd = p.as_dict(attrs=['cmdline'])
        if cmd['cmdline']:
            if f'{sw_scripts}/sw_cast.py' in ' '.join(cmd['cmdline']):
                print(f'Screencast session {p} is allready running, terminate...')
                p.kill()
    """
    cmd = f'{sw_scripts}/sw_cast.py'
    Popen([cmd])


def process_event_wait(event, data):
    """___wait for the process event to be set___"""

    event.wait()
    print(f'{tc.GREEN}multiprocessing {event} done...{tc.END}')
    func = None
    args = None
    if data and isinstance(data, dict):
        if data.get('func'):
            func = data.get('func')
        if data.get('args'):
            args = data.get('args')
        if func and args:
            return func(*args)
        else:
            return func()
    return None


if __name__ == "__main__":
    pass

