"""
Copyright (c) 2020 Maslov N.G. Normatov R.R.

This file is part of StartWine-Launcher.
https://github.com/RusNor/StartWine-Launcher

StartWine-Launcher is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

StartWine-Launcher is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
StartWine-Launcher. If not, see http://www.gnu.org/licenses/.
"""

# from asyncio.timeouts import timeout
from time import time, perf_counter, sleep
import os
from os import environ, getenv, scandir
import socket
import platform
from os.path import join
import sys
from sys import exit
import pty
from subprocess import Popen, run, check_output, PIPE, DEVNULL, CalledProcessError
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from multiprocessing.pool import ThreadPool
from threading import Thread
import urllib.request
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import re
import json
import shutil

import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import ConnectionError, JSONDecodeError, ReadTimeout
from PIL import Image
import psutil
from psutil import Process

from sw_data import *
from sw_data import hash_
from sw_data import Msg as msg
from sw_data import TermColors as tc
from sw_dlm import DLManager, Manifest, JSONManifest


def set_print_mem_info():
    """___print used memory info___"""
    mem_info = Process().memory_full_info()
    # mem_map = Process().memory_maps(grouped=True)
    rss_memory = round(mem_info.rss / (1024**2), 2)
    shared_memory = round(mem_info.shared / (1024**2), 2)
    print(
        tc.SELECTED
        + tc.YELLOW
        + "\n----------------< MEMORY_INFO >----------------\n"
        + tc.END,
        "\n",
        tc.VIOLET2
        + "SW MEMORY:     "
        + tc.GREEN
        + str(rss_memory - shared_memory)
        + tc.END,
        "\n",
        tc.VIOLET2
        + "RSS MEMORY:    "
        + tc.GREEN
        + str(round(mem_info.rss / (1024**2), 2))
        + tc.END,
        "\n",
        tc.VIOLET2
        + "VMS_MEMORY:    "
        + tc.GREEN
        + str(round(mem_info.vms / (1024**2), 2))
        + tc.END,
        "\n",
        tc.VIOLET2
        + "TEXT_MEMORY:   "
        + tc.GREEN
        + str(round(mem_info.text / (1024**2), 2))
        + tc.END,
        "\n",
        tc.VIOLET2
        + "SHARED_MEMORY: "
        + tc.GREEN
        + str(round(mem_info.shared / (1024**2), 2))
        + tc.END,
        "\n",
        tc.VIOLET2
        + "LIB_MEMORY:    "
        + tc.GREEN
        + str(round(mem_info.lib / (1024**2), 2))
        + tc.END,
        "\n",
        tc.VIOLET2
        + "DATA_MEMORY:   "
        + tc.GREEN
        + str(round(mem_info.data / (1024**2), 2))
        + tc.END,
        "\n",
        tc.VIOLET2
        + "USS_MEMORY:    "
        + tc.GREEN
        + str(round(mem_info.uss / (1024**2), 2))
        + tc.END,
        "\n",
        tc.VIOLET2
        + "PSS_MEMORY:    "
        + tc.GREEN
        + str(round(mem_info.pss / (1024**2), 2))
        + tc.END,
        "\n",
        tc.VIOLET2
        + "SWAP_MEMORY:   "
        + tc.GREEN
        + str(round(mem_info.swap / (1024**2), 2))
        + tc.END,
        "\n",
    )


def get_app_path() -> str:
    """___get application path___"""
    app_path = getenv("SW_EXEC")
    if app_path == "" or app_path is None:
        app_path = "StartWine"
    else:
        app_suffix = str(Path(app_path).suffix).strip('"')
        if app_suffix == ".lnk":
            app_name, app_suffix, app_lnk = get_lnk_data(app_path)
            get_lnk_exec(app_name, app_path, app_lnk)
            app_path = getenv("SW_EXEC")
            print(f"{tc.VIOLET2}LNK_APP_PATH:{tc.END}", app_path)

    return app_path if app_path else "StartWine"


def get_out(app_path: str|Path = ""):
    """___get application name___"""
    if not app_path:
        app_path = get_app_path()

    if app_path == str("StartWine"):
        app_name = app_path
    else:
        app_name = str(Path(app_path).stem).strip('"').replace(" ", "_")

    return app_name


def get_suffix():
    """___get application suffix___"""
    app_path = get_app_path()
    app_suffix = str(Path(app_path).suffix).strip('"')

    return app_suffix


def get_swd_path(swd: str|Path) -> str:
    app_exec = "StartWine"
    if Path(swd).exists():
        app_dict = app_info(f"{swd}")
        app_exec = (
            app_dict.get("Exec", "StartWine")
                .replace(f'env "{sw_start}" ', "").strip('"')
        )

    return app_exec


def get_hash_name(path: str|Path = "") -> str:
    """___get application path from exe data___"""
    path = str(path).strip('"')
    if not path:
        path = get_app_path().strip('"')
    path_hash = hash_(path)

    return path_hash


def get_lnk_data(lnk_path):
    """___get filename extension and path from .lnk file___"""
    lnk_path = lnk_path.strip('"')

    with open(lnk_path, "rb") as f:
        text = f.read().decode(errors="replace")
        f.close()

    try:
        decode_string = [x for x in text.split(":") if ".exe" in x.lower()]
    except (Exception,):
        return None, None, None
    else:
        if len(decode_string) > 0:
            decode_exe = decode_string[-1].replace("\\", "/")
            re_suffix = ".exe"
        else:
            try:
                decode_string = [x for x in text.split(":") if ".bat" in x.lower()]
            except (Exception,):
                return None, None, None
            else:
                if len(decode_string) > 0:
                    decode_exe = decode_string[-1].replace("\\", "/")
                    re_suffix = ".bat"
                else:
                    try:
                        decode_string = [
                            x for x in text.split(":") if ".msi" in x.lower()
                        ]
                    except (Exception,):
                        return None, None, None
                    else:
                        if len(decode_string) > 0:
                            decode_exe = decode_string[-1].replace("\\", "/")
                            re_suffix = ".msi"
                        else:
                            decode_exe = None
                            re_suffix = None

        if decode_exe is not None:
            parent_path = Path(decode_exe).parent
            if str(parent_path).startswith("/"):
                parent_path = Path(str(parent_path).lstrip("/"))

            format_name = Path(decode_exe).stem.strip("\0")
            suffix = Path(decode_exe).suffix
            suffix = "." + "".join([e for e in suffix if e.isalpha()])
            trash_symbols = re.sub(f"(?i){re_suffix}", "", suffix)
            format_suffix = suffix.replace(trash_symbols, "").strip("\0")
            format_path = f"{parent_path}/{format_name}{format_suffix}".strip("\0")

            print(
                tc.SELECTED + tc.GREEN,
                "-----------------< LNK DATA >-----------------\n"
                + tc.END
                + f"APP_NAME={format_name}\n"
                + f"APP_SUFFIX={format_suffix}\n"
                + f"APP_PATH={format_path}",
            )
            return format_name, format_suffix, format_path
        else:
            return None, None, None


def get_lnk_exec(app_name, app_path, app_lnk):
    """___get executable file path from x-ms-shortcut___"""
    if app_lnk is not None:
        partitions = psutil.disk_partitions()
        exist_path = ""
        format_app_name = app_name.replace(" ", "_")

        lnk = sw_path.joinpath(f"{app_lnk}")
        pfx_lnk = sw_pfx.joinpath(f"pfx_{format_app_name}", "drive_c", f"{app_lnk}")
        pfx_default_lnk = sw_pfx_default.joinpath("drive_c", f"{app_lnk}")

        for x in sorted(partitions):
            for m in ["/mnt/", "/run/media/", "/home", "/var/"]:
                if m in x.mountpoint:
                    exist_path = Path(f"{x.mountpoint}", f"{app_lnk}")
                    if exist_path.parent.exists() and not exist_path.exists():
                        lst = exist_path.parent.glob("*.exe", case_sensitive=False)
                        exist_list = [
                            x for x in lst if app_name.lower() in str(x.stem).lower()
                        ]
                        if exist_list:
                            exist_path = exist_list[0]

                    environ["SW_EXEC"] = f'"{exist_path}"'
                    print(f"{tc.BLUE}FOUND_EXEC:{tc.END}", f'"{exist_path}"')
                    break

        if exist_path == "":
            if lnk.exists():
                exist_path = lnk
                environ["SW_EXEC"] = f'"{exist_path}"'
                print(f"{tc.BLUE}FOUND_EXEC:{tc.END}", f'"{exist_path}"')

            elif pfx_default_lnk.exists():
                exist_path = pfx_default_lnk
                environ["SW_EXEC"] = f'"{exist_path}"'
                print(f"{tc.BLUE}FOUND_EXEC:{tc.END}", f'"{exist_path}"')

            elif pfx_lnk.exists():
                exist_path = pfx_lnk
                environ["SW_EXEC"] = f'"{exist_path}"'
                print(f"{tc.BLUE}FOUND_EXEC:{tc.END}", f'"{exist_path}"')
            else:
                print(f"{tc.RED}LNK_ERROR: executable not found for {app_path}{tc.END}")
                environ["SW_EXEC"] = "StartWine"


def create_app_conf():
    """___create application config___"""
    app_name = get_out()
    app_conf = sw_app_config.joinpath(app_name)
    launcher_conf = sw_app_config.joinpath(".default", app_name)
    sw_exe_path = get_app_path()

    if not app_conf.exists():
        if sw_exe_path == "StartWine":
            app_conf = sw_app_config.joinpath("StartWine")
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

        print(f"{tc.RED}Create app conf... {tc.GREEN}{app_conf}{tc.END}")


def clear_tmp():
    """___remove shortcuts from tmp directory___"""
    if sw_tmp.exists():
        for x in scandir(path=sw_tmp):
            x_path = Path(join(sw_tmp, x.name))
            if x_path.is_file():
                if ".desktop" in str(x_path):
                    x_path.unlink()


def start_tray():
    """___run menu in system tray___"""
    if sw_cfg.get("on_tray") == "True":
        p = Popen(["ps", "-AF"], stdout=PIPE, encoding="UTF-8")
        out, _ = p.communicate()

        is_active = []
        for line in out.splitlines():
            if str("sw_start -t") in line or str("sw_start --tray") in line:
                is_active.append("1")
                break

        if not is_active:
            try:
                p = Popen([sw_start, "-t"])
                process_workers.append(p)
            except (Exception, KeyboardInterrupt) as e:
                print(e)
                p.kill()
            else:
                print(f"{tc.VIOLET2}SW_TRAY: {tc.GREEN}done", tc.END)


def get_pfx_path():
    """___get current prefix path___"""
    app_name = get_out()
    try:
        dpath = sw_app_config.joinpath(app_name)
        pfx = dpath.read_text().splitlines()
    except (Exception,):
        dpath = sw_app_config.joinpath("StartWine")
        pfx = dpath.read_text().splitlines()

    if str('export SW_USE_PFX="pfx_default"') in pfx:
        pfx_name = "pfx_default"
        pfx_path = f"{sw_pfx.joinpath(pfx_name)}"
    else:
        pfx_name = "pfx_" + str(get_out()).replace("StartWine", "default").replace(
            "default_", "default"
        )
        pfx_path = f"{sw_pfx.joinpath(pfx_name)}"

    return pfx_path


def get_pfx_name():
    """___get application prefix name___"""
    pfx_path = get_pfx_path()
    pfx_name = str(Path(pfx_path).stem)
    pfx_label = pfx_name.replace("pfx_", "")
    pfx_names = [pfx_name, pfx_label]

    return pfx_names


def write_app_conf(x_path: str | Path):
    """___create application config when create shortcut___"""
    app_name = str(Path(x_path).stem).strip('"').replace(" ", "_")
    launcher_conf = sw_app_config.joinpath(".default", app_name)
    app_conf = sw_app_config.joinpath(app_name)

    if not app_conf.exists():
        if not launcher_conf.exists():
            _ = app_conf.write_text(sw_default_config.read_text())
            app_conf.chmod(0o755)
        else:
            _ = app_conf.write_text(launcher_conf.read_text())
            app_conf.chmod(0o755)


def write_changed_wine(changed_wine):
    """___write changed wine to application config___"""
    app_name = get_out()
    app_conf = sw_app_config.joinpath(app_name)
    app_conf_dict = app_conf_info(app_conf, ["SW_USE_WINE"])
    try:
        _ = app_conf.write_text(
            app_conf.read_text().replace(
                app_conf_dict["SW_USE_WINE"], f'export SW_USE_WINE="{changed_wine}"'
            )
        )
    except IOError as e:
        print(f"{e}")


def write_app_stat(stat_path: str, var: str, val: float):
    """___Writing total time in the app___"""
    if Path(stat_path).exists():
        text = Path(stat_path).read_text()
        lines = text.splitlines()
        line = [x for x in lines if f"{var}=" in x]
        if len(line) > 0:
            cur_val = line[0].split("=")[1]
            new_val = "None"

            if var == "Time":
                new_val = round(float(val) + float(cur_val), 2)
            elif var == "Fps":
                new_val = round(float(val) + float(cur_val), 2) / 2

            new_line = f"{var}={new_val}"
            with open(stat_path, "w") as f:
                _ = f.write(text.replace(line[0], new_line))
                f.close()
        else:
            new_val = round(float(val), 2)
            new_line = f"\n{var}={new_val}"
            with open(stat_path, "a") as f:
                _ = f.write(new_line)
                f.close()
    else:
        print(f"{stat_path} not exists")


def read_app_stat(stat_path: str, var: str):
    """___Reading total time in the app___"""
    if Path(stat_path).exists():
        lines = Path(stat_path).read_text().splitlines()
        line = [line for line in lines if f"{var}=" in line]

        if len(line) > 0:
            val = line[0].split("=")[1]
        else:
            val = 0.0

        if var == "Time":
            if float(val) < 60:
                t_val = msg.msg_dict["seconds"]
                val = round(float(val), 2)
                return f"{val} {t_val}"

            elif 60 < float(val) < 3600:
                t_val = msg.msg_dict["minutes"]
                val = round(float(val) / 60, 2)
                return f"{val} {t_val}"

            elif 3600 <= float(val) < 86400:
                t_val = msg.msg_dict["hours"]
                val = round(float(val) / 3600, 2)
                return f"{val} {t_val}"

            elif float(val) > 86400:
                t_val = msg.msg_dict["days"]
                val = round(float(val) / 86400, 2)
                return f"{val} {t_val}"

            else:
                val = f"0.0 {msg.msg_dict['seconds']}"
                return val
        else:
            return val
    else:
        val = 0.0
        return val


def read_overlay_output(app_name: str):
    """___Getting average fps from output log___"""
    fps_tmp = sw_tmp.joinpath("stats", f"{app_name}.txt")
    if fps_tmp.exists():
        with open(fps_tmp, "r") as f:
            lines = f.read().splitlines()
            f.close()

        if len(lines) != 0:
            count = 0
            val = 0
            for line in lines:
                count += 1
                try:
                    val += float(line.split(", ")[2])
                except (Exception,):
                    pass
            else:
                fps = float(val / count)
                return fps
        else:
            return None
    else:
        return None


def app_info(x_path: str | Path) -> dict[str, str]:
    """___get application settings dictionary___"""
    app_dict: dict[str, str] = {}
    if Path(x_path).exists():
        x_path = x_path
    elif str(sw_app_config) in str(x_path):
        x_path = sw_app_config.joinpath("StartWine")
    else:
        x_path = ""

    if x_path:
        read_text = Path(x_path).read_text().splitlines()
        text_list = [x for x in read_text if "=" in x]
        count = range(len(text_list))

        for i in count:
            app_dict[(text_list[i].split("=")[0])] = text_list[i].split("=")[1]

    return app_dict


def app_conf_info(x_path: str | Path, x_list: list[str]) -> dict[str, str]:
    """___get application config dictionary___"""
    app_conf_dict: dict[str, str] = {}
    if Path(x_path).exists():
        x_path = x_path
    elif str(sw_app_config) in str(x_path):
        x_path = sw_app_config.joinpath("StartWine")
    else:
        x_path = ""

    if x_path:
        read_text = Path(x_path).read_text().splitlines()
        text_list = [x for x in read_text if "export" in x]

        for x in x_list:
            for t in text_list:
                if x + "=" in t:
                    app_conf_dict[x] = t

    return app_conf_dict


def preload_runlib(enable_env: bool):
    """___preload runlib functions___"""
    app_name = get_out()
    if enable_env:
        for k, v in env_dict.items():
            print(f"{tc.BLUE}{k}={tc.GREEN}{v}{tc.END}")
            environ[f"{k}"] = f"{v}"

    cmd = f'"{sw_runlib}" "{app_name}"'
    _ = run(cmd, shell=True, check=False)
    print(f"{tc.VIOLET2}PRELOAD_RUNLIB: {tc.YELLOW}done{tc.END}")


def get_exe_icon():
    """___get icon from exe file___"""
    app_path = get_app_path()
    app_suffix = get_suffix()
    hash_name = get_hash_name()
    app_def_icon = list(sw_app_default_icons.rglob(f"{hash_name}_*x256.png"))

    if len(app_def_icon) > 0:
        print(f"{tc.VIOLET}SW_DEFAULT_ICON: {tc.BLUE}{app_def_icon}{tc.END}")
    else:
        func = 'CREATE_ICON "$@"'
        if app_suffix:
            sw_fsh.write_text("\n".join([fshread[0], fshread[1], func]))
            run(f"{sw_fsh} {app_path}", shell=True)


def try_get_appid_json():
    """___get json data file from url___"""
    try:
        request_urlopen(hgf_app_id, sw_appid_json, True)
    except Exception as e:
        print(e)
        return
    else:
        if sw_appid_json.exists():
            with open(sw_appid_json, mode="r", encoding="utf-8") as f:
                json_data = json.load(f)
                f.close()

            with open(sw_appid_json, "w", encoding="utf-8") as f:
                f.write(json.dumps(json_data, indent=0))
                f.close()
                print(
                    f"{tc.VIOLET2}SW_APPID_JSON: "
                    + f"{tc.GREEN}write appid json data: done{tc.END}"
                )


def convert_image(in_file, out_file, width, height, crop=False, position=None):
    """___convert and resize image mime type files___"""
    ratio = width / height
    try:
        img = Image.open(in_file)
    except (Exception, IOError) as e:
        print(e)
    else:
        w, h = img.size
        rt = w / h
        if crop and position is None:
            if rt > ratio:
                left = (w - (h * ratio)) / 2
                right = w - left
                top = 0
                bottom = h
                img = img.crop((left, top, right, bottom))

            elif rt < ratio:
                left = 0
                right = w
                top = (h - (w / ratio)) / 2
                bottom = h - top
                img = img.crop((left, top, right, bottom))

        elif crop and position:
            left, top, right, bottom = position
            img = img.crop((left, top, right, bottom))

        try:
            imc = img.convert("RGB")
        except (Exception, IOError) as e:
            print(e)
        else:
            try:
                imr = imc.resize((width, height), Image.Resampling.LANCZOS)
            except (Exception, IOError) as e:
                print(e)
            else:
                try:
                    imr.save(out_file, "JPEG")
                except (Exception, IOError) as e:
                    print(e)
                else:
                    return True
    return False


def convert_image_to_jpeg(in_file, out_file):
    """___convert image to JPEG format___"""
    try:
        img = Image.open(in_file)
    except (Exception, IOError) as e:
        print(e)
    else:
        try:
            imc = img.convert("RGB")
        except (Exception, IOError) as e:
            print(e)
        else:
            imc.save(out_file, "JPEG")
            return True

    return False


def cache_to_horizontal_image(cache):
    """___convert cached content to horizontal image___"""
    current_image_path = Path(str(getenv(f"{get_out()}")))
    app_path = get_app_path()
    app_name = str(get_out()).replace("_", " ")
    hash_name = get_hash_name(app_path)
    app_id = Path(cache).stem
    edited_name = edit_cur_name(app_name)
    name = current_image_path.stem
    name = name.replace("_vertical_", "_horizontal_")

    if not sw_app_hicons.joinpath(f"{name}.jpg").exists():
        name = f"{hash_name}_horizontal_{edited_name}_{app_id}"

    destination = str(sw_app_hicons.joinpath(f"{name}.jpg"))
    try:
        convert_image(cache, destination, 640, 360, True)
    except (Exception,):
        shutil.move(cache, destination)
        exe_data.set_(str(app_path), "horizontal", f"{name}.jpg")
    else:
        exe_data.set_(str(app_path), "horizontal", f"{name}.jpg")


def cache_to_vertical_image(cache):
    """___convert cached content to vertical image___"""
    current_image_path = Path(str(getenv(f"{get_out()}")))
    app_path = get_app_path()
    app_name = str(get_out()).replace("_", " ")
    hash_name = get_hash_name(app_path)
    app_id = Path(cache).stem
    edited_name = edit_cur_name(app_name)
    name = current_image_path.stem
    name = name.replace("_horizontal_", "_vertical_")

    if not sw_app_vicons.joinpath(f"{name}.jpg").exists():
        name = f"{hash_name}_vertical_{edited_name}_{app_id}"

    destination = str(sw_app_vicons.joinpath(f"{name}.jpg"))
    try:
        convert_image(cache, destination, 400, 600, True)
    except (Exception,):
        shutil.move(cache, destination)
        exe_data.set_(str(app_path), "vertical", f"{name}.jpg")
    else:
        exe_data.set_(str(app_path), "vertical", f"{name}.jpg")


def cache_to_startup_image(cache):
    """___convert cached content to startup image___"""
    current_image_path = Path(str(getenv(f"{get_out()}")))
    app_path = get_app_path()
    name = current_image_path.stem
    name = name.replace("_horizontal_", "_artwork_").replace(
        "_vertical_", "_artwork_"
    )

    if sw_app_artwork.joinpath(f"{name}.jpg").exists():
        try:
            sw_app_hicons.joinpath(f"{name}.jpg").unlink()
        except (Exception,) as e:
            print(e)

    destination = str(sw_app_artwork.joinpath(f"{name}.jpg"))

    try:
        convert_image(cache, destination, 1920, 620, True)
    except (Exception,):
        shutil.move(cache, destination)
        exe_data.set_(str(app_path), "artwork", f"{name}.jpg")
    else:
        exe_data.set_(str(app_path), "artwork", f"{name}.jpg")


def download_content(url, dest, headers=None):
    """___download content from open URL___"""
    if headers:
        url = Request(url, headers=headers)
    try:
        response = urlopen(url, timeout=10.0)
    except (HTTPError, URLError, ConnectionError, ReadTimeout) as e:
        print(f"{tc.RED}Download failed!{tc.END}", e, url)
        return
    else:
        with response as res, open(dest, "wb") as out:
            try:
                shutil.copyfileobj(res, out)
                res.close()
            except (Exception,) as e:
                print(f"{tc.RED}Copy file object error!{tc.END}", e)
                dest.unlink()
                return

        print(f"Download to {tc.GREEN}{Path(dest).name}{tc.END} comlete")


def download_with_convert(url, dest, width=400, height=600, crop=False, pos=()):
    """___download content from open URL___"""
    download_content(url, dest)
    if Path(dest).exists():
        if pos:
            convert_image(dest, dest, width, height, crop, pos)
        else:
            convert_image(dest, dest, width, height, crop)


def request_urlopen(url, dest, auth):
    """___download content from open URL___"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 \
        (KHTML, like Gecko) Chrome/30.0.1599.101 Safari/537.36",
        "Accept-Language": "ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "keep-alive",
        "Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
    }
    if auth:
        key = "9bd57c167c0f9b466539d0c8f9bdbd70"
        headers["Authorization"] = f"Bearer {key}"
    try:
        response = urlopen(Request(url, headers=headers), timeout=5.0)
    except (HTTPError, URLError, ConnectionError, ReadTimeout) as e:
        print(e)
    else:
        with response as res, open(dest, "wb") as out:
            try:
                shutil.copyfileobj(res, out)
            except (Exception,) as e:
                print(tc.RED, "CopyFileObjectError:", e, tc.END)
                dest.unlink()
            else:
                res.close()
                print(tc.GREEN, f"Download to {dest} comlete", tc.END)


def try_download_logo(app_id, app_path, original_name, orientation):
    """___try download application logo by id___"""
    image_type = Path("")
    image_dir = Path("")
    width = 256
    height = 256

    if orientation == "artwork":
        image_type = "library_hero"
        image_dir = sw_app_artwork
        width = 1920
        height = 620

    elif orientation == "horizontal":
        image_type = "header"
        image_dir = sw_app_hicons
        width = 640
        height = 360

    elif orientation == "vertical":
        image_type = "library_600x900_2x"
        image_dir = sw_app_vicons
        width = 400
        height = 600

    hash_name = get_hash_name(app_path)
    image_name = f"{hash_name}_{orientation}_{original_name}_s{app_id}.jpg"
    out_file = image_dir.joinpath(image_name)

    if not out_file.exists():
        url_steam = f"{STEAM_APPS_URL}/{app_id}/{image_type}.jpg"
        # url_steam = f"https://cdn.cloudflare.steamstatic.com/steam/apps/{app_id}/{image_type}.jpg"
        try:
            urllib.request.urlretrieve(url_steam, f"{out_file}")
            # request_urlopen(url_steam, f"{out_file}")
        except (Exception,) as e:
            print(f"{tc.RED} Download: {e} {tc.END}")
            return False
        else:
            convert_image(out_file, out_file, width, height)
            print(
                f"{tc.GREEN} Download {orientation} image complete: "
                f"{tc.YELLOW} {app_id} {tc.RED} {original_name} {tc.END}"
            )
            return True
    else:
        print(f"{tc.RED} Download {orientation} image: Skip {tc.END}")
        return True


def get_steam_appid_dict(org_name, dsc_name, dir_name, exe_name, match_type):
    """___get application id dictionary from json data___"""

    app_id_dict = dict()

    if not sw_appid_json.exists():
        return app_id_dict

    org = edit_cur_name(org_name).upper() if org_name else "original"
    dsc = edit_cur_name(dsc_name).upper() if dsc_name else "description"
    dir = edit_cur_name(dir_name).upper() if dir_name else "directory"
    exe = edit_cur_name(exe_name).upper() if exe_name else "executable"

    dsc_not_dup = True if dsc != org else False
    dir_not_dup = True if dir != org and dir != dsc else False
    exe_not_dup = True if exe != org and exe != dsc and exe != dir else False

    with open(sw_appid_json) as f:
        json_data = json.load(f)
        app_data = json_data
        f.close()

    for app in app_data:
        a_name = str(app["name"])
        a_name = re.sub(r"\(.*?\)", "", a_name)
        a_name = re.sub(r"[ЁёА-я]", "", a_name)
        a_name = re.sub(r"[^a-zA-Z0-9\s]", "", a_name)

        for word in exclude_double_words:
            if word[0] in a_name:
                a_name = a_name.replace(word[0], word[1])

        for word in exclude_single_words:
            if word[0] in a_name:
                a_name = a_name.replace(word[0], word[1])

        a_name = a_name.upper().strip()
        a_name = " ".join(a_name.split())

        key_name = str_to_roman(a_name)

        if org_name:
            fmt_name = org_name.upper()
            fmt_name = str_to_roman(fmt_name)

            if match_type == "inaccurate_match":
                if f"{org} " in a_name or f"{fmt_name} " in key_name:
                    key_name = fmt_name

            if key_name == fmt_name or a_name == org:
                app_id = app["appid"]
                name = app["name"]
                app_id_dict[f"original_{name}_{app_id}"] = (app_id, name)

        if dsc_name and dsc_not_dup:
            fmt_name = dsc_name.upper()
            fmt_name = str_to_roman(fmt_name)

            if match_type == "inaccurate_match":
                if f"{dsc} " in a_name or f"{fmt_name} " in key_name:
                    key_name = fmt_name

            if key_name == fmt_name or a_name == dsc:
                app_id = app["appid"]
                name = app["name"]
                app_id_dict[f"description_{name}_{app_id}"] = (app_id, name)

        if dir_name and dir_not_dup:
            fmt_name = dir_name.upper()
            fmt_name = str_to_roman(fmt_name)

            if match_type == "inaccurate_match":
                if f"{dir} " in a_name or f"{fmt_name} " in key_name:
                    key_name = fmt_name

            if key_name == fmt_name or a_name == dir:
                app_id = app["appid"]
                name = app["name"]
                app_id_dict[f"directory_{name}_{app_id}"] = (app_id, name)

        if exe_name and exe_not_dup and len(exe_name) > 3:
            fmt_name = exe_name.upper()
            fmt_name = str_to_roman(fmt_name)

            if match_type == "inaccurate_match":
                if f"{exe} " in a_name or f"{fmt_name} " in key_name:
                    key_name = fmt_name

            if key_name == fmt_name or a_name == exe:
                app_id = app["appid"]
                name = app["name"]
                app_id_dict[f"exe_{name}_{app_id}"] = (app_id, name)

    if app_id_dict:
        sorted_items = sorted(app_id_dict.items(), key=lambda x: len(x[1][1]))
        app_id_dict = dict(sorted_items)

    print(tc.BEIGE, f"{match_type}:", tc.YELLOW, app_id_dict.keys(), tc.END)
    return app_id_dict


def get_igdb_appid_dict(org_name, dsc_name, dir_name, exe_name, match_type):
    """___get application id dictionary from json data___"""

    app_id_dict = dict()
    session, auth_info = get_igdb_access()

    org = edit_cur_name(org_name).upper() if org_name else "original"
    dsc = edit_cur_name(dsc_name).upper() if dsc_name else "description"
    dir = edit_cur_name(dir_name).upper() if dir_name else "directory"
    exe = edit_cur_name(exe_name).upper() if exe_name else "executable"

    dsc_not_dup = True if dsc != org else False
    dir_not_dup = True if dir != org and dir != dsc else False
    exe_not_dup = True if exe != org and exe != dsc and exe != dir else False

    if org_name:
        fmt_name = org_name.upper()
        fmt_name = str_to_roman(fmt_name)
        print("SEARCH NAME:", org)

        cur_data = get_igdb_game_info(org, session, auth_info)
        if not cur_data:
            cur_data = get_igdb_game_info(org_name, session, auth_info)

        if cur_data:
            for game_data in cur_data:
                app_id = game_data.get("id", "")
                a_name = game_data.get("name", "")

                a_name = re.sub(r"\(.*?\)", "", a_name)
                a_name = re.sub(r"[ЁёА-я]", "", a_name)
                a_name = re.sub(r"[^a-zA-Z0-9\s]", "", a_name)

                for word in exclude_double_words:
                    if word[0] in a_name:
                        a_name = a_name.replace(word[0], word[1])

                for word in exclude_single_words:
                    if word[0] in a_name:
                        a_name = a_name.replace(word[0], word[1])

                a_name = a_name.upper().strip()
                a_name = " ".join(a_name.split())

                key_name = str_to_roman(a_name)

                if match_type == "inaccurate_match":
                    if f"{exe} " in a_name or f"{fmt_name} " in key_name:
                        name = game_data.get("name")
                        if name:
                            app_id_dict[f"original_{name}_{app_id}"] = game_data

                if key_name == fmt_name or a_name == org:
                    name = game_data.get("name")
                    if name:
                        app_id_dict[f"original_{name}_{app_id}"] = game_data

    if dsc_name and dsc_not_dup:
        fmt_name = dsc_name.upper()
        fmt_name = str_to_roman(fmt_name)
        print("SEARCH NAME:", dsc)

        cur_data = get_igdb_game_info(dsc, session, auth_info)
        if not cur_data:
            cur_data = get_igdb_game_info(dsc_name, session, auth_info)

        if cur_data:
            for game_data in cur_data:
                app_id = game_data.get("id", "")
                a_name = game_data.get("name", "")
                a_name = re.sub(r"\(.*?\)", "", a_name)
                a_name = re.sub(r"[ЁёА-я]", "", a_name)
                a_name = re.sub(r"[^a-zA-Z0-9\s]", "", a_name)

                for word in exclude_double_words:
                    if word[0] in a_name:
                        a_name = a_name.replace(word[0], word[1])

                for word in exclude_single_words:
                    if word[0] in a_name:
                        a_name = a_name.replace(word[0], word[1])

                a_name = a_name.upper().strip()
                a_name = " ".join(a_name.split())

                key_name = str_to_roman(a_name)

                if match_type == "inaccurate_match":
                    if f"{exe} " in a_name or f"{fmt_name} " in key_name:
                        name = game_data.get("name")
                        if name:
                            app_id_dict[f"description_{name}_{app_id}"] = game_data

                if key_name == fmt_name or a_name == dsc:
                    name = game_data.get("name")
                    if name:
                        app_id_dict[f"description_{name}_{app_id}"] = game_data

    if dir_name and dir_not_dup:
        fmt_name = dir_name.upper()
        fmt_name = str_to_roman(fmt_name)
        print("SEARCH NAME:", dir)

        cur_data = get_igdb_game_info(dir, session, auth_info)
        if not cur_data:
            cur_data = get_igdb_game_info(dir_name, session, auth_info)

        if cur_data:
            for game_data in cur_data:
                app_id = game_data.get("id", "")
                a_name = game_data.get("name", "")
                a_name = re.sub(r"\(.*?\)", "", a_name)
                a_name = re.sub(r"[ЁёА-я]", "", a_name)
                a_name = re.sub(r"[^a-zA-Z0-9\s]", "", a_name)

                for word in exclude_double_words:
                    if word[0] in a_name:
                        a_name = a_name.replace(word[0], word[1])

                for word in exclude_single_words:
                    if word[0] in a_name:
                        a_name = a_name.replace(word[0], word[1])

                a_name = a_name.upper().strip()
                a_name = " ".join(a_name.split())

                key_name = str_to_roman(a_name)

                if match_type == "inaccurate_match":
                    if f"{exe} " in a_name or f"{fmt_name} " in key_name:
                        name = game_data.get("name")
                        if name:
                            app_id_dict[f"directory_{name}_{app_id}"] = game_data

                if key_name == fmt_name or a_name == dir:
                    name = game_data.get("name")
                    if name:
                        app_id_dict[f"directory_{name}_{app_id}"] = game_data

    if exe_name and exe_not_dup and len(exe_name) > 3:
        fmt_name = exe_name.upper()
        fmt_name = str_to_roman(fmt_name)
        print("SEARCH NAME:", exe)

        cur_data = get_igdb_game_info(exe, session, auth_info)
        if not cur_data:
            cur_data = get_igdb_game_info(exe_name, session, auth_info)

        if cur_data:
            for game_data in cur_data:
                app_id = game_data.get("id", "")
                a_name = game_data.get("name", "")

                a_name = re.sub(r"\(.*?\)", "", a_name)
                a_name = re.sub(r"[ЁёА-я]", "", a_name)
                a_name = re.sub(r"[^a-zA-Z0-9\s]", "", a_name)

                for word in exclude_double_words:
                    if word[0] in a_name:
                        a_name = a_name.replace(word[0], word[1])

                for word in exclude_single_words:
                    if word[0] in a_name:
                        a_name = a_name.replace(word[0], word[1])

                a_name = a_name.upper().strip()
                a_name = " ".join(a_name.split())

                key_name = str_to_roman(a_name)

                if match_type == "inaccurate_match":
                    if f"{exe} " in a_name or f"{fmt_name} " in key_name:
                        name = game_data.get("name")
                        if name:
                            app_id_dict[f"exe_{name}_{app_id}"] = game_data

                if key_name == fmt_name or a_name == exe:
                    name = game_data.get("name")
                    if name:
                        app_id_dict[f"exe_{name}_{app_id}"] = game_data

    if app_id_dict:
        sorted_items = sorted(app_id_dict.items(), key=lambda x: len(x[1]["name"]))
        app_id_dict = dict(sorted_items)

    print(tc.BEIGE, f"{match_type.capitalize()}:", tc.YELLOW, app_id_dict.keys(), tc.END)
    return app_id_dict


def check_download_gamesdb(app_id_dict, app_path, orientation):
    """___search and download content from gamesdb___"""
    hash_name = get_hash_name(app_path)
    for key, (app_id, name) in app_id_dict.items():
        print(
            tc.VIOLET2
            + f"Try download by {key}: "
            + f"{app_id} {name}"
            + tc.END
        )
        game_db = dict()
        get_gog_content(game_db, app_id, request_headers, "steam")
        swd_json = sw_fm_cache_swd.joinpath(f"{hash_name}_{app_id}.json")
        create_json_data(swd_json, game_db)
        swd_data = read_json_data(swd_json)

        for idx, data in swd_data.items():
            title = data.get("title")
            if orientation == "vertical":
                url_cover = data.get("cover", {}).get("url_format")
                if url_cover and title:
                    vertical = sw_app_vicons.joinpath(
                        f"{hash_name}_vertical_{title}_{idx}.jpg"
                    )
                    url_cover = (
                        url_cover.replace("{formatter}", "")
                        .replace("{ext}", "jpg")
                        .replace(" ", "%20")
                    )
                    download_with_convert(url_cover, vertical, 400, 600)
                    if vertical.exists():
                        return True

            if orientation == "horizontal":
                url_logo = data.get("logo", {}).get("url_format")
                if url_logo and title:
                    horizontal = sw_app_hicons.joinpath(
                        f"{hash_name}_horizontal_{title}_{idx}.jpg"
                    )
                    url_logo = (
                        url_logo.replace("{formatter}", "")
                        .replace("{ext}", "jpg")
                        .replace(" ", "%20")
                    )
                    download_with_convert(url_logo, horizontal, 640, 360)
                    if horizontal.exists():
                        return True

            if orientation == "artwork":
                url_artwork = data.get("horizontal_artwork", {}).get("url_format")
                if url_artwork and title:
                    artwork = sw_app_artwork.joinpath(
                        f"{hash_name}_artwork_{title}_{idx}.jpg"
                    )
                    url_artwork = (
                        url_artwork.replace("{formatter}", "")
                        .replace("{ext}", "jpg")
                        .replace(" ", "%20")
                    )
                    download_with_convert(
                        url_artwork, artwork, 1920, 620, True, (0,0,1920,620))
                    if artwork.exists():
                        return True
    return False


def check_download_igdb_cover(game_data, app_path):
    """___check and download content from igdb___"""
    if game_data:
        idx = game_data.get("id")
        title = game_data.get("name")

        cover = game_data.get("cover", {})
        hash_name = get_hash_name(app_path)

        vertical = sw_app_vicons.joinpath(
            f"{hash_name}_vertical_{title}_{idx}.jpg"
        )
        if cover:
            cover_id = cover.get("image_id")
            url_cover = f"{IGDB_IMAGE_URL}/t_720p/{cover_id}.jpg"
            print(tc.YELLOW, "Try download:", tc.END, title, url_cover)
            download_with_convert(url_cover, vertical, 400, 600)

            if vertical.exists():
                return True
    return False


def check_download_igdb_horizontal(game_data, app_path):
    """___check and download content from igdb___"""
    if game_data:
        idx = game_data.get("id")
        title = game_data.get("name")

        artworks = game_data.get("artworks", [])
        hash_name = get_hash_name(app_path)

        horizontal = sw_app_hicons.joinpath(
            f"{hash_name}_horizontal_{title}_{idx}.jpg"
        )
        for artwork in artworks:
            art_id = artwork.get("image_id")
            art_width = artwork.get("width")
            art_height = artwork.get("height")
            art_type = artwork.get("artwork_type")
            url_artwork = f"{IGDB_IMAGE_URL}/t_720p/{art_id}.jpg"

            if ((art_type == 3 and (art_width / art_height) > 1)
                or (art_type == 2 and (art_width / art_height) > 1)
                or (art_type == 1 and (art_width / art_height) > 1)):
                    print(tc.YELLOW, "Try download:", tc.END, title, url_artwork)
                    download_with_convert(url_artwork, horizontal, 640, 360)

                    if horizontal.exists():
                        return True
    return False


def check_download_igdb_artwork(game_data, app_path):
    """___check and download content from igdb___"""
    if game_data:
        idx = game_data.get("id")
        title = game_data.get("name")

        artworks = game_data.get("artworks", [])
        hash_name = get_hash_name(app_path)

        art = sw_app_artwork.joinpath(
            f"{hash_name}_artwork_{title}_{idx}.jpg"
        )
        for artwork in artworks:
            art_id = artwork.get("image_id")
            art_width = artwork.get("width")
            art_height = artwork.get("height")
            art_type = artwork.get("artwork_type")
            url_artwork = f"{IGDB_IMAGE_URL}/t_1080p/{art_id}.jpg"

            if ((art_type == 2 and (art_width / art_height) > 1)
                or (art_type == 1 and (art_width / art_height) > 1)):
                    print(tc.YELLOW, "Try download:", tc.END, title, url_artwork)
                    download_with_convert(
                        url_artwork, art, 1920, 620, True, (0,0,1920,620))

                    if art.exists():
                        return True
    return False


def compare_name(orig_name, desc_name, dir_name, exe_name, app_path):
    """___compare application metadata info with application id data___"""

    has_cover = False
    has_horizontal = False
    has_artwork = False

    steam_dict = get_steam_appid_dict(
        orig_name, desc_name, dir_name, exe_name, "exact_match")

    if steam_dict:
        has_cover = check_download_steamdb(steam_dict, app_path, "vertical")
        if not has_cover:
            has_cover = check_download_gamesdb(steam_dict, app_path, "vertical")

        has_horizontal = check_download_steamdb(steam_dict, app_path, "horizontal")

        has_artwork = check_download_steamdb(steam_dict, app_path, "artwork")
        if not has_artwork:
            has_artwork = check_download_gamesdb(steam_dict, app_path, "artwork")

    if not has_cover or not has_horizontal or not has_artwork:
        igdb_dict = get_igdb_appid_dict(
            orig_name, desc_name, dir_name, exe_name, "exact_match"
        )
        if not has_cover:
            for _, data in igdb_dict.items():
                if check_download_igdb_cover(data, app_path):
                    has_cover = True
                    break

        if not has_horizontal:
            for _, data in igdb_dict.items():
                if check_download_igdb_horizontal(data, app_path):
                    has_horizontal = True
                    break

        if not has_artwork:
            for _, data in igdb_dict.items():
                if check_download_igdb_artwork(data, app_path):
                    has_artwork = True
                    break

    if not has_cover or not has_horizontal or not has_artwork:
        igdb_dict_ = get_igdb_appid_dict(
            orig_name, desc_name, dir_name, exe_name, "inaccurate_match"
        )
        if not has_cover:
            for _, data in igdb_dict_.items():
                if check_download_igdb_cover(data, app_path):
                    break

        if not has_horizontal:
            for _, data in igdb_dict_.items():
                if check_download_igdb_horizontal(data, app_path):
                    break

        if not has_artwork:
            for _, data in igdb_dict_.items():
                if check_download_igdb_artwork(data, app_path):
                    break

    # # if not v_result:
    # #     compare_sgdb_horizontal(
    # #         orig_name,
    # #         desc_name,
    # #         dir_name,
    # #         exe_name,
    # #         app_name,
    # #         "inaccurate_match",
    # #     )

    # # if not h_result:
    # #     compare_sgdb_vertical(
    # #         orig_name,
    # #         desc_name,
    # #         dir_name,
    # #         exe_name,
    # #         app_name,
    # #         "inaccurate_match",
    # #     )


def compare_sgdb_vertical(
    orig_name, desc_name, dir_name, exe_name, app_name, match_type):
    """___compare application metadata info with application id data___"""
    vicon = hicon = heroes = None
    compare_dict = {
        orig_name: "Original name",
        desc_name: "Description name",
        dir_name: "Directory name",
        exe_name: "Exe name",
        app_name: "App name",
    }
    for name, desc in compare_dict.items():
        if name:
            print(
                f"{tc.GREEN}Check and try download by {desc}: \
                    {tc.RED}{name} {tc.GREEN}vertical sgdb image{tc.END}"
            )
            vicon, hicon, heroes = check_download_sgdb(
                name, app_name, "600", "900", "vertical", match_type
            )
            if not vicon:
                vicon, hicon, heroes = check_download_sgdb(
                    name, app_name, "660", "930", "vertical", match_type
                )
                if vicon:
                    break
            else:
                break

    return vicon, hicon, heroes


def compare_sgdb_horizontal(
    orig_name, desc_name, dir_name, exe_name, app_name, match_type):
    """___compare application metadata info with application id data___"""
    vicon = hicon = heroes = None
    compare_dict = {
        orig_name: "Original name",
        desc_name: "Description name",
        dir_name: "Directory name",
        exe_name: "Exe name",
        app_name: "App name",
    }
    for name, desc in compare_dict.items():
        if name:
            print(
                f"{tc.GREEN}Check and try download by {desc}: \
                    {tc.RED}{name}{tc.GREEN} horizontal sgdb image {tc.END}"
            )
            vicon, hicon, heroes = check_download_sgdb(
                name, app_name, "460", "215", "horizontal", match_type
            )
            if not hicon:
                vicon, hicon, heroes = check_download_sgdb(
                    name, app_name, "920", "430", "horizontal", match_type
                )
                if hicon:
                    break
            else:
                break

    return vicon, hicon, heroes


def edit_cur_name(cur_name):
    """___edit application name for searching content___"""

    length = len(cur_name)
    count = 0
    parts = []

    is_alpha_around = (
        lambda: not cur_name[i - 1].isdigit()
            or (length > (i + 1) and cur_name[i + 1].isdigit())
    )

    is_lower_around = (
        lambda: not cur_name[i - 1].isupper()
            or (length > (i + 1) and cur_name[i + 1].islower())
    )

    for i, e in enumerate(list(cur_name)):
        for _ in cur_name[count:i]:
            if (e.isdigit() and is_alpha_around()) or (e.isupper() and is_lower_around()):
                part = "".join(c for c in cur_name[count:i])
                parts.append(part)
                count = i
                break

    nums = []
    words = []
    parts.append(cur_name[count:])

    for i, p in enumerate(parts):
        pr = p.replace(" ", "")

        if pr.isdigit() and not parts[i - 1].replace(" ", "").isdigit():
            nums.append(p)

        if not pr.isdigit():
            words.append(p)

    edit_name = "*".join(parts)

    for n in nums:
        edit_name = edit_name.replace(f"*{n}", f" {n}")

    for w in words:
        edit_name = edit_name.replace(f"*{w}", f" {w}")

    edit_name = edit_name.replace("*", "")
    edit_name = " ".join([x for x in edit_name.split(" ") if x])

    print(tc.GREEN, "EditedName:", edit_name, tc.END)
    return edit_name


def get_sgdb_match(data, cur_name, match_type):
    """___sort searching app id by match type___"""
    app_id_list = list()
    name_list = list()
    for app in data:
        key_name = str(app["name"].encode("ascii", "ignore"), encoding="utf-8")
        key_name = re.sub(r"[ЁёА-я]", "", key_name)

        for letter in exclude_letters:
            key_name = key_name.replace(letter[0], letter[1])

        for word in exclude_single_words:
            key_name = key_name.replace(word[0], word[1])

        for word in exclude_double_words:
            if word[0] in key_name:
                key_name = key_name.replace(word[0], word[1])

        key_name = "".join(e for e in key_name.upper() if e.isalnum())
        key_name = str_to_roman(key_name)

        cur_name = "".join(e for e in cur_name.upper() if e.isalnum())
        cur_name = str_to_roman(cur_name)

        if match_type == "inaccurate_match":
            if cur_name in key_name or key_name in cur_name:
                cur_name = key_name

        if cur_name == key_name:
            app_id_list.append(app["id"])
            name_list.append(app["name"])

    return app_id_list, name_list


def check_download_sgdb(cur_name, app_name, width, height, orientation, match_type):
    """___search and download content from steamgriddb___"""
    vicon = hicon = heroes = None
    if cur_name:
        app_name_isalnum = "".join(e for e in app_name if e.isalnum())
        edited_name = edit_cur_name(cur_name)
        url_search = (
            f"{SGDB_BASE_URL}/search/autocomplete/{edited_name}"
        )
        dst_json = sw_fm_cache_database.joinpath(f"{edited_name}.json")
        print(f"{tc.VIOLET}Search by Edited name: {tc.RED}{edited_name}{tc.END}")
        try:
            request_urlopen(url_search, dst_json, True)
        except (Exception,) as e:
            print(e)
            return vicon, hicon, heroes

        dst_data = []
        data = []
        app_id = None
        data_name = None

        if Path(dst_json).exists():
            try:
                with open(dst_json, mode="r", encoding="utf-8") as f:
                    dst_json_data = json.load(f)
                    dst_data = dst_json_data["data"]
                    f.close()
            except (OSError, IOError, JSONDecodeError) as e:
                print(e)
                return vicon, hicon, heroes

        if dst_data:
            app_id_list, name_list = get_sgdb_match(dst_data, cur_name, match_type)
            if app_id_list:
                print(app_id_list, name_list)
                app_id = app_id_list[0]
                data_name = name_list[0]

        if app_id:
            url_app_id = f"{SGDB_BASE_URL}/grids/game/{app_id}?dimentions={width}x{height}"
            heroes = check_sgdb_heroes(app_name_isalnum, app_id, data_name)
            json_name = f"{app_name_isalnum}_{orientation}_{app_id}.json"
            json_cache = sw_fm_cache_database.joinpath(json_name)

            try:
                request_urlopen(url_app_id, json_cache, True)
            except (Exception,) as e:
                print(e)
                return vicon, hicon, heroes

            if json_cache.exists():
                try:
                    with open(json_cache, mode="r", encoding="utf-8") as f:
                        json_data = json.load(f)
                        data = json_data["data"]
                        f.close()
                except (Exception, JSONDecodeError) as e:
                    return vicon, hicon, heroes

            url_icon = []
            if data:
                for value in data:
                    if int(value["width"]) == int(width):
                        url_icon.append(value["url"])
                        break

            if url_icon:
                jpg_name = f"{app_name_isalnum}_{orientation}_{data_name}_{app_id}.jpg"
                jpg_hicon = f"{app_name_isalnum}_horizontal_{data_name}_{app_id}.jpg"
                jpg_vicon = f"{app_name_isalnum}_vertical_{data_name}_{app_id}.jpg"
                jpg_cache = sw_fm_cache_database.joinpath(jpg_name)
                hicon = sw_app_hicons.joinpath(jpg_hicon)
                vicon = sw_app_vicons.joinpath(jpg_vicon)

                try:
                    request_urlopen(url_icon[0], jpg_cache, False)
                except (Exception,) as e:
                    print(e)
                    return vicon, hicon, heroes

                if orientation == "horizontal":
                    try:
                        convert_image(jpg_cache, hicon, 640, 360)
                    except (Exception,):
                        shutil.copy2(jpg_cache, hicon)
                        print(
                            f"{tc.GREEN} Copy horizontal image: "
                            + f"{tc.YELLOW} {app_id} {tc.RED} {data_name} {tc.END}"
                        )
                    else:
                        print(
                            f"{tc.GREEN} Convert horizontal image: "
                            + f"{tc.YELLOW} {app_id} {tc.RED} {data_name} {tc.END}"
                        )

                elif orientation == "vertical":
                    try:
                        convert_image(jpg_cache, vicon, 400, 600)
                    except (Exception,):
                        shutil.copy2(jpg_cache, vicon)
                        print(
                            f"{tc.GREEN} Copy vertical image: "
                            + f"{tc.YELLOW} {app_id} {tc.RED} {data_name} {tc.END}"
                        )
                    else:
                        print(
                            f"{tc.GREEN} Convert vertical image: "
                            + f"{tc.YELLOW} {app_id} {tc.RED} {data_name} {tc.END}"
                        )
                else:
                    print(
                        f"{tc.GREEN} content not found {tc.YELLOW} "
                        + f"{app_id} {tc.RED} {data_name} {tc.END}"
                    )

                if jpg_cache.exists():
                    for path in sw_fm_cache_database.iterdir():
                        if path.is_file() and path.exists():
                            try:
                                path.unlink()
                            except:
                                pass

                print(f"{tc.GREEN}Done{tc.END}")
                return vicon, hicon, heroes
            else:
                print(f"{tc.RED}URL data is empty, content not found...{tc.END}")
                return vicon, hicon, heroes
        else:
            print(f"{tc.RED}App ID is None, content not found...{tc.END}")
            return vicon, hicon, heroes
    else:
        print(f"{tc.RED}Current app name is None, content not found...{tc.END}")
        return vicon, hicon, heroes


def get_app_id_dict():
    """___get dictionary of app IDs from icon names___"""
    id_dict = dict()
    for icon in sw_app_vicons.iterdir():
        app_nm = str(icon.stem).split("_")[0]
        app_id = str(icon.stem).split("_")[-1]
        if not "s" in app_id and not "x" in app_id:
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
    ext_data_dict = read_json_data(sw_external_json)
    url_stm_id = (
        f"{SGDB_BASE_URL}/games/id/{app_id}?platformdata=steam"
    )
    external_json_cache = sw_fm_cache_database.joinpath(
        f"{app_name_isalnum}_{app_id}.json"
    )
    try:
        request_urlopen(url_stm_id, external_json_cache, True)
    except Exception as e:
        print(e)
        return
    else:
        if external_json_cache.exists():
            with open(external_json_cache, mode="r", encoding="utf-8") as f:
                external_json = json.load(f)
                f.close()

            if external_json.get("data"):
                ext_data = external_json.get("data")
                if ext_data.get("external_platform_data"):
                    ext_plat_data = ext_data.get("external_platform_data")
                    if ext_plat_data.get("steam"):
                        stm_id = ext_plat_data["steam"][0]["id"]
                        stm_nm = ext_data["name"]
                        if ext_data_dict.get(f"{app_name_isalnum}") is None:
                            ext_data_dict[f"{app_name_isalnum}"] = {
                                "app_id": f"{app_id}",
                                "steam_id": f"{stm_id}",
                                "name": f"{stm_nm}",
                                "exe_name": f"{app_name_isalnum}",
                            }
                            with open(
                                sw_external_json, mode="w", encoding="utf-8"
                            ) as f:
                                f.write(json.dumps(ext_data_dict))
                                f.close()
                        print(
                            f"{tc.VIOLET}External {app_name_isalnum} data {stm_nm}: {stm_id} {tc.END}"
                        )
                    else:
                        print(
                            f"{tc.RED}External {app_name_isalnum} data not found{tc.END}"
                        )
                else:
                    print(f"{tc.RED}External {app_name_isalnum} data not found{tc.END}")
            else:
                print(f"{tc.RED}External {app_name_isalnum} data not found{tc.END}")


def check_sgdb_heroes(app_name_isalnum, app_id, data_name):
    """___check steamgriddb and try to download heroes logo by app id___"""
    part_of_path = sw_app_artwork.joinpath(f"{app_name_isalnum}_artwork_")
    if not f"{part_of_path}" in str([x for x in list(sw_app_artwork.iterdir())]):
        size_dict = {3840: 1240, 1920: 620, 1600: 650}
        url_artwork_icon = []
        for width, height in size_dict.items():
            url_heroes = f"{SGDB_BASE_URL}/heroes/game/{app_id}?dimentions={width}x{height}"
            heroes_name = f"{app_name_isalnum}_artwork_{app_id}.json"
            heroes_cache = sw_fm_cache_database.joinpath(heroes_name)
            try:
                request_urlopen(url_heroes, heroes_cache, True)
            except Exception as e:
                print(e)
                return False
            else:
                if heroes_cache.exists():
                    with open(heroes_cache, mode="r", encoding="utf-8") as f:
                        json_data = json.load(f)
                        if len(json_data["data"]) > 0:
                            for value in json_data["data"]:
                                if str(value["style"]) in [
                                    "alternate",
                                    "blurred",
                                ] and int(value["width"]) == int(width):
                                    url_artwork_icon.append(value["url"])
                                    break
                        f.close()
        else:
            if len(url_artwork_icon) > 0:
                print(url_artwork_icon)
                jpg_name = f"{app_name_isalnum}_artwork_{data_name}_{app_id}.jpg"
                jpg_cache = sw_fm_cache_database.joinpath(jpg_name)
                try:
                    request_urlopen(url_artwork_icon[0], jpg_cache, False)
                except Exception as e:
                    print(e)
                    return False
                else:
                    heroes = sw_app_artwork.joinpath(jpg_name)
                    try:
                        convert_image(jpg_cache, heroes, 3840, 1240)
                    except (Exception,):
                        shutil.copy2(jpg_cache, heroes)
                        print(
                            f"{tc.GREEN}Copy heroes image: {app_id} {data_name} {tc.END}"
                        )
                    else:
                        print(
                            f"{tc.GREEN}Convert heroes image: {app_id} {data_name} {tc.END}"
                        )
                    return heroes
            else:
                print(f"{tc.RED}Heroes image not found...{tc.END}")
                return False
    else:
        print(
            f"{tc.GREEN} Heroes image {app_name_isalnum} exists! skip... {tc.END}"
        )
        return True


def check_download_steamdb(app_id_dict, app_path, orientation):
    """___check steamdb and try download logo by app id___"""
    check_io = False
    for key, (idx, name) in app_id_dict.items():
        if "original" in key:
            print(tc.VIOLET2, f"Try download by OrigName: {idx} {name}", tc.END)
            check_io = try_download_logo(idx, app_path, name, orientation)
            if check_io:
                break

    if not check_io:
        for key, (idx, name) in app_id_dict.items():
            if "description" in key:
                print(tc.VIOLET2, f"Try download by DescName: {idx} {name}", tc.END)
                check_io = try_download_logo(idx, app_path, name, orientation)
                if check_io:
                    break

    if not check_io:
        for key, (idx, name) in app_id_dict.items():
            if "directory" in key:
                print(tc.VIOLET2, f"Try download by DirName: {idx} {name}", tc.END)
                check_io = try_download_logo(idx, app_path, name, orientation)
                if check_io:
                    break

    if not check_io:
        for key, (idx, name) in app_id_dict.items():
            if "exe" in key:
                print(tc.VIOLET2, f"Try download by ExeName: {idx} {name}", tc.END)
                check_io = try_download_logo(idx, app_path, name, orientation)
                if check_io:
                    break

    return check_io


def get_meta_prod(metadata):
    """___get exe product name info from metadata___"""
    try:
        md_prod = metadata["ProductName"]
    except (Exception,):
        print(f"{tc.YELLOW}ProductName: {tc.RED}metadata not found{tc.END}")
        return None
    else:
        return md_prod


def get_meta_orig(app_name, app_path):
    """___get exe original name info from metadata___"""
    cmd = str()
    out_cmd = None
    metadata_original = None

    exe_list = list(
        Path(Path(app_path.strip('"')).parent).rglob("*.exe", case_sensitive=False)
    )
    original_path = [x for x in exe_list if "-Win64-Shipping.exe" in str(x)]

    if len(original_path) == 0:
        original_path = [x for x in exe_list if f"{app_name}" in str(x)]

    if len(original_path) != 0:
        if len(original_path) == 1:
            cmd = f'{sw_start} --metadata "{original_path[0]}"'
        elif len(original_path) > 1:
            cmd = f'{sw_start} --metadata "{original_path[1]}"'

        out_cmd = run(cmd, shell=True, stdout=PIPE).stdout
        try:
            metadata_original = json.loads(out_cmd)
        except (Exception,):
            print("<< OriginalFileName: metadata not found... >>")
            return None
        else:
            try:
                md_orig_prod = metadata_original["ProductName"]
            except (Exception,):
                print("<< ProductName of OriginalFileName: metadata not found >>")
                return None
            else:
                return md_orig_prod

    return None


def get_meta_desc(metadata):
    """___get exe description info from metadata___"""
    try:
        md_desc = metadata["FileDescription"]
    except (Exception,):
        print(f"{tc.YELLOW}FileDescription: {tc.RED}metadata not found{tc.END}")
        return None
    else:
        return md_desc


def exe_metadata(args):
    get_exe_metadata(*args)


def get_exe_metadata(app_name, app_path, event=None):
    """___get exe logo id from json data___"""
    dir_list = list()
    metadata = None
    orig_name = None
    desc_name = None
    dir_name = None
    md_prod = None
    md_desc = None

    print_metadata = lambda: print(
        tc.SELECTED + tc.GREEN,
        "-----------------< METADATA >-----------------" + tc.END,
    )
    cmd = f'{sw_start} --metadata {app_path}'
    out_cmd = run(cmd, shell=True, stdout=PIPE).stdout

    try:
        metadata = json.loads(out_cmd)
    except (Exception,):
        print_metadata()
        print(f"{tc.RED}Exe metadata not found...{tc.END}")
    else:
        md_prod = get_meta_prod(metadata)
        md_desc = get_meta_desc(metadata)

        if md_prod in ["BootstrapPackagedGame", None]:
            md_prod = get_meta_orig(app_name, app_path)
            if md_prod in ["BootstrapPackagedGame", None]:
                md_prod = None

        if md_prod is not None:
            md_prod = re.sub(r"\(.*?\)", "", md_prod)
            md_prod = re.sub(r"[ЁёА-я]", "", md_prod)

            for word in exclude_double_words:
                md_prod = md_prod.replace(word[0], word[1])

            for word in exclude_single_words:
                md_prod = md_prod.replace(word[0], word[1])

            orig_name = "".join(e for e in md_prod if e.isalnum() or e == " ")
            orig_name = orig_name.strip()

            if orig_name == "":
                orig_name = None

            print_metadata()
            print(f"<<OriginalName: {orig_name}>>")

        if md_desc in ["BootstrapPackagedGame", None]:
            md_desc = get_meta_orig(app_name, app_path)
            if md_desc in ["BootstrapPackagedGame", None]:
                md_desc = None

        if md_desc is not None:
            md_desc = re.sub(r"\(.*?\)", "", md_desc)
            md_desc = re.sub(r"[ЁёА-я]", "", md_desc)

            for word in exclude_double_words:
                md_desc = md_desc.replace(word[0], word[1])

            for word in exclude_single_words:
                md_desc = md_desc.replace(word[0], word[1])

            desc_name = "".join(e for e in md_desc if e.isalnum() or e == " ")
            desc_name = desc_name.strip()

            if desc_name == "":
                desc_name = None

            print_metadata()
            print(f"<<FileDescription: {desc_name}>>")

    a_name = re.sub(r"\(.*?\)", "", app_name)
    a_name = re.sub(r"[ЁёА-я]", "", a_name)

    for e in a_name:
        if not e.isalnum():
            a_name = a_name.replace(e, " ")

    for word in exclude_double_words:
        a_name = a_name.replace(word[0], word[1])

    for word in exclude_single_words:
        a_name = a_name.replace(word[0], word[1])

    exe_name = "".join(e for e in a_name if e.isalnum())
    exe_name = exe_name.strip()

    if exe_name == "":
        exe_name = None

    print_metadata()
    print(f"<<ExeName: {exe_name}>>")

    path_parts = Path(app_path.strip('"')).parent.parts
    dirs = [x for x in path_parts if not x.upper() in str(exclude_names).upper()]

    for d in dirs:
        d = re.sub(r"\(.*?\)", "", d)
        d = re.sub(r"[ЁёА-я]", "", d)

        for e in d:
            if not e.isalnum():
                d = d.replace(e, " ")

        for word in exclude_double_words:
            d = d.replace(word[0], word[1])

        for word in exclude_single_words:
            d = d.replace(word[0], word[1])

        dir_name = "".join(e for e in d if e.isalnum() or e == " ")

        if dir_name != "":
            dir_list.append(dir_name)

    if len(dir_list) > 0:
        dir_name = dir_list[-1].strip()
    else:
        dir_name = None

    print_metadata()
    print(f"<<DirectoryName: {dir_name}>>")

    compare_name(orig_name, desc_name, dir_name, exe_name, app_path)

    if event:
        event.set()


def check_store_image(env_name):
    """___check if image exists for store application___"""

    store_path = None
    vertical_image = getenv(env_name)

    if vertical_image:
        horizontal_image = vertical_image.replace("vertical", "horizontal")
        artwork_image = vertical_image.replace("vertical", "artwork")

        idx_ext = vertical_image.split("_")[-1]
        dest_name = vertical_image.split("_")[-2]

        vname = f"{dest_name}_vertical_{idx_ext}"
        hname = f"{dest_name}_horizontal_{idx_ext}"
        aname = f"{dest_name}_artwork_{idx_ext}"

        if env_name == "EPIC_VERTICAL_IMAGE":
            store_path = sw_epic_icons
        elif env_name == "GOG_VERTICAL_IMAGE":
            store_path = sw_gog_icons
        else:
            return

        if (store_path.joinpath(vname).exists()
                and not sw_app_vicons.joinpath(vertical_image).exists()):
            source = store_path.joinpath(vname)
            dest = sw_app_vicons.joinpath(vertical_image)
            shutil.copy2(source, dest)

        if (store_path.joinpath(hname)
                and not sw_app_hicons.joinpath(horizontal_image).exists()):
            source = store_path.joinpath(hname)
            dest = sw_app_hicons.joinpath(horizontal_image)
            shutil.copy2(source, dest)

        if (store_path.joinpath(aname)
                and not sw_app_artwork.joinpath(artwork_image).exists()):
            source = store_path.joinpath(aname)
            dest = sw_app_artwork.joinpath(artwork_image)
            shutil.copy2(source, dest)


def check_exe_logo(app_path):
    """___check if image exists for current application___"""
    hicons = False
    vicons = False
    artwork = False
    hash_name = get_hash_name(app_path)

    for icon in Path(f"{sw_app_hicons}").iterdir():
        if hash_name == str(Path(icon).name).split("_")[0]:
            hicons = True

    for icon in Path(f"{sw_app_vicons}").iterdir():
        if hash_name == str(Path(icon).name).split("_")[0]:
            vicons = True

    for icon in Path(f"{sw_app_artwork}").iterdir():
        if hash_name == str(Path(icon).name).split("_")[0]:
            artwork = True

    if hicons and vicons and artwork:
        return True
    else:
        return False


def get_bookmark_list():
    """___get bookmarks list from cache file___"""
    bookmarks_list.clear()
    with open(sw_bookmarks, "r") as f:
        lines = f.read().splitlines()
        for s in lines:
            bookmarks_list.append(s)
            f.close()

    return bookmarks_list


def get_playlist():
    """___get playlist from cache file___"""
    playlist.clear()
    with open(sw_playlist, "r") as f:
        lines = f.read().splitlines()
        for s in lines:
            playlist.append(s)
            f.close()

    return playlist


def get_media_metadata(media_path):
    """___get media info from metadata___"""
    md_media = {}
    cmd = f'{sw_start} --audiotags "{media_path}"'
    out_cmd = run(cmd, shell=True, stdout=PIPE).stdout
    try:
        media_metadata = json.loads(out_cmd)
    except (Exception,) as e:
        print("<< MediaFile: metadata not found... >>", e)
    else:
        for md in ["album", "title", "artist", "year"]:
            if media_metadata.get(md):
                data = media_metadata.get(md, msg.msg_dict["unknown"])
                md_media[md] = data

    return md_media


def get_media_info(x_file):
    """___get media info from metadata___"""
    media_data = msg.msg_dict["unknown"]
    if x_file is not None:
        path = x_file.get_path()
        md_media = get_media_metadata(f"{path}")
        md_info = str()
        if len(md_media) > 0:
            for k, v in md_media.items():
                md_info += f"{msg.msg_dict[k.lower()]}:\t{v}\n"
            media_data = md_info

    return media_data


def volume_control(volume, step):
    """___volume control dictionary for gstreamer media controls___"""
    value = volume.get("volume") if volume.get("volume") else 1.0
    if value < 0.0:
        value = 0.0
    if value > 1.0:
        value = 1.0
    volume["volume"] = value + float(step)
    message = round((value + float(step)) * 100, 0)
    notify_send(f"SwMedia volume {message}%")


def notify_send(data):
    """___send notify to desktop___"""
    try:
        Popen(f'notify-send -t 1500 "{data}"', shell=True)
    except (Exception, OSError, IOError) as e:
        print(e)


def echo_func_name(func_name, event=None):
    """___write and run function to function.sh___"""
    app_path = get_app_path()
    app_name = get_out()
    func = func_name + str(' "$@"')
    args = getenv("SW_EXEC_ARGS")
    exe_args = args if args and args != "None" else ""

    if app_name == "steam":
        environ["SteamGameId"] = f"{exe_args}"
        if exe_args:
            exe_args = f"-offline -silent -applaunch {exe_args}"

    if str(func) == str('ADD_SHORTCUT_TO_MENU "$@"') or str(func) == str(
        'ADD_SHORTCUT_TO_DESKTOP "$@"'
    ):
        shortcut_name = f"export CUSTOME_GAME_NAME={getenv('CUSTOM_GAME_NAME')}"
        shortcut_path = f"export SW_DESKTOP_DIR={getenv('CUSTOM_GAME_PATH')}"

        sw_fsh.write_text(
            "\n".join([fshread[0], fshread[1], shortcut_name, shortcut_path, func])
        )
        run(f"{sw_fsh} {app_path} {exe_args}", shell=True)
    else:
        sw_fsh.write_text("\n".join([fshread[0], fshread[1], func]))
        stderr_log = open(sw_logs.joinpath(f"{app_name}.log"), "w")
        run(
            f"{sw_fsh} {app_path} {exe_args}",
            shell=True,
            stderr=stderr_log,
            encoding="utf-8",
        )
        stderr_log.close()

    if event:
        print(f"Event {app_name} done")
        event.set()


def cs_wine(wine_name, _, app_path):
    """___write and run create shortcut function to function.sh___"""
    wine_download = (
        wine_func_dict.get(wine_name) if wine_func_dict.get(wine_name) else None
    )
    func_cs = 'CREATE_SHORTCUT "$@"'

    if (
        not sw_wine.joinpath(f"{wine_name}", "bin", "wine").exists()
        and wine_download is not None
    ):
        wine_ok = "export WINE_OK=1"
        func_download = f'{wine_download} "$@"'

        sw_fsh.write_text(
            "\n".join([fshread[0], fshread[1], wine_ok, func_download, func_cs])
        )
        run(f"{sw_fsh} {app_path}", shell=True)
    else:
        sw_fsh.write_text("\n".join([fshread[0], fshread[1], func_cs]))
        run(f"{sw_fsh} {app_path}", shell=True)


def echo_wine(wine_name, name_ver, wine_ver):
    """___write and run download wine function to function.sh___"""
    app_path = get_app_path()
    export_wine_ver = f'export {name_ver}="{wine_ver}"'
    wine_num = wine_name + str(' "$@"')
    sw_fsh.write_text("\n".join([fshread[0], fshread[1], export_wine_ver, wine_num]))
    run(f"{sw_fsh} {app_path}", shell=True)


def echo_install_dll(dll_list):
    """___install changed dll from winetricks list___"""
    app_path = get_app_path()
    func_name = 'SW_WINETRICKS "$@"'
    export_dll = f'export DLL="{" ".join(dll_list)}"'
    print(f"{tc.VIOLET2}setup_list: {tc.GREEN}{' '.join(dll_list)}{tc.END}")

    sw_fsh.write_text("\n".join([fshread[0], fshread[1], export_dll, func_name]))
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
    cmd = "vulkaninfo | grep driverName | cut -d '=' -f2"
    proc = run(cmd, shell=True, stderr=DEVNULL, stdout=PIPE, encoding="UTF-8")
    vulkan_dri = str(proc.stdout[0:]).splitlines()

    for dri in vulkan_dri:
        d = dri.replace(" ", "")
        q.append(d)


def check_wine():
    """___check the existence of the path to wine___"""
    app_name = get_out()
    app_conf = sw_app_config.joinpath(app_name)
    app_dict = app_info(app_conf)
    wine = app_dict["export SW_USE_WINE"].strip('"')

    if not sw_wine.joinpath(f"{wine}", "bin", "wine").exists():
        return wine, False
    else:
        return wine, True


def check_winedevice(winedevice, event=None):
    """___Check winedevice process___"""
    found = None
    while found is None:
        winedevice = [
            p.info["name"]
            for p in psutil.process_iter(["pid", "name"])
            if "winedevice" in p.info["name"]
        ]
        if not winedevice:
            sleep(1)
        else:
            found = 1
            print(winedevice)

        if event and event.is_set():
            break
    else:
        while winedevice:
            winedevice = [
                p.info["name"]
                for p in psutil.process_iter(["pid", "name"])
                if "winedevice" in p.info["name"]
            ]
            sleep(3)

            if event and event.is_set():
                break


def find_process(app_suffix):
    """___Return a list of processes matching name___"""
    procs = psutil.Process(os.getpid()).children(recursive=True)
    for p in procs:
        try:
            ls = p.as_dict(attrs=["name"])
        except (Exception,):
            pass
        else:
            n = ls["name"]
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
    cpu_core_num = 0
    try:
        cpu_affinity = psutil.Process().cpu_affinity()
    except (Exception,):
        count = psutil.cpu_count()
        if count:
            cpu_core_num = int(count)
    else:
        if cpu_affinity:
            cpu_core_num = len(cpu_affinity)

    return cpu_core_num


def get_wayland_compositor_name():
    """___Get wayland compositor name by unix socket pid___"""
    system = platform.system()
    if system == "Linux" and getenv("WAYLAND_DISPLAY"):
        wayland_display = environ.get("WAYLAND_DISPLAY", "wayland-0")
        xdg_runtime_dir = environ.get("XDG_RUNTIME_DIR", "/tmp")
        socket_path = Path(xdg_runtime_dir).joinpath(wayland_display)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(f"{socket_path}")
        pid = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED)
        sock.close()
        try:
            with open(f"/proc/{pid}/comm", mode="r", encoding="utf-8") as f:
                return f.read().strip()
        except (FileNotFoundError, PermissionError, OSError):
            return None
    else:
        return None


def run_vulkan(event=None):
    """___run application in vulkan mode___"""
    if getenv("SW_PIN") == "1":
        sw_fsh.write_text("\n".join([fshread[0], fshread[1], 'RUN_VULKAN "$@"']))
        run("sw_pin", shell=True, encoding="utf-8")
    else:
        echo_func_name("RUN_VULKAN", event)


def run_opengl():
    """___run application in opengl mode___"""
    echo_func_name("SW_USE_OPENGL='1' RUN_VULKAN")


def debug_vulkan():
    """___run application in vulkan debug mode___"""
    echo_func_name("DEBUG_VULKAN")


def debug_opengl():
    """___run application in opengl debug mode___"""
    echo_func_name("SW_USE_OPENGL='1' DEBUG_VULKAN")


def run_native(app_path, app_args):
    """___Running native executable___"""

    if app_args:
        if "steam" in Path(app_path).name.lower():
            cmd = f"mangohud {app_path} -offline -silent -applaunch {app_args}"
        else:
            cmd = f"mangohud {app_path} {app_args}"

        print(f"Running {app_path} {app_args}")
        master, slave = pty.openpty()
        with Popen(cmd, shell=True, stdout=slave, stdin=slave, stderr=slave):
            os.close(slave)
            with open(master, "r") as stdout:
                try:
                    for line in stdout:
                        print("[STEAM ZHOPA]:", line.rstrip())
                        if (
                            "Removing process" in line
                            and f"for gameID {app_args}" in line
                        ):
                            sleep(3)
                            print("Shutdown...")
                            run(["steam", "-shutdown"])
                            exit(0)
                except (OSError, IOError) as e:
                    print(f"[ERROR] {e}")
    else:
        if "steam" in Path(app_path).name.lower():
            cmd = f"{app_path}"
        else:
            cmd = f"mangohud {app_path}"
        print(f"Running {app_path}")
        run(cmd, shell=True)


def run_install_launchers(x_name):
    """___run install launchers function___"""
    launcher_name = str(x_name).upper()
    echo_func_name(f"INSTALL_{launcher_name}")


def cb_btn_wine_1(wine_ver):
    """___"""
    echo_wine("WINE_1", "STAG_VER", wine_ver)


def cb_btn_rm_wine_1(wine_ver):
    """___"""
    echo_wine("RM_WINE_1", "STAG_VER", wine_ver)


def cb_btn_wine_2(wine_ver):
    """___"""
    echo_wine("WINE_2", "SP_VER", wine_ver)


def cb_btn_rm_wine_2(wine_ver):
    """___"""
    echo_wine("RM_WINE_2", "SP_VER", wine_ver)


def cb_btn_wine_3(wine_ver):
    """___"""
    echo_wine("WINE_3", "GE_VER", wine_ver)


def cb_btn_rm_wine_3(wine_ver):
    """___"""
    echo_wine("RM_WINE_3", "GE_VER", wine_ver)


def cb_btn_wine_4(wine_ver):
    """___"""
    echo_wine("WINE_4", "STAG_VER", wine_ver)


def cb_btn_rm_wine_4(wine_ver):
    """___"""
    echo_wine("RM_WINE_4", "STAG_VER", wine_ver)


def cb_btn_wine_5(wine_ver):
    """___"""
    echo_wine("WINE_5", "EM_VER", wine_ver)


def cb_btn_rm_wine_5(wine_ver):
    """___"""
    echo_wine("RM_WINE_5", "EM_VER", wine_ver)


def run_screencast():
    """___"""
    if Path(dir_videos).exists():
        cmd = [f"{sw_cast}", "-r", f"--output={dir_videos}"]
    else:
        cmd = [f"{sw_cast}", "-r"]
    try:
        Popen(cmd)
    except (Exception, OSError, IOError) as e:
        print(e)


def run_screenshot():
    """___"""
    if Path(dir_pics).exists():
        cmd = [f"{sw_cast}", "-s", f"--output={dir_pics}"]
    else:
        cmd = [f"{sw_cast}", "-s"]
    try:
        Popen(cmd)
    except (Exception, OSError, IOError) as e:
        print(e)


def process_event_wait(event, data):
    """___wait for the process event to be set___"""
    event.wait()
    print(f"{tc.GREEN}Multiprocessing {event} {data} done...{tc.END}")
    func = None
    args = []
    if data and isinstance(data, dict):
        if data.get("func"):
            func = data.get("func")
        if data.get("args"):
            args = data.get("args")
        if func and args:
            return func(*args)
        if func and not args:
            return func()
    return None


def on_mangohud_preview(monitor_height):
    """___run mangohud preview___"""
    get_mangohud_config(monitor_height)
    try:
        Popen(f'mangohud "{sw_start}" -v', shell=True)
    except (Exception, OSError, IOError) as e:
        print("Error:", e)


def get_mangohud_config(monitor_height):
    """___get mangohud config from application config___"""
    key_reload = "Control_L+Shift_L+r"
    gl_x = "0"
    gl_y = "0"

    mh_config = str()
    app_name = get_out()
    app_conf = sw_app_config.joinpath(app_name)
    app_conf_read = app_conf.read_text().splitlines()

    for line in app_conf_read:
        if "MANGOHUD_CONFIG" in line:
            mh_config = str(line.split('"')[1])

        if "SW_USE_MESA_OVERLAY_HUD" in line:
            environ["SW_USE_MESA_OVERLAY_HUD"] = str(line.split("=")[1])

        if "SW_USE_GALLIUM_HUD" in line:
            environ["SW_USE_GALLIUM_HUD"] = str(line.split("=")[1])

    for x in mh_config.split(","):
        if "reload_cfg" in x:
            mh_config = mh_config.replace(x + ",", "")
            key_reload = "Control_L+Shift_L+r"

    if monitor_height:
        font_size = int(monitor_height / 55)
    else:
        font_size = 14

    mhud_conf = (
        f"reload_cfg={key_reload},offset_x={gl_x},offset_y={gl_y},"
        + f"{default_mangohud},font_size={font_size},{mh_config}"
    )
    print(f"{tc.BLUE}MANGOHUD_CONFIG:", tc.YELLOW, mhud_conf, tc.END)
    environ["MANGOHUD_CONFIG"] = mhud_conf


def on_winecfg():
    """___run wine settings___"""
    echo_func_name("WINECFG")


def on_wineconsole():
    """___run wine console___"""
    echo_func_name("WINECONSOLE")


def on_regedit():
    """___run wine regedit___"""
    echo_func_name("REGEDIT")


def on_explorer():
    """___run wine file explorer___"""
    echo_func_name("WINEFILE")


def on_uninstaller():
    """___run wine uninstaller___"""
    echo_func_name("UNINSTALLER")


def on_clear_shader_cache():
    """___clear shader cache___"""
    if sw_mesa_shader_cache.exists():
        for cache in sw_mesa_shader_cache.iterdir():
            if cache.is_dir():
                shutil.rmtree(cache)
            if cache.is_file():
                cache.unlink()

    if sw_mesa_shader_cache_sf.exists():
        for cache in sw_mesa_shader_cache_sf.iterdir():
            if cache.is_dir():
                shutil.rmtree(cache)
            if cache.is_file():
                cache.unlink()

    if sw_mesa_shader_cache_db.exists():
        for cache in sw_mesa_shader_cache_db.iterdir():
            if cache.is_dir():
                shutil.rmtree(cache)
            if cache.is_file():
                cache.unlink()

    if sw_radv_shader_cache.exists():
        for cache in sw_radv_shader_cache.iterdir():
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

    if sw_nvgl_shader_cache.exists():
        for cache in sw_nvgl_shader_cache.iterdir():
            if cache.is_dir():
                shutil.rmtree(cache)
            if cache.is_file():
                cache.unlink()

    if sw_nvidia_shader_cache.exists():
        for cache in sw_nvidia_shader_cache.iterdir():
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

    print(f'{tc.RED}Clear shader cache...{tc.END}')


def remove_app_name(app_name, original_name):
    """___remove application prefix and shortcuts___"""

    if sw_shortcuts.joinpath(f"{app_name}.swd").exists():
        sw_shortcuts.joinpath(f"{app_name}.swd").unlink()

    if sw_pfx.joinpath(f"pfx_{app_name}").exists():
        shutil.rmtree(sw_pfx.joinpath(f"pfx_{app_name}"))

    if sw_local.joinpath(f"{app_name}.desktop").exists():
        sw_local.joinpath(f"{app_name}.desktop").unlink()

    if Path(dir_desktop).joinpath(f"{app_name}.desktop").exists():
        Path(dir_desktop).joinpath(f"{app_name}.desktop").unlink()

    if sw_local.joinpath(f"{original_name}.desktop").exists():
        sw_local.joinpath(f"{original_name}.desktop").unlink()

    if Path(dir_desktop).joinpath(f"{original_name}.desktop").exists():
        Path(dir_desktop).joinpath(f"{original_name}.desktop").unlink()


def remove_app_data(exe_data, app_name, app_path, external=False, platform=False):
    """___remove application data___"""

    data = exe_data.get_(app_path)
    original_name = app_name

    if data and not platform:
        original_name = data.get("name", app_name)

        default_name = str(data.get("default"))
        default_path = sw_app_default_icons.joinpath(default_name)

        if default_path.exists():
            default_path.unlink()

        cover_name = str(data.get("vertical"))
        cover_path = sw_app_vicons.joinpath(cover_name)

        if cover_path.exists():
            cover_path.unlink()

        art_name = str(data.get("horizontal"))
        art_path = sw_app_hicons.joinpath(art_name)

        if art_path.exists():
            art_path.unlink()

        artwork_name = str(data.get("artwork"))
        artwork_path = sw_app_artwork.joinpath(artwork_name)

        if artwork_path.exists():
            artwork_path.unlink()

        exe_data.del_(app_path)
        write_json_data(sw_exe_data_json, exe_data)

    if external:
        write_json_data(sw_gog_exe_data_json, gog_exe_data)
        write_json_data(sw_epic_exe_data_json, epic_exe_data)
    remove_app_name(app_name, original_name)


def remove_selected_swd(x_path):
    """___remove selected swd and associated data___"""
    worker_list = []
    for x in x_path:
        external = True
        platform = False

        if Path(x.get_path()).is_file() or Path(x.get_path()).is_symlink():
            swd = x.get_path()
            app_path = get_swd_path(swd)
            app_name = Path(swd).stem
            data = exe_data.get_(app_path)

            if data and data.get("platform"):
                external = True
                platform = True

            t = Thread(
                target=remove_app_data,
                args=(exe_data, app_name, app_path, external, platform)
            )
            worker_list.append(t)
            t.start()

    for worker in worker_list:
        worker.join()


def on_pfx_remove(event=None):
    """___remove current prefix___"""
    echo_func_name("REMOVE_PFX", event)


def on_pfx_reinstall():
    """___reinstall current prefix___"""
    echo_func_name("REINSTALL_PFX")


def on_pfx_backup():
    """___backup current prefix___"""
    echo_func_name("SW_PFX_BACKUP")


def on_pfx_restore():
    """___restore current prefix___"""
    echo_func_name("SW_PFX_RESTORE")


def on_app_saves_backup():
    """___backup of app saves___"""
    echo_func_name("SW_APP_SAVES_BACKUP")


def on_app_saves_restore():
    """___restoring saves from backup___"""
    echo_func_name("SW_APP_SAVES_RESTORE")


def add_shortcut_to_menu(shortcut_name):
    """___add application shortcut to system menu___"""
    if not sw_local.joinpath(f"{shortcut_name}").exists():
        environ["CUSTOM_GAME_NAME"] = f'"{shortcut_name}"'
        echo_func_name("ADD_SHORTCUT_TO_MENU")


def add_shortcut_to_desktop(custom_name, custom_path):
    """___add application shortcut to desktop___"""
    if not Path(dir_desktop).joinpath(f"{custom_name}").exists():
        environ["CUSTOM_GAME_NAME"] = f'"{custom_name}"'

        if custom_path is None:
            environ["CUSTOM_GAME_PATH"] = f'"{dir_desktop}"'
        else:
            environ["CUSTOM_GAME_PATH"] = f'"{custom_path}"'

        echo_func_name("ADD_SHORTCUT_TO_DESKTOP")


def on_regedit_patch():
    """___registry patch for current prefix___"""
    echo_func_name("TRY_REGEDIT_PATCH")


def check_sw_update():
    """___checking update___"""
    echo_func_name("try_update_sw")


def get_dll_info(x_path):
    """___get installed dll list from winetricks log___"""
    w_log = Path(f"{x_path}").joinpath("winetricks.log")
    if w_log.exists():
        read_w_log = w_log.read_text().splitlines()
        return read_w_log
    else:
        read_w_log = []
        return read_w_log


def get_file_signature(path):
    """___Get file signature.___"""
    try:
        data = open(path, "rb").read()
    except IOError:
        return None

    header_byte = str(data[0:3]).encode("hex").lower()
    return header_byte


def get_file_mimetype(path):
    """___Get file mime type.___"""
    mime_type = None
    if Path(path).exists():
        cmd = check_output(f'file --mime-type "{path}"', shell=True, encoding="utf-8")
        mime_type = cmd.split()[-1] if cmd.split() else None
    return mime_type


def get_lineno():
    """___Get file line number.___"""
    lineno = None
    try:
        exec_info = sys.exc_info()
    except (Exception, IOError, OSError):
        return None
    else:
        if exec_info:
            try:
                opt_info = exec_info[-1]
            except (IOError, OSError, IndexError):
                return None
            else:
                if opt_info:
                    lineno = opt_info.tb_lineno
    return lineno


class Clipper:
    """___Clibboard manger.___"""

    def __init__(self):
        self.clip = "wl" if getenv("WAYLAND_DISPLAY") else "xclip"

    def copy(self, data: str | None = None) -> None:
        if self.clip == "wl":
            try:
                Popen(["wl-copy", f"{data}"])
            except (Exception, OSError, IOError) as e:
                print(e)

    def paste(self, _: str | None = None) -> None:
        if self.clip == "wl":
            try:
                Popen(["wl-paste"])
            except (Exception, OSError, IOError) as e:
                print(e)


def fetch_steam_data(vdf=None, steam_db=None):
    """___fetch steam vdf library data___"""
    if vdf and vdf.exists():
        print(f"{tc.VIOLET2}STEAM_VDF: {tc.GREEN}{vdf} found.{tc.END}")

        with open(vdf, mode="r", encoding="utf-8") as f:
            data = f.read()

        dt = data.replace("\t", "").replace("\n", "")
        re_apps = re.findall(r'"apps"{.*?}', dt)
        apps = []
        if re_apps:
            for x in re_apps:
                app = re.sub(r'[apps{}"]', ",", x)
                apps.append(app)
            apps = set(x for x in ",".join(apps).split(",") if x != "")

        info_workers = list()
        if apps:
            for app_id in apps:
                t = Thread(target=get_steam_game_info, args=(app_id, steam_db))
                t.start()
                info_workers.append(t)

            for w in info_workers:
                w.join()
    return vdf


def search_steam_content(appcache, steam_db=None):
    """___search steam content and update exe data___"""
    if not steam_db:
        steam_db = read_json_data(sw_steam_db)

    for app_id, app_data in steam_db.items():
        original_name = app_data.get("name", "").replace("/", "")
        app_name = "".join(e for e in original_name if e.isalnum())
        app_path = f'"steam://rungameid/{app_id}"'
        hash_name = get_hash_name(app_path)
        appcache_id = Path(f"{appcache}").joinpath(f"{app_id}")

        if appcache_id.exists():
            icon_default_name = f"{app_name}_{app_name}_x256.png"
            icon_default_path = sw_app_default_icons.joinpath(icon_default_name)

            for icon in appcache_id.iterdir():
                orientation = None
                if (
                    icon.is_file()
                    and icon.suffix == ".jpg"
                    and not "header" in str(icon.name)
                    and not "library" in str(icon.name)
                    and not "logo" in str(icon.name)
                ):
                    if not icon_default_path.exists():
                        shutil.copy2(icon, icon_default_path)
                        exe_data.set_(app_path, f"default", icon_default_name)

                if str(icon.name) == "header.jpg":
                    orientation = "horizontal"

                if str(icon.name) == "library_header.jpg":
                    orientation = "horizontal"

                if str(icon.name) == "library_600x900.jpg":
                    orientation = "vertical"

                if str(icon.name) == "library_hero.jpg":
                    orientation = "artwork"

                if orientation:
                    icon_name = (
                        f"{hash_name}_{orientation}_{original_name}_s{app_id}.jpg"
                    )
                    icon_path = sw_app_icons.joinpath(orientation, icon_name)
                    if not icon_path.exists():
                        shutil.copy2(icon, icon_path)
                        exe_data.set_(app_path, orientation, icon_name)


def download_steam_content(steam_db=None):
    """___download steam content and update exe data___"""
    if not steam_db:
        steam_db = read_json_data(sw_steam_db)

    start = perf_counter()
    image_workers = list()

    for app_id, app_data in steam_db.items():
        original_name = app_data.get("name", "").replace("/", "")
        app_name = ''.join(e for e in original_name if e.isalnum())
        app_path = f'"steam://rungameid/{app_id}"'
        item = get_hash_name(app_path)

        for orientation in ["horizontal", "vertical", "artwork"]:
            img_name = f"{item}_{orientation}_{original_name}_s{app_id}.jpg"
            img_path = sw_app_icons.joinpath(orientation, img_name)

            if not img_path.exists():
                exe_data.set_(app_path, orientation, img_name)
                t = Thread(
                    target=try_download_logo,
                    args=(app_id, app_path, original_name, orientation),
                )
                t.start()
                image_workers.append(t)

        exe_data.set_(app_path, "id", app_id)
        exe_data.set_(app_path, "name", original_name)
        exe_data.set_(app_path, "path", f'"steam://rungameid/{app_id}"')
        exe_data.set_(app_path, "platform", f"steam")
        write_native_swd(app_name, f'"steam://rungameid/{app_id}"')

    for w in image_workers:
        w.join()

    write_json_data(sw_exe_data_json, exe_data)
    end = perf_counter() - start
    print(f"{tc.GREEN2}Download steam content: {end}{tc.END}")


def get_steam_content(vdf=[], appcache=[], event=None, download=True):
    """___try to get steam content for steam apps.___"""
    if not vdf:
        if sw_steam_share_vdf.exists():
            vdf.append(sw_steam_share_vdf)
            appcache.append(sw_steam_share_appcache)

        if sw_steam_home_vdf.exists():
            vdf.append(sw_steam_home_vdf)
            appcache.append(sw_steam_home_appcache)

        if sw_steam_pfx_vdf.exists():
            vdf.append(sw_steam_pfx_vdf)
            appcache.append(sw_steam_pfx_appcache)

    if vdf and appcache:
        steam_db = dict()
        start = perf_counter()
        for v, c in zip(vdf, appcache):
            is_ok = fetch_steam_data(v, steam_db)
            if is_ok and download:
                search_steam_content(c)
                download_steam_content()

        founded = [v.get("name") for _, v in steam_db.items()]
        create_json_data(sw_steam_db, steam_db)
        end = perf_counter() - start
        print(f"{tc.GREEN2}GET_STEAM_INFO: {end}{tc.END}")
        print(f"{tc.GREEN2}STEAM_GAMES: {founded}{tc.END}")
    else:
        print(f"{tc.RED}libraryfolders.vdf not found, skip...{tc.END}")

    if event:
        event.set()


def get_steam_game_info(idx, db):
    """___get steam game info___"""
    dt = dict()
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, "
            "like Gecko) Chrome/30.0.1599.101 Safari/537.36"
        ),
        "Accept-Language": "ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4",
        "Accept": "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "keep-alive",
        "Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
    }
    try:
        res = requests.get(f"{url_app_dtls}{idx}", headers=headers, timeout=10.0)
    except (HTTPError, URLError, ConnectionError, ReadTimeout) as e:
        print(e)
    else:
        if res.status_code == 200:
            dt = res.json()

    if dt.get(idx, {}).get("data", {}).get("name"):
        db[idx] = {}
        db[idx]["name"] = dt.get(idx, {}).get("data", {}).get("name")
        db[idx]["description"] = (
            dt.get(idx, {}).get("data", {}).get("short_description")
        )
        db[idx]["language"] = dt.get(idx, {}).get("data", {}).get("supported_languages")
        db[idx]["image"] = dt.get(idx, {}).get("data", {}).get("header_image")
        db[idx]["requirements"] = dt.get(idx, {}).get("data", {}).get("pc_requirements")
        db[idx]["developers"] = dt.get(idx, {}).get("data", {}).get("developers")
        db[idx]["publishers"] = dt.get(idx, {}).get("data", {}).get("publishers")
        db[idx]["platforms"] = dt.get(idx, {}).get("data", {}).get("platforms")
        db[idx]["genres"] = dt.get(idx, {}).get("data", {}).get("genres")
        db[idx]["release"] = dt.get(idx, {}).get("data", {}).get("release_date")
        db[idx]["background"] = dt.get(idx, {}).get("data", {}).get("background")
        db[idx]["raw"] = dt.get(idx, {}).get("data", {}).get("background_raw")


def get_gog_auth_request():
    """___get gog authentication request___"""
    gcid = bytes.fromhex(GOG_CLIENT_ID).decode("utf-8")
    auth_params = {
        "client_id": gcid,
        "redirect_uri": GOG_REDIRECT_URI,
        "response_type": "code",
        "layout": "galaxy",
    }
    try:
        auth_request = requests.Request(
            "GET", GOG_AUTH_URL, params=auth_params
        ).prepare()
    except (HTTPError, URLError, ConnectionError, ReadTimeout) as e:
        print(f"{tc.RED}AuthGOGRequestError at line {get_lineno()}: {e}{tc.END}")
        return None
    else:
        return auth_request


def refresh_gog_token(auth_info=None, timeout=10.0, result=[]):
    """___refresh gog database access token___"""
    refresh_token = None
    if not auth_info:
        auth_info = read_json_data(sw_gog_auth)
        refresh_token = auth_info.get("refresh_token")

    if refresh_token:
        gcid = bytes.fromhex(GOG_CLIENT_ID).decode("utf-8")
        gcst = bytes.fromhex(GOG_CLIENT_SECRET).decode("utf-8")
        token_data = {
            "client_id": gcid,
            "client_secret": gcst,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        try:
            res = requests.post(GOG_TOKEN_URL, data=token_data, timeout=timeout)
        except (Exception, HTTPError, URLError, ConnectionError, ReadTimeout) as e:
            print(
                f"{tc.RED}Connection error {__file__} at line "
                f"{get_lineno()}: {tc.YELLOW2}{e}{tc.END}"
            )
            result.append(e)
        else:
            if res.status_code == 200:
                auth_info = res.json()
                create_json_data(sw_gog_auth, auth_info)
            else:
                print(
                    f"{tc.RED}Refresh token request error {__file__} at line "
                    f"{get_lineno()}: {tc.YELLOW2}{res.status_code}{tc.END}"
                )
                result.append(res)
    else:
        print(
            f"{tc.RED}Refresh token request error {__file__} at line "
            f"{get_lineno()}{tc.END}"
        )
        result.append("Authentication failed!")


def get_gog_access(code):
    """___get gog database access token___"""
    gcid = bytes.fromhex(GOG_CLIENT_ID).decode("utf-8")
    gcst = bytes.fromhex(GOG_CLIENT_SECRET).decode("utf-8")
    token_data = {
        "client_id": gcid,
        "client_secret": gcst,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": GOG_REDIRECT_URI,
    }
    try:
        res = requests.post(GOG_TOKEN_URL, data=token_data, timeout=10.0)
    except (Exception, HTTPError, URLError, ConnectionError, ReadTimeout) as e:
        print(
            f"{tc.RED}Connection error {__file__} at line "
            f"{get_lineno()}: {tc.YELLOW2}{e}{tc.END}"
        )
    else:
        if res.status_code == 200:
            auth_info = res.json()
            fetch_gog_data(auth_info)
        else:
            print(
                f"{tc.RED}Token request error {__file__} at line "
                f"{get_lineno()}: {tc.YELLOW2}{res.status_code}{tc.END}"
            )


def fetch_gog_data(auth_info=None):
    """___fetch gog games library data of authorized user___"""
    if not auth_info:
        auth_info = read_json_data(sw_gog_auth)

    start = perf_counter()
    access_token = auth_info.get("access_token")
    auth_info["time_in"] = f"{int(time())}"

    lang = sw_lang.split("_")[0]
    accept_lang = "-".join(sw_lang.split("_"))

    headers = {
        "Authorization": f"Bearer {access_token}",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, "
            "like Gecko) Chrome/30.0.1599.101 Safari/537.36"
        ),
        "Accept-Language": f"{accept_lang},{lang};q=0.8,en-US;q=0.6,en;q=0.4",
        "Accept": "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "keep-alive",
        "Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
    }
    download_content(GOG_USER_DATA_GAMES, sw_gog_id, headers=headers)
    download_content(GOG_USER, sw_gog_user, headers=headers)

    user_data_info = read_json_data(sw_gog_id)
    owned = user_data_info.get("owned") if user_data_info.get("owned") else []
    if owned:
        thread_workers = list()
        game_db = dict()
        game_dt = dict()
        for game_id in owned:
            t_dt = Thread(
                target=get_gog_details, args=(game_dt, game_id, headers)
            )
            t_db = Thread(
                target=get_gog_content, args=(game_db, game_id, headers, "gog")
            )
            t_dt.start()
            t_db.start()
            thread_workers.append(t_dt)
            thread_workers.append(t_db)

        for thread in thread_workers:
            thread.join()

        create_json_data(sw_gog_auth, auth_info)
        create_json_data(sw_gog_db, game_db)
        create_json_data(sw_gog_dt, game_dt)

        gog_data = read_json_data(sw_gog_db)

        t_args = list()
        for app_name, data in gog_data.items():
            title = data.get("title")
            url_cover = data.get("cover", {}).get("url_format")

            if url_cover and title:
                vertical = sw_gog_icons.joinpath(f"{title}_vertical_{app_name}.jpg")
                if not vertical.exists():
                    url_cover = (
                        url_cover.replace("{formatter}", "")
                        .replace("{ext}", "jpg")
                        .replace(" ", "%20")
                    )
                    t_args.append([url_cover, vertical])

        cpu = get_cpu_core_num()
        cpu = cpu if cpu > 2 else 4
        num_workers = min(30, (cpu - 2))

        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            _ = {executor.submit(download_with_convert, x[0], x[1]): x for x in t_args}

        end = perf_counter() - start
        print(f"Download gog content: {end}")


def get_gog_details(game_dt, game_id, headers):
    """___get gog library game details___"""

    dt = dict()
    try:
        dt = requests.get(
            f"{GOG_GAME_DT}/{game_id}.json",
            headers=headers,
            timeout=10.0
        ).json()
    except (HTTPError, URLError, ConnectionError, ReadTimeout, JSONDecodeError) as e:
        print(f"{tc.RED}Connection error: {e}{tc.END}")

    game_dt[game_id] = dt


def get_gog_content(game_db, game_id, headers, platform):
    """___get gog library content___"""

    db = dict()
    dtl = dict()
    steam_db = dict()
    try:
        db = requests.get(
            f"{GOG_GAMES_DB_PLATFORMS}/{platform}/external_releases/{game_id}",
            headers=headers,
            timeout=10.0
        ).json()
    except (HTTPError, URLError, ConnectionError, ReadTimeout, JSONDecodeError) as e:
        print(f"{tc.RED}Connection error: {e}{tc.END}")
        return

    game_db[game_id] = {}
    game = db.get("game")

    if game:
        game_db[game_id]["title"] = game.get("title", {}).get("*", "")
        game_db[game_id]["developers"] = [
            x.get("name") for x in game.get("developers", [])
        ]
        game_db[game_id]["publishers"] = [
            x.get("name") for x in game.get("publishers", [])
        ]
        game_db[game_id]["platform"] = [
            x.get("name") for x in db.get("supported_operating_systems", [])
        ]
        game_db[game_id]["release"] = game.get("first_release_date", "")
        game_db[game_id]["genres"] = [
            x.get("name", {}).get("*") for x in game.get("genres", [])
        ]
        game_db[game_id]["rating"] = game.get("aggregated_rating")
        game_db[game_id]["languages"] = [
            x.get("code") for x in db.get("available_languages", [])
        ]
        game_db[game_id]["description"] = game.get("summary", {}).get("*")
        game_db[game_id]["cover"] = game.get("vertical_cover", {})
        game_db[game_id]["logo"] = game.get("logo", {})
        game_db[game_id]["horizontal_artwork"] = game.get("horizontal_artwork", {})

        for release in game.get("releases"):
            if release.get("platform_id") == "steam":
                ext_id = release.get("external_id")
                try:
                    dtl = requests.get(
                        f"{url_app_dtls}{ext_id}", headers=headers, timeout=10.0
                    ).json()
                except (HTTPError, URLError, ConnectionError, ReadTimeout, JSONDecodeError) as e:
                    print(f"{tc.RED}Error at line {get_lineno()}: {e}{tc.END}")
                else:
                    if dtl:
                        steam_db = dtl.get(f"{ext_id}", {}).get("data", {})

                    if steam_db:
                        title = steam_db.get("name")
                        developers = steam_db.get("developers", [])
                        publishers = steam_db.get("publishers", [])
                        platform = steam_db.get("platforms", {})
                        languages = steam_db.get("supported_languages")
                        requirements = steam_db.get("pc_requirements", [])
                        desc = steam_db.get("short_description")
                        rating = steam_db.get("metacritic", {}).get("score")
                        genres = [
                            x.get("description") for x in steam_db.get("genres", [])
                        ]
                        release = steam_db.get("release_date", {}).get("date")

                        game_db[game_id]["ext_title"] = title
                        game_db[game_id]["ext_developers"] = developers
                        game_db[game_id]["ext_publishers"] = publishers
                        game_db[game_id]["ext_platform"] = platform
                        game_db[game_id]["ext_release"] = release
                        game_db[game_id]["ext_genres"] = genres
                        game_db[game_id]["ext_rating"] = rating
                        game_db[game_id]["ext_languages"] = languages
                        game_db[game_id]["ext_requirements"] = requirements
                        game_db[game_id]["ext_description"] = desc


def get_gog_game_info(idx, game, product):
    """___get info about game from gog store data.___"""
    game_name = None
    cover = None
    devels = None
    platform = None
    release = None
    version = None
    genres = None
    rating = None
    languages = None
    requirements = None
    desc = None
    info = {}
    size = []
    dl_dict = {}
    game_name = game.get("title")

    if game_name:
        if sw_gog_icons.joinpath(f"{game_name}_vertical_{idx}.jpg").exists():
            cover = str(sw_gog_icons.joinpath(f"{game_name}_vertical_{idx}.jpg"))

    ext_devel = game.get("ext_developers") if game.get("ext_developers") else None
    devels = game.get("developers") if game.get("developers") else ext_devel

    ext_release = game.get("ext_release") if game.get("ext_release") else None
    release = game.get("release").split("T")[0] if game.get("release") else ext_release

    ext_genres = game.get("ext_genres") if game.get("ext_genres") else None
    genres = game.get("genres") if game.get("genres") else ext_genres

    ext_rating = (
        str(round(game.get("ext_rating"), 1)) if game.get("ext_rating") else None
    )
    rating = str(round(game.get("rating"), 1)) if game.get("rating") else ext_rating

    ext_desc = game.get("description") if game.get("description") else None
    desc = game.get("ext_description") if game.get("ext_description") else ext_desc

    ext_langs = game.get("languages") if game.get("languages") else "English"
    languages = game.get("ext_languages") if game.get("ext_languages") else ext_langs

    html_except = [
        "</strong>",
        "<br>",
        "</br>",
        "<b>",
        "</b>",
        "<i>",
        "</i>",
        "<ul",
        "<ul>",
        "</ul>",
        "<li>",
        "</li>",
        'class="bb_ul"',
        "<",
        ">",
        "=",
        "/",
        "&",
    ]

    if desc:
        for x in html_except:
            desc = desc.replace(x, "")

        desc = desc.replace("\n", " ").replace('"', "")

    if languages:
        if isinstance(languages, list):
            languages = ", ".join(languages)

        for x in html_except:
            languages = languages.replace(x, "")

        lang_list = [x for x in languages.split("strong")]
        languages = " ".join(lang_list).capitalize()

    req = game.get("ext_requirements")
    if req and isinstance(req, dict):
        requirements = req.get("minimum")
        if requirements:
            for x in html_except:
                requirements = requirements.replace(x, "")
            requirements = requirements.split("strong")[1:]
            # format_req = requirements[0].split(':')[1]
            requirements = "\n".join(requirements)

    if product:
        dl = product.get("downloads")

        if isinstance(dl, list) and len(dl) > 0:
            dl_dict = dl[0][1]

            if isinstance(dl_dict, dict):
                platform = list(x.capitalize() for x in dl_dict.keys())

                if dl_dict.get("linux"):
                    linux_installer = dl_dict.get("linux")
                    if linux_installer:
                        for installer in linux_installer:
                            # name = installer['name']
                            version = installer["version"]
                            size.append(installer["size"])

                elif dl_dict.get("windows"):
                    win_installer = dl_dict.get("windows")
                    if win_installer:
                        for installer in win_installer:
                            # name = installer['name']
                            version = installer["version"]
                            size.append(installer["size"])
        if devels:
            info[msg.msg_dict.get("developer")] = ", ".join(devels).replace("&", "and")
        if platform:
            info[msg.msg_dict.get("platform")] = ", ".join(platform)
        if release:
            info[msg.msg_dict.get("release")] = release
        if version:
            info[msg.msg_dict.get("version")] = version
        if genres:
            info[msg.msg_dict.get("genres")] = ", ".join(genres).replace("&", "and")
        if rating:
            info[msg.msg_dict.get("rating")] = rating
        if languages:
            info[msg.msg_dict.get("language")] = languages
        if size:
            t_size = 0
            for s in size:
                if "MB" in s:
                    mb_size = float("".join([e for e in s if not e.isalpha()]))
                    kb_size = int(mb_size * 1048576)
                    t_size += kb_size
                elif "GB" in s:
                    gb_size = float("".join([e for e in s if not e.isalpha()]))
                    kb_size = int(gb_size * 1073741824)
                    t_size += kb_size

            info[msg.msg_dict.get("download_size")] = f"{round(t_size/1073741824, 2)} Gb"
        if desc:
            desc = " ".join(desc.replace("&", "and").splitlines())
        if requirements:
            info[msg.msg_dict["requirements"]] = ""

    return game_name, cover, info, desc, requirements, size, dl_dict


def run_innoextract(dest, data=[]):
    """___Extract exe installer___"""
    dest_dir = Path(dest).parent
    try:
        run(f'innoextract -e "{dest}" -d "{dest_dir}"', shell=True, check=True)
    except (IOError, OSError, CalledProcessError) as e:
        print(f"{tc.RED}Extraction error: {e}{tc.END}")
        shutil.rmtree(dest_dir)
        print(f'{tc.YELLOW2}Remove "{dest_dir}" after error...{tc.END}')

    for d in data:
        if Path(d).is_file():
            Path(d).unlink()
            print(f'{tc.YELLOW2}Remove "{Path(d).name}" after extraction...{tc.END}')


def run_binwalk(dest, data=[]):
    """___Extract sh native installer___"""
    dest_dir = Path(dest).parent
    try:
        run(f'binwalk -e "{dest}" -C "{dest_dir}"', shell=True, check=True)
    except (IOError, OSError, CalledProcessError) as e:
        print(f"{tc.RED}Extraction error: {e}{tc.END}")
        shutil.rmtree(dest_dir)
        print(f'{tc.YELLOW2}Remove "{dest_dir}" after error...{tc.END}')

    for d in data:
        if Path(d).is_file():
            Path(d).unlink()
            print(f'{tc.YELLOW2}Remove "{Path(d).name}" after extraction...{tc.END}')


def write_native_swd(app_name, app_path):
    """___Create shortcut for native executable.___"""
    swd = sw_shortcuts.joinpath(f"{app_name}.swd")
    try:
        with open(swd, mode="w", encoding="utf-8") as f:
            f.write(f"Exec={app_path}")
            f.close()
    except (IOError, OSError, PermissionError) as e:
        print(f"{tc.RED}Error at line {get_lineno()}: {e}{tc.END}")


def download_gog_game(
    name, size_data, url_data, total_size=[], dest_list=[], workers=[]):
    """___Request and download gog game installer.___"""
    refresh_gog_token()
    auth_info = read_json_data(sw_gog_auth)

    if auth_info:
        access_token = auth_info["access_token"]
        headers = {
            "Authorization": f"Bearer {access_token}",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, "
                "like Gecko) Chrome/30.0.1599.101 Safari/537.36"
            ),
            "Accept-Language": "ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4",
            "Accept": "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive",
            "Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
        }
        t_size = 0
        for url, size in zip(url_data, size_data):
            s_size = float("".join([e for e in size if e.isnumeric()]))
            if "MB" in size:
                s_size = int(s_size * 1048576)
            elif "GB" in size:
                s_size = int(s_size * 1073741824)
            try:
                res = urlopen(
                    Request(f"{GOG_API_URL}{url}", headers=headers),
                    timeout=10.0
                )
            except (HTTPError, URLError, ConnectionError, ReadTimeout) as e:
                print(
                    f"{tc.RED}Connection error {__file__} at line "
                    f"{get_lineno()}: {tc.YELLOW2}{e}{tc.END}"
                )
            else:
                if res:
                    res_url = res.geturl()

                    sw_gog_games.joinpath(f"{name}").mkdir(parents=True, exist_ok=True)
                    dest = sw_gog_games.joinpath(f"{name}", f"{Path(res_url).name}")

                    content_length = res.info().get(name="Content-Length")
                    if content_length:
                        s_size = int(content_length)

                    t_size += s_size
                    dest_list.append(dest)

                    t = Thread(target=download_content, args=(res_url, dest, headers))
                    t.start()
                    workers.append(t)

        total_size.append(t_size)


def get_gog_game_exe(dest_dir, idx):
    """___get gog game executable path from goggame.info___"""
    # gog_game_info = Path(f"{dest_dir}").joinpath(f"goggame-{idx}.info")
    gog_game_info = list(Path(f"{dest_dir}").rglob(f"goggame-{idx}.info", case_sensitive=False))
    dest_name = str(Path(dest_dir).name)
    data = dict()
    app_name = None
    exe = None
    exe_path = None
    cmd_line = None
    args = None

    for info in gog_game_info:
        if info.exists():
            with open(info, mode="r", encoding="utf-8") as f:
                text = f.read()
                data = json.loads(text)
            break

    play_tasks = data.get("playTasks")
    if play_tasks and isinstance(play_tasks, list):
        for task in play_tasks:
            if task.get("isPrimary"):
                args = task.get("arguments")
                path = task.get("path").replace("\\", "/")
                exe = Path(path).name if task.get("path") else None
                if exe:
                    exe_list = list(
                        Path(f"{dest_dir}").rglob(f"{exe}", case_sensitive=False)
                    )
                    if exe_list:
                        exe_path = exe_list[0] if exe_list[0].exists() else None
                        if exe_path:
                            app_name = str(exe_list[0].stem).replace(" ", "_")

        if args and str(exe).lower() == "dosbox.exe":
            conf_list = list(Path(f"{dest_dir}").rglob("*.conf", case_sensitive=False))
            args_list = list()

            if exe_path:
                exe_dir = Path(exe_path).parent

                for conf in conf_list:
                    conf_name = Path(conf).name
                    shutil.copy2(conf, exe_dir.joinpath(conf_name))
                    args_list.append(f'-conf "{conf_name}"')

                if args_list:
                    app_name = "".join([e for e in dest_name if e.isalnum()])
                    shutil.copy2(exe_path, exe_dir.joinpath(f"{app_name}.exe"))
                    exe_path = exe_dir.joinpath(f"{app_name}.exe")
                    cmd_line = " ".join(args_list) + " -noconsole"
        elif args:
            cmd_line = args.replace("\\", "/")

    return app_name, exe_path, cmd_line


def get_gog_game_sh(dest_dir):
    """___get gog native game executable path___"""
    exe_path = None
    app_name = "".join([e for e in str(dest_dir.name) if e.isalnum()])
    exe_list = list(Path(dest_dir).rglob("start.sh", case_sensitive=False))
    if exe_list:
        exe_path = exe_list[0] if exe_list[0].exists() else None
    return app_name, exe_path


def download_gog_covers(idx, title, data, swd=None):
    """___download gog game cover and artwork___"""
    t_workers = list()
    url_logo = data.get("logo", {}).get("url_format")

    if url_logo and title:
        horizontal = sw_gog_icons.joinpath(f"{title}_horizontal_{idx}.jpg")
        if swd:
            horizontal = sw_app_hicons.joinpath(f"{swd}_horizontal_{title}_{idx}.jpg")

        if not horizontal.exists():
            url_logo = (
                url_logo.replace("{formatter}", "")
                .replace("{ext}", "jpg")
                .replace(" ", "%20")
            )

            t = Thread(target=download_content, args=(url_logo, horizontal))
            t_workers.append(t)
            t.start()

    url_artwork = data.get("horizontal_artwork", {}).get("url_format")

    if url_artwork and title:
        artwork = sw_gog_icons.joinpath(f"{title}_artwork_{idx}.jpg")
        if swd:
            artwork = sw_app_artwork.joinpath(f"{swd}_artwork_{title}_{idx}.jpg")

        if not artwork.exists():
            url_artwork = (
                url_artwork.replace("{formatter}", "")
                .replace("{ext}", "jpg")
                .replace(" ", "%20")
            )

            t = Thread(target=download_content, args=(url_artwork, artwork))
            t_workers.append(t)
            t.start()

    for thread in t_workers:
        thread.join()


def download_epic_covers(app_name, title, data):
    """___download epic game artwork___"""
    url = data.get("horizontal")
    if url and title:
        url = url.replace(" ", "%20")
        horizontal = sw_epic_icons.joinpath(f"{title}_horizontal_{app_name}.jpg")
        artwork = sw_epic_icons.joinpath(f"{title}_artwork_{app_name}.jpg")
        if not artwork.exists():
            download_content(url, artwork)
            convert_image(artwork, horizontal, 640, 360)


def get_epic_auth_session():
    """___get epic games auth session___"""
    session = None
    auth_info = read_json_data(sw_epic_auth)
    if auth_info:
        session = requests.session()
        headers: dict[str, str | bytes] = {
            "User-Agent": (
                f"{EPIC_USER_AGENT} Mozilla/5.0 (Windows NT 6.1; WOW64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101 "
                "Safari/537.36"
            ),
            "Accept-Language": f"ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4",
            "Accept": "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive",
            "Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
        }
        session.headers = headers
        session.headers["Authorization"] = f"Bearer {auth_info['access_token']}"

    return session


def check_epic_auth():
    """___check epic games authorization success___"""
    count = 0
    data = {}
    page_html = sw_fm_cache.joinpath("page.html")
    while not page_html.exists():
        sleep(0.1)
        count += 1
        if count > 200:
            print(f"{tc.RED}Error: Failed to get authorizationCode{tc.END}")
            break
    else:
        with open(page_html, "r", encoding="utf-8") as f:
            html = f.read()
            f.close()

        page_html.unlink()

        matches = re.findall(r"{.*?}", html, re.DOTALL)
        for match in matches:
            m = match.replace("=\n", "")
            data = json.loads(m)

        if data.get("authorizationCode"):
            authorization_code = data.get("authorizationCode")
            print(f"{tc.GREEN}EPIC_AUTH_CODE:{tc.END}", authorization_code)
            get_epic_access(authorization_code)
        else:
            return


def refresh_epic_token(auth_info=None, timeout=10.0, result=[]):
    """___refresh epic database access token___"""
    if not auth_info:
        auth_info = read_json_data(sw_epic_auth)
        refresh_token = auth_info.get("refresh_token")
    else:
        refresh_token = auth_info.get("refresh_token")

    if refresh_token:
        ecid = bytes.fromhex(EPIC_CLIENT_ID).decode("utf-8")
        ecst = bytes.fromhex(EPIC_CLIENT_SECRET).decode("utf-8")
        auth = HTTPBasicAuth(ecid, ecst)
        data = {
            "client_id": ecid,
            "client_secret": ecst,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        try:
            res = requests.post(EPIC_OAUTH_URL, data=data, auth=auth, timeout=timeout)
        except (Exception, HTTPError, URLError, ConnectionError, ReadTimeout) as e:
            print(f"{tc.RED}Refresh token error: {e}{tc.END}")
            result.append(e)
        else:
            if res.status_code == 200:
                auth_info = res.json()
                create_json_data(sw_epic_auth, auth_info)
            else:
                print(f"{tc.RED}Refresh token error: {res.status_code}{tc.END}")
                result.append(res)
    else:
        print(f"{tc.RED}Refresh token error: auth_info not found{tc.END}")
        result.append("Authentication failed!")


def get_igdb_access():
    """___get twitch database access token___"""

    session = requests.session()
    auth_info = {}
    auth = HTTPBasicAuth(IGDB_CLIENT_ID, IGDB_CLIENT_SECRET)
    data = dict(
        client_id=IGDB_CLIENT_ID,
        client_secret=IGDB_CLIENT_SECRET,
        grant_type="client_credentials",
    )
    try:
        res = session.post(IGDB_OAUTH_URL, data=data, auth=auth, timeout=10.0)
    except (Exception, HTTPError, URLError, ConnectionError, ReadTimeout) as e:
        print(f"{tc.RED}{e}{tc.END}")
    else:
        if res.status_code == 200:
            auth_info = res.json()
        else:
            print(f"{tc.VIOLET2}Request error: {tc.RED}{res.text}{tc.END}")

    return session, auth_info


def get_igdb_game_info(game_name, session=None, auth_info=None):
    """______"""
    game_info = {}
    if not session:
        session, auth_info = get_igdb_access()

    if auth_info:
        session.headers["Client-ID"] = IGDB_CLIENT_ID
        session.headers["Authorization"] = f"Bearer {auth_info['access_token']}"
        try:
            res = session.get(
                IGDB_GAMES_URL,
                params=dict(fields=f'name,cover.*,artworks.*; search "{game_name}";'),
                timeout=10.0,
            )
        except (Exception, HTTPError, URLError, ConnectionError, ReadTimeout) as e:
            print(f"{tc.RED}Getting assets error: {e}{tc.END}")
            return {}
        else:
            if res.status_code == 200:
                game_info = res.json()
            else:
                print(f"{tc.VIOLET2}Request error: {tc.RED}{res.text}{tc.END}")

    return game_info


def get_epic_access(authorization_code):
    """___get epic database access token___"""

    session = requests.session()
    ecid = bytes.fromhex(EPIC_CLIENT_ID).decode("utf-8")
    ecst = bytes.fromhex(EPIC_CLIENT_SECRET).decode("utf-8")
    auth = HTTPBasicAuth(ecid, ecst)
    data = dict(
        grant_type="authorization_code",
        code=authorization_code,
        token_type="eg1",
    )
    try:
        res = session.post(EPIC_OAUTH_URL, data=data, auth=auth, timeout=10.0)
    except (Exception, HTTPError, URLError, ConnectionError, ReadTimeout) as e:
        print(f"{tc.RED}{e}{tc.END}")
    else:
        if res.status_code == 200:
            auth_info = res.json()
            fetch_epic_data(session, auth_info)
        else:
            print(f"{tc.VIOLET2}Request error: {tc.RED}{res.text}{tc.END}")


def fetch_epic_data(session=None, auth_info=None):
    """___fetch epic games library data of authorized user___"""

    if not session:
        session = requests.session()

    if not auth_info:
        auth_info = read_json_data(sw_epic_auth)

    start = perf_counter()
    lang = sw_lang.split("_")[0]
    accept_lang = "-".join(sw_lang.split("_"))
    headers: dict[str, str | bytes] = {
        "User-Agent": (
            f"{EPIC_USER_AGENT} Mozilla/5.0 (Windows NT 6.1; WOW64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101 "
            "Safari/537.36"
        ),
        "Accept-Language": f"{accept_lang},{lang};q=0.8,en-US;q=0.6,en;q=0.4",
        "Accept": "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "keep-alive",
        "Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
    }
    session.headers = headers
    session.headers["Authorization"] = f"Bearer {auth_info['access_token']}"
    asset_data = get_epic_assets(session)
    account_id = auth_info.get("account_id")
    if account_id:
        item_data = dict()
        thread_workers = list()

        for asset in asset_data:
            if isinstance(asset, dict):
                app_name = asset.get("appName")
                namespace = asset.get("namespace")
                catalog = asset.get("catalogItemId")
                version = asset.get("buildVersion")

                if app_name and namespace and catalog:
                    t = Thread(
                        target=get_epic_content,
                        args=(session, app_name, namespace, catalog, item_data, version),
                    )
                    t.start()
                    thread_workers.append(t)

        for thread in thread_workers:
            thread.join()

        create_json_data(sw_epic_auth, auth_info)
        create_json_data(sw_epic_assets, asset_data)
        create_json_data(sw_epic_items, item_data)

        epic_data = read_json_data(sw_epic_items)

        t_args = list()
        for app_name, data in epic_data.items():
            title = data.get("title")
            url = data.get("vertical")
            vertical = sw_epic_icons.joinpath(f"{title}_vertical_{app_name}.jpg")

            if url and title and not vertical.exists():
                t_args.append([url.replace(" ", "%20"), vertical])

        cpu = get_cpu_core_num()
        cpu = cpu if cpu > 2 else 4
        num_workers = min(30, (cpu - 2))

        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            _ = {executor.submit(download_with_convert, x[0], x[1]): x for x in t_args}

        end = perf_counter() - start
        print(f"Download epic content: {end}")


def get_epic_assets(session, platform="Windows", label="Live"):
    """___epic epic games library assets___"""
    assets = {}
    try:
        res = session.get(
            f"{EPIC_LAUNCHER_URL}/launcher/api/public/assets/{platform}",
            params=dict(label=label),
            timeout=10.0,
        )
    except (Exception, HTTPError, URLError, ConnectionError, ReadTimeout) as e:
        print(f"{tc.RED}Getting assets error: {e}{tc.END}")
    else:
        if res.status_code == 200:
            assets = res.json()

    return assets


def get_epic_content(session, app_name, namespace, catalog_id, item_data, version):
    """___download epic games library content___"""
    item_data[app_name] = {}
    params = dict(
        id=catalog_id,
        includeDLCDetails=True,
        includeMainGameDetails=True,
        country="US",
        locale="en",
    )
    try:
        res = session.get(
            f"{EPIC_CATALOG_URL}/{namespace}/bulk/items", params=params, timeout=10.0
        )
    except (Exception, HTTPError, URLError, ConnectionError, ReadTimeout) as e:
        print(f"{tc.RED}Connection error: {e}{tc.END}")
        return

    if res.status_code == 200:
        game = res.json()
        item = game.get(catalog_id, {})
        item_data[app_name]["namespace"] = namespace
        item_data[app_name]["catalog"] = catalog_id
        item_data[app_name]["version"] = version
        item_data[app_name]["date"] = item.get("creationDate", "")
        item_data[app_name]["offline"] = (
            item.get("customAttributes", {})
            .get("CanRunOffline", {})
            .get("value", False)
        )
        item_data[app_name]["ownership"] = (
            item.get("customAttributes", {})
            .get("OwnershipToken", {})
            .get("value", False)
        )
        item_data[app_name]["folder"] = item.get("customAttributes", {}).get(
            "FolderName"
        )
        item_data[app_name]["description"] = item.get("description", "")
        item_data[app_name]["developer"] = item.get("developer", "")
        item_data[app_name]["platform"] = item.get("releaseInfo", [{}])[0].get(
            "platform", []
        )

        if item:
            title = item.get("title")
            if title:
                languages, requirements, release, genres, short_desc = get_epic_info(
                    session, title
                )
                item_data[app_name]["title"] = title
                item_data[app_name]["release"] = release
                item_data[app_name]["genres"] = genres
                item_data[app_name]["languages"] = languages
                item_data[app_name]["requirements"] = requirements
                item_data[app_name]["short_description"] = short_desc

                key_images = item.get("keyImages")
                if key_images:
                    for image in key_images:
                        url = image.get("url")
                        image_type = image.get("type")
                        if url and image_type:
                            if image_type == "DieselGameBoxTall":
                                item_data[app_name]["vertical"] = url
                            elif image_type == "DieselGameBox":
                                item_data[app_name]["horizontal"] = url

    get_epic_ext_info(session, item_data, app_name)


def get_epic_ext_info(session, item_data, app_name):
    """___Get external info from games data base.___"""
    try:
        ext_res = session.get(f"{EPIC_EXTERNAL}/{app_name}", timeout=10.0)
    except (Exception, HTTPError, URLError, ConnectionError, ReadTimeout) as e:
        print(f"{tc.RED}Connection error: {e}{tc.END}")
        return

    if ext_res.status_code == 200:
        ext_data = ext_res.json()
        ext_game = ext_data.get("game")
        if ext_game:
            item_data[app_name]["ext_title"] = ext_game.get("title", {}).get("*", "")
            item_data[app_name]["ext_developers"] = [
                x.get("name") for x in ext_game.get("developers", [])
            ]
            item_data[app_name]["ext_publishers"] = [
                x.get("name") for x in ext_game.get("publishers", [])
            ]
            item_data[app_name]["ext_release"] = ext_game.get("first_release_date", "")
            item_data[app_name]["ext_description"] = ext_game.get("summary", {}).get(
                "*"
            )
            item_data[app_name]["ext_genres"] = [
                x.get("name", {}).get("*") for x in ext_game.get("genres", [])
            ]
            item_data[app_name]["ext_rating"] = ext_game.get("aggregated_rating")
            item_data[app_name]["ext_platform"] = [
                x.get("name") for x in ext_data.get("supported_operating_systems", [])
            ]
            item_data[app_name]["ext_languages"] = [
                x.get("code") for x in ext_data.get("available_languages", [])
            ]

            ext_releases = ext_game.get("releases")
            get_steam_ext_info(session, ext_releases, item_data, app_name)


def get_steam_ext_info(session, ext_releases, item_data, item_id):
    """___Get external info from steam data base.___"""
    for release in ext_releases:
        if release.get("platform_id") == "steam":
            ext_id = release.get("external_id")
            try:
                ext_res = session.get(f"{url_app_dtls}{ext_id}", timeout=10.0)
            except (Exception, HTTPError, URLError, ConnectionError, ReadTimeout) as e:
                print(f"{tc.RED}Connection error: {e}{tc.END}")
                return

            if ext_res.status_code == 200:
                dtl = ext_res.json()
                steam_db = dtl.get(f"{ext_id}", {}).get("data", {})
                if steam_db:
                    title = steam_db.get("name")
                    developers = steam_db.get("developers", [])
                    publishers = steam_db.get("publishers", [])
                    languages = steam_db.get("supported_languages")
                    requirements = steam_db.get("pc_requirements", [])
                    desc = steam_db.get("short_description")
                    rating = steam_db.get("metacritic", {}).get("score")
                    genres = [x.get("description") for x in steam_db.get("genres", [])]
                    release = steam_db.get("release_date", {}).get("date")
                    platform = steam_db.get("platforms")

                    item_data.get(item_id)["st_title"] = title
                    item_data.get(item_id)["st_developers"] = developers
                    item_data.get(item_id)["st_publishers"] = publishers
                    item_data.get(item_id)["st_release"] = release
                    item_data.get(item_id)["st_requirements"] = requirements
                    item_data.get(item_id)["st_description"] = desc
                    item_data.get(item_id)["st_genres"] = genres
                    item_data.get(item_id)["st_rating"] = rating
                    item_data.get(item_id)["st_platform"] = platform
                    item_data.get(item_id)["st_languages"] = languages


def get_epic_info(session, title):
    """___Get info from epic games data base.___"""
    title = title.lower().replace(" demo", "").replace("demo", "").replace("-", " ")
    parted = title.split(":")[0]
    re_title = re.sub(r"[^\w\s]", "", title).split(" ")
    re_parted = re.sub(r"[^\w\s]", "", parted).split(" ")
    format_title = "-".join([t for t in re_title if t != " " and t != ""]).rstrip("-")
    format_parted = "-".join([t for t in re_parted if t != " " and t != ""]).rstrip("-")
    languages = []
    requirements = []
    release = None
    genres = []
    desc = None
    status = False
    url0 = f"{EPIC_STORE_CONTENT_URL}/ru/content/products/{format_title}"
    url1 = f"{EPIC_STORE_CONTENT_URL}/ru/content/products/{format_parted}"

    try:
        res = requests.get(url0, headers=session.headers, timeout=10.0)
    except (HTTPError, URLError, ConnectionError, ReadTimeout) as e:
        print(f"{tc.RED}Connection error: {e}{tc.END}")
        return languages, requirements, release, genres, desc

    if res.status_code == 200:
        status = True
    else:
        try:
            res = requests.get(url1, headers=session.headers, timeout=10.0)
        except (HTTPError, URLError, ConnectionError, ReadTimeout) as e:
            print(f"{tc.RED}Connection error: {e}{tc.END}")
            return languages, requirements, release, genres, desc
        else:
            if res.status_code == 200:
                status = True
    if status:
        product = res.json()
        if product.get("pages", []):
            p0 = product.get("pages", [{}])[0].get("data", {})
            languages = p0.get("requirements", {}).get("languages", [])
            release = p0.get("meta", {}).get("releaseDate", "")
            genres = p0.get("meta", {}).get("tags", [])
            desc = p0.get("about", {}).get("shortDescription")
            if not desc or desc == "":
                desc = p0.get("about", {}).get("description")
                if not desc or desc == "":
                    if len(product.get("pages", [])) > 1:
                        p1 = product.get("pages")[1].get("data", {})
                        desc = p1.get("about", {}).get("shortDescription")
                        if not desc or desc == "":
                            desc = p1.get("about", {}).get("description")
                            print(title, format_title, format_parted, "None")

            systems = p0.get("requirements", {}).get("systems", [])
            for sys in systems:
                if sys.get("systemType") == "Windows":
                    requirements = sys.get("details", [])

    return languages, requirements, release, genres, desc


def get_epic_game_info(idx, db):
    """___get epic game info from data___"""
    game_name = db.get("title")
    namespace = db.get("namespace")
    catalog = db.get("catalog")
    cover = None
    info = {}
    devels = None
    platform = None
    release = None
    version = None
    genres = None
    rating = None
    languages = None
    requirements = None
    desc = None

    if game_name:
        if sw_epic_icons.joinpath(f"{game_name}_vertical_{idx}.jpg").exists():
            cover = str(sw_epic_icons.joinpath(f"{game_name}_vertical_{idx}.jpg"))

        st_devel = db.get("st_developer") if db.get("st_developer") else "--"
        ext_devel = db.get("developer") if db.get("developer") else st_devel
        developer = (
            ", ".join(db.get("ext_developers"))
            if db.get("ext_developers")
            else ext_devel
        )
        publisher = (
            ", ".join(db.get("ext_publishers")) if db.get("ext_publishers") else ""
        )

        st_plat = (
            ", ".join([x.capitalize() for x in db.get("st_platform")])
            if db.get("st_platform")
            else "--"
        )
        ext_plat = (
            ", ".join([x.capitalize() for x in db.get("platform")])
            if db.get("platform")
            else st_plat
        )
        platform = (
            ", ".join([x.capitalize() for x in db.get("ext_platform")])
            if db.get("ext_platform")
            else ext_plat
        )

        st_desc = db.get("st_description")
        sh_desc = db.get("short_description")
        ext_desc = db.get("ext_description")
        ext_desc = (
            " ".join(ext_desc.replace("&", "and").splitlines()) if ext_desc else ""
        )
        st_desc = (
            " ".join(st_desc.replace("&", "and").splitlines()) if st_desc else ext_desc
        )
        desc = (
            " ".join(sh_desc.replace("&", "and").splitlines()) if sh_desc else st_desc
        )

        ext_genres = ", ".join(db.get("ext_genres")) if db.get("ext_genres") else "--"
        st_genres = (
            ", ".join(db.get("st_genres")) if db.get("st_genres") else ext_genres
        )
        genres = [x.capitalize() for x in db.get("genres", [])]
        genres = ", ".join(genres) if genres else st_genres

        ext_release = db.get("release").split("T")[0] if db.get("release") else "--"
        st_release = (
            db.get("st_release").split("T")[0] if db.get("st_release") else ext_release
        )
        release = (
            db.get("ext_release").split("T")[0] if db.get("ext_release") else st_release
        )

        version = db.get("version") if db.get("version") else "--"
        st_rating = str(round(db.get("st_rating"), 1)) if db.get("st_rating") else "--"
        rating = (
            str(round(db.get("ext_rating"), 1)) if db.get("ext_rating") else st_rating
        )

        ext_langs = db.get("languages") if db.get("languages") else "English"
        languages = db.get("st_languages") if db.get("st_languages") else ext_langs

        html_except = [
            "</strong>",
            "<br>",
            "</br>",
            "<b>",
            "</b>",
            "<i>",
            "</i>",
            "<ul",
            "<ul>",
            "</ul>",
            "<li>",
            "</li>",
            'class="bb_ul"',
            "<",
            ">",
            "=",
            "/",
            "&",
        ]

        if languages:
            if isinstance(languages, list):
                languages = ", ".join(languages)

            for x in html_except:
                languages = languages.replace(x, "")

            lang_list = [x for x in languages.split("strong")]
            languages = " ".join(lang_list).capitalize()

        if developer != "" and publisher != "":
            devels = ", ".join(set([developer, publisher]))

        elif developer == "":
            devels = publisher

        elif publisher == "":
            devels = developer

        req = []
        if db.get("requirements"):
            for x in db.get("requirements", []):
                req.append(f"{x.get('title')}: {x.get('minimum')}")
                # req.append(f"{x.get('title')}: {x.get('recommended')}")
        else:
            minimum = None
            st_req = db.get("st_requirements")
            if req and isinstance(req, dict):
                minimum = st_req.get("minimum")
                if minimum:
                    for x in html_except:
                        minimum = minimum.replace(x, "")
                    minimum = "\n".join(minimum.split("strong"))
                req.append(minimum)

        requirements = "\n".join(req)

        if devels and devels != "--":
            info[msg.msg_dict.get("developer")] = devels.replace("&", "and")
        if platform and platform != "--":
            info[msg.msg_dict.get("platform")] = platform
        if release and release != "--":
            info[msg.msg_dict.get("release")] = release
        if version and version != "--":
            info[msg.msg_dict.get("version")] = version
        if genres and genres != "--":
            info[msg.msg_dict.get("genres")] = genres.replace("&", "and")
        if rating and rating != "--":
            info[msg.msg_dict.get("rating")] = rating
        if languages and languages != "--":
            info[msg.msg_dict.get("language")] = languages
        if requirements:
            info[msg.msg_dict["requirements"]] = ""

    return game_name, namespace, catalog, cover, info, desc, requirements


def get_epic_manifest(session, idx, namespace, catalog, man_dest, man_bak, url_list):
    """___get epic games product manifest data___"""

    if sw_fm_cache_epic_manifests.joinpath(f"{idx}.manifest").exists():
        exist_man = sw_fm_cache_epic_manifests.joinpath(f"{idx}.manifest")
        copy_man = sw_fm_cache_epic_manifests.joinpath(f"{idx}.bak.manifest")
        shutil.copy2(exist_man, copy_man)

        with open(copy_man, mode="rb") as f:
            bak_data = f.read()

        if bak_data[0:1] == b"{":
            print(f"{tc.YELLOW}Reading previous json Manifest...{tc.END}")
            read_data = JSONManifest.read_all(bak_data)
            man_bak.append(read_data)
        else:
            print(f"{tc.YELLOW}Reading previous byte Manifest...{tc.END}")
            read_data = Manifest.read_all(bak_data)
            man_bak.append(read_data)

    res_data = get_epic_manifest_info(session, idx, namespace, catalog)
    if res_data:
        man_data, dest_url = read_epic_manifest(session, idx, res_data)
        if man_data and dest_url:
            man_dest.append(man_data)
            url_list.append(dest_url)


def get_epic_manifest_info(session, idx, namespace, catalog):
    """___get manifest from epic games data base.___"""
    res_data = {}
    try:
        res = session.get(
            f"{EPIC_LAUNCHER_URL}/launcher/api/public/assets/v2/platform"
            f"/Windows/namespace/{namespace}/catalogItem/{catalog}/app"
            f"/{idx}/label/Live",
            timeout=10.0,
        )
    except (Exception, HTTPError, URLError, ConnectionError, ReadTimeout) as e:
        print(f"{tc.RED}Connection error at line {get_lineno()}: {e}{tc.END}")
    else:
        if res.status_code == 200:
            res_data = res.json()

    create_json_data(str(sw_fm_cache_epic.joinpath("manifests.json")), res_data)
    return res_data


def read_epic_manifest(session, idx, res_data):
    """___get info from epic manifest data.___"""
    params = None
    man_url = None
    man_data = None
    dest_url = None
    elements = res_data.get("elements")

    if elements:
        for data in elements:
            # version = data.get('buildVersion')
            mans = data.get("manifests")
            if mans:
                for m in mans:
                    qparams = m.get("queryParams", [])
                    for p in qparams:
                        if p.get("name") in ["f_token", "cf_token"]:
                            qvar = p.get("name")
                            qval = p.get("value")
                            if qvar and qvar:
                                man_url = m.get("uri")
                                params = f"{qvar}={qval}"

    if man_url and params:
        dest_url = str(man_url.rpartition("/")[0])
        try:
            res = session.get(f"{man_url}?{params}", timeout=10.0)
        except (Exception, HTTPError, URLError, ConnectionError, ReadTimeout) as e:
            print(f"{tc.RED}Connection error at line {get_lineno()}: {e}{tc.END}")
        else:
            if res.status_code == 200:
                man = str(sw_fm_cache_epic_manifests.joinpath(f"{idx}.manifest"))
                if res.content[0:1] == b"{":
                    print(f"{tc.YELLOW}Json Manifest found!{tc.END}")
                    man_data = JSONManifest.read_all(res.content)
                else:
                    print(f"{tc.YELLOW}Byte Manifest found!{tc.END}")
                    man_data = Manifest.read_all(res.content)
                try:
                    with open(man, mode="wb") as f:
                        f.write(res.content)
                except (OSError, IOError, PermissionError) as e:
                    print(f"Error: {e} writing {idx}.manifest failed")
            else:
                print(
                    f"{tc.RED}RequestError at line {get_lineno()}: {res.status_code}{tc.END}"
                )

    return man_data, dest_url


def get_epic_game_download_info(url, dest_dir, data, bak_data):
    """___get epic game download info___"""

    Path(dest_dir).mkdir(parents=True, exist_ok=True)
    cpu = get_cpu_core_num()
    cpu = cpu if cpu > 2 else 4
    num_workers = min(30, (cpu - 2))

    dl_manager = DLManager(
        dest_dir,
        url,
        cache_dir=f"{sw_tmp}",
        status_q=None,
        max_workers=num_workers,
        dl_timeout=20,
        resume_file=None,
        max_shared_memory=2048 * 1024 * 1024,
        bind_ip=None,
    )
    dl_info = dl_manager.run_analysis(
        manifest=data,
        old_manifest=bak_data,
        patch=True,
        resume=True,
        file_prefix_filter=None,
        file_exclude_filter=None,
        file_install_tag=None,
        processing_optimization=False,
    )
    print("Download info:", dl_info)
    return dl_manager, dl_info


def get_epic_entitlements(session, account_id, start=0):
    """___Get entitlements info from epic games data base.___"""
    ent_data = {}
    try:
        res = session.get(
            f"{EPIC_ENTITLEMENTS_URL}/entitlement/api/account/{account_id}/entitlements",
            params=dict(start=start, count=1000),
            timeout=10.0,
        )
    except (Exception, HTTPError, URLError, ConnectionError, ReadTimeout) as e:
        print(f"{tc.RED}Connection error: {e}{tc.END}")
    else:
        if res.status_code == 200:
            ent_data = res.json()

    create_json_data(sw_fm_cache_epic.joinpath("entitlements.json"), ent_data)
    return ent_data


def get_epic_game_access_token(session):
    """___Get game access token from epic games data base.___"""
    token_data = {}
    try:
        res = session.get(f"{EPIC_EXCHANGE_URL}", timeout=10.0)
    except (Exception, HTTPError, URLError, ConnectionError, ReadTimeout) as e:
        print(f"{tc.RED}Connection error: {e}{tc.END}")
    else:
        if res.status_code == 200:
            token_data = res.json()

    return token_data


def get_epic_ownership_token(session, account_id, namespace, catalog):
    """___Get ownership token info from epic games data base.___"""
    owner_data = {}
    try:
        res = session.post(
            f"{EPIC_ECOMMERCE_URL}/ecommerceintegration/api/public/"
            f"platforms/EPIC/identities/{account_id}/ownershipToken",
            data=dict(nsCatalogItemId=f"{namespace}:{catalog}"),
            timeout=10.0,
        )
    except (Exception, HTTPError, URLError, ConnectionError, ReadTimeout) as e:
        print(f"{tc.RED}Connection error: {e}{tc.END}")
    else:
        if res.status_code == 200:
            owner_data = res.content

    return owner_data


def set_gog_game_data(source, app_name, dest_dir, exe_path, exe_args, idx):
    """___copy gog game images to app icons directory___"""

    hash_name = get_hash_name(exe_path)
    dest_name = str(Path(dest_dir).name)
    exe_data.set_(exe_path, "name", dest_name)
    exe_data.set_(exe_path, "id", idx)
    exe_data.set_(exe_path, "path", exe_path)
    exe_data.set_(exe_path, "platform", "gog")

    gog_exe_data[idx] = {}
    gog_exe_data[idx]["app_name"] = f"{app_name}"
    gog_exe_data[idx]["name"] = f"{dest_name}"
    gog_exe_data[idx]["path"] = f"{exe_path}"
    gog_exe_data[idx]["args"] = f"{exe_args}"
    gog_exe_data[idx]["directory"] = f"{dest_dir}"
    gog_exe_data[idx]["installed"] = True

    icon_path = list(Path(dest_dir).rglob("icon.png", case_sensitive=False))
    app_name_isalnum = "".join(e for e in app_name if e.isalnum())
    icon_default = f"{app_name_isalnum}_{app_name_isalnum}_x256.png"
    icon_default_path = sw_app_default_icons.joinpath(icon_default)

    if icon_default_path.exists():
        exe_data.set_(exe_path, "default", icon_default)
        gog_exe_data[idx]["default"] = f"{icon_default}"

    elif icon_path and icon_path[0].exists():
        icon_path = icon_path[0]
        Thread(target=shutil.copy2, args=(icon_path, icon_default_path)).start()
        exe_data.set_(exe_path, "default", icon_default)
        gog_exe_data[idx]["default"] = f"{icon_default}"

    for icon in source.iterdir():
        if f"_vertical_{idx}" in str(icon.stem):
            vname = f"{hash_name}_vertical_{dest_name}_{idx}.jpg"
            vicon = sw_app_vicons.joinpath(vname)
            Thread(target=shutil.copy2, args=(icon, vicon)).start()
            exe_data.set_(exe_path, "vertical", vname)
            gog_exe_data[idx]["vertical"] = f"{vname}"

        if f"_horizontal_{idx}" in str(icon.stem):
            hname = f"{hash_name}_horizontal_{dest_name}_{idx}.jpg"
            hicon = sw_app_hicons.joinpath(hname)
            Thread(target=shutil.copy2, args=(icon, hicon)).start()
            exe_data.set_(exe_path, "horizontal", hname)
            gog_exe_data[idx]["horizontal"] = f"{hname}"

        if f"_artwork_{idx}" in str(icon.stem):
            artwork_name = f"{hash_name}_artwork_{dest_name}_{idx}.jpg"
            artwork = sw_app_artwork.joinpath(artwork_name)
            Thread(target=shutil.copy2, args=(icon, artwork)).start()
            exe_data.set_(exe_path, "artwork", artwork_name)
            gog_exe_data[idx]["artwork"] = f"{artwork_name}"

    write_json_data(sw_gog_exe_data_json, gog_exe_data)
    # write_json_data(sw_exe_data_json, exe_data)


def set_epic_game_data(app_name, dest_dir, exe_path, idx):
    """___copy epic game images to app icons directory___"""

    hash_name = get_hash_name(exe_path)
    dest_name = str(Path(dest_dir).name)
    exe_data.set_(exe_path, "name", dest_name)
    exe_data.set_(exe_path, "id", idx)
    exe_data.set_(exe_path, "path", f"{exe_path}")
    exe_data.set_(exe_path, "platform", "epic")

    epic_exe_data[idx] = {}
    epic_exe_data[idx]["app_name"] = f"{app_name}"
    epic_exe_data[idx]["name"] = f"{dest_name}"
    epic_exe_data[idx]["path"] = f"{exe_path}"
    epic_exe_data[idx]["args"] = ""
    epic_exe_data[idx]["directory"] = f"{dest_dir}"
    epic_exe_data[idx]["installed"] = True

    icon_path = list(Path(dest_dir).rglob("icon.png", case_sensitive=False))
    app_name_isalnum = "".join(e for e in app_name if e.isalnum())
    icon_default = f"{app_name_isalnum}_{app_name_isalnum}_x256.png"
    icon_default_path = sw_app_default_icons.joinpath(icon_default)

    if icon_default_path.exists():
        exe_data.set_(exe_path, "default", icon_default)
        epic_exe_data[idx]["default"] = f"{icon_default}"

    elif icon_path and icon_path[0].exists():
        icon_path = icon_path[0]
        Thread(target=shutil.copy2, args=(icon_path, icon_default_path)).start()
        exe_data.set_(exe_path, "default", icon_default)
        epic_exe_data[idx]["default"] = f"{icon_default}"

    for icon in sw_epic_icons.iterdir():
        if f"_vertical_{idx}" in str(icon.stem):
            vname = f"{hash_name}_vertical_{dest_name}_{idx}.jpg"
            vicon = sw_app_vicons.joinpath(vname)
            Thread(target=shutil.copy2, args=(icon, vicon)).start()
            exe_data.set_(exe_path, "vertical", vname)
            epic_exe_data[idx]["vertical"] = f"{vname}"

        if f"_horizontal_{idx}" in str(icon.stem):
            hname = f"{hash_name}_horizontal_{dest_name}_{idx}.jpg"
            hicon = sw_app_hicons.joinpath(hname)
            Thread(target=shutil.copy2, args=(icon, hicon)).start()
            exe_data.set_(exe_path, "horizontal", hname)
            epic_exe_data[idx]["horizontal"] = f"{hname}"

        if f"_artwork_{idx}" in str(icon.stem):
            artwork_name = f"{hash_name}_artwork_{dest_name}_{idx}.jpg"
            artwork = sw_app_artwork.joinpath(artwork_name)
            Thread(target=shutil.copy2, args=(icon, artwork)).start()
            exe_data.set_(exe_path, "artwork", artwork_name)
            epic_exe_data[idx]["artwork"] = f"{artwork_name}"

    write_json_data(sw_epic_exe_data_json, epic_exe_data)
    # write_json_data(sw_exe_data_json, exe_data)


def get_epic_exe_args(idx, exe_args, result=[]):
    """___get epic game executable launch arguments___"""

    refresh_epic_token(None, 3.0, result)
    if result:
        return

    auth_info = read_json_data(sw_epic_auth)
    epic_items = read_json_data(sw_epic_items)
    item_data = epic_items.get(idx, {})
    user_name = auth_info.get("displayName")
    account_id = auth_info.get("account_id")
    session = get_epic_auth_session()
    access_token = get_epic_game_access_token(session).get("code", "")

    if sw_lang.split("_"):
        language_code = sw_lang.split("_")[0]
    else:
        language_code = "en"

    namespace = item_data.get("namespace")
    catalog = item_data.get("catalog")
    ownership = item_data.get("ownership")
    exe_args.extend(
        [
            "-AUTH_LOGIN=unused",
            f"-AUTH_PASSWORD={access_token}",
            "-AUTH_TYPE=exchangecode",
            f"-epicapp={idx}",
            "-epicenv=Prod",
        ]
    )
    if ownership:
        owner_data = get_epic_ownership_token(session, account_id, namespace, catalog)
        if owner_data:
            owt = sw_fm_cache_epic.joinpath(f"{namespace}{catalog}.ovt")
            with open(owt, mode="wb") as f:
                f.write(bytes(owner_data))
            exe_args.append(f"-epicovt={owt}")

    exe_args.extend(
        [
            "-EpicPortal",
            f"-epicusername={user_name}",
            f"-epicuserid={account_id}",
            f"-epiclocale={language_code}",
            f"-epicsandboxid={namespace}",
        ]
    )
    exe_args = " ".join(exe_args)
    environ["SW_EXEC_ARGS"] = f"{exe_args}"
    print(f"{tc.RED}SW_EXEC_ARGS: {tc.GREEN}{exe_args}{tc.END}")


def get_dir_size(size, data):
    """___get size of files in current directory___"""
    s_list = list()
    for root, _, files in walk(data):
        for f in files:
            try:
                size += os.stat(join(root, f)).st_size
            except (Exception,):
                pass
            else:
                s_list.append(size)
    return s_list


def check_dir_size(dest_dir, total_size):
    """___check directory size___"""
    dir_size = 0
    size_ok = True
    if Path(dest_dir).exists():
        try:
            dir_size = get_dir_size(0, dest_dir)[-1]
        except IndexError:
            pass
        if int(dir_size) < int(total_size):
            size_ok = False
        print("Current size:", dir_size, "Total size:", total_size)
    return size_ok


def check_diff_files(dest_dir, data):
    """___check differences between file lists___"""
    exist_files = []
    for _, _, f in Path(dest_dir).walk():
        for x in f:
            exist_files.append(x)

    if isinstance(data, Manifest):
        man_list = data.file_manifest_list
        if man_list:
            data_files = [Path(e.filename).name for e in man_list.elements]
        else:
            data_files = []
    else:
        data_files = data

    diff = set(data_files) - set(exist_files)
    return diff


def set_environ(key, value):
    """___set environment variable___"""
    environ[key] = f"{value}"
    print(f"{tc.RED}{key}: {tc.GREEN}{value}{tc.END}")


def check_app_icons(event=None):
    """___check application icons___"""
    t_args = list()
    icons = [x.name for x in sw_app_vicons.iterdir()]

    for swd in Path(sw_shortcuts).iterdir():
        if swd.is_file():
            swd_read = swd.read_text().splitlines()
            arg = [x.split("=")[1].strip('"') for x in swd_read if "Exec=" in x]
            if arg:
                app_path = [x for x in str(arg[0]).split('"')]
                app_name = Path(app_path[0]).stem
                hash_name = get_hash_name(app_path[0])
                app_icon_names = " ".join(icons)
                re_app = re.findall(rf"{hash_name}_.*?jpg", app_icon_names)
                if not re_app:
                    t_args.append([app_name, f'"{app_path[0]}"'])

    cpu = get_cpu_core_num()
    cpu = cpu if cpu > 2 else 4
    num_workers = min(30, (cpu - 2))

    with ThreadPool(num_workers) as p:
        res = p.imap_unordered(exe_metadata, t_args)
        for r in res:
            print(r)

    if event:
        event.set()


if __name__ == "__main__":
    pass
