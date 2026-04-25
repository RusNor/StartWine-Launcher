#!/usr/bin/python3
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

# from types import CoroutineType
# import sys
# import random
# from threading import Thread, Event
from time import time, sleep
from os import environ, walk, chdir
from grp import getgrgid as get_gid
from pwd import getpwuid as get_uid
from sys import argv
from pathlib import Path
from subprocess import Popen, run
import multiprocessing as mp
import asyncio
from functools import partial
import itertools
import fcntl
import psutil
from typing import ClassVar, Iterable

from textual.app import App, ComposeResult
from textual.types import NoSelection
from textual.command import Hit, Hits, Provider    #, DiscoveryHit
from textual.suggester import SuggestFromList
from textual.renderables.gradient import LinearGradient
from textual.screen import Screen, ModalScreen
from textual.widget import Widget
from textual.binding import Binding
from textual.events import Key
from textual.reactive import var
from textual.containers import Container, Horizontal, Vertical, VerticalScroll, Grid
from textual.widgets import (
    ListView, OptionList, SelectionList, DataTable, Button, Label, Input, Select,
    DirectoryTree, TabbedContent, Header, TabPane, Footer, Static, Pretty,
    ListItem, LoadingIndicator
)
from textual.widgets._tree import TOGGLE_STYLE
# Tree, TreeNode
from textual.widgets.selection_list import Selection
from textual.widgets.option_list import Option

from rich.syntax import Syntax
from rich.traceback import Traceback
from rich.style import Style
from rich.text import Text
from rich.console import RenderableType

from sw_data import *
from sw_data import Msg as msg
from sw_data import TermColors as tc
from sw_func import *
try:
    from sw_input import run_zero_device_redirection
    input_active = True
except (Exception, ImportError) as e:
    print(e)
    input_active = False
    run_zero_device_redirection = None


set_backend_environ()

import gettext
_ = gettext.gettext

try:
    from textual.theme import Theme
except ModuleNotFoundError:
    custom_theme = None
else:
    custom_theme = Theme(
        name="darkside",
        primary="#aa4500",
        secondary="#009999",
        boost="#40999920",
        foreground="#808080",
        background="#121418",
        success="#009999",
        accent="#009999",
        warning="#aa4500",
        error="#aa4500",
        surface="#181A21",
        panel="#0e0f12",
        dark=True,
    )


DARK_COLORS = """
$foreground: ansi_bright_black;
$primary: orangered;
$secondary: ansi_bright_cyan;
$background: #121418;
$surface: #181A21;
$panel: #0E0F12;
$warning: orangered;
$boost: $secondary 10%;
$error: orangered;
$success: ansi_bright_cyan;
$accent: ansi_bright_cyan;
$text_color: ansi_white;
$text_accent: ansi_bright_white;
"""

LIGHT_COLORS = """
$foreground: ansi_bright_black;
$primary: orangered;
$secondary: ansi_cyan;
$background: ansi_white;
$surface: ansi_white;
$panel: ansi_white;
$warning: orangered;
$boost: $secondary 10%;
$error: orangered;
$success: ansi_cyan;
$accent: ansi_cyan;
$text_color: ansi_black;
$text_accent: ansi_black;
"""

CSS_THEME = """
/*
BORDERS:
'ascii', 'blank', 'dashed', 'double', 'heavy', 'hidden', 'hkey', 'inner',
'none', 'outer', 'panel', 'round', 'solid', 'tall', 'thick', 'vkey', or 'wide'
*/

$text_color: $text 70%;
$text_accent: $text;

/*
$text-primary: $text_color;
$text-secondary: $text_color 70%;
$text-accent: $accent;
$text-warning: $warning;
$text-error: $error;
$text-success: $success;
*/

$block-cursor-foreground: $text;
$block-cursor-background: $primary;
/*$block-cursor-text-style: bold;*/
$block-cursor-blurred-foreground: $text;
$block-cursor-blurred-background: $primary 70%;
/*$block-cursor-blurred-text-style: none;*/
$block-hover-background: $boost;

$input-cursor-background: $foreground;
$input-cursor-foreground: $text;
/*$input-cursor-text-style: none;*/
/*$input-selection-background: $text 10%;*/

$footer-foreground: $foreground;
$footer-background: $panel;
$footer-key-foreground: $accent;
$footer-key-background: transparent;
$footer-description-foreground: $text;
$footer-description-background: transparent;
$footer-item-background: transparent;

$border: round $foreground;
$border_accent: round $accent;
$border_error: round $error;

$primary-background: $primary 50%;
$secondary-background: $secondary 50%;

$primary-lighten-1: $primary;
$primary-lighten-2: $primary;
$primary-lighten-3: $primary;
$primary-darken-1: $primary 75%;
$primary-darken-2: $primary 50%;
$primary-darken-3: $primary 25%;

$secondary-lighten-1: $secondary;
$secondary-lighten-2: $secondary;
$secondary-lighten-3: $secondary;
$secondary-darken-1: $secondary 75%;
$secondary-darken-2: $secondary 50%;
$secondary-darken-3: $secondary 25%;

$primary-background-lighten-1: $primary-background;
$primary-background-lighten-2: $primary-background;
$primary-background-lighten-3: $primary-background;
$primary-background-darken-1: $primary-background 75%;
$primary-background-darken-2: $primary-background 50%;
$primary-background-darken-3: $primary-background 25%;

$secondary-background-lighten-1: $secondary-background;
$secondary-background-lighten-2: $secondary-background;
$secondary-background-lighten-3: $secondary-background;
$secondary-background-darken-1: $secondary-background 75%;
$secondary-background-darken-2: $secondary-background 50%;
$secondary-background-darken-3: $secondary-background 25%;

$background-lighten-1: $background;
$background-lighten-2: $background;
$background-lighten-3: $background;
$background-darken-1: $background 75%;
$background-darken-2: $background 50%;
$background-darken-3: $background 25%;

$surface-lighten-1: $surface;
$surface-lighten-2: $surface;
$surface-lighten-3: $surface;
$surface-darken-1: $surface 75%;
$surface-darken-2: $surface 50%;
$surface-darken-3: $surface 25%;

$panel-lighten-1: $panel;
$panel-lighten-2: $panel;
$panel-lighten-3: $panel;
$panel-darken-1: $panel 75%;
$panel-darken-2: $panel 50%;
$panel-darken-3: $panel 25%;

$warning-lighten-1: $warning;
$warning-lighten-2: $warning;
$warning-lighten-3: $warning;
$warning-darken-1: $warning 75%;
$warning-darken-2: $warning 50%;
$warning-darken-3: $warning 25%;

$error-lighten-1: $error;
$error-lighten-2: $error;
$error-lighten-3: $error;
$error-darken-1: $error 75%;
$error-darken-2: $error 50%;
$error-darken-3: $error 25%;

$success-lighten-1: $success;
$success-lighten-2: $success;
$success-lighten-3: $success;
$success-darken-1: $success 75%;
$success-darken-2: $success 50%;
$success-darken-3: $success 25%;

$accent-lighten-1: $success;
$accent-lighten-2: $success;
$accent-lighten-3: $success;
$accent-darken-1: $success 75%;
$accent-darken-2: $success 50%;
$accent-darken-3: $success 25%;

/*
$primary-muted: $primary 70%;
$secondary-muted: $secondary 70%;
$accent-muted: $accent 70%;
$warning-muted: $warning 70%;
$error-muted: $error 70%;
$success-muted: $success 70%;
*/

Widget {
    color: $text_color;
}
.title_accent, Tab {
    color: $text_accent;
}
Screen {
    grid-size: 1 1;
    grid-columns: 1fr;
    grid-rows: 1fr;
    grid-gutter: 1;
}
Header, Footer {
    height: 1;
    background: $panel;
}
CommandInput, CommandInput:focus, CommandInput:blur {
    border: blank;
    width: 98%;
    background: transparent;
    padding-left: 0;
}
CommandPalette:inline {
    min-height: 20;
}
CommandPalette {
    align-horizontal: center;
}
CommandPalette OptionList > .option-list--option-highlighted,
CommandPalette OptionList > .option-list--option-hover {
    background: $accent-muted;
}
CommandPalette > .command-palette--help-text {
    text-style: dim not bold;
}
CommandPalette:dark > .command-palette--highlight {
    text-style: bold;
    color: $warning;
}
CommandPalette > .command-palette--highlight {
    text-style: bold;
    color: $warning-darken-2;
}
CommandPalette > Vertical {
    margin-top: 1;
    height: 100%;
    visibility: hidden;
    background: transparent;
}
CommandPalette #--input {
    height: auto;
    visibility: visible;
    border: $border;
}
CommandPalette #--input.--list-visible {
    border-bottom: none;
}
CommandPalette #--input Label {
    margin-top: 1;
    margin-left: 1;
}
CommandPalette #--input Button {
    min-width: 7;
    margin-right: 1;
}
CommandPalette #--results {
    overlay: screen;
    height: auto;
}
CommandPalette LoadingIndicator {
    height: auto;
    visibility: hidden;
    border-bottom: $border;
}
CommandPalette LoadingIndicator.--visible {
    visibility: visible;
}
SwTerminalShell.-show-sidebar #sidebar {
    display: block;
    max-width: 100%;
}
SwTerminalShell.-show-partitions #partition_view {
    display: block;
    max-height: 100%;
}
BSOD {
    content-align-vertical: middle;
    content-align-horizontal: center;
    background: blue;
    color: white;
}
BSOD Static.title {
    margin: 10 0 0 0;
}
Progress {
    width: 100%;
    height: 100%;
}
LoadingIndicator {
    height: 3;
    align: center middle;
    background: $panel;
}
Splash Static {
    width: 40;
}
Splash,
Progress #center_box,
DialogQuestion,
DialogQuit,
DialogInfo,
DialogEntry,
DialogData,
DialogOptions {
    align: center middle;
}
ButtonBox Label,
SelectBox Label,
InputBox Label,
LabelBox Label {
    text-style: bold;
}
ButtonBox>#horizontal_box,
SelectBox>#horizontal_box,
InputBox>#horizontal_box,
LabelBox>#horizontal_box {
    width: auto;
    height: auto;
    border: $border;
}
ButtonBox Static,
SelectBox Static,
InputBox Static,
LabelBox Static {
    margin: 0 0 0 1;
}
Button {
    width: 100%;
    height: 3;
    border: $border;
    color: $text_accent;
    background: transparent;
}
Button:hover {
  color: $accent !important;
  border: $border_accent;
}
Button:focus {
  color: $accent !important;
  border: $border_accent;
}
Input {
    background: transparent;
    padding: 0 3;
    border: $border;
    width: 100%;
    height: 3;
}
Input>.input--selection {
    text-style: reverse;
}
Input:focus {
    border: $border_accent;
}
Input>.input--cursor {
    background: $surface;
    text-style: reverse;
}
Input>.input--placeholder, Input>.input--suggestion {
    color: $text-disabled;
}
Input.-invalid {
    border: $border_error;
}
Input.-invalid:focus {
    border: $border_error;
}
Select {
    height: auto;
    & > SelectCurrent {
        width: 100%;
        height: 3;
        border: $border;
        background: transparent;
    }
    & > SelectOverlay {
        width: 1fr;
        display: none;
        height: auto;
        max-height: 12;
        overlay: screen;
        constrain: inflect;
        border: $border;
    }
    &:focus > SelectCurrent {
        border: $border_accent;
    }
    .up-arrow {
        display: none;
    }
    &.-expanded .down-arrow {
        display: none;
    }
    &.-expanded .up-arrow {
        display: block;
    }
    &.-expanded > SelectOverlay {
        display: block;
    }
    &.-expanded > SelectCurrent {
        border: $border_accent;
    }
}
SelectionList {
    background: $background;
    border: $border;
}
SelectionList:focus {
    border: $border_accent;
}
ListItem {
    height: 3;
    padding: 0 -1;
}
#settings_view ListItem {
    height: 5;
    padding: 0 -1;
}
#settings_view ListItem InputBox,
#settings_view ListItem SelectBox {
    height: 5;
    background: $surface;
}
ListItem ButtonBox>#horizontal_box,
ListItem SelectBox>#horizontal_box,
ListItem InputBox>#horizontal_box,
ListItem LabelBox>#horizontal_box {
    width: auto;
    height: auto;
    border: none;
}
ListItem > Widget {
    height: 3;
    margin: 0 1;
    border: $border;
    content-align: left middle;
}
ListItem > Widget:hover {
    background: transparent;
}
ListItem > Widget :focus {
    color: $accent !important;
    border: $border_accent;
}
ListView:focus > ListItem.--highlight > Widget {
    color: $accent !important;
    border: $border_accent;
}
ListView > ListItem.--highlight {
    background: transparent;
}
ListView:focus > ListItem.--highlight {
    color: $accent !important;
}
#sidebar {
    display: none;
    opacity: 0.0;
    width: 34;
    min-width: 34;
    margin: 1 0;
    height: 100%;
    border: $border;
    overflow: auto;
    content-align: center middle;
    dock: right;
    text-align: left;
}
#left_tree_view {
    width: 100%;
    background: $background;
    border: $border;
}
#left_tree_view > .directory-tree--folder {
    text-style: bold;
}
#left_tree_view > .directory-tree--extension {
    text-style: italic;
}
#left_tree_view > .directory-tree--hidden {
    color: $text 50%;
}
#left_tree_view > .directory-tree--exec {
    color: $text-accent;
    background: $accent-muted;
    text-style: bold;
}
#commandline {
    dock: bottom;
}
#partition_view {
    display: none;
    border: $border;
}
#left_tree_view,
#partition_view,
#sidebar,
ListView,
OptionList,
SelectionList,
VerticalScroll,
HorizontalScroll {
/*    scrollbar-gutter: stable;*/
    scrollbar_color: $primary;
    scrollbar_color_hover: $accent;
    scrollbar_color_active: $accent;
    scrollbar_background: $background;
    scrollbar-corner-color: $background;
    scrollbar_background_hover: $background;
    scrollbar_background_active: $background;
}
#about_grid {
    grid-size: 2;
    grid-rows: 10;
    grid-columns: 1fr;
    grid-gutter: 0;
    width: 100%;
    height: auto;
    align: center middle;
}
#settings_grid {
    grid-size: 1;
    grid-rows: 5;
    grid-columns: 1fr;
    grid-gutter: 0;
    width: 100%;
    height: auto;
    align: center middle;
}
#launchers_grid {
    grid-size: 1;
    grid-rows: 10;
    grid-columns: 1fr;
    grid-gutter: 0;
    width: 100%;
    height: auto;
    align: center middle;
}
#wine_grid {
    grid-size: 1;
    grid-rows: 8;
    grid-columns: 1fr;
    grid-gutter: 0;
    width: 100%;
    height: auto;
    align: center middle;
}
#dialog {
    grid-size: 2;
    padding: 0 1;
    width: 60;
    max-height: 24;
    height: 16;
    border: $border;
}
#dialog {
    color: $text_color;
    background: $background;
}
#dialog_action {
    width: 60;
    height: 22;
    border: $border;
    align: center middle;
    content-align: center middle;
}
#dialog_action {
    color: $text_color;
    background: $background;
}
#question {
    column-span: 2;
    height: 1fr;
    width: 1fr;
    content-align: center middle;
}
#error_message,
#any-key {
    content-align-horizontal: center;
}
.title {
    width: 1fr;
    content-align-horizontal: center;
    text-style: bold reverse;
}
#progress {
    height: 1;
    margin: 2 2 2 2;
    content-align: center middle;
}
#code-view {
    overflow: auto scroll;
    min-width: 100%;
    min-height: 100%;
}
#code {
    min-width: 100%;
    min-height: 100%;
}
#quit {
    height: 3;
    border: $border_error 60%;
}
#quit:hover {
    color: $error !important;
    border: $border_error;
}
"""

ERROR_TEXT = """
An error has occurred. To continue:

Press Enter to return to Windows, or

Press CTRL+ALT+DEL to restart your computer. If you do this,
you will lose any unsaved information in all open applications.

Error: 0E : 016F : BFF9B3D4
"""

exe_mime_dict = {
    'application/x-ms-dos-executable': '.exe',
    'application/x-ms-shortcut': '.lnk',
    'application/x-bat': '.bat',
    'application/x-msi': '.msi',
    'application/x-msdownload': '.exe',
    'application/vnd.microsoft.portable-executable': '.exe',
    'application/x-msdos-program': '.exe',
}

COLORS = [
    "#0080ff",
    "#0099ff",
    "#00bbff",
    "#00ffff",
    "#00ffbb",
    "#00ff99",
    "#00ff80",
]
STOPS = [(i / (len(COLORS) - 1), color) for i, color in enumerate(COLORS)]

KEY_TABLE = {
    'й': 'q', 'ц': 'w', 'у': 'e', 'к': 'r', 'е': 't', 'н': 'y', 'г': 'u',
    'ш': 'i', 'щ': 'o', 'з': 'p', 'х': '[', 'ъ': ']', 'ф': 'a', 'ы': 's',
    'в': 'd', 'а': 'f', 'п': 'g', 'р': 'h', 'о': 'j', 'л': 'k', 'д': 'l',
    'ж': ';', 'э': "'", 'я': 'z', 'ч': 'x', 'с': 'c', 'м': 'v', 'и': 'b',
    'т': 'n', 'ь': 'm', 'б': ',', 'ю': '.', '.': '/',
    'Й': 'Q', 'Ц': 'W', 'У': 'E', 'К': 'R', 'Е': 'T', 'Н': 'Y', 'Г': 'U',
    'Ш': 'I', 'Щ': 'O', 'З': 'P', 'Х': '[', 'Ъ': ']', 'Ф': 'A', 'Ы': 'S',
    'В': 'D', 'А': 'F', 'П': 'G', 'Р': 'H', 'О': 'J', 'Л': 'K', 'Д': 'L',
    'Ж': ';', 'Э': "'", 'Я': 'Z', 'Ч': 'X', 'С': 'C', 'М': 'V', 'И': 'B',
    'Т': 'N', 'Ь': 'M', 'Б': ',', 'Ю': '.', '.': '/',
}
KEY_T = str.maketrans(KEY_TABLE)

def _t(key: str) -> str:
    try:
        k = key.translate(KEY_T)
    except (KeyError, LookupError):
        return ''
    else:
        return k

def update_exe_data(item):
    """Update executable items data."""
    check_exe_data(sw_exe_data_json, sw_shortcuts, sw_app_icons)
    global exe_data
    exe_data = ExeData(read_json_data(sw_exe_data_json))
    print(f'{tc.GREEN}Update exe data {item}... Done{tc.END}')


def try_get_exe_logo(event=None):
    """Try to get image for current application."""
    app_path = get_app_path()
    app_name = get_out()
    if app_name != 'StartWine' and not check_exe_logo(app_name):
        p = mp.Process(target=get_exe_metadata, args=(app_name, app_path, event))
        process_workers.append(p)
        p.start()
        data = {'func': update_exe_data, 'args': (app_name,)}
        Thread(target=process_event_wait, args=(event, data)).start()


def on_cs_wine(app_name, app_path, func_wine):
    """Create shortcut and update exe data."""
    exe_data.set_(app_path, 'path', app_path)
    if not check_exe_logo(app_name):
        mp_event = mp.Event()
        p = mp.Process(target=get_exe_metadata, args=(app_name, app_path, mp_event))
        data = {'func': update_exe_data, 'args': (app_name,)}
        Thread(target=process_event_wait, args=(mp_event, data)).start()
        process_workers.append(p)
        p.start()

    cs_wine(func_wine, app_name, app_path)
    #t = Thread(target=cs_wine, args=(func_wine, app_name, app_path))
    #t.start()


def on_app_conf_default():
    """Reset application configuration to default."""
    app_name = get_out()
    app_conf = sw_app_config.joinpath(app_name)
    launcher_conf = sw_app_config.joinpath('.default', app_name)

    if not launcher_conf.exists():
        try:
            app_conf.write_text(sw_default_config.read_text())
        except IOError:
            pass
    else:
        try:
            app_conf.write_text(launcher_conf.read_text())
        except IOError:
            pass


def check_app_conf() -> bool:
    """Checking application configuration."""
    app_name = get_out()
    app_conf = sw_app_config.joinpath(app_name)
    app_dict = app_info(app_conf)
    for x in (lp_title + switch_labels):
        try:
            app_dict[f'export SW_USE_{x}']
        except KeyError:
            return False
    return True


def on_stop():
    """Terminate all wine process."""
    winedevices = (
        [
            p.info['pid'] for p in psutil.process_iter(['pid', 'name'])
            if 'winedevice' in p.info['name']
        ]
    )
    for proc in winedevices:
        psutil.Process(proc).kill()

    Popen(f"{sw_start} --kill", shell=True)


def get_wineloader_list(wineloader_list):
    """Get wine loader list."""
    for r, _, f in walk(sw_wine):
        for w in f:
            if w == 'wine' and '/bin/wine' in f'{r}/{w}':
                p = Path(r).joinpath(w)
                wineloader_list.append(f'{p}')
                break
    else:
        for w in wine_list:
            wine_dir = latest_wine_dict.get(w)
            if wine_dir:
                f_wine = sw_wine.joinpath(f'{wine_dir}', 'files', 'bin', 'wine')
                try:
                    wineloader_list.remove(f'{f_wine}')
                except (Exception,):
                    pass

                b_wine = sw_wine.joinpath(f'{wine_dir}', 'bin', 'wine')
                try:
                    wineloader_list.remove(f'{b_wine}')
                except (Exception,):
                    pass


def get_wineloader_dict(wineloader_list, wineloader_dict):
    """Get wine loader dictionary."""
    for w in wine_list:
        wine_dir = latest_wine_dict[w]
        if wine_dir is not None:
            wineloader_dict[wine_dir] = str(wine_dir)

    if len(wineloader_list) > 0:
        for wine in wineloader_list:
            w = str(Path(wine).parent.parent).replace('/files', '').replace('/dist', '')
            key = str(Path(w).name)
            wineloader_dict[key] = str(key)


def change_wine_activate(wine_name):
    """Write changed wine to app configuration."""
    app_name = get_out()
    app_conf = sw_app_config.joinpath(app_name)
    app_conf_dict = app_conf_info(app_conf, ['SW_USE_WINE'])

    try:
        changed_wine = wine_list_dict[wine_name]
    except (Exception,):
        changed_wine = wine_name

    app_conf.write_text(
        app_conf.read_text().replace(
            app_conf_dict['SW_USE_WINE'],
            f'export SW_USE_WINE="{changed_wine}"'
        )
    )


def change_pfx_activate(pfx_name):
    """Write changed prefix to app configuration."""
    app_name = get_out()
    app_conf = sw_app_config.joinpath(app_name)
    app_conf_dict = app_conf_info(app_conf, ['SW_USE_PFX'])

    if pfx_name == prefix_labels[0]:
        changed_pfx = f'export SW_USE_PFX="pfx_default"'
    else:
        changed_pfx = f'export SW_USE_PFX="pfx_{app_name}"'

    app_conf.write_text(
        app_conf.read_text().replace(
            app_conf_dict['SW_USE_PFX'],
            changed_pfx
        )
    )


def get_directory_size(size, data: Path|str) -> float:
    """Get size of files in the current directory"""
    for root, _, files in Path(data).walk():
        for f in files:
            try:
                size += Path(root).joinpath(f).stat().st_size
            except (Exception,):
                pass
    return size


def get_format_dir_size(path: Path) -> str:
    """Get format size of files in the current directory"""
    size = get_directory_size(0, path)
    return get_format_size(Path(path).name, size)


def get_format_size(name, size) -> str:
    """Get format size of."""
    str_size = ""
    if len(str(round(size, 2))) <= 6:
        str_size = f'{str(round(size/1024, 2))} Kib / {str(round(size/1000, 2))} Kb'

    elif 6 < len(str(round(size, 2))) <= 9:
        str_size = f'{str(round(size/1024**2, 2))} Mib / {str(round(size/1000**2, 2))} Mb'

    elif len(str(round(size, 2))) > 9:
        str_size = f'{str(round(size/1024**3, 2))} Gib / {str(round(size/1000**3, 2))} Gb'

    return ': '.join([name, str_size])


def non_block_read(output) -> str:
    out = ''
    fd = output.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    try:
        out = output.read().decode("UTF-8")
    except:
        out = ''
    return out


class ActionList(ListView):
    """List view widget."""

    BINDINGS = [
        Binding("r,enter", "select", str(msg.ctx_dict['cursor_down']), show=False),
        Binding("k,up", "cursor_up", str(msg.ctx_dict['cursor_up']), show=False),
        Binding("j,down", "cursor_down", str(msg.ctx_dict['cursor_down']), show=False),
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)


class OpsList(OptionList):
    """List view widget."""

    BINDINGS = [
        Binding("r,enter", "select", str(msg.ctx_dict['cursor_down']), show=False),
        Binding("k,up", "cursor_up", str(msg.ctx_dict['cursor_up']), show=False),
        Binding("j,down", "cursor_down", str(msg.ctx_dict['cursor_down']), show=False),
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)


class SelectList(SelectionList[str]):
    """List view widget."""

    BINDINGS = [
        Binding("k,up", "cursor_up", str(msg.ctx_dict['cursor_up']), show=False),
        Binding("j,down", "cursor_down", str(msg.ctx_dict['cursor_down']), show=False),
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)


class DtTable(DataTable):
    """List view widget."""

    BINDINGS = [
        Binding("r,enter", "select_cursor", str(msg.msg_dict['select']), show=False),
        Binding("k,up", "cursor_up", str(msg.ctx_dict['cursor_up']), show=False),
        Binding("j,down", "cursor_down", str(msg.ctx_dict['cursor_down']), show=False),
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)


class TextView(Screen):
    """Text view widget."""

    BINDINGS = [("escape", "app.pop_screen()", str(msg.tt_dict['back_main']))]

    def __init__(self, text: str|None = None, path: str|Path|None = None) -> None:
        super().__init__()
        self.text = text
        self.path = path
        self.syntax = self.set_syntax()

    def on_mount(self) -> None:
        """"""
        self.auto_refresh = 1 / 30

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        yield Header()
        with VerticalScroll():
            yield Static(self.syntax, id='code', expand=True)
        yield Footer()

    def set_syntax(self):
        """"""
        if self.text:
            try:
                syntax = Syntax(str(self.text), lexer='bash', line_numbers=True,
                    word_wrap=False, indent_guides=True, theme='lightbulb',
                )
            except (Exception,):
                syntax = Traceback(theme='lightbulb', width=None)
        elif self.path:
            try:
                syntax = Syntax.from_path(str(self.path), line_numbers=True,
                    word_wrap=False, indent_guides=True, theme='lightbulb',
                )
            except (Exception,):
                syntax = Traceback(theme='lightbulb', width=None)
        else:
            syntax = ''

        return syntax


class StdoutView(Widget):
    """Stdout view widget."""

    def __init__(self, text: str|None = None, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.text = text if text else ''

    def on_mount(self) -> None:
        """"""
        self.auto_refresh = 1 / 30

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        with VerticalScroll():
            yield Static(self.text, id='stdout', expand=True)


class DialogQuestion(ModalScreen[str]):
    """Modal screen with message."""

    BINDINGS = [
        ('escape,q', 'app.pop_screen', str(msg.tt_dict['back_main'])),
        ('h,l,left,right', 'switch_focus', ''),
    ]

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__()

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        yield Grid(
            Label(self.message, id='question'),
            Button(msg.msg_dict['cancel'], id='quit'),
            Button(msg.msg_dict['ok'], id='ok'),
            id="dialog",
        )

    def action_switch_focus(self):
        self.app.simulate_key('tab')

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Emitted when the button is clicked"""
        self.dismiss(event.button.id)


class DialogOptions(ModalScreen[dict]):
    """Modal screen with option list."""

    BINDINGS = [('escape,q', 'app.pop_screen', msg.tt_dict['back_main'])]

    def __init__(self, message: str, data: dict, align=None, width=None,
            height=None) -> None:
        self.message = message
        self.data = data
        self.align = align
        self.width = width
        self.height = height
        super().__init__()

    def on_mount(self) -> None:
        sum_size = 0
        label = self.query_one("#question")
        label.styles.height = 1

        for _ in self.data:
            sum_size += 2

        box = self.query_one('#dialog_action')
        box.styles.width = self.width if self.width else 60
        box.styles.height = self.height if self.height else sum_size + 6

        if self.align:
            for opt in self.query(OptionList):
                opt.styles.text_align = self.align

    def options(self):
        for k, v in self.data.items():
            yield Option(str(v),str(k))
            yield None

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        with Container(id='dialog_action'):
            yield Label(self.message, id='question')
            yield OpsList(*(self.options()))

    def on_option_list_option_selected(self, event) -> None:
        data = dict()
        data["key"] = str(event.option.id)
        data["value"] = str(self.data.get(event.option.id))
        self.dismiss(data)


class DialogData(ModalScreen[dict]):

    BINDINGS = [('escape,q', 'app.pop_screen', msg.tt_dict['back_main'])]

    def __init__(self, message: str, data: dict, align=None, width=None,
            height=None) -> None:
        self.message = message
        self.data = data
        self.align = align
        self.width = width
        self.height = height
        super().__init__()

    def on_mount(self) -> None:
        """Set widget properties."""
        sum_size = 0
        table = self.query_one(DataTable)
        table.cursor_type = 'row'
        table.add_column(self.message, width=self.width)
        table.add_column('Description', width=self.width)

        for k, v in self.data.items():
            table.add_row(str(k), str(v), key=str(k))
            sum_size += 1

        table.styles.width = self.width if self.width else 60
        table.styles.height = self.height if self.height else sum_size + 3

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        yield DtTable(id='dialog_action')

    def on_data_table_row_selected(self, row_selected) -> None:
        """Emitted when data table row selected."""
        data = dict()
        data["key"] = str(row_selected.row_key.value)
        data["value"] = str(row_selected.row_key.value)
        self.dismiss(data)


class DialogEntry(ModalScreen[dict]):
    """Modal screen with input entry."""

    BINDINGS = [
        ('escape,q', 'app.pop_screen', msg.tt_dict['back_main']),
    ]

    def __init__(self, message: str, data: str) -> None:
        self.message = message
        self.data = data
        super().__init__()

    def on_mount(self) -> None:
        """Set widget properties."""
        label = self.query_one("#question")
        label.styles.height = 3
        self.entry.styles.column_span = 2
        for btn in self.query(Button):
            btn.styles.width = 40
            btn.styles.height = 3

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        self.entry = Input(value=str(self.data))
        with Grid(id='dialog'):
            yield Label(self.message, id='question')
            yield self.entry
            yield Button(msg.msg_dict['cancel'], id='quit')
            yield Button(msg.msg_dict['ok'], id='ok')

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Emitted when the button is clicked."""
        data = dict()
        data["key"] = str(event.button.id)
        data["value"] = str(self.entry.value)
        self.dismiss(data)

    def on_input_submitted(self, _: Input.Submitted) -> None:
        """Emitted when the input is submitted."""
        data = dict()
        data["key"] = str('ok')
        data["value"] = str(self.entry.value)
        self.dismiss(data)


class DialogInfo(ModalScreen[bool]):
    """Modal screen with message."""

    BINDINGS = [('escape,q', 'app.pop_screen', msg.tt_dict['back_main'])]

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__()

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        yield Grid(
            Label(self.message, id='question'),
            Button(msg.msg_dict['cancel'], id='quit'),
            id='dialog',
        )

    def on_button_pressed(self, _: Button.Pressed) -> None:
        """Emitted when the button is clicked"""
        self.dismiss(False)


class DialogQuit(ModalScreen[bool]):
    """Modal screen with message."""

    BINDINGS = [
        ('escape,q', 'app.pop_screen', msg.tt_dict['back_main']),
        ('h,l,left,right', 'switch_focus', ''),
    ]

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        yield Grid(
            Label('Are you sure you want to quit?', id='question'),
            Button(msg.msg_dict['shutdown'], id='quit'),
            Button(msg.msg_dict['cancel'], id='cancel'),
            id='dialog',
        )

    def action_switch_focus(self):
        self.app.simulate_key('tab')

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Emitted when the button is clicked"""
        if event.button.id == 'quit':
            self.dismiss(True)
        else:
            self.dismiss(False)


class BSOD(Screen):
    """Windows BSOD screen."""

    BINDINGS = [('escape', 'app.pop_screen', msg.tt_dict['back_main'])]

    def __init__(self) -> None:
        super().__init__(name='bsod')

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        yield Static(' Windows ', classes='title')
        yield Static(ERROR_TEXT, id='error_message')
        yield Static('Press any key to continue [blink]_[/]', id='any-key')
        yield Footer()


class ButtonBox(Widget):
    """Box with label and button."""

    def __init__(self, title: str, desc: str, label: str, data: str, idn: str,
                    width=None, height=None, box_height=None) -> None:
        self.title = title
        self.desc = desc
        self.label = label
        self.data = data
        self.idn = idn
        self.width = width if width else 20
        self.height = height if height else 3
        self.box_height = box_height
        super().__init__()

    def on_mount(self) -> None:
        """Set widget properties."""
        if self.box_height:
            self.styles.height = self.box_height

        for button in self.query(Button):
            button.styles.width = self.width
            button.styles.height = self.height
            button.styles.margin = 0

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        with Horizontal(id='horizontal_box'):
            with Vertical():
                yield Label(str(self.title), classes='title_accent')
                yield Static(str(self.desc))
            yield Button(label=self.label, name=self.data, id=self.idn)


class InputBox(Widget):
    """Box widget with input entry."""

    BINDINGS = [
        Binding('escape', 'toggle_focus', 'Toggle focus', show=False),
    ]

    def __init__(self, title: str, desc: str, placeholder: str, value: str, type,
            max_length=3, data=None, link=None, width=None, height=None, idx=None) -> None:
        self.title = title
        self.desc = desc
        self.placeholder = placeholder
        self.type = type
        self.value = value
        self.data = data
        self.link = link
        self.width = width if width else 30
        self.height = height if height else 3
        self.max_length = 0 if self.type == 'text' else max_length
        self.idx = idx if idx else self.title
        super().__init__()

    def on_mount(self) -> None:
        """Set widget properties."""
        for select in self.query(Input):
            select.styles.width = self.width
        if self.data:
            for btn in self.query(Button):
                btn.styles.width = self.data['width']
                btn.styles.height = self.data['height']

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        with Horizontal(id='horizontal_box'):
            with Vertical():
                yield Label(str(self.title), classes='title_accent')
                yield Static(str(self.desc))
                if self.link:
                    yield Pretty(self.link)
            yield Input(
                placeholder=self.placeholder, name=self.title, value=self.value,
                type=self.type, max_length=self.max_length, id=self.idx
            )
            if self.data:
                yield Button(
                    label=self.data['label'], name=self.data['name'],
                    id=self.data['id']
                )

    def action_toggle_focus(self):
        self.screen.focus_next()


class SelectBox(Widget):
    """Box widget with selection entry."""

    BINDINGS = [
        Binding('escape', 'toggle_focus', 'Toggle focus', show=False),
    ]

    def __init__(self, title: str, desc: str, select: list, value: str | NoSelection,
            data=None, link=None, width=None, height=None, idn=None) -> None:
        self.title = title
        self.desc = desc
        self.select = select
        self.value = value
        self.data = data
        self.link = link
        self.width = width if width else 30
        self.height = height if height else 3
        self.idn = idn if idn else title
        super().__init__()

    def on_mount(self) -> None:
        """Set widget properties."""
        for select in self.query(Select):
            select.styles.width = self.width
            select.styles.height = self.height

        if self.data:
            for btn in self.query(Button):
                btn.styles.width = self.data['width']
                btn.styles.height = self.data['height']

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        with Horizontal(id='horizontal_box'):
            with Vertical():
                yield Label(str(self.title), classes='title_accent')
                yield Static(str(self.desc))
                if self.link:
                    yield Pretty(self.link)
            yield Select(
                options=[(s, s) for s in self.select], name=self.idn,
                value=self.value, prompt='', id=self.idn
            )
            if self.data:
                yield Button(
                    label=self.data['label'], name=self.data['name'],
                )

    def set_width(self, width):
        for select in self.query(Select):
            select.styles.width = width

    def action_toggle_focus(self):
        self.screen.focus_next()


class LabelBox(Widget):
    """Box widget with label."""

    def __init__(self, label: str, desc: str) -> None:
        self.label = label
        self.desc = desc
        super().__init__()

    def on_mount(self) -> None:
        """Set widget properties."""
        for label in self.query(Label):
            label.styles.width = 20

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        with Horizontal(id='horizontal_box'):
            with Vertical(id='box'):
                yield Label(self.label, classes='title_accent')
                yield Static(self.desc)


class Progress(Screen):
    """Splash screen with progress indicator."""

    BINDINGS = [
        Binding("escape", "stop", msg.tt_dict['stop'])
    ]

    def __init__(self, label: str) -> None:
        self.label = label
        super().__init__()

    def on_mount(self) -> None:
        """Set widget properties."""

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        yield Splash(self.label)
        yield Footer()

    def action_stop(self) -> None:
        """Close current screen and back to main."""
        self.app.pop_screen()
        on_stop()


class Splash(Container):
    """Custom widget that extends Container."""

    def __init__(self, label: str) -> None:
        self.label = label
        super().__init__()

    def on_mount(self) -> None:
        """Set widget properties."""
        for v in self.query(Vertical):
            v.styles.align = ('center', 'middle')
            v.styles.height = 6
            v.styles.background = 'transparent'
        self.auto_refresh = 1 / 30

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        with Vertical():
            yield Static(self.label, classes='title')
            yield Static(progress_dict['app_loading'], classes='title')
            yield LoadingIndicator()

    def render(self) -> RenderableType:
        return LinearGradient(45, STOPS)


class LaunchersView(Screen):
    """Apps and stores view page."""

    BINDINGS = [("escape", "app.pop_screen()", msg.tt_dict['back_main'])]

    def __init__(self, config=None) -> None:
        self.config = config
        super().__init__()

    def on_mount(self) -> None:
        """Set widget properties."""
        for box in self.query(ButtonBox):
            box.styles.height = 10

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        yield Header()
        with VerticalScroll():
            with Grid(id='launchers_grid'):
                for launcher, data in launchers_descriptions.items():
                    desc = '\n'.join(
                        [f'{msg.msg_dict.get(k)}: {v}' for k, v in data.items()]
                    )
                    title = launcher.replace('_', ' ')
                    label = msg.msg_dict['install']
                    yield ButtonBox(
                        title=str(title), desc=str(desc), label=label,
                        data=str(launcher), idn='install', box_height=10
                    )
        yield Footer()

    async def run_install(self, x_name, event):
        run_install_launchers(x_name)
        event.set()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == 'install':
            with self.app.suspend():
                mp_event = mp.Event()
                data = {'func': update_exe_data, 'args': (event.button.name,)}
                Thread(target=process_event_wait, args=(mp_event, data)).start()
                worker = self.app.run_worker(
                    self.run_install(event.button.name, mp_event), thread=True
                )
                await worker.wait()


class WineBuildsView(Screen):
    """Wine builds view page."""

    BINDINGS = [("escape", "app.pop_screen()", msg.tt_dict['back_main'])]

    def __init__(self) -> None:
        super().__init__()
        self.winever_data = winever_data
        self.len_item = 0

    def on_mount(self) -> None:
        """Set widget properties."""
        self.box_update.styles.height = 10
        for select in self.query(SelectBox):
            select.set_width(self.len_item + 8)
            select.styles.height = 10

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        self.box_update = ButtonBox(
            title=vl_dict['install_wine'], desc=str_iw_title_desc,
            label=msg.msg_dict['check_wine_updates'], data='update',
            idn='update', width=30, box_height=10
        )
        yield Header()
        yield self.box_update
        with VerticalScroll():
            with Grid(id='wine_grid'):
                for wine, label in zip(wine_list, wine_labels):
                    wine_model = list()
                    if self.winever_data is not None:
                        for x in self.winever_data[wine].split(' '):
                            if x != '':
                                wine_dir = str(Path(Path(x).stem).stem)
                                wine_model.append(wine_dir)
                                if len(wine_dir) > self.len_item:
                                    self.len_item = len(wine_dir)
                    data = {
                        'label': msg.msg_dict['install'], 'name': wine,
                        'id': wine, 'width': 1, 'height': 3
                    }
                    yield SelectBox(
                        label, wine_descriptions[wine], wine_model, Select.BLANK,
                        data=data, link=wine_source_dict[wine], idn=wine
                    )
        yield Footer()

    def update_wine_view(self):
        """Update wine builds view."""
        (self.winever_data, self.latest_wine_dict, self.wine_download_dict
            ) = get_wine_dicts()
        self.refresh(repaint=True, layout=True, recompose=True)

    async def run_update_wine_ver(self):
        echo_func_name('try_get_wine_ver')

    async def run_download_wine(self, wine_func, name_ver, wine_ver):
        echo_wine(wine_func, name_ver, wine_ver)

    async def func(self, worker, queues):
        """"""
        f = worker.get('f')
        x = worker.get('x')

        if x:
            await f(*x)
        else:
            await f()

        for queue in queues:
            f = queue.get('f')
            x = queue.get('x')
            if x:
                return f(*x)
            else:
                return f()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Emitted when the button is clicked."""
        if event.button.id == 'update':
            event.button.set_loading(True)
            w = {'f': self.run_update_wine_ver, 'x': []}
            q = [{'f': self.update_wine_view, 'x': []}]
            t = Thread(target=asyncio.run, args=(self.func(w, q),))
            t.start()
        else:
            wine_func = name_ver = wine_ver = None
            for select in self.query(Select):
                if select.name == event.button.name:
                    wine_ver = str(select.value).replace('-amd64', '').replace('-x86_64', '')
                    wine_ver = ''.join([e for e in wine_ver if not e.isalpha()]).strip('-')
                    wine_func = wine_func_dict[str(event.button.name)]
                    name_ver = wine_ver_dict[str(event.button.name)]
                    break

            with self.app.suspend():
                echo_wine(wine_func, name_ver, wine_ver)


class AboutView(Screen):
    """About view page."""

    BINDINGS = [("escape", "app.switch_mode('main_screen')", msg.tt_dict['back_main'])]

    def __init__(self) -> None:
        super().__init__()

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        yield Header()
        with VerticalScroll():
            yield Label(f'StartWine {str_sw_version}', classes='title')
            with Grid(id='about_grid'):
                for key, desc in about_menu_dict.items():
                    yield LabelBox(about_dict[key], desc)
                for label, link in donation_source.items():
                    yield Button(f'{label}: {link}', name=link)
        yield Footer()


class LaunchSettings(VerticalScroll):
    """Launch settings view page."""

    def __init__(self, app_name=None, app_conf=sw_app_config.joinpath("StartWine"), app_dict={}) -> None:
        super().__init__()
        self.app_name = app_name
        self.app_conf = app_conf
        self.app_dict = app_dict
        self.var_dict = dict()
        self.error_message = [
            msg.msg_dict['app_conf_incorrect'] + f' {self.app_name}.',
            msg.msg_dict['app_conf_reset']
        ]
        self.model_dict = combo_model_dict

    def on_mount(self) -> None:
        """Activate launch settings."""
        self.btn_reset.styles.height = 5
        self.list_view.focus()

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        input_count = -1
        self.btn_reset = ButtonBox(
            title=settings_dict['launch_settings'], desc=str_lp_subtitle,
            label=' ' + settings_dict['set_app_default'], data='reset',
            idn='reset', width=30,
        )
        self.list_view = ActionList(id='settings_view')

        yield self.btn_reset
        with self.list_view:
            for title, desc in zip(lp_title, lp_desc):
                value = self.app_dict.get(f'export SW_USE_{title}')
                value = value[1:-1] if value else ""
                if title in lp_entry_list:
                    input_count += 1
                    yield ListItem(
                        InputBox(
                            str(title),
                            str(desc),
                            str_example[input_count],
                            value, 'text'
                        ),
                        name=str(title)
                    )
                elif title in lp_combo_list:
                    model = self.model_dict[title]
                    if value not in model:
                        value = Select.BLANK
                    yield ListItem(
                        SelectBox(str(title), str(desc), model, value),
                        name=str(title)
                    )
                else:
                    value = "0" if value == "" or value == "0.0" else value.split(':')[0]
                    yield ListItem(
                        InputBox(str(title), str(desc), str(), str(value), 'number'),
                        name=str(title)
                    )

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Emitted when item selected."""
        event.stop()
        name = event.item.name
        widget = [w for w in self.query(f'#{name}') if w.name == name]

        for w in widget:
            w.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Emitted when enter pressed."""
        if str(event.input.name) == 'WINE_CPU_TOPOLOGY':
            cpu_affinity = ''
            cpu = str(event.input.value) if str(event.input.value) != '' else '0'
            str_cpu = '' if cpu == '' or cpu == '0' else f'{cpu}'
            idx = ','.join([str(x) for x in range(int(cpu))])
            if idx != '' and str_cpu != '':
                cpu_affinity = f'{str_cpu}:{idx}'
            self.var_dict[str(event.input.name)] = cpu_affinity
        else:
            self.var_dict[str(event.input.name)] = str(event.input.value)

    def on_select_changed(self, event: Select.Changed) -> None:
        """Emitted when selected item changed."""
        value = '' if event.select.value == Select.BLANK else event.select.value
        self.var_dict[str(event.select.name)] = str(value)

    def write_changed_value(self):
        """Write value to app config when changed."""
        self.app_dict = app_info(self.app_conf)
        for var, val in self.var_dict.items():
            _val = self.app_dict[f'export SW_USE_{var}']
            val = val if val == '0' or val == '1' else f'"{val}"'
            self.app_conf.write_text(
                self.app_conf.read_text().replace(
                    f'export SW_USE_{var}={_val}',
                    f'export SW_USE_{var}={val}'
                )
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Emitted when the button is clicked"""
        if event.button.id == 'reset':
            self.app.push_screen(
                DialogQuestion(msg.msg_dict['reset_settings']),
                self.check_reset
            )

    def check_reset(self, answer) -> None:
        """Callback result with data."""
        if answer == 'ok':
            on_app_conf_default()
            self.app.pop_screen()


class LaunchOptions(Container):
    """Launch settings view page."""

    def __init__(self, app_name=None, app_conf=sw_app_config.joinpath("StartWine"), app_dict={}) -> None:
        super().__init__()
        self.app_name = app_name
        self.app_conf = app_conf
        self.app_dict = app_dict
        self.var_dict = dict()

    def on_mount(self) -> None:
        """Activate launch settings."""
        self.btn_reset.styles.height = 5
        self.selection.styles.height = '1fr'
        self.selection.focus()

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        self.btn_reset = ButtonBox(
            title=settings_dict['launch_settings'], desc=str_lp_subtitle,
            label=' ' + settings_dict['set_app_default'], data='reset',
            idn='reset', width=30,
        )
        selection_list = []
        for title, desc in zip(switch_labels, switch_descriptions):
            s = Selection(f'{title}'.ljust(30) + f'{desc}', str(title), False)
            if self.app_dict.get(f'export SW_USE_{title}') == '1':
                s = Selection(f'{title}'.ljust(30) + f'{desc}', str(title), True)
            selection_list.append(s)

        self.selection = SelectList(*selection_list)
        yield self.btn_reset
        yield self.selection

    def write_changed_value(self):
        """Write value to app config when changed."""
        self.app_dict = app_info(self.app_conf)

        for name in switch_labels:
            self.var_dict[str(name)] = str(0)

        for selected in self.selection.selected:
            self.var_dict[str(selected)] = str(1)

        for var, val in self.var_dict.items():
            _val = self.app_dict[f'export SW_USE_{var}']
            val = val if val == '0' or val == '1' else f'"{val}"'
            self.app_conf.write_text(
                self.app_conf.read_text().replace(
                    f'export SW_USE_{var}={_val}',
                    f'export SW_USE_{var}={val}'
                )
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Emitted when the button is clicked"""
        if event.button.id == 'reset':
            self.app.push_screen(
                DialogQuestion(msg.msg_dict['reset_settings']),
                self.check_reset
            )

    def check_reset(self, answer) -> None:
        """Callback result with data."""
        if answer == 'ok':
            on_app_conf_default()
            self.app.pop_screen()


class VkBasaltSettings(Container):
    """vkBasalt settings view page."""

    def __init__(self, app_name=None, app_conf=sw_app_config.joinpath("StartWine")) -> None:
        super().__init__()
        self.app_name = app_name
        self.app_conf = app_conf
        self.app_dict = app_info(self.app_conf)

    def on_mount(self) -> None:
        """Activate vkBasalt settings."""
        self.input_effect.styles.height = 5
        self.selection.styles.height = '1fr'
        self.selection.focus()

    def compose(self) -> ComposeResult:
        """Compose user interface."""

        self.input_effect = InputBox(
            title=settings_dict['vkbasalt_settings'], desc=str_vk_subtitle,
            placeholder=str_vk_intensity, max_length=2, type="number",
            value=str(float(self.app_dict[export_vkbasalt_cas][1:-1])*100),
            idx='effect_value',
        )
        selection_list = []
        export_value = self.app_dict[export_vkbasalt_effects][1:-1]
        for title, desc in vkbasalt_dict.items():
            s = Selection(f'{title}'.ljust(30) + f'{desc}', str(title), False)
            if str(title).lower() in str(export_value).lower():
                s = Selection(f'{title}'.ljust(30) + f'{desc}', str(title), True)
            selection_list.append(s)

        self.selection = SelectList(*selection_list)
        yield self.input_effect
        yield self.selection

    def write_changed_value(self) -> None:
        """write changed value to app config."""
        self.app_dict = app_info(self.app_conf)
        export_value = self.app_dict[export_vkbasalt_effects][1:-1]
        self.app_conf.write_text(
            self.app_conf.read_text().replace(
                f'{export_vkbasalt_effects}="{export_value}"',
                f'{export_vkbasalt_effects}="cas:{":".join(set(self.selection.selected))}"'
            )
        )

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Emitted when the button is clicked"""
        if event.input.id == 'effect_value':
            self.app_dict = app_info(self.app_conf)
            export_value = self.app_dict[export_vkbasalt_cas][1:-1]
            event_value = int(event.input.value) / 100
            self.app_conf.write_text(
                self.app_conf.read_text().replace(
                    f'{export_vkbasalt_cas}="{export_value}"',
                    f'{export_vkbasalt_cas}="{event_value}"',
                )
            )


class MangoHudSettings(Container):
    """MangoHud settings view page."""

    def __init__(self, app_name=None, app_conf=sw_app_config.joinpath("StartWine")) -> None:
        self.app_name = app_name
        self.app_conf = app_conf
        self.app_dict = app_info(self.app_conf)
        self.value_list = list()
        super().__init__()

    def on_mount(self) -> None:
        """Activate MangoHud settings."""
        self.btn_preview.styles.height = 5
        self.selection.styles.height = '1fr'
        self.selection.focus()

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        self.btn_preview = ButtonBox(
            title=settings_dict['mangohud_settings'], desc=str_mh_subtitle,
            label=' ' + preview_label, data='preview',
            idn='preview', width=30,
        )
        selection_list = []
        export_value = self.app_dict[export_mangohud_config][1:-1]
        for title, desc in zip(check_mh_labels, check_mh_description):
            s = Selection(f'{title.upper()}'.ljust(30) + f'{desc}', str(title), False)
            if str(title).lower() in str(export_value).lower():
                s = Selection(f'{title.upper()}'.ljust(30) + f'{desc}', str(title), True)
            selection_list.append(s)

        self.selection = SelectList(*selection_list)
        yield self.btn_preview
        yield self.selection

    def write_changed_value(self) -> None:
        """write chamged value to app config."""
        self.app_dict = app_info(self.app_conf)
        export_value = self.app_dict[export_mangohud_config][1:-1]
        self.app_conf.write_text(
            self.app_conf.read_text().replace(
                f'{export_mangohud_config}="{export_value}"',
                f'{export_mangohud_config}="{",".join(set(self.selection.selected))}"'
            )
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Emitted when the button is clicked"""
        if event.button.id == 'preview':
            self.write_changed_value()
            on_mangohud_preview(None)


class Tools(Container):
    """MangoHud settings view page."""

    BINDINGS = [
        Binding("k,up", "focus_up", ''),
        Binding("j,down", "focus_down", ''),
    ]

    def __init__(self, app_name=None, app_conf=sw_app_config.joinpath("StartWine"), app_dict={}) -> None:
        self.app_name = app_name
        self.app_conf = app_conf
        self.app_dict = app_dict
        self.data = list(wine_tools_dict.keys()) + list(prefix_tools_dict.keys())
        self.next = itertools.cycle(self.data)
        self.prev = itertools.cycle(reversed(self.data))
        super().__init__()

    def on_mount(self) -> None:
        """Activate MangoHud settings."""
        for box in self.query(ButtonBox):
            box.styles.height = 5

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        with VerticalScroll():
            with Grid(id='settings_grid'):
                for name, label in wine_tools_dict.items():
                    yield ButtonBox(
                        title=str(label), desc=str(wine_tools_desc_dict[name]),
                        label=msg.msg_dict['run'],
                        idn=name, data=name, width=30,
                    )
                for name, label in prefix_tools_dict.items():
                    yield ButtonBox(
                        title=str(label), desc=str(prefix_tools_desc_dict[name]),
                        label=msg.msg_dict['run'],
                        idn=name, data=name, width=30,
                    )

    def action_focus_up(self):
        prv = next(self.prev)
        self.query(f'#{prv}').focus()

    def action_focus_down(self):
        nxt = next(self.next)
        self.query(f'#{nxt}').focus()

    async def run_event(self, func):
        echo_func_name(func)

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == 'wine_settings':
            event.button.set_loading(True)
            worker = self.app.run_worker(self.run_event('WINECFG'), thread=True)
            await worker.wait()
            event.button.set_loading(False)

        elif event.button.id == 'wine_console':
            event.button.set_loading(True)
            worker = self.app.run_worker(self.run_event('WINECONSOLE'), thread=True)
            await worker.wait()
            event.button.set_loading(False)

        elif event.button.id == 'regedit':
            event.button.set_loading(True)
            worker = self.app.run_worker(self.run_event('REGEDIT'), thread=True)
            await worker.wait()
            event.button.set_loading(False)

        elif event.button.id == 'file_explorer':
            event.button.set_loading(True)
            worker = self.app.run_worker(self.run_event('WINEFILE'), thread=True)
            await worker.wait()
            event.button.set_loading(False)

        elif event.button.id == 'uninstaller':
            event.button.set_loading(True)
            worker = self.app.run_worker(self.run_event('UNINSTALLER'), thread=True)
            await worker.wait()
            event.button.set_loading(False)

        elif event.button.id == 'winetricks':
            self.app.push_screen(WinetricksView())

        elif event.button.id == 'clear_shader_cache':
            text_message = msg.msg_dict['clear_shader_cache']
            self.app.push_screen(DialogQuestion(text_message), self.check_message)

        elif event.button.id == 'pfx_remove':
            exe_data.set_(get_app_path(), 'path', None)
            event.button.set_loading(True)
            worker = self.app.run_worker(self.run_event('REMOVE_PFX'), thread=True)
            await worker.wait()
            event.button.set_loading(False)

        elif event.button.id == 'pfx_reinstall':
            event.button.set_loading(True)
            worker = self.app.run_worker(self.run_event('REINSTALL_PFX'), thread=True)
            await worker.wait()
            event.button.set_loading(False)

        elif event.button.id == 'pfx_backup':
            event.button.set_loading(True)
            worker = self.app.run_worker(self.run_event('SW_PFX_BACKUP'), thread=True)
            await worker.wait()
            event.button.set_loading(False)

        elif event.button.id == 'pfx_restore':
            event.button.set_loading(True)
            worker = self.app.run_worker(self.run_event('SW_PFX_RESTORE'), thread=True)
            await worker.wait()
            event.button.set_loading(False)

        elif event.button.id == 'saves_backup':
            event.button.set_loading(True)
            worker = self.app.run_worker(self.run_event('SW_APP_SAVES_BACKUP'), thread=True)
            await worker.wait()
            event.button.set_loading(False)

        elif event.button.id == 'saves_restore':
            event.button.set_loading(True)
            worker = self.app.run_worker(self.run_event('SW_APP_SAVES_RESTORE'), thread=True)
            await worker.wait()
            event.button.set_loading(False)

    def check_message(self, answer) -> None:
        """Callback result with data."""
        if answer == 'ok':
            on_clear_shader_cache()


class WinetricksView(Screen):
    """Winetricks settings view page."""

    BINDINGS = [
        Binding("escape", "close", msg.tt_dict['back_main']),
        Binding("right", "next_tab", "Next tab", show=True, key_display='', priority=True),
        Binding("left", "prev_tab", "Previous tab", show=True, key_display='', priority=True),
    ]

    def __init__(self, app_conf=sw_app_config.joinpath("StartWine"), app_dict={}) -> None:
        super().__init__()
        self.app_conf = app_conf
        self.app_dict = app_dict
        self.w_log = get_dll_info(get_pfx_path())
        self.tabs_list = ['install_fonts', 'install_dll']
        self.n_tabs = itertools.cycle(self.tabs_list)
        self.p_tabs = itertools.cycle(reversed(self.tabs_list))

    def on_mount(self) -> None:
        """Activate MangoHud settings."""
        self.dll_selection.focus()
        self.btn_install.styles.height = 5
        for container in self.query(TabbedContent):
            container.styles.height = '1fr'

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        self.btn_install = ButtonBox(
            title='Winetricks', desc=str_winetricks_subtitle,
            label=' ' + msg.msg_dict['install'], data='install',
            idn='install', width=30, box_height=5
        )

        dll_selection_list = []
        for title, desc in dll_dict.items():
            s = Selection(f'{title}'.ljust(30) + f'{desc}', str(title), False)
            if str(title) in self.w_log:
                s = Selection(
                    prompt=f'{title}'.ljust(30) + f'{desc}',
                    value=str(title),
                    initial_state=True,
                    disabled=True
                )
            dll_selection_list.append(s)

        fnt_selection_list = []
        for title, desc in fonts_dict.items():
            s = Selection(f'{title}'.ljust(30) + f'{desc}', str(title), False)
            if str(title) in self.w_log:
                s = Selection(
                    prompt=f'{title}'.ljust(30) + f'{desc}',
                    value=str(title),
                    initial_state=True,
                    disabled=True
                )
            fnt_selection_list.append(s)

        self.dll_selection = SelectList(*dll_selection_list)
        self.fnt_selection = SelectList(*fnt_selection_list)

        yield Header()
        with VerticalScroll():
            yield self.btn_install
            with TabbedContent():
                with TabPane(libs_tab_label, id='install_dll'):
                    with VerticalScroll():
                        yield self.dll_selection
                with TabPane(fonts_tab_label, id='install_fonts'):
                    with VerticalScroll():
                        yield self.fnt_selection
            yield Footer()

    def update_dll_list(self):
        """Update winetricks view page."""
        self.w_log = get_dll_info(get_pfx_path())
        self.refresh(repaint=True, layout=True, recompose=True)

    async def run_intsall(self, dll_list):
        echo_install_dll(dll_list)

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == 'install':
            dll_list = list(
                self.dll_selection.selected + self.fnt_selection.selected
            )
            for w in self.w_log:
                for dll in dll_list:
                    if dll == w:
                        dll_list.remove(dll)

            with self.app.suspend():
                worker = self.app.run_worker(self.run_intsall(dll_list), thread=True)
                await worker.wait()
                self.update_dll_list()

    def action_next_tab(self):
        """Switch to the next tab."""
        tab = next(self.n_tabs)
        self.query_one(TabbedContent).active = tab
        self.focus_tab(tab)

    def action_prev_tab(self):
        """Switch to the previous tab."""
        tab = next(self.p_tabs)
        self.query_one(TabbedContent).active = tab
        self.focus_tab(tab)

    def focus_tab(self, tab):
        """Focus selection list in the current tab."""
        if tab == "install_dll":
            self.dll_selection.focus()

        if tab == "install_fonts":
            self.fnt_selection.focus()

    def action_close(self) -> None:
        """Close current screen and back to main."""
        self.app.pop_screen()


class SettingsView(Screen):
    """Launch settings view page."""

    BINDINGS = [
        Binding("escape", "close", str(msg.tt_dict['back_main']), show=True),
        Binding("right", "next_tab", "Next tab", show=True, key_display='', priority=True),
        Binding("left", "prev_tab", "Previous tab", show=True, key_display='', priority=True),
        Binding("t", "stop", str(msg.tt_dict['stop']), show=True),
        Binding("r", "run('run')", str(msg.msg_dict['run']), show=True),
        Binding("w", "wine", str(msg.msg_dict['cw']), show=True),
        Binding("p", "prefix", str_prefix.replace(':', ''), show=True),
        Binding("s", "show_tab('winetricks')", "Winetricks", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.app_name = get_out()
        self.app_path = get_app_path().strip('"')
        self.app_conf = sw_app_config.joinpath(self.app_name)
        self.app_dict = app_info(self.app_conf)
        self.wineloader_list = list()
        self.wineloader_dict = dict()
        self.prefix_dict = dict()
        self.wine = self.app_dict['export SW_USE_WINE'][1:-1]
        if 'pfx_default' in self.app_dict['export SW_USE_PFX'][1:-1]:
            self.prefix = prefix_labels[0]
        else:
            self.prefix = prefix_labels[1]

        self.tabs_list = [
            'launch_options', 'mangohud_settings', 'vkbasalt_settings',
            'tools', 'launch_settings',
        ]
        self.n_tabs = itertools.cycle(self.tabs_list)
        self.p_tabs = itertools.cycle(reversed(self.tabs_list))

    def on_mount(self) -> None:
        """Activate launch settings."""
        self.btn_stop.styles.width = 1
        self.horizontal.styles.height = 3

        for container in self.query(TabbedContent):
            container.styles.height = '1fr'

        for button in [self.btn_start, self.btn_wine, self.btn_pfx]:
            button.styles.width = "1fr"

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        self.horizontal = Horizontal()
        self.btn_stop =  Button(' ' + msg.msg_dict['stop'], id='stop')
        self.btn_start =  Button(' ' + msg.msg_dict['run'], id='run')
        self.btn_wine = Button('󰕰 ' + self.wine, id='wine')
        self.btn_pfx = Button(' ' + self.prefix, id='prefix')
        self.tab_launch_settings = TabPane(
            msg.msg_dict['launch_settings'], id="launch_settings"
        )
        self.launch_settings = LaunchSettings(
            self.app_name, self.app_conf, self.app_dict
        )
        self.tab_launch_options = TabPane(str_title_startup, id="launch_options")
        self.launch_options = LaunchOptions(self.app_name, self.app_conf, self.app_dict)
        self.tab_tools = TabPane(msg.tt_dict['tools'], id="tools")
        self.tools = Tools(self.app_name, self.app_conf, self.app_dict)
        self.tab_mangohud = TabPane('MangoHud', id="mangohud_settings")
        self.mangohud_settings = MangoHudSettings(self.app_name, self.app_conf)
        self.tab_vkbasalt = TabPane('vkBasalt', id="vkbasalt_settings")
        self.vkbasalt_settings = VkBasaltSettings(self.app_name, self.app_conf)

        yield Header()
        with VerticalScroll():
            with self.horizontal:
                yield self.btn_stop
                yield self.btn_start
                yield self.btn_wine
                yield self.btn_pfx

            with TabbedContent():
                with self.tab_launch_settings:
                    yield self.launch_settings
                with self.tab_launch_options:
                    yield self.launch_options
                with self.tab_mangohud:
                    yield self.mangohud_settings
                with self.tab_vkbasalt:
                    yield self.vkbasalt_settings
                with self.tab_tools:
                    yield self.tools
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Emitted when the button is clicked"""
        if event.button.id == 'stop':
            self.action_stop()

        elif event.button.id == 'run':
            self.action_run()

        elif event.button.id == 'wine':
            self.action_wine()

        elif event.button.id == 'prefix':
            self.action_prefix()

    def action_run(self) -> None:
        """Run current application."""
        if Path(self.app_path).exists():
            write_app_conf(Path(f'{self.app_path}'))
            self.write_changed_value()
            self.app.sub_title = f'Run {Path(self.app_path).name}'
            self.app.push_screen(Progress(self.app_path))
            app.on_start()
        else:
            self.app.push_screen(DialogInfo(msg.msg_dict['lnk_error']))

    def action_stop(self):
        """Terminate all wine process."""
        on_stop()

    def action_wine(self):
        """Change wine."""
        get_wineloader_list(self.wineloader_list)
        get_wineloader_dict(self.wineloader_list, self.wineloader_dict)
        self.app.push_screen(
            DialogOptions(str_current_wine, self.wineloader_dict),
            self.check_wine
        )

    def action_prefix(self):
        """Change prefix."""
        for p, l in zip(prefix_list, prefix_labels):
            self.prefix_dict[p] = l
        self.app.push_screen(
            DialogOptions(str_current_prefix, self.prefix_dict, align='center'),
            self.check_prefix
        )

    def action_next_tab(self) -> None:
        """Switch to the next tab."""
        tab = next(self.n_tabs)
        self.query_one(TabbedContent).active = tab
        self.focus_tab(tab)

    def action_prev_tab(self) -> None:
        """Switch to the previous tab."""
        tab = next(self.n_tabs)
        self.query_one(TabbedContent).active = tab
        self.focus_tab(tab)

    def focus_tab(self, tab):
        """Focus selection list in the current tab."""
        if tab == "launch_settings":
            self.launch_settings.list_view.focus()

        if tab == "tools":
            pass

        if tab == "launch_options":
            self.launch_options.selection.focus()

        if tab == "mangohud_settings":
            self.mangohud_settings.selection.focus()

        if tab == "vkbasalt_settings":
            self.vkbasalt_settings.selection.focus()

    def action_show_tab(self, tab: str) -> None:
        """Switch to a new tab."""
        if tab == "winetricks":
            self.app.push_screen(WinetricksView())

    def check_wine(self, data) -> None:
        """Callback result with data."""
        wine_label = data["key"]
        self.btn_wine.label = '󰕰 ' + str(wine_label)
        change_wine_activate(wine_label)

    def check_prefix(self, data) -> None:
        """Callback result with data."""
        self.btn_pfx.label = ' ' + str(data['value'])
        change_pfx_activate(data['key'])

    def write_changed_value(self):
        """Write changed value to app settings."""
        self.launch_settings.write_changed_value()
        self.launch_options.write_changed_value()
        self.mangohud_settings.write_changed_value()
        self.vkbasalt_settings.write_changed_value()

    def action_close(self) -> None:
        """Close current screen and back to main."""
        self.write_changed_value()
        self.app.pop_screen()


class DirTree(DirectoryTree):
    """Directory tree view."""
    COMPONENT_CLASSES: ClassVar[set[str]] = {
        "directory-tree--extension",
        "directory-tree--file",
        "directory-tree--folder",
        "directory-tree--hidden",
        "directory-tree--exec",
    }
    BINDINGS = [
        Binding("k,up", "cursor_up", str(msg.ctx_dict['cursor_up']), show=False),
        Binding("j,down", "cursor_down", str(msg.ctx_dict['cursor_down']), show=False),
        Binding("l,right", "toggle_node", str(msg.ctx_dict['toggle_node']), show=False),
        Binding("h,left", "go_back", str(msg.tt_dict['back_up']), show=False),
        Binding("gg,home", "scroll_home", str(msg.tt_dict['scroll_up']), show=False),
        Binding("G,end", "scroll_end", 'Scroll down', show=False),
        Binding("space", "toggle_node", str(msg.ctx_dict['toggle_node']), show=False),
        Binding("enter", "select_cursor", str(msg.msg_dict['select']), show=False),
        Binding(".", "toggle_hidden", str(msg.ctx_dict['show_hidden_files'][0]), show=False),
    ]
    pattern = None
    if sw_cfg.get('hidden_files') == 'True':
        show_hidden_files = var(True)
    else:
        show_hidden_files = var(False)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def render_label(self, node, base_style: Style, style: Style) -> Text:
        """Render a label for the given node.
        Args:
            node: A tree node.
            base_style: The base style of the widget.
            style: The additional style for the label.

        Returns:
            A Rich Text object containing the label.
        """
        node_label = node._label.copy()
        node_label.stylize(style)

        if not self.is_mounted:
            return node_label

        if node._allow_expand:
            prefix = ("📂 " if node.is_expanded else "📁 ", base_style + TOGGLE_STYLE)
            node_label.stylize_before(
                self.get_component_rich_style("directory-tree--folder", partial=True)
            )
        else:
            prefix = (
                "📄 ",
                base_style,
            )
            node_label.stylize_before(
                self.get_component_rich_style("directory-tree--file", partial=True),
            )
            node_label.highlight_regex(
                r"\..+$",
                self.get_component_rich_style(
                    "directory-tree--extension", partial=True
                ),
            )

        if node_label.plain.startswith("."):
            node_label.stylize_before(
                self.get_component_rich_style("directory-tree--hidden")
            )

        if node_label.plain.lower().endswith(".exe"):
            node_label.stylize_before(
                self.get_component_rich_style("directory-tree--exec")
            )

        text = Text.assemble(prefix, node_label)
        return text

    def filter_paths(self, paths: Iterable[Path]) -> Iterable[Path]:
        """Filter hidden files."""

        if self.pattern:
            paths = [path for path in paths if str(self.pattern) in path.name]

        if not self.show_hidden_files:
            paths = [path for path in paths if not path.name.startswith('.')]
            return paths
        else:
            return paths

    def sort_func(self, x_list):
        """file sorting function in the list"""

        sorted_list = list()
        sorting_files = (
            app.cfg.get('sorting_files') if app.cfg.get('sorting_files') else 'name'
        )
        sorting_reverse = (
            app.cfg.get('sorting_reverse') if app.cfg.get('sorting_reverse') else 'False'
        )
        if sorting_files == 'type':
            sorted_list_by_type = sorted(
                [x for x in x_list],
                key=lambda x: str(x.stat().st_mode),
                reverse=eval(str(sorting_reverse))
            )
            sorted_list = sorted_list_by_type

        elif sorting_files == 'size':
            sorted_list_by_size = sorted(
                [x for x in x_list],
                key=lambda x: str(round(x.stat().st_size/1024/1024, 4)),
                reverse=eval(str(sorting_reverse))
            )
            sorted_list = sorted_list_by_size

        elif sorting_files == 'date':
            sorted_list_by_date = sorted(
                [x for x in x_list],
                key=lambda x: str(x.stat().st_atime),
                reverse=eval(str(sorting_reverse))
            )
            sorted_list = sorted_list_by_date

        elif sorting_files == 'name':
            sorted_list_by_name = sorted(
                [x for x in x_list],
                key=lambda x: str(x.name),
                reverse=eval(str(sorting_reverse))
            )
            sorted_list = sorted_list_by_name
        else:
            pass

        return sorted_list

    def action_toggle_hidden(self) -> None:
        """Called in response to key binding."""
        self.show_hidden_files = not self.show_hidden_files
        self.reload()


class Commandline(Input):
    """Commandline input widget."""

    BINDINGS = [
        Binding('escape,up', 'toggle_focus', 'Toggle focus', show=False),
        Binding('f5,ctrl+d', 'copy_text', 'Copy', show=False),
        Binding('f6,ctrl+x', 'cut_text', 'Cut', show=False),
        Binding('ctrl+v', 'paste_text', 'Paste', show=False),
    ]
    select_on_focus = var(True)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def action_toggle_focus(self):
        self.clear()
        #self.app.simulate_key('tab')

    def action_cut_text(self):
        self.app.copy_to_clipboard(str(self.value))
        Clipper().copy(str(self.value))
        self.clear()
        self.notify(msg.msg_dict['copied_to_clipboard'])

    def action_copy_text(self):
        self.app.copy_to_clipboard(str(self.value))
        Clipper().copy(str(self.value))
        self.notify(msg.msg_dict['copied_to_clipboard'])

    def action_paste_text(self):
        self.value = self.value + self.app.clipboard
        self.action_end()


class SuggestInput(SuggestFromList):
    """Completion suggestions based on a fixed list of options."""

    def __init__(self, suggestions: list = [], case_sensitive: bool = False) -> None:
        self.suggestions = suggestions
        self.case_sensitive = case_sensitive
        super().__init__(
            suggestions=self.suggestions, case_sensitive=self.case_sensitive)

class Menu:
    """menu options list."""
    options = {
        'shortcuts': ' ' + msg.msg_dict['shortcuts'],
        'files': ' ' + msg.msg_dict['files_tree'],
        'launchers': ' ' + msg.msg_dict['launchers'],
        'install_wine': '󰕰 ' + msg.msg_dict['install_wine'],
        'hotkeys': '󰌌 ' + str_title_hotkeys,
        'about': ' ' + msg.msg_dict['about'],
        'shutdown': '  ' + msg.msg_dict['shutdown'],
    }


class MainScreen(Screen):
    """Main screen view page."""

    HOTKEYS = [
        Binding(':,;', '', str(msg.ctx_dict['command_line'])),
        Binding('$', 'shell', str(msg.ctx_dict['shell'])),
        Binding('backslash,ctrl+f', '', str(msg.tt_dict['search'])),
        Binding('enter,r', '', str(msg.msg_dict['select'])),
        Binding('space', '', str(msg.ctx_dict['toggle'])),
        Binding('tab', '', str(msg.ctx_dict['toggle_focus'])),
        Binding('escape', '', str(msg.tt_dict['back_main'])),
        Binding('up,k', '', str(msg.ctx_dict['cursor_up'])),
        Binding('down,j', '', str(msg.ctx_dict['cursor_down'])),
        Binding('right,l', '', str(msg.ctx_dict['toggle_node'])),
        Binding('left,h', '', str(msg.tt_dict['back_up'])),
        Binding('home,gg', '', str(msg.ctx_dict['scroll_up'])),
        Binding('end, G', '', str(msg.ctx_dict['scroll_down'])),
        Binding('pageup', '', str(msg.ctx_dict['page_up'])),
        Binding('pagedn', '', str(msg.ctx_dict['page_down'])),
        Binding('gr', '', 'cd /'),
        Binding('ge', '', 'cd /etc'),
        Binding('gh', '', 'cd /home'),
        Binding('gm', '', 'cd /mnt'),
        Binding('go', '', 'cd /opt'),
        Binding('gv', '', 'cd /var'),
        Binding('gu', '', 'cd /usr'),
        Binding('gl', '', 'cd ~/.local/share'),
        Binding('gs', '', f'cd {sw_shortcuts}'),
        Binding('ga', '', f'cd {sw_games}'),
        Binding('gc', '', f'cd {sw_app_config}'),
        Binding('gp', '', f'cd {sw_pfx}'),
        Binding('gb', '', f'cd {sw_pfx_backup}'),
        Binding('gw', '', f'cd {sw_wine}'),
        Binding('gt', '', f'cd {sw_tmp}'),
        Binding('gd', '', f'cd {sw_fm_cache}'),
        Binding('/', '', str(msg.msg_dict['partitions'])),
        Binding('.,ctrl+h', '', str(msg.ctx_dict['show_hidden_files'][0])),
        Binding('z', '', str(msg.ctx_dict['filter_files'])),
        Binding('f2,a,ctrl+r', '', str(msg.ctx_dict['rename'][0])),
        Binding('f3,i', '', str(msg.ctx_dict['view'])),
        Binding('f4,E,ctrl+e', '', str(msg.ctx_dict['open'])),
        Binding('f5,yy,ctrl+d', '', str(msg.ctx_dict['copy'][0])),
        Binding('f6,dd,ctrl+x', '', str(msg.ctx_dict['cut'][0])),
        Binding('pp,ctrl+v', '', str(msg.ctx_dict['paste'][0])),
        Binding('insert', '', str(msg.ctx_dict['create'])),
        Binding('shift+l', '', str(msg.ctx_dict['link'][0])),
        Binding('f7,ctrl+n', '', str(msg.ctx_dict['create_dir'][0])),
        Binding('f8,delete', '', str(msg.ctx_dict['remove'])),
        Binding('f9,M', '', str(msg.tt_dict['view_menu'])),
        Binding('f10,q,ctrl+c', '', str(msg.msg_dict['shutdown'])),
        Binding('ma,f1,?', '', str(msg.msg_dict['about'])),
        Binding('mk,ctrl+k', '', str(msg.ctx_dict['show_hotkeys'][0])),
        Binding('mw,ctrl+w', '', str(msg.msg_dict['install_wine'])),
        Binding('ml,ctrl+l', '', str(msg.msg_dict['launchers'])),
    ]

    BINDINGS = [
        Binding(':,;', 'command_line', str(msg.ctx_dict['command_line']), show=False),
        Binding('/', 'toggle_partitions', str(msg.msg_dict['partitions']), show=True),
        Binding('$', 'shell', str(msg.ctx_dict['shell']), show=False),
        Binding('gs,ctrl+s', 'open_shortcuts', msg.msg_dict['shortcuts'], show=False),
        Binding('ml,ctrl+l', 'toggle_launchers', msg.msg_dict['launchers'], show=False),
        Binding('mw,ctrl+w', 'toggle_winebuilds', msg.msg_dict['install_wine'], show=False),
        Binding('r', 'run_file', str(msg.ctx_dict['open_with']), show=False),
        Binding('pp,ctrl+v', 'paste_file', str(msg.ctx_dict['paste'][0]), show=False),
        Binding('f1,?', 'toggle_about', str(msg.msg_dict['about']), show=True, key_display='F1'),
        Binding('f2,a,ctrl+r', 'rename_file', str(msg.ctx_dict['rename'][0]), show=True, key_display='F2'),
        Binding('f3,i', 'set_text', str(msg.ctx_dict['view']), show=True, key_display='F3'),
        Binding('f4,E,ctrl+e', 'open_editor', str(msg.ctx_dict['open']), show=True, key_display='F4'),
        Binding('f5,yy,ctrl+d', 'copy_file', str(msg.ctx_dict['copy'][0]), show=True, key_display='F5'),
        Binding('f6,dd,ctrl+x', 'cut_file', str(msg.ctx_dict['cut'][0]), show=True, key_display='F6'),
        Binding('insert', 'create_file', str(msg.ctx_dict['create']), show=False),
        Binding('shift+l', 'create_link', str(msg.ctx_dict['link'][0]), show=False),
        Binding('f7,ctrl+n', 'create_directory', str(msg.ctx_dict['create_dir'][0]), show=True, key_display='F7'),
        Binding('f8,delete', 'delete_file', str(msg.ctx_dict['remove']), show=True, key_display='F8'),
        Binding('f9', 'toggle_menu', str(msg.tt_dict['view_menu']), show=True, key_display='F9'),
        Binding('M', 'toggle_bookmarks', str(msg.tt_dict['bookmarks']), show=False),
        Binding('f10,q,ctrl+c', 'shutdown', str(msg.msg_dict['shutdown']), show=True, key_display='F10'),
        Binding('ctrl+k', 'show_hotkeys', str(msg.ctx_dict['show_hotkeys'][0]), show=False),
        Binding('k,up', 'cursor_up', str(msg.ctx_dict['cursor_up']), show=False),
        Binding('j,down', 'cursor_down', str(msg.ctx_dict['cursor_down']), show=False),
        Binding('l,right', 'toggle_node', str(msg.ctx_dict['toggle_node']), show=False),
        Binding('h,left', 'go_back', str(msg.tt_dict['back_up']), show=False),
        Binding('gg,home', 'scroll_home', str(msg.tt_dict['scroll_up']), show=False),
        Binding('G,end', 'scroll_end', str(msg.ctx_dict['scroll_down']), show=False),
        Binding('pageup', 'page_up', str(msg.ctx_dict['page_up']), show=False),
        Binding('pagedn', 'page_down', str(msg.ctx_dict['page_down']), show=False),
        Binding('.,ctrl+h', 'toggle_hidden', str(msg.ctx_dict['show_hidden_files'][0]), show=False),
        Binding('z', "filter", str(msg.ctx_dict['filter_files']), show=False),
        Binding('escape', 'hide_panel', str(msg.tt_dict['back_main']), show=False),
        #TODO Binding("", "add_bookmark", str(msg.ctx_dict['add_bookmark']), show=True),
        #TODO Binding("", "compress_file", str(msg.ctx_dict['compress']), show=True),
        #TODO Binding("", "properties", str(msg.ctx_dict['properties'][0]), show=True),
    ]
    if sw_cfg.get('control_panel') == 'show':
        show_sidebar = var(True)
    else:
        show_sidebar = var(False)

    show_partitions = var(False)
    show_output = var(False)

    def __init__(self) -> None:
        super().__init__(id='main_screen', name='main_screen')
        # self.left_files = None
        self.current_file = None
        # self.current_node = None
        self.clipboard_type = None
        self.cmd_list = [
            'sw://app', 'sw://store', 'sw://wine', 'sw://touch', 'sw://mkdir',
            'sw://delete', 'sw://filter', 'sw://menu', 'sw://edit', 'sw://shell',
            'sw://run', 'sw://inspect', 'sw://open', 'sw://about', 'sw://shutdown',
            'sw://part', 'sw://home', 'sw://local', 'sw://config', 'sw://cache',
            'sw://tmp', 'sw://pfx', 'sw://backup', 'sw://extract', 'sw://compress',
            'sw://gr', 'sw://gh', 'sw://gm', 'sw://go', 'sw://ge', 'sw://gl',
            'sw://gs', 'sw://gb', 'sw://gc', 'sw://gp', 'sw://gw', 'sw://gt',
            'sw://gv', 'sw://gu', 'sw://gd', 'sw://gg', 'sw://ma', 'sw://ml',
            'sw://mw', 'sw://mh', 'sw://yy', 'sw://dd', 'sw://pp', 'sw://hotkeys'
        ]
        self.history = self.get_history()

    def get_history(self) -> list:
        """Get shell history list."""
        data_list = []
        history = []
        bash = Path.home().joinpath('.bash_history')
        zsh = Path.home().joinpath('.zhistory')

        if bash.exists():
            with open(bash, 'rb') as f:
                data = f.read().decode('ascii','ignore')
                f.close()
            data_list = data_list + data.splitlines()

        if zsh.exists():
            with open(zsh, 'rb') as f:
                data = f.read().decode('ascii','ignore')
                f.close()
            data_list = data_list + data.splitlines()

        history = self.cmd_list + data_list
        history.reverse()

        return history

    def on_mount(self) -> None:
        """Set widget properties."""
        self.left_files.focus()
        self.query_one('#sidebar').styles.animate(
            'opacity', value=1.0, duration=1.0
        )
        self.query_one('#left_tree_view').styles.animate(
            'opacity', value=1.0, duration=1.0
        )
        self.table.cursor_type = 'row'
        self.table.add_columns(
            *[
                msg.msg_dict['device_name'], msg.msg_dict['free'],
                msg.msg_dict['total'], msg.msg_dict['file_type'],
                msg.msg_dict['device_id'], msg.msg_dict['mount_options']
            ]
        )
        for x in sorted(disk_parts):
            for m in ['/mnt/', '/run/media/', '/home']:
                if m in x.mountpoint:
                    mountpoint = x.mountpoint
                    if '.Xauthority' not in mountpoint:
                        fs_size = psutil.disk_usage(mountpoint).total
                        fs_free = psutil.disk_usage(mountpoint).free
                        fmt_size = GLib.format_size(int(fs_size))
                        fmt_free = GLib.format_size(int(fs_free))

                        self.table.add_row(
                            mountpoint, fmt_free, fmt_size, x.fstype, x.device,
                            x.opts, key=mountpoint
                        )

        for n, x in enumerate(app.path_list):
            node = self.left_files.get_node_at_line(n)
            if node and node.data and str(node.data.path) == str(app.path):
                self.left_files.select_node(node)
                chdir(app.root_path)

    def compose(self) -> ComposeResult:
        """Compose user interface."""
        tooltip = """Note: Enter "sw://command" to run in an isolated environment. \
            To run on the system side, enter as usual.
            """
        self.suggester = SuggestInput(suggestions=self.history, case_sensitive=False)
        self.commandline = Commandline(
            placeholder=' ', id='commandline',
            suggester=self.suggester, tooltip=tooltip, select_on_focus = False
        )
        self.left_files = DirTree(path=app.root_path, id='left_tree_view')
        self.table = DtTable(id='partition_view')
        self.sidebar = TabbedContent(id='sidebar')

        yield Header(show_clock=True)
        with Container():
            with Vertical():
                yield self.left_files
                yield self.table
            yield self.commandline

        with self.sidebar:
            with TabPane(btn_dict['bookmarks']):
                yield OpsList(*(self.bookmarks()), id="bookmarks")
        yield Footer()

    def bookmarks(self):
        for b, u in termmarks_dict.items():
            label = u[1] if u[1] else str(Path(b).name)
            yield Option(str(u[0]) + label, id=b)
            yield None

    def on_input_changed(self, event) -> None:
        """Emitted when input value changed."""
        if event.input.id == 'commandline':
            if event.input.value in self.cmd_list:
                if event.input.value.startswith(f'sw://filter'):
                    pass
                else:
                    #self.app.simulate_key('enter')
                    self.action_execute_cmd(event.input.value)
                    self.commandline.clear()
                    self.left_files.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Emitted when enter pressed."""
        if str(event.value).startswith(f'sw://'):
            self.action_execute_cmd(event.value)
            self.commandline.clear()
        else:
            with self.app.suspend():
                try:
                    run(f'clear && hostexec {event.value}', shell=True)
                except (Exception,):
                    run(f'clear && {event.value}', shell=True)
                input(f"{msg.tt_dict['back_main']}: ")

    def on_option_list_option_selected(self, event):
        """Emitted when item is selected."""
        if Path(event.option.id).exists():
            self.action_open_location(event.option.id)

    def check_option_list(self, event):
        """Emitted when item is selected."""
        if event['key'] == 'shortcuts':
            self.action_open_location(sw_shortcuts)

        elif event['key'] == 'files':
            self.action_open_location('/')

        elif event['key'] == 'launchers':
            self.app.push_screen(LaunchersView())

        elif event['key'] == 'install_wine':
            self.app.push_screen(WineBuildsView())

        elif event['key'] == 'hotkeys':
            self.action_show_hotkeys()

        elif event['key'] == 'about':
            self.app.switch_mode('about')

        elif event['key'] == 'shutdown':
            app.action_shutdown()

    def on_directory_tree_file_selected(
            self, event: DirectoryTree.FileSelected) -> None:
        """Emitted when a file in the directory tree is selected."""
        event.stop()
        self.action_run_file(event.path)

    def on_directory_tree_directory_selected(self, event) -> None:
        """Emitted when directory tree node selected."""
        self.current_node = event.node
        self.current_file = str(event.node.data.path)
        self.left_files.path = str(event.node.data.path)
        chdir(self.left_files.path)

    def file_info(self):
        """Get the status of a file or a file descriptor."""
        name = Path(str(self.current_file)).name
        try:
            file_info = Path(str(self.current_file)).stat()
        except (OSError, IOError, PermissionError):
            file_info = None

        if file_info is not None:
            try:
                size = file_info.st_size
            except (OSError, IOError, PermissionError):
                size = 0

            size = get_format_size(name, size)
            label_size = msg.msg_dict['file_size']
            label_group = msg.msg_dict['user_group']
            label_access = msg.msg_dict["access"]
            try:
                uid = file_info.st_uid
            except (OSError, IOError, PermissionError):
                user = 'unknown'
            else:
                try:
                    user =  get_uid(uid).pw_name
                except (KeyError, OSError, IOError, PermissionError):
                    user = uid
            try:
                gid = file_info.st_gid
            except (OSError, IOError, PermissionError):
                group = 'unknown'
            else:
                try:
                    group =  get_gid(gid).gr_name
                except (KeyError, OSError, IOError, PermissionError):
                    group = gid
            try:
                mode = oct(file_info.st_mode)
            except (OSError, IOError, PermissionError):
                permission = 'unknown'
            else:
                mode = list(mode[:-4:-1])
                mode.reverse()
                permission = ' '.join([access_dict[int(m)] for m in mode])

            self.left_files.border_subtitle = (
                f'{label_size} {size} {label_group}: {user} {group} {label_access}: {permission}'
            )

    def on_tree_node_highlighted(self, event):
        """Emitted when directory tree node highlighted."""
        self.app.sub_title = event.node.data.path
        self.current_node = event.node
        self.current_file = str(event.node.data.path)
        self.file_info()

    def on_data_table_row_selected(self, row_selected) -> None:
        """Emitted when data table row selected."""
        if Path(row_selected.row_key.value).exists():
            self.action_open_location(row_selected.row_key.value)
        else:
            self.app.push_screen(DialogInfo(msg.msg_dict['does_not_exist']))

    def on_key(self, event: Key):
        """Set subtitle when key presssed."""

        event.key = f'{_t(event.key)}'

        if event.key == 'y':
            self.commandline.focus()
            self.commandline.value = 'sw://y'
            self.commandline.action_end()

        if event.key == 'd':
            self.commandline.focus()
            self.commandline.value = 'sw://d'
            self.commandline.action_end()

        if event.key == 'p':
            self.commandline.focus()
            self.commandline.value = 'sw://p'
            self.commandline.action_end()

        if event.key == 'g':
            self.commandline.focus()
            self.commandline.value = 'sw://g'
            self.commandline.action_end()

        if event.key == 'm':
            self.commandline.focus()
            self.commandline.value = 'sw://m'
            self.commandline.action_end()

        if event.key == 'z':
            self.commandline.focus()
            self.commandline.value = 'sw://filter '
            self.commandline.action_end()

    def action_execute_cmd(self, cmd):
        """Execute shell command."""
        execute = cmd.removeprefix('sw://')

        if f'sw://app' == cmd or f'sw://gs' == cmd:
            self.action_open_shortcuts()

        elif f'sw://part' == cmd:
            self.action_toggle_partitions()

        elif f'sw://root' == cmd or f'sw://gr' == cmd:
            self.action_open_location('/')

        elif f'sw://etc' == cmd or f'sw://ge' == cmd:
            self.action_open_location('/etc')

        elif f'sw://mnt' == cmd or f'sw://gm' == cmd:
            self.action_open_location('/mnt')

        elif f'sw://opt' == cmd or f'sw://go' == cmd:
            self.action_open_location('/opt')

        elif f'sw://var' == cmd or f'sw://gv' == cmd:
            self.action_open_location('/var')

        elif f'sw://usr' == cmd or f'sw://gu' == cmd:
            self.action_open_location('/usr')

        elif f'sw://home' == cmd or f'sw://gh' == cmd:
            self.action_open_location(Path.home())

        elif f'sw://local' == cmd or f'sw://gl' == cmd:
            self.action_open_location(Path.home().joinpath('.local/share'))

        elif f'sw://tmp' == cmd or f'sw://gt' == cmd:
            self.action_open_location(sw_tmp)

        elif f'sw://cache' == cmd or f'sw://gd' == cmd:
            self.action_open_location(sw_fm_cache)

        elif f'sw://config' == cmd or f'sw://gc' == cmd:
            self.action_open_location(sw_app_config)

        elif f'sw://pfx' == cmd or f'sw://gp' == cmd:
            self.action_open_location(sw_pfx)

        elif f'sw://backup' == cmd or f'sw://gb' == cmd:
            self.action_open_location(sw_pfx_backup)

        elif f'sw://games' == cmd or f'sw://ga' == cmd:
            self.action_open_location(sw_games)

        elif f'sw://gw' == cmd:
            self.action_open_location(sw_wine)

        elif f'sw://touch' == cmd or f'sw://cw' == cmd:
            self.action_create_file()

        elif f'sw://mkdir' == cmd:
            self.action_create_directory()

        elif f'sw://delete' == cmd:
            self.action_delete_file()

        elif f'sw://dd' == cmd:
            self.action_cut_file()

        elif f'sw://yy' == cmd:
            self.action_copy_file()

        elif f'sw://pp' == cmd:
            self.action_paste_file()

        elif f'sw://gg' == cmd:
            self.left_files.action_scroll_home()

        elif f'sw://filter' in cmd:
            self.left_files.pattern = cmd.removeprefix('sw://filter').replace(' ', '')
            self.left_files.reload()

        elif f'sw://edit' == cmd:
            self.left_files.focus()
            self.action_open_editor()

        elif f'sw://inspect' == cmd:
            self.action_set_text()

        elif f'sw://open' in cmd:
            path = cmd.split(' ')[-1] if len(cmd.split(' ')) > 1 else None
            if path:
                self.action_open_location(path)

        elif f'sw://about' == cmd or f'sw://ma' == cmd:
            self.left_files.focus()
            self.app.switch_mode('about')

        elif f'sw://hotkeys' == cmd or f'sw://mh' == cmd:
            self.left_files.focus()
            self.action_show_hotkeys()

        elif f'sw://store' == cmd or f'sw://ml' == cmd:
            self.left_files.focus()
            self.action_toggle_launchers()

        elif f'sw://wine' == cmd or f'sw://mw' == cmd:
            self.left_files.focus()
            self.action_toggle_winebuilds()

        elif f'sw://shutdown' == cmd:
            app.action_shutdown()

        else:
            with self.app.suspend():
                run(f'clear && {execute}', shell=True)
                input(f"{msg.tt_dict['back_main']}: ")

    def action_run_file(self, path=None):
        """Emitted when a file in the directory tree is selected."""
        path = path if path else self.current_file

        if path and Path(path).is_file():
            mime_type = get_file_mimetype(f'{path}')

            if mime_type in exe_mime_dict.keys():
                environ['SW_EXEC'] = f'"{path}"'
                data = exe_data.get_(str(path))

                if data and data.get('path') and data.get('path') != 'None':
                    buttons = {
                        'run': msg.msg_dict['run'],
                        'open_with': msg.ctx_dict['open_with'],
                        'settings': msg.msg_dict['settings'],
                        'remove': msg.msg_dict['remove'],
                        'quit': msg.msg_dict['cancel'],
                    }
                else:
                    buttons = {
                        'run': msg.msg_dict['run'],
                        'open_with': msg.ctx_dict['open_with'],
                        'wine': msg.msg_dict['cs'],
                        'settings': msg.msg_dict['settings'],
                        'quit': msg.msg_dict['cancel'],
                    }
                self.app.push_screen(
                    DialogOptions(str(Path(path).name), buttons, align='center'),
                    self.check_answer
                )

            elif Path(path).suffix == '.swd':
                exe_path = get_swd_path(path)
                data = exe_data.get_(str(exe_path))
                app_path = data.get('path') if data else None

                if app_path and Path(app_path).exists():
                    environ['SW_EXEC'] = f'"{app_path}"'
                    buttons = {
                        'run': msg.ctx_dict['run'],
                        'open': msg.ctx_dict['open_location'],
                        'open_with': msg.ctx_dict['open_with'],
                        'settings': msg.ctx_dict['app_settings'],
                        'remove': msg.ctx_dict['remove'],
                        'quit': msg.msg_dict['cancel'],
                    }
                    self.app.push_screen(
                        DialogOptions(
                            str(Path(app_path).name), buttons, align='center'
                        ),
                        self.check_answer
                    )
                else:
                    self.app.push_screen(DialogInfo(msg.msg_dict['lnk_error']))

            elif Path(path).suffix == '.desktop':
                arg = [
                    x for x in Path(str(path)).read_text().splitlines() if 'Exec=' in x
                ]
                exe = str(arg[0].split('=')[1]) if arg else None
                environ['SW_EXEC'] = f'"{path}"'
                environ['SW_COMMANDLINE'] = f'{exe}'

                if exe:
                    buttons = {
                        'run_desktop': msg.msg_dict['run'],
                        'open_desktop': msg.msg_dict['open'],
                        'open_with': msg.ctx_dict['open_with'],
                        'quit': msg.msg_dict['cancel'],
                    }
                    self.app.push_screen(
                        DialogOptions(str(Path(path).name), buttons, align='center'),
                        self.check_answer
                    )
                else:
                    self.app.push_screen(DialogInfo(msg.msg_dict['lnk_error']))

            elif mime_type in text_mime_types:
                self.action_open_editor(path)

            elif mime_type in bin_mime_types:
                Popen(f'{path}', shell=True)
            else:
                Popen(f'sw_open --file "{path}"', shell=True)

    def check_answer(self, answer) -> None:
        """User response callback."""
        path = get_app_path()
        name = Path(path.strip('"')).name

        if answer['key'] == 'run':
            write_app_conf(Path(f'{path}'))
            self.app.sub_title = f'{name}'
            self.app.push_screen(Progress(str(name)))
            app.on_start()

        elif answer['key'] == 'run_desktop':
            with self.app.suspend():
                try:
                    run(f'hostexec {getenv("SW_COMMANDLINE")}', shell=True)
                except (Exception,):
                    run(f'{getenv("SW_COMMANDLINE")}', shell=True)
                input(f"{msg.tt_dict['back_main']}: ")

        elif answer['key'] == 'open':
            self.app.sub_title = f'{name}'
            self.action_open_location(str(Path(path.strip('"')).parent))

        elif answer['key'] == 'open_desktop':
            self.action_open_editor(path.strip('"'))

        elif answer['key'] == 'open_with':
            with self.app.suspend():
                Popen(f'sw_open --file {path}', shell=True)

        elif answer['key'] == 'wine':
            self.app.sub_title = f'{name}'
            app.request_create_shortcut()

        elif answer['key'] == 'settings':
            write_app_conf(Path(f'{path}'))
            if check_app_conf():
                self.app.sub_title = f'{name}'
                self.app.push_screen(SettingsView())
            else:
                self.error_message = [
                    msg.msg_dict['app_conf_incorrect'] + f' {name}.',
                    msg.msg_dict['app_conf_reset']
                ]
                app.on_error(self.error_message, app.check_reset)

        elif answer['key'] == 'remove':
            self.app.sub_title = f'{name}'
            exe_data.set_(get_app_path(), 'path', None)

            with self.app.suspend():
                on_pfx_remove()

            self.left_files.reload()

        elif answer['key'] == 'quit':
            self.app.sub_title = 'Cancel'

    def action_command_line(self) -> None:
        """call function in command line."""
        self.commandline.focus()
        self.commandline.value = 'sw://'

    def action_shell(self) -> None:
        """call function in command line."""
        with self.app.suspend():
            try:
                run('hostexec $SHELL', shell=True)
            except (Exception,):
                run('$SHELL', shell=True)

    def action_go_back(self) -> None:
        """Return to the parent directory."""
        if self.current_node:
            if self.current_node.parent:
                self.left_files.select_node(self.current_node.parent)
                chdir(self.left_files.path)
            else:
                self.action_open_location(Path(self.current_node.data.path).parent)
        else:
            self.action_open_location(Path(self.left_files.path).parent)

    def action_set_text(self) -> None:
        """Open selected file in a TextView."""
        if self.current_node:
            path = self.current_node.data.path if self.current_file else None
            if path and Path(path).is_file():
                self.app.push_screen(TextView(path=path))
                self.app.sub_title = str(path)

    def action_open_location(self, path=None):
        """Open the file location in a directory tree."""
        path = path if path else self.current_file

        if path and Path(path).is_file():
            try:
                self.left_files.path = str(Path(path).parent)
            except (IOError, OSError, PermissionError) as e:
                self.app.push_screen(DialogInfo(str(e)))
            else:
                chdir(self.left_files.path)
                self.left_files.reload()

        elif path and Path(path).is_dir():
            try:
                self.left_files.path = str(Path(path))
            except (IOError, OSError, PermissionError) as e:
                self.app.push_screen(DialogInfo(str(e)))
            else:
                chdir(self.left_files.path)
                self.left_files.reload()

    def action_open_editor(self, path=None):
        """Open the file in a text editor."""
        path = path if path else self.current_file
        if path and Path(path).is_file():
            with self.app.suspend():
                if app.EDITOR == 'micro':
                    run([f'{app.EDITOR}', f'{path}'])
                else:
                    try:
                        run(['hostexec', f'{app.EDITOR}', f'{path}'])
                    except (Exception,):
                        run([f'{app.EDITOR}', f'{path}'])

    def action_open_with(self, path=None):
        """Open the file using the launch program."""
        path = path if path else self.current_file
        if path:
            Popen(f'sw_open --file {path}', shell=True)

    def watch_show_sidebar(self, show_sidebar: bool) -> None:
        """Called when show_sidebar is modified."""
        self.app.set_class(show_sidebar, '-show-sidebar')

    def watch_show_output(self, show_output: bool) -> None:
        """Called when show_output is modified."""
        self.app.set_class(show_output, '-show-output')

    def watch_show_partitions(self, show_partitions: bool) -> None:
        """Called when show_partitions is modified."""
        self.app.set_class(show_partitions, '-show-partitions')

    def action_hide_panel(self):
        """"""
        if self.show_partitions:
            self.show_partitions = False
            self.left_files.focus()

        if self.show_sidebar:
            self.show_sidebar = False
            self.left_files.focus()

        if self.show_output:
            self.show_output = False
            self.left_files.focus()

    def action_show_hotkeys(self) -> None:
        """Called in response to key binding."""
        _bindings = self.HOTKEYS
        _dict = dict([
            (str(b.key), str(b.description)) for b in _bindings
        ])
        self.app.push_screen(
            DialogData(
                msg.ctx_dict['show_hotkeys'][0], _dict, height='80%', align='center'
            )
        )

    def action_toggle_partitions(self) -> None:
        """Called in response to key binding."""
        self.show_partitions = not self.show_partitions
        if self.show_partitions:
            self.table.focus()
        else:
            self.left_files.focus()

    def action_toggle_menu(self) -> None:
        """Called in response to key binding."""
        self.app.push_screen(
            DialogOptions(msg.tt_dict['view_menu'], Menu.options, align='center'),
            self.check_option_list
        )

    def action_toggle_bookmarks(self) -> None:
        """Called in response to key binding."""
        self.show_sidebar = not self.show_sidebar
        if self.show_sidebar:
            self.query_one('#bookmarks').focus()
        else:
            self.left_files.focus()

    def action_open_shortcuts(self) -> None:
        """Called in response to key binding."""
        self.action_open_location(sw_shortcuts)

    def action_toggle_launchers(self) -> None:
        """Called in response to key binding."""
        self.app.push_screen(LaunchersView())

    def action_toggle_winebuilds(self) -> None:
        """Called in response to key binding."""
        self.app.push_screen(WineBuildsView())

    def action_toggle_about(self) -> None:
        """Called in response to key binding."""
        self.app.switch_mode('about')

    def action_create_file(self) -> None:
        """Create new empty file."""
        path = self.current_file
        if path:
            parent = Path(path) if Path(path).is_dir() else Path(path).parent
            count = int()
            message = str(msg.ctx_dict['create'])
            new_file = parent.joinpath(f'sample{count}.txt')
            while new_file.exists():
                count += 1
                new_file = Path(parent).joinpath(f'sample{count}.txt')
            else:
                self.app.push_screen(
                    DialogEntry(message, str(new_file)), self.check_create_file)

    def check_create_file(self, answer) -> None:
        """Emitted when responding to create sybolic link request."""
        if answer['key'] == 'ok':
            target = answer['value']
            self.on_create_file(target)

    def on_create_file(self, path) -> None:
        """Create new empty file."""
        try:
            Path(path).touch()
        except (IOError, OSError, PermissionError) as e:
            self.notify(str(e))
        finally:
            self.left_files.reload()

    def action_create_directory(self) -> None:
        """Create new inode directory."""
        path = self.current_file
        if path:
            parent = Path(path) if Path(path).is_dir() else Path(path).parent
            count = int()
            message = msg.ctx_dict['create_dir'][0]
            new_dir = Path(parent).joinpath(f'{msg.msg_dict["new_dir"]} {count}')
            while new_dir.exists():
                count += 1
                new_dir = Path(parent).joinpath(f'{msg.msg_dict["new_dir"]} {count}')
            else:
                self.app.push_screen(
                    DialogEntry(message, str(new_dir)), self.check_create_dir)

    def check_create_dir(self, answer) -> None:
        """Emitted when responding to create sybolic link request."""
        if answer['key'] == 'ok':
            target = answer['value']
            self.on_create_dir(target)

    def on_create_dir(self, path) -> None:
        """Create new inode directory."""
        try:
            Path(path).mkdir(parents=True, exist_ok=True)
        except (IOError, OSError, PermissionError) as e:
            self.notify(str(e))
        finally:
            self.left_files.reload()

    def action_create_link(self) -> None:
        """Create symbolic link to current file or directory."""
        path = self.current_file
        if path:
            parent = Path(path) if Path(path).is_dir() else Path(path).parent
            count = int()
            # message = msg.ctx_dict['link'][0]
            name = Path(path).name
            link = parent.joinpath(f'{msg.msg_dict["file_link"]} {count} {name}')
            while link.exists():
                count += 1
                link = parent.joinpath(f'{msg.msg_dict["file_link"]} {count} {name}')
            else:
                self.on_create_link(link, path)

    def on_create_link(self, link, path) -> None:
        """Create symbolic link to current file or directory."""
        try:
            Path(link).symlink_to(Path(path))
        except (IOError, OSError, PermissionError) as e:
            self.notify(str(e))
        finally:
            self.left_files.reload()

    def action_rename_file(self) -> None:
        """Request to rename the current file or directory."""
        path = self.current_file if self.current_file else None
        if path:
            message = msg.msg_dict['rename']
            self.app.push_screen(DialogEntry(message, path), self.check_rename)

    def check_rename(self, answer) -> None:
        """Emitted when responding to a file rename request."""
        if answer['key'] == 'ok':
            path = self.current_file if self.current_file else None
            target = answer['value']
            if path:
                self.on_rename_file(path, target)

    def on_rename_file(self, path, target) -> None:
        """Rename the current file or directory."""
        target = Path(path).parent.joinpath(Path(target).name)
        try:
            Path(path).rename(target)
        except (IOError, OSError, PermissionError) as e:
            self.notify(str(e))
        finally:
            self.left_files.reload()

    def action_cut_file(self) -> None:
        """Cut the current file or directory."""
        self.clipboard_type = 'cut'
        self.app.copy_to_clipboard(str(self.current_file))
        Clipper().copy(str(self.current_file))
        self.notify(msg.msg_dict['copied_to_clipboard'])

    def on_cut_file(self, source) -> None:
        """Cut the current file or directory."""
        path = self.current_file
        if path:
            parent = Path(path) if Path(path).is_dir() else Path(path).parent
            source_name = Path(source).name
            target = Path(parent).joinpath(source_name)

            if Path(source) != target and Path(source) != Path(parent):
                if target.exists() and Path(source).name == target.name:
                    self.notify(msg.msg_dict['replace_override'])

                if Path(source).is_symlink():
                    shutil.move(source, target)

                elif Path(source).is_file():
                    shutil.move(source, target)

                elif Path(source).is_dir():
                    shutil.copytree(source, target, symlinks=True, dirs_exist_ok=True)
                    shutil.rmtree(source)
                else:
                    self.notify(f'File: {source} is not a file or directory')
            else:
                self.notify(msg.msg_dict['equal_paths'])

    def action_copy_file(self) -> None:
        """Copy the current file or directory."""
        self.clipboard_type = 'copy'
        self.app.copy_to_clipboard(str(self.current_file))
        Clipper().copy(str(self.current_file))
        self.notify(msg.msg_dict['copied_to_clipboard'])

    def on_copy_file(self, source) -> None:
        """Cut the current file or directory."""
        path = self.current_file
        if path:
            parent = Path(path) if Path(path).is_dir() else Path(path).parent
            source_name = Path(source).name
            target = Path(parent).joinpath(source_name)

            if Path(source) != target and Path(source) != Path(parent):
                if Path(source).is_file() or Path(source).is_symlink():
                    if target.exists() and Path(source).name == target.name:
                        Path(target).unlink()
                        shutil.copy2(source, target, follow_symlinks=False)
                    else:
                        shutil.copy2(source, target, follow_symlinks=False)
                elif Path(source).is_dir():
                    shutil.copytree(source, target, symlinks=True, dirs_exist_ok=True)
                else:
                    self.notify(f'File: {source} is not a file or directory')

            elif Path(source) == target and Path(source) != Path(parent):
                target = Path(f'{parent}').joinpath(f'{str_copy}_{source_name}')
                count = int()
                while target.exists():
                    count += 1
                    target = Path(
                        f'{parent}').joinpath(f'{str_copy}{count}_{source_name}')
                shutil.copy2(source, target, follow_symlinks=False)
            else:
                self.notify(msg.msg_dict['equal_paths'])

    def action_paste_file(self) -> None:
        """Paste the current file or directory."""
        if self.clipboard_type and self.clipboard_type == 'cut':
            self.on_cut_file(self.app.clipboard)
            self.left_files.reload()

        elif self.clipboard_type and self.clipboard_type == 'copy':
            self.on_copy_file(self.app.clipboard)
            self.left_files.reload()

    def action_delete_file(self) -> None:
        """Request to delete the current file or directory."""
        path = self.current_file if self.current_file else None
        if path:
            if Path(path).suffix == '.swd':
                exe_path = get_swd_path(path)
                data = exe_data.get_(str(exe_path))
                app_path = data.get('path') if data else None
                if app_path and Path(app_path).exists():
                    environ['SW_EXEC'] = f'"{app_path}"'
                    message = ' '.join(
                        [msg.msg_dict['remove_pfx'], str(Path(path).stem)])
                else:
                    message = ' '.join([msg.msg_dict['permanently_delete'], str(path)])
            else:
                message = ' '.join([msg.msg_dict['permanently_delete'], str(path)])
            self.app.push_screen(DialogQuestion(message), self.check_deletion)

    def check_deletion(self, answer) -> None:
        """Emitted when responding to a file deletion request."""
        if answer == 'ok':
            path = self.current_file if self.current_file else None
            if path:
                if Path(path).suffix == '.swd':
                    exe_data.set_(get_app_path(), 'path', None)
                    with self.app.suspend():
                        on_pfx_remove()
                    self.left_files.reload()
                else:
                    self.on_remove_file(path)

    def on_remove_file(self, path) -> None:
        """Delete current file or directory."""
        if Path(path).is_file() or Path(path).is_symlink():
            try:
                Path(path).unlink()
            except (IOError, OSError, PermissionError) as e:
                self.notify(str(e))
            finally:
                self.left_files.reload()

        elif Path(path).is_dir():
            try:
                shutil.rmtree(path)
            except (IOError, OSError, PermissionError) as e:
                self.notify(str(e))
            finally:
                self.left_files.reload()


class SysCommands(Provider):
    """A command provider."""

    # @property
    def get_themes(self) -> tuple:
        """The system commands to reveal to the command palette."""
        themes = tuple(
            (f'{theme.capitalize()}.theme', app.action_theme, 'Theme')
                for theme, _ in app.available_themes.items()
        )
        return themes

    async def startup(self) -> None:
        worker = self.app.run_worker(self.get_themes, thread=True)
        self.data = await worker.wait()

    # async def discover(self) -> Hits:
    #     for name, runnable, help_text in self._system_commands:
    #         yield DiscoveryHit(
    #             name,
    #             runnable,
    #             help=help_text,
    #         )

    async def search(self, query: str) -> Hits:
        matcher = self.matcher(query)
        assert isinstance(self.app, SwTerminalShell)
        for name, runnable, help_text in self.data:
            if (match := matcher.match(name)) > 0:
                yield Hit(
                    match,
                    matcher.highlight(name),
                    partial(runnable, name),
                    help=help_text,
                )


class RunCommands(Provider):
    """A command provider."""

    def read_data(self) -> list:
        """Get a list of Shortcuts."""
        data = list()
        for x in sw_shortcuts.iterdir():
            exe_path = get_swd_path(x)
            data.append(exe_data.get_(exe_path))
        return data

    async def startup(self) -> None:
        worker = self.app.run_worker(self.read_data, thread=True)
        self.data = await worker.wait()

    async def search(self, query: str) -> Hits:
        matcher = self.matcher(query)
        assert isinstance(self.app, SwTerminalShell)
        for data in self.data:
            command = f"Run {str(data.get('name'))}"
            score = matcher.match(command)
            if score > 0:
                yield Hit(
                    score,
                    matcher.highlight(command),
                    partial(self.app.open, data.get('path')),
                    #help="Run app in Vulkan or OpenGL mode",
                )


class SwTerminalShell(App[str]):
    """StartWine terminal shell."""

    if getenv("SW_EDITOR"):
        EDITOR = getenv("SW_EDITOR")
    elif getenv("EDITOR") and getenv("EDITOR"):
        EDITOR = getenv("EDITOR")
    else:
        EDITOR = 'micro'

    TITLE = 'StartWine Terminal Shell'
    SUB_TITLE = ''
    COMMANDS = {SysCommands} | {RunCommands}
    COMMAND_PALETTE_BINDING = 'ctrl+backslash'
    SCREENS = {
        "bsod": BSOD,
        "main_screen": MainScreen,
        "about": AboutView,
    }
    BINDINGS = [
        Binding("B", "app.push_screen('bsod')", "BSOD", show=False),
        Binding('!', 'splash', '', show=False),
        Binding('#', 'arc_theme', 'Toggle theme', show=False),
        Binding('shift+f2', 'screenshot', 'Screenshot', show=False, priority=True),
        Binding('shift+f3', 'screenrecord', 'Screen recording', show=False, priority=True),
        Binding('backslash,ctrl+f', 'command_palette', 'Command palette', show=False),
        Binding('q', 'shutdown', str(msg.msg_dict['shutdown']), show=False),
        Binding('ctrl+c', 'shutdown', str(msg.msg_dict['shutdown']), show=False),
        Binding('f10', 'shutdown', str(msg.msg_dict['shutdown']), show=True, key_display='F10'),
    ]
    MODES = {
        "bsod": BSOD,
        "main_screen": MainScreen,
        "about": AboutView,
    }
    watch_css = True
    dark = False if sw_cfg.get('color_scheme') == 'light' else True

    if custom_theme:
        CSS = CSS_THEME
    else:
        if dark:
            CSS = DARK_COLORS + CSS_THEME
        else:
            CSS = LIGHT_COLORS + CSS_THEME

    def __init__(self, root_path: str|Path = str(), path=str(), *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cfg = sw_cfg
        self.path = path
        self.theme_name = (
            sw_cfg.get('shell_theme') if sw_cfg.get('shell_theme') else 'darkside'
        )
        if self.path:
            self.root_path = root_path
            self.path_list = [p for p in Path(self.path).parent.iterdir()]
        else:
            self.root_path: str|Path = (
                str(self.cfg.get('current_dir'))
                    if self.cfg.get('current_dir') else root_path
            )
            self.path_list = [p for p in Path(self.root_path).parent.iterdir()]

        if self.cfg.get('hidden_files') == 'False':
            self.path_list = [p for p in self.path_list if not p.name.startswith(".")]

    def on_mount(self) -> None:
        """Set widget properties."""
        if custom_theme:
            self.register_theme(custom_theme)
            self.theme = str(self.theme_name)

        self.switch_mode("main_screen")

    def open(self, sw_exec: str) -> None:
        """Show options for the current executable."""
        self.sw_exec = sw_exec
        environ['SW_EXEC'] = f'"{sw_exec}"'
        buttons = {
            'run': msg.ctx_dict['run'],
            'open': msg.ctx_dict['open_location'],
            'open_with': msg.ctx_dict['open_with'],
            'settings': msg.ctx_dict['app_settings'],
            'remove': msg.ctx_dict['remove'],
            'quit': msg.msg_dict['cancel'],
        }
        self.app.push_screen(
            DialogOptions(str(Path(sw_exec).name), buttons, align='center'),
            self.check_answer
        )

    def check_answer(self, answer) -> None:
        """User response callback."""
        if answer['key'] == 'run':
            write_app_conf(Path(f'"{self.sw_exec}"'))
            self.sub_title = f'{Path(self.sw_exec).name}'
            self.push_screen(Progress(str(self.sw_exec)))
            self.on_start()

        elif answer['key'] == 'open':
            main_screen = self.screen_stack[0]
            main_screen.left_files.path = str(Path(self.sw_exec).parent)

        elif answer['key'] == 'settings':
            write_app_conf(Path(f'"{self.sw_exec}"'))

            if check_app_conf():
                self.app.sub_title = f'{Path(self.sw_exec).name}'
                self.app.push_screen(SettingsView())
            else:
                self.error_message = [
                    msg.msg_dict['app_conf_incorrect'] + f'{Path(self.sw_exec).name} ',
                    msg.msg_dict['app_conf_reset']
                ]
                self.on_error(self.error_message, self.check_reset)

        elif answer['key'] == 'remove':
            exe_data.set_(get_app_path(), 'path', None)

            with self.app.suspend():
                on_pfx_remove()

            main_screen = self.screen_stack[0]
            main_screen.left_files.reload()

        elif answer['key'] == 'cancel':
            self.app.sub_title = 'Cancel'

    def on_error(self, message: list, callback=None) -> None:
        """Error message handler."""
        self.app.push_screen(
            DialogQuestion("\n".join(message)),
            callback
        )

    def check_reset(self, answer):
        if answer == 'ok':
            on_app_conf_default()
            self.app.push_screen(SettingsView())

    def on_start(self):
        """Running application in vulkan or opengl mode."""

        app_path = get_app_path()
        swd_data = exe_data.get_(str(app_path))

        if swd_data and swd_data.get('id', {}):
            app_id = swd_data.get('id')
            app_id = app_id if app_id else ""
            exe_args = []
            epic_item_data = epic_exe_data.get(app_id, {})
            gog_item_data = gog_exe_data.get(app_id, {})

            if epic_item_data:
                get_epic_exe_args(app_id, exe_args)
                self._on_start()

            elif gog_item_data:
                exe_args = gog_item_data.get('args', {})
                if exe_args and exe_args != "None":
                    set_environ('SW_EXEC_ARGS', f'{exe_args}')
                    self._on_start()
                else:
                    self._on_start()
            else:
                self._on_start()
        else:
            self._on_start()

    def _on_start(self):
        """Running application in vulkan or opengl mode."""

        wine, exist = check_wine()
        if not exist:
            self.request_wine(wine)
        else:
            self.run_app()

    def get_wine_run(self, func_name: str, answer):
        """___download wine and run app___"""
        if answer == 'ok':
            with self.app.suspend():
                app_name = get_out()
                app_conf = sw_app_config.joinpath(app_name)
                app_conf_dict = app_conf_info(app_conf, switch_labels)

                if app_conf_dict.get('CONTROLLER'):
                    controller = str(app_conf_dict.get('CONTROLLER')).split('=')[1]
                    if controller == '0':
                        rc_dict['controller_active'] = False
                    else:
                        rc_dict['bind_profile'] = app_bind_profile
                echo_func_name(func_name)
            on_stop()
            self.app.pop_screen()

    def request_wine(self, wine):
        """___wine download request___"""

        wine_ver = wine.replace('-amd64', '').replace('-x86_64', '')
        wine_ver = ''.join([e for e in wine_ver if not e.isalpha()]).strip('-')
        name_ver = None
        func_wine = wine_download_dict.get(wine)

        if func_wine == 'WINE_1':
            name_ver = 'STAG_VER'

        if func_wine == 'WINE_2':
            name_ver = 'SP_VER'

        if func_wine == 'WINE_3':
            name_ver = 'GE_VER'

        if func_wine == 'WINE_4':
            name_ver = 'STAG_VER'

        if name_ver:
            func_name = f'{name_ver}="{wine_ver}" WINE_OK=1 {func_wine} && RUN_VULKAN'
            text_message = f"{wine} {msg.msg_dict['wine_not_exists']}"
            self.app.push_screen(
                screen=DialogQuestion(text_message),
                callback=partial(self.get_wine_run, func_name)
            )
        else:
            message = msg.msg_dict['wine_not_found']
            self.app.push_screen(DialogInfo(message))

    def request_create_shortcut(self):
        """Run create shortcut function."""
        app_path = get_app_path()
        app_name = get_out()
        _, latest_wine_dict, _ = get_wine_dicts()
        wine = latest_wine_dict.get('wine_proton_ge')

        if not wine:
            message = msg.msg_dict['wine_not_found']
            self.app.push_screen(DialogInfo(message))

        elif sw_wine.joinpath(f'{wine}', 'bin', 'wine').exists():
            with self.app.suspend():
                on_cs_wine(app_name, app_path, wine)
            self.notify(str(msg.msg_dict.get('shortcut_completed')))
        else:
            wine, exist = check_wine()
            if not exist:
                wine_ver = wine.replace('-amd64', '').replace('-x86_64', '')
                wine_ver = ''.join([e for e in wine_ver if not e.isalpha()]).strip('-')
                name_ver = 'GE_VER'
                func_wine = 'WINE_3'
                text_message = f"{wine} {msg.msg_dict['wine_not_exists']}"
                self.app.push_screen(
                    DialogQuestion(text_message),
                    partial(self.get_wine_create_shortcut, func_wine, name_ver, wine_ver, wine)
                )
            else:
                with self.app.suspend():
                    on_cs_wine(app_name, app_path, wine)
                self.notify(str(msg.msg_dict.get('shortcut_completed')))

    def get_wine_create_shortcut(self, func_wine, name_ver, wine_ver, wine, answer):
        """Download wine and create shortcut."""
        if answer == 'ok':
            app_path = get_app_path()
            app_name = get_out()
            with self.app.suspend():
                echo_wine(func_wine, name_ver, wine_ver)
                on_cs_wine(app_name, app_path, wine)

    def wait_exe_proc(self, app_suffix):
        """Waiting for the executing process to pop screen"""
        found = False
        while not found:
            sleep(0.1)
            found = find_process(app_suffix)
        else:
            self.app.pop_screen()

    def run_app(self):
        """Running the executable."""

        app_name = get_out()
        app_suffix = get_suffix()
        app_conf = sw_app_config.joinpath(f'{app_name}')
        app_conf_dict = app_conf_info(app_conf, switch_labels)
        debug_disable = app_conf_dict.get('WINEDBG_DISABLE', '=1').split('=')[1]
        opengl = app_conf_dict.get('OPENGL', '=0').split('=')[1]
        controller = app_conf_dict.get('CONTROLLER', '=0').split('=')[1]

        if controller == '0':
            rc_dict['controller_active'] = False
        else:
            rc_dict['bind_profile'] = app_bind_profile

        if opengl == '1':
            if debug_disable == '1':
                thread_start = Thread(target=run_opengl)
                thread_start.start()
            else:
                thread_start = Thread(target=debug_opengl)
                thread_start.start()
        else:
            if debug_disable == '1':
                thread_start = Thread(target=run_vulkan)
                thread_start.start()
            else:
                thread_start = Thread(target=debug_vulkan)

        t_info = Thread(target=self.wait_exe_proc, args=(app_suffix,))
        t_info.start()

    def action_splash(self) -> None:
        """"""
        self.app.push_screen(Progress(str_oops))

    def action_theme(self, theme: str) -> None:
        """Toggle and refresh css theme."""
        self.theme = f'{theme}'.lower().replace('.theme', '')
        self.refresh_css()

    def action_screenshot(
            self, filename: str | None = None, path: str | None = None) -> None:
        """Save an SVG file containing the current contents of the screen."""
        if not path:
            filename = f'sw_screenshot_{int(time())}.svg'
            path = str(Path.home())
        else:
            filename = f'sw_screenshot_{int(time())}.svg'

        self.save_screenshot(filename, path)

    def action_screenrecord(self) -> None:
        """capture the screen or window for record."""
        run_screencast()

    def action_shutdown(self) -> None:
        """Called in response to key binding."""
        self.app.push_screen(DialogQuit(), self.check_quit)

    def check_quit(self, answer) -> None:
        """Exit the application callback."""
        if answer:
            main_screen = self.screen_stack[0]
            if main_screen.current_file:
                path = main_screen.current_file
                parent = Path(path) if Path(path).is_dir() else Path(path).parent
                self.cfg['current_dir'] = str(parent)
            else:
                self.cfg['current_dir'] = str(main_screen.left_files.path)

            if not main_screen.show_sidebar:
                self.cfg['control_panel'] = 'hide'
            else:
                self.cfg['control_panel'] = 'show'

            if main_screen.left_files.show_hidden_files:
                self.cfg['hidden_files'] = 'True'
            else:
                self.cfg['hidden_files'] = 'False'

            self.cfg['shell_theme'] = f'{self.theme}'

            write_json_data(sw_exe_data_json, exe_data)
            write_menu_conf(self.cfg)

            self.app.exit('Shutdown')


if __name__ == '__main__':
    path = str()
    root_path: str|Path = str()

    if len(argv) >= 2 and Path(str(argv[1])).exists():
        if Path(str(argv[1])).is_dir():
            root_path = str(argv[1])
        else:
            path = str(argv[1])
            root_path = str(Path(str(argv[1])).parent)

    mp_event = mp.Event()
    mgr = mp.Manager()
    kc_dict = mgr.dict()
    vol_dict = mgr.dict()
    rc_dict = mgr.dict()
    rc_dict['controller_active'] = True
    rc_dict['bind_profile'] = default_gui_bind_profile

    if input_active:
        rc_proc =  mp.Process(
            target=run_zero_device_redirection, args=(mp_event, rc_dict)
        )
        process_workers.append(rc_proc)
        rc_proc.start()

    app = SwTerminalShell(root_path=root_path, path=path)
    app.run()

    for p in process_workers:
        p.terminate()
