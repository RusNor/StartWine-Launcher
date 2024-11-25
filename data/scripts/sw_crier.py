#!/usr/bin/env python3

import os
import sys
import time
from sys import argv, exit
from pathlib import Path
import shutil
from warnings import filterwarnings
import json
import urllib.request
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from subprocess import run
import itertools
from collections import deque
from time import sleep
import io
import struct
import pefile
from PIL import Image

if os.getenv('GSK_RENDERER') == 'vulkan':
    os.environ['ENABLE_VKBASALT'] = '0'

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Gdk', '4.0')
from gi.repository import Gdk, Gio, GLib, Gtk, Gsk, Graphene, Pango
from sw_data import Msg as msg
from sw_data import TermColors as tc
filterwarnings('ignore')

#############################___PATH_DATA___:

program_name = 'StartWine'
sw_scripts = Path(__file__).absolute().parent
sw_path = Path(sw_scripts).parent.parent
sw_default_path = Path(f'{Path.home()}/.local/share/StartWine')
sw_menu_json = Path(f'{sw_scripts}/sw_menu.json')
sw_css_dark = Path(f'{sw_path}/data/img/sw_themes/css/dark/gtk.css')
sw_css_light = Path(f'{sw_path}/data/img/sw_themes/css/light/gtk.css')
sw_css_custom = Path(f'{sw_path}/data/img/sw_themes/css/custom/gtk.css')
sw_logo = Path(f'{sw_path}/data/img/gui_icons/sw_large_light.svg')
icon_folder = f'{sw_path}/data/img/gui_icons/hicolor/symbolic/apps/folder-symbolic.svg'

ICON_DIR_ENTRY_FORMAT = (
    'GRPICONDIRENTRY',
    ('B,Width', 'B,Height','B,ColorCount','B,Reserved',
     'H,Planes','H,BitCount','I,BytesInRes','H,ID')
)
ICON_DIR_FORMAT = ('GRPICONDIR', ('H,Reserved', 'H,Type','H,Count'))

############################___SET_CSS_STYLE___:

gtk_css_provider = Gtk.CssProvider()

if sw_menu_json.exists():

    with open(sw_menu_json, 'r', encoding='utf-8') as f:
        dict_ini = json.load(f)
        f.close()

    if dict_ini['color_scheme'] == 'dark':

        gtk_css_provider.load_from_file(Gio.File.new_for_path(bytes(sw_css_dark)))
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            gtk_css_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )
    elif dict_ini['color_scheme'] == 'light':
        gtk_css_provider.load_from_file(Gio.File.new_for_path(bytes(sw_css_light)))
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            gtk_css_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )
    elif dict_ini['color_scheme'] == 'custom':
        gtk_css_provider.load_from_file(Gio.File.new_for_path(bytes(sw_css_custom)))
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            gtk_css_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )


class SourceSelectionWindow(Gtk.Application):
    """___Dialog window for selecting source to capture___"""
    def __init__(self, app=None, mon_dict=None, xid_dict=None, callback=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        GLib.set_prgname(program_name)
        self.mon_dict = mon_dict
        self.xid_dict = xid_dict
        self.callback = callback

    def do_activate(self):
        """______"""

        win_store = Gio.ListStore()
        win_factory = Gtk.SignalListItemFactory()
        win_factory.connect('setup',self.factory_setup)
        win_factory.connect('bind', self.factory_bind)
        win_model = Gtk.MultiSelection.new(win_store)
        win_view = Gtk.ListView(css_name='sw_listview', single_click_activate=True)
        win_view.set_model(win_model)
        win_view.set_factory(win_factory)
        win_view.connect('activate', self.view_activate)

        mon_store = Gio.ListStore()
        mon_factory = Gtk.SignalListItemFactory()
        mon_factory.connect('setup', self.factory_setup)
        mon_factory.connect('bind', self.factory_bind)
        mon_model = Gtk.MultiSelection.new(mon_store)
        mon_view = Gtk.ListView(css_name='sw_listview', single_click_activate=True)
        mon_view.set_model(mon_model)
        mon_view.set_factory(mon_factory)
        mon_view.connect('activate', self.view_activate)

        stack = Gtk.Stack(
            css_name='sw_stack', transition_duration=250,
            transition_type=Gtk.StackTransitionType.SLIDE_LEFT_RIGHT
        )
        stack.add_titled(mon_view, 'screens', 'Screens')
        stack.add_titled(win_view, 'windows', 'Windows')

        stack_switcher = Gtk.StackSwitcher(css_name='sw_stackswitcher', stack=stack)

        box = Gtk.Box(css_name='sw_box', orientation=Gtk.Orientation.VERTICAL)
        box.append(stack_switcher)
        box.append(stack)

        self.update_store(win_store, 'windows')
        self.update_store(mon_store, 'monitors')

        self.window = Gtk.Window(css_name='sw_window', application=self, child=box)
        self.window.remove_css_class('background')
        self.window.add_css_class('sw_background')
        self.window.set_default_size(930, 420)
        self.window.connect('close-request', self.terminate)
        self.window.present()

    def update_store(self, store, name):
        """______"""

        store.remove_all()
        if name == 'monitors':
            count = -1
            for num, mon in self.mon_dict.items():
                string = f"{mon['name']}:{mon['model']}"
                item = Gtk.Label(name=f'screen_{num}', label=string)
                store.append(item)

        if name == 'windows':
            count = -1
            for xid, name in self.xid_dict.items():
                count += 1
                item = Gtk.Label(name=f'{xid}', label=f'{name}')
                store.append(item)

    def factory_setup(self, factory, item_list):
        """______"""

        label = Gtk.Label(
            css_name='sw_box_view', xalign=0, ellipsize=Pango.EllipsizeMode.END
        )
        box = Gtk.Box(css_name='sw_box', hexpand=True)
        box.append(label)
        item_list.set_child(box)

    def factory_bind(self, factory, item_list):
        """______"""

        item = item_list.get_item()
        box = item_list.get_child()
        label = box.get_first_child()
        label.set_name(item.get_name())
        label.set_label(item.get_label())

    def view_activate(self, view, position):
        """______"""

        item = view.get_model().get_item(position)
        xid = item.get_name()
        name = item.get_label()
        self.window.close()
        self.quit()
        if self.callback:
            data = None
            if 'screen_' in xid:
                data = self.mon_dict.get(position)
            else:
                data = self.xid_dict.get(xid)

            return self.callback(xid, name, data)

    def terminate(self, window):
        """______"""

        if self.callback:
            self.callback(None, None, None)


class SwPathManager(Gtk.Application):
    """StartWine install path chooser."""

    def __init__(self, source_path):
        super().__init__(flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.source_path = source_path
        self.local_path = f'{Path.home()}/.local/share/StartWine'
        self.window = None
        self.label_btn_ok = None
        self.btn_ok = None
        self.headerbar = None
        self.entry_main = None
        self.label_main = None
        self.image = None
        self.paintable_icon = None
        self.image_folder = None
        self.btn_main = None
        self.box_entry = None
        self.grid_content = None
        #self.connect('activate', self.activate)

    def do_activate(self):

        self.window = Gtk.Window(
                                application=self,
                                css_name='sw_window',
                                default_height=320,
                                default_width=640,
        )
        self.window.remove_css_class('background')
        self.window.add_css_class('sw_background')
        self.window.set_resizable(False)

        self.label_btn_ok = Gtk.Label(css_name='sw_label', label=msg.msg_dict['ok'])
        self.btn_ok = Gtk.Button(css_name='sw_button_accept')
        self.btn_ok.set_valign(Gtk.Align.CENTER)
        self.btn_ok.set_child(self.label_btn_ok)
        self.btn_ok.set_size_request(120, 16)
        self.btn_ok.connect('clicked', self._accept_response)

        self.headerbar = Gtk.HeaderBar(
                        css_name='sw_header_top',
                        show_title_buttons=False,
        )
        self.headerbar.pack_end(self.btn_ok)
        self.headerbar.set_title_widget(Gtk.Label())

        self.entry_main = Gtk.Entry(
                                    css_name='sw_entry',
                                    margin_start=8,
                                    margin_end=8,
                                    hexpand=True,
                                    valign=Gtk.Align.CENTER,
                                    text=str(self.source_path),
        )
        self.label_main = Gtk.Label(css_name='sw_label', label=msg.msg_dict['select_sw_path'])

        self.image = Gtk.Picture(css_name='sw_picture')
        self.image.set_content_fit(Gtk.ContentFit.COVER)
        self.image.set_margin_start(64)
        self.image.set_margin_end(64)
        self.image.set_size_request(-1, 128)
        self.paintable_icon = Gtk.IconPaintable.new_for_file(
                                Gio.File.new_for_path(f'{sw_logo}'), 1024, 1
        )
        self.image.set_paintable(self.paintable_icon)

        self.image_folder = Gtk.Image(css_name='sw_image')
        self.image_folder.set_from_file(icon_folder)

        self.btn_main = Gtk.Button(css_name='sw_button')
        self.btn_main.set_halign(Gtk.Align.END)
        self.btn_main.set_child(self.image_folder)
        self.btn_main.set_tooltip_markup(msg.msg_dict['select_sw_path'])
        self.btn_main.connect('clicked', self._select_path)

        self.box_entry = Gtk.Box(css_name='sw_box', orientation=Gtk.Orientation.HORIZONTAL)
        self.box_entry.append(self.entry_main)
        self.box_entry.append(self.btn_main)

        self.grid_content = Gtk.Grid(css_name='sw_grid')
        self.grid_content.set_row_spacing(16)
        self.grid_content.set_column_spacing(32)
        self.grid_content.set_margin_top(32)
        self.grid_content.set_margin_bottom(32)
        self.grid_content.set_margin_start(32)
        self.grid_content.set_margin_end(32)
        self.grid_content.attach(self.image, 0, 1, 1, 1)
        self.grid_content.attach(self.label_main, 0, 2, 1, 1)
        self.grid_content.attach(self.box_entry, 0, 3, 1, 1)

        self.window.set_titlebar(self.headerbar)
        self.window.set_child(self.grid_content)
        self.window.present()
        self.entry_main.select_region(0,0)

    def _select_path(self, _button):

        title = msg.msg_dict['change_directory']
        dialog = SwDialogDirectory(title=title)
        dialog.select_folder(
                    parent=self.window,
                    cancellable=Gio.Cancellable(),
                    callback=self._get_folder,
        )

    def _get_folder(self, dialog, res):

        try:
            result = dialog.select_folder_finish(res)
        except GLib.GError:
            pass
        else:
            self.entry_main.set_text(str(result.get_path()))

    def _accept_response(self, _button):

        dest_path = Path(self.entry_main.get_text())

        if not str(dest_path).endswith('StartWine'):
            if dest_path.exists():
                dest_path = Path(f'{dest_path}/StartWine')
            else:
                self.label_main.add_css_class('warning')
                self.label_main.set_label(msg.msg_dict['correct_path'])
                print(f'path {dest_path} not exists')
                return f'path {dest_path} not exists'

        if dest_path == Path(self.source_path):
            try_create_swrc(dest_path)
            print('run StartWine...')
            self.window.close()
        else:
            if dest_path.exists():
                print('path exists, skip...')
                if (str(dest_path) != str(self.local_path)
                        and Path(self.local_path).exists()):
                    shutil.rmtree(self.local_path)

                try_create_swrc(dest_path)
                print('run StartWine...')
                self.window.close()
            else:
                if str(dest_path).endswith('StartWine'):
                    print('move StartWine...')
                    if not Path(dest_path).parent.exists():
                        Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
                    try:
                        shutil.move(self.source_path, dest_path)
                    except IOError as e:
                        print(e)
                    else:
                        try_create_swrc(dest_path)
                self.window.close()

        return None


def try_create_swrc(dest_path):
    """___write new program path to rc config___"""

    if not Path(f'{Path.home()}/.config').exists():
        Path(f'{Path.home()}/.config').mkdir(parents=True, exist_ok=True)

    with open(f'{Path.home()}/.config/swrc', 'w', encoding='utf-8') as rc:
        rc.write(f'{dest_path}')
        rc.close()


def run_menu():
    """___run menu from config path___"""

    if Path(f'{Path.home()}/.config/swrc').exists():
        with open(f'{Path.home()}/.config/swrc', 'r', encoding='utf-8') as rc:
            dest_path = rc.read().splitlines()[0]
            rc.close()
        run(f'{dest_path}/data/scripts/sw_menu.py', start_new_session=True, check=False)
    else:
        print(f'{Path.home()}/.config/swrc not found...')


class SwCrier(Gtk.Application):
    """Application for providing a set of dialog windows."""
    def __init__(
                self, app=None, title=None, text_message=None, message_type=None,
                response=None, file=None, mime_types=None, *args, **kwargs):
        super().__init__(
                        flags=Gio.ApplicationFlags.FLAGS_NONE,
                        *args, **kwargs
        )
        GLib.set_prgname(program_name)

        if app is None:
            self.app = self
        else:
            self.app = app

        self.title = title
        self.text_message = text_message
        self.message_type = message_type
        self.response = response
        self.file = file
        self.mime_types = mime_types
        self.connect('activate', self.activate)

    def activate(self, app):
        """Activate application."""

        if self.message_type in ['INFO', 'ERROR', 'WARNING']:
            self.info()

        elif self.message_type == 'QUESTION':
            self.question()

        elif self.message_type == 'TEXT':
            self.text_editor()

        elif self.message_type == 'FILE':
            self.file_selector()

        else:
            on_helper()

    def info(self):
        """Building the info dialog window."""

        header = Gtk.HeaderBar(
                        css_name='sw_header_top',
                        show_title_buttons=False,
        )
        label = Gtk.Label(
                        css_name='sw_label',
                        margin_top=8,
                        margin_bottom=8,
                        margin_start=8,
                        margin_end=8,
                        wrap=True,
                        natural_wrap_mode=True,
                        label=self.text_message,
        )
        btn_ok = Gtk.Button(
                        css_name='sw_button_accept',
                        label=msg.msg_dict['ok'],
                        valign=Gtk.Align.CENTER,
                        margin_start=4,
                        margin_end=4,
                        margin_bottom=4,
                        margin_top=4,
        )
        btn_ok.set_size_request(120, 16)
        box_content = Gtk.Box(
                        css_name='sw_message_box',
                        orientation=Gtk.Orientation.VERTICAL,
                        spacing=8,
        )
        dialog = Gtk.Window(
                        css_name='sw_window',
                        application=self.app,
                        titlebar=header,
                        title=f'{program_name} {self.message_type}',
                        child=box_content,
                        default_height=120,
                        default_width=540,
        )
        dialog.remove_css_class('background')
        dialog.add_css_class('sw_background')
        box_content.append(label)
        header.pack_end(btn_ok)
        btn_ok.connect('clicked', self.cb_btn, dialog)
        btn_ok.grab_focus()
        dialog.set_default_size(540, 120)
        dialog.set_size_request(540, 120)
        dialog.set_resizable(False)
        dialog.present()

    def question(self):
        """Building the question dialog window."""

        if self.response is None:
            self.response = [msg.msg_dict['yes'], msg.msg_dict['no']]

        header = Gtk.HeaderBar(
                        css_name='sw_header_top',
                        show_title_buttons=False,
        )
        label = Gtk.Label(
                        css_name='sw_label',
                        margin_top=8,
                        margin_bottom=8,
                        margin_start=8,
                        margin_end=8,
                        wrap=True,
                        natural_wrap_mode=True,
                        label=self.text_message,
        )
        btn_yes = Gtk.Button(
                        css_name='sw_button_accept',
                        label=self.response[0],
                        valign=Gtk.Align.CENTER,
                        margin_start=4,
                        margin_end=4,
                        margin_bottom=4,
                        margin_top=4,
        )
        btn_yes.set_size_request(120, 16)

        btn_no = Gtk.Button(
                        css_name='sw_button_cancel',
                        label=self.response[1],
                        valign=Gtk.Align.CENTER,
                        margin_start=4,
                        margin_end=4,
                        margin_bottom=4,
                        margin_top=4,
        )
        btn_no.set_size_request(120, 16)

        box_content = Gtk.Box(
                        css_name='sw_message_box',
                        orientation=Gtk.Orientation.VERTICAL,
                        spacing=8,
        )
        dialog = Gtk.Window(
                        css_name='sw_window',
                        application=self.app,
                        titlebar=header,
                        title=f'{program_name} {self.message_type}',
                        child=box_content,
                        default_height=120,
                        default_width=540,
        )
        dialog.remove_css_class('background')
        dialog.add_css_class('sw_background')
        box_content.append(label)
        header.pack_end(btn_yes)
        header.pack_start(btn_no)
        btn_yes.connect('clicked', self.cb_btn, dialog)
        btn_yes.grab_focus()
        btn_no.connect('clicked', self.cb_btn_cancel)

        ctrl_key = Gtk.EventControllerKey()
        ctrl_key.connect('key_pressed', self.key_pressed, dialog)
        dialog.add_controller(ctrl_key)
        dialog.set_default_size(540, 120)
        dialog.set_size_request(540, 120)
        dialog.set_resizable(False)
        dialog.present()

    def key_pressed(self, _ctrl_key, keyval, _keycode, _state, _dialog):
        if keyval == Gdk.KEY_Escape:
            return self.cb_btn_cancel(None)

    def text_editor(self):
        """Building the text editor view."""

        if Path(self.file).is_file():
            title = str(Path(self.file).stem)
            text = Path(self.file).read_text(encoding='utf-8')
        else:
            title = str(self.file)
            text = str(self.file)

        header = Gtk.HeaderBar(
                            css_name='sw_header_top',
                            show_title_buttons=False
        )
        dialog = Gtk.Window(
                        css_name='sw_window',
                        application=self.app,
                        titlebar=header,
                        title=title,
        )
        dialog.remove_css_class('background')
        dialog.add_css_class('sw_background')
        dialog.set_default_size(1280, 720)

        btn_save = Gtk.Button(
                        css_name='sw_button_accept',
                        label=msg.msg_dict['save'],
                        valign=Gtk.Align.CENTER,
        )
        btn_save.set_size_request(120, 16)

        btn_cancel = Gtk.Button(
                        css_name='sw_button_cancel',
                        label=msg.msg_dict['cancel'],
                        valign=Gtk.Align.CENTER,
        )
        btn_cancel.set_size_request(120, 16)

        textview = Gtk.TextView(
                        css_name='sw_textview',
                        vexpand=True,
                        hexpand=True,
                        wrap_mode=Gtk.WrapMode.WORD,
                        left_margin=16,
        )
        textview.remove_css_class('view')
        textview.add_css_class('text')
        buffer = Gtk.TextBuffer()
        textview.set_buffer(buffer)
        buffer.set_text(text)

        scrolled = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    propagate_natural_height=True,
                                    propagate_natural_width=True,
        )
        btn_save.connect('clicked', self.cb_btn_save, dialog, buffer)
        btn_cancel.connect('clicked', self.cb_btn_cancel)
        header.pack_end(btn_save)
        header.pack_start(btn_cancel)
        scrolled.set_child(textview)
        dialog.set_child(scrolled)
        dialog.present()

    def file_selector(self, window=None, data=None, *args, **kwargs):
        """Calling the file selection dialog window."""

        if window is None:
            window = Gtk.Window(application=self, css_name='sw_window')

        dialog = SwDialogDirectory(
                    path=self.file, title=self.title, mime_types=self.mime_types,
                    *args, **kwargs
        )
        if data:
            dialog.select_folder(
                        parent=window,
                        cancellable=Gio.Cancellable(),
                        callback=self.cb_select_folder,
                        user_data=data,
            )

        elif Path(self.file).is_file():
            dialog.open(
                        parent=window,
                        cancellable=Gio.Cancellable(),
                        callback=self.cb_select_file,
                        user_data=data,
            )
        elif Path(self.file).is_dir():
            dialog.select_folder(
                        parent=window,
                        cancellable=Gio.Cancellable(),
                        callback=self.cb_select_folder,
                        user_data=data,
            )

    def cb_select_file(self, dialog, res, data):
        """Callback from the folder selection dialog."""

        try:
            result = dialog.open_finish(res)
        except GLib.GError:
            _path = '1'
        else:
            _path = result.get_path()
            if data:
                try:
                    Path(_path).write_text(data, encoding='utf-8')
                except (OSError, IOError) as e:
                    print(e)

        self.quit()
        print(_path)
        return _path

    def cb_select_folder(self, dialog, res, data):
        """Callback from the folder selection dialog."""

        try:
            result = dialog.select_folder_finish(res)
        except GLib.GError:
            _path = '1'
        else:
            _path = result.get_path()
            if data:
                name = time.strftime('%Y%M%d%S')
                try:
                    Path(f'{_path}/{name}.txt').write_text(data, encoding='utf-8')
                except (OSError, IOError) as e:
                    print(e)

        if _path is None:
            _path = '1'

        self.quit()
        print(_path)
        return _path

    def cb_btn(self, _btn, dialog):
        """Callback from the accept button."""

        dialog.close()
        self.quit()
        p = '0'
        print(p)
        #return p

    def cb_btn_save(self, _btn, dialog, buffer):
        """Callback from the save button."""

        startiter, enditer = buffer.get_bounds()
        buffer_text = buffer.get_text(startiter, enditer, False)

        if Path(self.file).is_file():
            Path(self.file).write_text(buffer_text, encoding='utf-8')
            self.quit()
        else:
            self.file_selector(window=dialog, data=buffer_text)

        p = '0'
        print(p)
        return p

    def cb_btn_cancel(self, _btn):
        """Callback from the cancel button."""

        self.quit()
        p = '1'
        print(p)
        return p


class SwDialogEntry(Gtk.Widget):
    """___Custom dialog widget with entry row___"""
    def __init__(
            self, app=None, title=None, text_message=None, response=None, func=None,
            num=None, string_list=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.app = app
        self.title = title
        self.text_message = text_message
        self.response = response
        self.func = func
        self.num = num
        self.string_list = string_list
        self.window = self.app.get_windows()[0]
        self.box = None
        self.dialog_entry()

    def get_child(self):
        """___get dialog child box___"""
        return self.box

    def dialog_entry(self):
        """___dialog window with entry row___"""

        headerbar = Gtk.HeaderBar(
                            css_name='sw_header_top',
                            show_title_buttons=False,
        )
        self.box = Gtk.Box(
                    css_name='sw_box',
                    orientation=Gtk.Orientation.HORIZONTAL,
        )
        self.dialog = Gtk.Window(
                            css_name='sw_window',
                            application=self.app,
                            transient_for=self.window,
                            modal=True,
                            titlebar=headerbar,
                            title=self.title,
                            child=self.box,
        )
        self.dialog.remove_css_class('background')
        self.dialog.add_css_class('sw_background')

        btn_cancel = Gtk.Button(
                            css_name='sw_button_cancel',
                            label=msg.msg_dict['cancel'],
                            valign=Gtk.Align.CENTER,
        )
        btn_cancel.set_size_request(120, 16)

        btn_accept = Gtk.Button(
                            css_name='sw_button_accept',
                            label=self.response,
                            valign=Gtk.Align.CENTER,
        )
        btn_accept.set_size_request(120, 16)

        btn_accept.connect(
            'clicked', cb_btn_response, self.window, self.dialog, self.func[0]
        )
        btn_cancel.connect(
            'clicked', cb_btn_response, self.window, self.dialog, self.func[1]
        )
        headerbar.pack_start(btn_cancel)
        headerbar.pack_end(btn_accept)
        btn_accept.grab_focus()

        for i in range(self.num):
            entry = Gtk.Entry(
                            css_name='sw_entry',
                            margin_start=8,
                            margin_end=8,
                            hexpand=True,
                            valign=Gtk.Align.CENTER,
                            text=self.text_message[i]
            )
            entry.connect(
                'activate', cb_btn_response, self.window, self.dialog, self.func[0]
            )
            self.box.append(entry)

        dropdown_menu = Gtk.DropDown(
                                    css_name='sw_dropdown',
                                    valign=Gtk.Align.CENTER,
                                    margin_end=8,
                                    show_arrow=True,
        )
        if self.string_list is not None:
            model = Gtk.StringList()
            for string in self.string_list:
                model.append(string)

            dropdown_menu.set_size_request(96, -1)
            dropdown_menu.set_model(model)
            self.box.append(dropdown_menu)

        self.ctrl_key = Gtk.EventControllerKey()
        self.ctrl_key.connect('key_pressed', self.key_pressed, self.dialog)
        self.dialog.add_controller(self.ctrl_key)
        self.dialog.set_size_request(540, 120)
        self.dialog.set_resizable(False)
        self.dialog.present()
        return self.dialog

    def key_pressed(self, _ctrl_key_press, keyval, keycode, state, dialog):
        if keyval == Gdk.KEY_Escape:
            return self.dialog.close()


class SwDialogQuestion(Gtk.Widget):
    """___custom dialog question widget for text message___"""
    def __init__(
            self, _app=None, title=None, text_message=None, _response=None, func=None,
            *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.app = _app
        self.title = title
        self.text_message = text_message
        self.response = _response
        self.func = func
        self.window = self.app.get_windows()[0]
        self.dialog = None
        self.width = 540
        self.height = 120

        if self.title is None:
            self.title = ""

        if self.text_message is None:
            self.text_message = ['', '']

        self.dialog_question()

    def dialog_question(self):
        """___dialog question window for text message___"""

        title_label = Gtk.Label(
                        css_name='sw_label_title',
                        margin_top=8,
                        margin_bottom=8,
                        margin_start=8,
                        margin_end=8,
                        wrap=True,
                        natural_wrap_mode=True,
                        label=self.text_message[0],
        )
        label = Gtk.Label(
                        css_name='sw_label_desc',
                        margin_top=8,
                        margin_bottom=8,
                        margin_start=8,
                        margin_end=8,
                        wrap=True,
                        natural_wrap_mode=True,
                        label=self.text_message[1],
        )
        box_image = Gtk.Box(
                        css_name='sw_box',
                        orientation=Gtk.Orientation.VERTICAL,
                        spacing=8,
                        halign=Gtk.Align.CENTER,
        )
        box_message = Gtk.Box(
                        css_name='sw_message_box',
                        orientation=Gtk.Orientation.VERTICAL,
                        spacing=8,
        )
        box_message.append(box_image)
        box_message.append(title_label)
        box_message.append(label)

        scrolled = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    vexpand=True,
                                    hexpand=True,
                                    propagate_natural_height=True,
                                    child=box_message
        )
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        headerbar = Gtk.HeaderBar(
                                css_name='sw_header_top',
                                show_title_buttons=False
        )
        box = Gtk.Box(
                    css_name='sw_box',
                    orientation=Gtk.Orientation.VERTICAL,
                    spacing=8,
                    vexpand=True,
        )
        box.append(scrolled)

        box_btn = Gtk.Box(
                        css_name='sw_box',
                        orientation=Gtk.Orientation.VERTICAL,
                        spacing=8,
                        margin_start=16,
                        margin_end=16,
                        margin_top=16,
                        margin_bottom=16,
        )
        box.append(box_btn)

        self.dialog = Gtk.Window(
                            css_name='sw_window',
                            application=self.app,
                            titlebar=headerbar,
                            title=self.title,
                            modal=True,
                            transient_for=self.window,
                            child=box,
        )
        self.dialog.remove_css_class('background')
        self.dialog.add_css_class('sw_background')

        if self.response is None:
            self.response = [msg.msg_dict['yes'], msg.msg_dict['no']]
            btn_yes = Gtk.Button(
                                css_name='sw_button_accept',
                                label=self.response[0],
                                valign=Gtk.Align.CENTER,
            )
            btn_yes.set_size_request(96, 16)
            btn_no = Gtk.Button(
                                css_name='sw_button_cancel',
                                label=self.response[1],
                                vexpand=True,
                                valign=Gtk.Align.CENTER,
            )
            btn_no.set_size_request(96, 16)
            btn_yes.connect(
                'clicked', cb_btn_response, self.window, self.dialog, self.func[0]
            )
            btn_no.connect(
                'clicked', cb_btn_response, self.window, self.dialog, self.func[1]
            )
            headerbar.pack_start(btn_no)
            headerbar.pack_end(btn_yes)
            btn_yes.grab_focus()
        else:
            count = -1
            for res, func in zip(self.response, self.func):
                count += 1
                if res == msg.msg_dict['cancel']:
                    btn = Gtk.Button(css_name='sw_button_cancel', label=res)
                else:
                    btn = Gtk.Button(css_name='sw_button', label=res)

                btn.set_name(str(count))
                btn.connect('clicked', cb_btn_response, self.window, self.dialog, func)
                box_btn.append(btn)

        self.ctrl_key = Gtk.EventControllerKey()
        self.ctrl_key.connect('key_pressed', self.key_pressed, self.dialog)
        self.dialog.add_controller(self.ctrl_key)
        self.dialog.set_size_request(self.width, self.height)
        self.dialog.set_resizable(False)
        self.dialog.present()

    def key_pressed(self, _ctrl_key, keyval, _keycode, _state, _dialog):
        if keyval == Gdk.KEY_Escape:
            return self.dialog.close()


def cb_btn_response(self, parent_window, dialog, func):
    """___response calback when accept button clicked___"""

    if not parent_window.get_visible():
        if (self.get_label() != msg.msg_dict['run']
                and self.get_label() != msg.msg_dict['cancel']):

            parent_window.set_hide_on_close(False)
            parent_window.set_visible(True)
            parent_window.unminimize()

    if func is not None:
        if isinstance(func, dict):
            fn = list(func)[0]
            args = func[fn]

        elif isinstance(func, tuple):
            fn = func[0]
            args = func[1]

        elif isinstance(func, list):
            fn = func[0]
            args = func
            args.remove(fn)
        else:
            args = None

        dialog.close()

        if args is None:
            return func()

        return fn(*args)

    return dialog.close()


class SwDialogDirectory(Gtk.FileDialog):
    """___file chooser dialog window___"""
    def __init__(self, path=None, title=None, mime_types=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.path = path
        self.title = title
        self.mime_types = mime_types
        self.mime_list = [
            'inode/directory',
            'inode/symlink',
            'application/x-ms-dos-executable',
            'application/x-ms-shortcut',
            'application/x-bat',
            'application/x-msi',
            'application/x-msdownload',
            'application/vnd.microsoft.portable-executable'
            'application/x-wine-extension-msp',
            'application/x-msdos-program',
            'application/x-executable',
            'application/x-shellscript',
            'application/vnd.appimage'
            'application/x-desktop',
            'application/x-zerosize'
            'text/plain',
            'text/x-python',
            'text/x-python3',
            'text/win-bat',
            'text/x-ms-regedit',
            'text/x-log',
        ]
        self.dialog_directory()

    def dialog_directory(self):
        """___dialog window for choose directory___"""

        if self.path is None:
            self.path = f'{Path.home()}'

        if self.title is None:
            self.title = 'Files'

        if self.mime_types is None:
            self.mime_types = self.mime_list

        file = Gio.File.new_for_commandline_arg(self.path)

        if Path(self.path).is_file():
            self.set_initial_file(file)

        elif Path(self.path).is_dir():
            self.set_initial_folder(file)

        file_filter = Gtk.FileFilter()
        file_filter.set_name('files')

        for mime_type in self.mime_types:
            file_filter.add_mime_type(mime_type)

        self.set_accept_label('_OK')
        self.set_default_filter(file_filter)
        self.set_modal(True)
        self.set_title(self.title)

        return self


class SwWidget(Gtk.Grid):
    """___custom widget with different effects"""
    def __init__(
                self,
                width=0,
                height=0,
                child=None,
                file=None,
                texture=None,
                effects=None,
                blur=0.0,
                corner=0.0,
                border_width=0.0,
                border_color='#00000000',
                shadow_color='#00000000',
                background_color='#00000000',
                *args, **kwargs):
        super().__init__(*args, **kwargs)
        if effects is None:
            effects = []
        self.width = width
        self.height = height
        self.child = child
        self.file = file
        self.effects = effects
        self.blur = blur
        self.border_width = border_width
        self.corner = corner
        self.background = Gdk.RGBA()
        self.background.parse(background_color)
        self.border = Gdk.RGBA()
        self.border.parse(border_color)
        self.shadow = Gdk.RGBA()
        self.shadow.parse(shadow_color)
        self.tick = None
        self.texture = texture
        self.flip_texture = None
        self.content_fit = None
        self.shadow_color = None
        self.border_color = None
        self.background_color = None
        self.snapshot = None
        self.add_tick_callback(self._tick_callback)

    def do_snapshot(self, snapshot):
        """..."""

        self.snapshot = snapshot
        x = self.width
        y = self.height

        rect = Graphene.Rect().init(0, 0, x, y)
        rrect = Gsk.RoundedRect()
        rrect.init_from_rect(rect, self.corner)

        if 'rounded' in self.effects:
            self.snapshot.pop()
            self.snapshot.push_rounded_clip(rrect)

        if 'blur' in self.effects:
            self.snapshot.push_blur(self.blur)

        if 'reverse' in self.effects:
            point = Graphene.Point()
            point.x = x
            point.y = y
            self.snapshot.translate(point)
            self.snapshot.rotate(180.0)

        if self.file is not None and self.texture is not None:
            trilinear = Gsk.ScalingFilter.TRILINEAR
            self.snapshot.append_scaled_texture(self.texture, trilinear, rect)

        if 'shadow' in self.effects:
            snapshot.append_inset_shadow(
                        rrect, self.shadow, 0, 0, self.border_width, self.blur
            )

        if 'gradient' in self.effects:
            start_point = Graphene.Point()
            end_point = Graphene.Point()
            start_point.x = 0
            start_point.y = 0
            end_point.x = x/2
            end_point.y = y/2
            stop_a = Gsk.ColorStop()
            stop_b = Gsk.ColorStop()
            stop_a.offset = 0.8
            stop_b.offset = 0.8
            stop_a.color = self.background
            stop_b.color = self.shadow
            stops = [stop_a, stop_b]
            snapshot.append_linear_gradient(rect, start_point, end_point, stops)

        if 'gradient' not in self.effects:
            builder = Gsk.PathBuilder.new()
            builder.add_rounded_rect(rrect)
            builder_path = builder.to_path()
            snapshot.append_fill(builder_path, Gsk.FillRule.WINDING, self.background)

        if 'blur' in self.effects:
            self.snapshot.pop()

        self.child = self.get_first_child()
        while self.child is not None:
            if self.child is not None:
                self.snapshot_child(self.child, self.snapshot)
                self.child = self.child.get_next_sibling()

    def do_size_allocate(self, width, height, baseline):
        """..."""
        self.width = width
        self.height = height

    def set_file(self, file: str):
        """..."""
        self.file = file
        if self.file is not None:
            try:
                self.texture = Gdk.Texture.new_from_filename(self.file)
            except GLib.Error as e:
                print(e.message)

        self.queue_draw()

    def set_texture(self, texture: Gdk.Texture):
        """..."""
        self.texture = texture

    def set_effects(self, effects: list):
        """..."""
        self.effects = effects

    def set_content_fit(self, content_fit):
        """..."""
        self.content_fit = content_fit

    def set_background(self, background_color: str):
        """..."""
        self.background_color = background_color
        self.background.parse(background_color)

    def get_background(self):
        """..."""
        return self.background.to_string()

    def set_shadow_color(self, shadow_color: str):
        """..."""
        self.shadow_color = shadow_color
        self.shadow.parse(shadow_color)

    def get_shadow_color(self):
        """..."""
        return self.shadow.to_string()

    def set_border_color(self, border_color: str):
        """..."""
        self.border_color = border_color
        self.border.parse(border_color)

    def get_border_color(self):
        """..."""
        return self.border.to_string()

    def _tick_callback(self, _snapshot, _frame_clock):
        """..."""
        self.width = self.get_width()
        self.height = self.get_height()
        self.child = self.get_first_child()
        self.queue_draw()

        return True


class SwProgressBar(Gtk.Widget):
    """___custom progress bar widget with some effects___"""
    def __init__(
                self,
                color='#aaaaaa',
                background_color='#000000',
                shadow_color='#2080ff',
                border_color='#2080ff',
                progress_foreground='#ff8020',
                progress_background='#2080ff',
                width=240,
                height=24,
                font_family='Sans',
                font_size=12,
                border=0,
                corner=32,
                text=None,
                show_text=False,
                fraction=None,
                pulse_step=250,
                style='circle',
                css_provider=None,
                orientation='horizontal',
                *args, **kwargs):
        super().__init__(
            *args, **kwargs,
            width_request=240, height_request=24)

        self.snapshot = None
        self.width = width
        self.height = height
        self.font_family = font_family
        self.font_size = font_size
        self.border = border
        self.corner = corner
        self.blur = 0.0

        self.ch = 0
        self.path_list = []
        self.rect_list = []

        self.counter = None
        self.tick = None
        self.max_count = 0
        self.text = text
        self.show_text = show_text
        self.fraction = fraction
        self.pulse_step = pulse_step
        self.timeout = None

        self.direct = list(range(10, 255))
        self.reverse = list(range(10, 255))
        self.reverse.reverse()
        self.iter_color = itertools.cycle(self.direct + self.reverse)
        self.orientation = orientation
        self.style = style
        self.css_provider = css_provider
        self.style_list = ['circle', 'rectangle', 'dash']

        self.fg = Gdk.RGBA()
        self.bg = Gdk.RGBA()
        self.sd = Gdk.RGBA()
        self.bd = Gdk.RGBA()
        self.p_fg = Gdk.RGBA()
        self.p_bg = Gdk.RGBA()

        self.color = color
        self.background_color = background_color
        self.shadow_color = shadow_color
        self.border_color = border_color
        self.progress_foreground = progress_foreground
        self.progress_background = progress_background

        self.fg.parse(color)
        self.bg.parse(background_color)
        self.sd.parse(shadow_color)
        self.bd.parse(border_color)
        self.p_fg.parse(progress_foreground)
        self.p_bg.parse(progress_background)

        self.set_size_request(self.width, self.height)

        if self.css_provider is not None:
            self.set_define_colors()

    def get_define_colors(self):
        """Get current define colors from css provider"""

        css_list = self.css_provider.to_string().splitlines()
        define_colors = {}
        for x in css_list:
            if '@define-color sw_' in x:
                if len([x.split(' ')[2].strip(';')]) > 0:
                    define_colors[x.split(' ')[1]] = [x.split(' ')[2].strip(';')][0]

        return define_colors

    def set_define_colors(self):
        """Set define color for custom widget from css theme."""

        dcolors = self.get_define_colors()

        if len(dcolors) != 0:
            self.set_foreground(dcolors['sw_invert_bg_color'])
            self.set_background(dcolors['sw_bg_color'])
            self.set_progress_color(
                                    dcolors['sw_invert_progress_color'],
                                    dcolors['sw_accent_fg_color'],
            )
            self.set_border_color(dcolors['sw_accent_fg_color'])
            self.set_shadow_color(dcolors['sw_accent_bg_color'])

    def check_tick_callback(self):
        """Check tick callback added or not."""

        if self.tick is not None:
            self.remove_tick_callback(self.tick)

        if self.counter is not None or self.fraction is not None:
            self.tick = self.add_tick_callback(self._tick_callback)

    def do_snapshot(self, snapshot):
        """Do snapshot of widget"""

        self.snapshot = snapshot
        self._bar(snapshot)

    def _text_layout(self, _snapshot):
        """Create Pango layout context"""

        font = Pango.FontDescription.new()
        font.set_family(self.font_family)
        font.set_size(self.font_size * Pango.SCALE)
        context = self.get_pango_context()
        layout = Pango.Layout(context)
        layout.set_font_description(font)
        metrics = context.get_metrics(font, context.get_language())
        self.ch = metrics.get_height() / 1000

        return layout, metrics

    def _set_pango_layout(self, snapshot, layout, metrics, x, _y):
        """Set Pango layout"""

        point = Graphene.Point()
        chr_w = metrics.get_approximate_char_width() / 1000
        dgt_w = metrics.get_approximate_digit_width() / 1000

        if self.text is not None:
            len_dgt = len([e for e in self.text if e.isdigit()])
            len_chr = len([e for e in self.text if e.isalpha()])
            point.x = x/2 - (len_chr * chr_w + len_dgt * dgt_w) / 2
            point.y = 0
            layout.set_text(self.text)
            snapshot.save()
            snapshot.translate(point)
            snapshot.append_layout(layout, self.fg)
            snapshot.restore()

        elif self.fraction is not None:
            text = f'{round(self.fraction * 100, 1)} %'
            len_dgt = len([e for e in text if e.isdigit()])
            len_chr = len([e for e in text if e.isalpha()])
            point.x = x/2 - (len_chr * chr_w + len_dgt * dgt_w) / 2
            point.y = 0
            layout.set_text(text)
            snapshot.save()
            snapshot.translate(point)
            snapshot.append_layout(layout, self.fg)
            snapshot.restore()

    def _set_shadow(self, snapshot, x, y):
        """Shadow and border layouts"""

        rectt = Graphene.Rect().init(0, self.ch, x, y)
        rrect = Gsk.RoundedRect()
        rrect.init_from_rect(rectt, self.corner)
        snapshot.append_outset_shadow(
                            rrect, self.sd, 0, 0, 1.0 + self.border, self.blur
        )
        builder = Gsk.PathBuilder.new()
        builder.add_rounded_rect(rrect)
        builder_path = builder.to_path()
        snapshot.append_fill(builder_path, Gsk.FillRule.WINDING, self.bg)

        snapshot.append_border(
                        rrect,
                        [self.border, self.border, self.border, self.border],
                        [self.bd, self.bd, self.bd, self.bd]
        )

    def _bar(self, snapshot):
        """Do snapshot of progressbar widget"""

        x = self.width
        y = self.height
        mc = self.max_count + 2
        self.ch = 0
        self.path_list = []
        self.rect_list = []

        if self.get_show_text():
            layout, metrics = self._text_layout(snapshot)
            self._set_shadow(snapshot, x, y)
            self._set_pango_layout(snapshot, layout, metrics, x, y)
        else:
            self._set_shadow(snapshot, x, y)

        builder = Gsk.PathBuilder.new()
        for i in range(0, self.max_count):
            _rect = Graphene.Rect()
            _point = Graphene.Point()
            _round = Gsk.RoundedRect()

            if self.style == 'circle':

                if self.orientation == 'horizontal':
                    _point.init(i * x/mc + 3*x/(2*mc), y/2 + self.ch)
                    builder.add_circle(_point, (y/(2*mc) + x/(2*mc))/4)

                elif self.orientation == 'vertical':
                    _point.init(x/2, y - 3*y/(2*mc) + self.ch - (i * y/mc))
                    builder.add_circle(_point, (y/(2*mc) + x/(2*mc))/4)

            elif self.style == 'rectangle':

                if self.orientation == 'horizontal':
                    _rect.init(
                        i * x/mc + 5*x/(4*mc), self.ch + y/3, x/(2*mc), y/3
                    )
                elif self.orientation == 'vertical':
                    _rect.init(
                        x/3, y*(5*mc - 9)/(5*mc) + self.ch - (i * y/mc), x/3, y/(2*mc)
                    )
                _round.init_from_rect(_rect, self.corner)
                builder.add_rounded_rect(_round)

            elif self.style == 'dash':

                if self.orientation == 'horizontal':
                    _rect.init(
                        i * x/mc + 5*x/(4*mc), self.ch + 47*y/96, x/(2*mc), y/48
                    )
                elif self.orientation == 'vertical':
                    _rect.init(
                        x/2 - x/48, y*(5*mc - 9)/(5*mc) + self.ch - (i * y/mc), x/24, y/48
                    )
                _round.init_from_rect(_rect, self.corner)
                builder.add_rounded_rect(_round)

            builder_path = builder.to_path()
            snapshot.append_fill(builder_path, Gsk.FillRule.WINDING, self.p_bg)
            self.path_list.append(builder_path)

        if self.counter is not None:
            count = self.counter
            for i in range(0, count):
                self.snapshot.append_fill(
                    self.path_list[i], Gsk.FillRule.WINDING, self.p_fg)

        if self.fraction is not None:
            count = round(int(self.fraction * self.max_count))
            for i in range(0, count):
                self.snapshot.append_fill(
                    self.path_list[i], Gsk.FillRule.WINDING, self.p_fg)

    def do_size_allocate(self, width, height, _baseline):
        """..."""

        self.width = width
        self.height = height

        if self.orientation == 'horizontal':

            if width < 160:
                self.width = 160

            if height < 16:
                self.height = 16

            self.max_count = int(self.width / 20) - 2

        if self.orientation == 'vertical':

            if width < 16:
                self.width = 16

            if height < 160:
                self.height = 160

            self.max_count = int(self.height / 20) - 2

    def set_fraction(self, fraction: int):
        """..."""
        self.check_tick_callback()
        self.fraction = fraction
        self.queue_draw()

    def get_fraction(self):
        """..."""
        return self.fraction

    def set_text(self, text: str):
        """..."""
        self.text = text

    def get_text(self):
        """..."""
        return self.text

    def set_show_text(self, show: bool):
        """..."""
        self.show_text = show

    def get_show_text(self):
        """..."""
        return self.show_text

    def set_pulse_step(self, step: int):
        """..."""
        self.pulse_step = step

    def get_pulse_step(self):
        """..."""
        return self.pulse_step

    def set_font_size(self, size: int):
        """..."""
        self.font_size = size

    def get_font_size(self):
        """..."""
        return self.font_size

    def set_foreground(self, color: str):
        """..."""
        self.color = color
        self.fg.parse(color)

    def get_foreground(self):
        """..."""
        return self.fg.to_string()

    def set_background(self, background_color: str):
        """..."""
        self.background_color = background_color
        self.bg.parse(background_color)

    def get_background(self):
        """..."""
        return self.bg.to_string()

    def set_shadow_color(self, shadow_color: str):
        """..."""
        self.shadow_color = shadow_color
        self.sd.parse(shadow_color)

    def get_shadow_color(self):
        """..."""
        return self.sd.to_string()

    def set_border_color(self, border_color: str):
        """..."""
        self.border_color = border_color
        self.bd.parse(border_color)

    def get_border_color(self):
        """..."""
        return self.bd.to_string()

    def set_progress_color(self, color: str, background_color: str):
        """..."""
        self.progress_foreground = color
        self.progress_background = background_color
        self.p_fg.parse(color)
        self.p_bg.parse(background_color)

    def get_progress_color(self):
        """..."""
        return self.p_fg.to_string(), self.p_bg.to_string()

    def set_size(self, width: int, height: int):
        """..."""
        self.width = width
        self.height = height
        self.set_size_request(self.width, self.height)

    def get_size(self):
        """..."""
        return [self.get_width(), self.get_height()]

    def set_border(self, width: int):
        """..."""
        self.border = width

    def get_border(self):
        """..."""
        return self.border

    def set_corner(self, corner: int):
        """..."""
        self.corner = corner

    def get_corner(self):
        """..."""
        return self.corner

    def set_style(self, style: str):
        """..."""
        if style not in self.style_list:
            print(f'Value error: The style must be one of {self.style_list}')
        else:
            self.style = style

    def get_style(self):
        """..."""
        return self.style

    def set_orientation(self, orientation: str):
        """..."""
        if orientation in ['horizontal', 'vertical']:
            self.orientation = orientation
        else:
            print('Value error: The orientation must be horizontal or vertical')

    def pulse(self):
        """..."""
        self.check_tick_callback()
        return self._update()

    def stop(self):
        """..."""
        GLib.Source.remove(self.timeout)
        self.counter = None
        self.queue_draw()

    def _update(self):
        """..."""
        self.fraction = 0.0
        if self.counter is None:
            self.counter = 0

        self.counter += 1
        if self.counter == self.max_count + 1:
            self.counter = 0

        self.queue_draw()
        return True

    def _tick_callback(self, _snapshot, _frame_clock):
        """..."""
        next_color = next(self.iter_color)
        self.blur = float(next_color / 5)
        self.queue_draw()
        return True


def download(_url, _filename):
    """___download content from url___"""

    request_headers = {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, '
            'like Gecko) Chrome/30.0.1599.101 Safari/537.36'
        ),
        'Accept-Language': 'fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Connection': 'keep-alive',
        'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
    }
    try:
        _response = urlopen(Request(_url, headers=request_headers))
    except HTTPError as e_1:
        print(e_1)
        try:
            urllib.request.urlretrieve(_url, _filename)
        except HTTPError as e_2:
            print(e_2)
            exit(1)
        else:
            exit(0)
    else:
        with _response as res, open(_filename, 'wb') as out:
            shutil.copyfileobj(res, out)
            res.close()
            exit(0)

def get_total_size(_url, _filename):

    totalsize = None
    try:
        totalsize = int(urlopen(_url).info().get(name='Content-Length'))
    except (Exception,):
        totalsize = None

    if totalsize is None:
        with urlopen(_url) as u:
            totalsize = u.length

    sys.stdout.write(f'Total size: {totalsize}\t{Path(_filename).name}\n')
    return totalsize

def download_progress(data, queue):

    bar_len = 50
    while True:
        for x in data:
            filename = x[0]
            totalsize = x[2]
            if Path(filename).exists():
                current = os.stat(filename).st_size
                if totalsize is None:
                    percent = 1.0
                    progress = '~' * bar_len
                    string = f'\r{tc.GREEN}[ {progress} ] {tc.YELLOW}[unknown]% {tc.VIOLET}{Path(filename).name}{tc.END}'
                else:
                    pac = "\u15E7"
                    percent = current / totalsize
                    block = int(round(bar_len * percent))
                    progress = '\u2501' * block + f'{pac}' + ('\u2022' * (bar_len - block))
                    string = f'\r{tc.GREEN}[ {progress} ] {tc.YELLOW}{round(percent*100)}% {tc.VIOLET}{Path(filename).name}{tc.END}'

                queue.append([string, percent])
        else:
            for i in range(len(queue)):
                sys.stdout.write('\x1b[1A\x1b[2K')
            else:
                for i in range(len(queue)):
                    sys.stdout.write(queue[i][0] + '\n')

            if sum([q[1] for q in queue]) == len(data):
                print('Done')
                return False


class SwDownloadBar(Gtk.Application):
    """___Custom application window with progress bar___"""

    def __init__(self, _url, _filename):
        super().__init__(
                        #application_id='ru.project.Crier',
                        flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        GLib.set_prgname(program_name)
        self.percent = 0
        self.exit = None
        self.url = _url
        self.totalsize = None

        try:
            with urlopen(_url) as u:
                self.totalsize = u.length
        except HTTPError as e:
            print(e)

        self.filename = _filename
        self.program_name = 'StartWine'
        self.window = None
        self.progressbar = None
        # self.connect('activate', self.activate)
        GLib.timeout_add(1000, self.update)

    def do_activate(self):
        """___activate application___"""

        self.window = Gtk.Window(
                            css_name='sw_window',
                            application=self,
                            default_height=120,
                            default_width=640,
                            resizable=False,
        )
        self.window.remove_css_class('background')
        self.window.add_css_class('sw_background')
        self.window.set_title(f'{self.program_name}')
        header = Gtk.HeaderBar(
                            css_name='sw_header_top',
                            show_title_buttons=False,
        )
        self.progressbar = SwProgressBar(
                                        css_name='sw_progressbar',
                                        hexpand=True,
                                        vexpand=True,
                                        margin_bottom=32,
                                        css_provider=gtk_css_provider,
        )
        self.progressbar.set_show_text(True)
        self.progressbar.set_size_request(420, 24)
        label = Gtk.Label(css_name='sw_label')
        name = str(list(self.filename.replace('/','\n').split())[-1])
        label.set_label(name)
        grid = Gtk.Grid(css_name='sw_message_box')
        grid.set_margin_start(32)
        grid.set_margin_end(32)
        grid.set_margin_bottom(8)
        grid.set_margin_top(8)
        grid.set_row_spacing(16)
        grid.attach(label, 0, 0, 1, 1)
        grid.attach(self.progressbar, 0, 1, 1, 1)
        self.window.set_titlebar(header)
        self.window.set_child(grid)
        self.add_window(self.window)
        self.window.grab_focus()
        self.window.present()

    def update(self):
        """___update self progress bar___"""

        if self.totalsize is None:
            print('Impossible to determine total size. URL not found...')
            self.window.close()
            self.exit = self.quit()
            exit(1)

        if Path(self.filename).exists():
            current = os.stat(self.filename).st_size
            self.percent = current / self.totalsize

            if self.exit is None:
                self.progressbar.set_fraction(self.percent)

            if self.percent >= 1:
                print('Download_completed_successfully.')
                self.window.close()
                self.exit = self.quit()

        return True


def extract_tar(_filename, _path):
    """___extract tar archive___"""

    if Path(_filename).exists():
        taro = tarfile.open(_filename)

        for member_info in taro.getmembers():
            taro.extract(member_info, path=_path)
            print('Extracting: ' + member_info.name)

        taro.close()
        print('Extraction_completed_successfully.')
        exit(0)
    else:
        print(f'{_filename} not exists...')
        exit(1)


def extract_zip(_filename, _path):
    """___extract zip archive___"""

    if Path(_filename).exists():
        zipo = zipfile.ZipFile(_filename)

        for member_info in zipo.namelist():
            print('Extracting: ' + member_info)
            zipo.extract(member_info, path=_path)

        zipo.close()
        print('Extraction_completed_successfully.')
        exit(0)
    else:
        print(f'{_filename} not exists...')
        exit(1)


class SwExtractBar(Gtk.Application):
    """___Custom application window with progress bar___"""

    def __init__(self, _filename, _path):
        super().__init__(
                        #application_id='ru.project.Crier',
                        flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        GLib.set_prgname(program_name)
        self.exit = None
        self.filename = _filename
        self.path = _path
        self.program_name = 'StartWine'
        self.window = None
        self.header = None
        self.progressbar = None
        self.label = None
        self.name = None
        self.grid = None

        # self.connect('activate', self.activate)
        GLib.timeout_add(100, self.update)

    def do_activate(self):
        """___activate application___"""

        self.window = Gtk.Window(
                                css_name='sw_window',
                                application=self,
                                default_height=120,
                                default_width=540,
                                resizable=False,
        )
        self.window.remove_css_class('background')
        self.window.add_css_class('sw_background')
        self.window.set_title(f'{self.program_name}')
        self.header = Gtk.HeaderBar(
                                    css_name='sw_header_top',
                                    show_title_buttons=False,
        )
        self.progressbar = SwProgressBar(
                                        css_name='sw_progressbar',
                                        hexpand=True,
                                        vexpand=True,
                                        margin_bottom=32,
                                        css_provider=gtk_css_provider,
        )
        self.progressbar.set_show_text(True)
        self.progressbar.set_text(Path(self.filename).name)
        self.label = Gtk.Label(css_name='sw_label')
        self.name = str('Extraction...')
        self.label.set_label(self.name)
        self.grid = Gtk.Grid(css_name='sw_message_box')
        self.grid.set_margin_start(32)
        self.grid.set_margin_end(32)
        self.grid.set_margin_bottom(8)
        self.grid.set_margin_top(8)
        self.grid.set_row_spacing(8)
        self.grid.attach(self.label, 0, 0, 1, 1)
        self.grid.attach(self.progressbar, 0, 1, 1, 1)
        self.window.set_titlebar(self.header)
        self.window.set_child(self.grid)
        self.add_window(self.window)
        self.window.grab_focus()
        self.window.present()

    def update(self):
        """___update self progress bar___"""

        if self.exit is not None:
            self.window.close()
            self.quit()
            return False

        self.progressbar.pulse()
        return True


    def extract_tar(self, _filename, _path):
        """___extract tar archive___"""

        if Path(_filename).exists():
            taro = tarfile.open(_filename)

            for member_info in taro.getmembers():
                taro.extract(member_info, path=_path)
                print('Extracting: ' + member_info.name)

            taro.close()
            print('Extraction_completed_successfully.')
            self.exit = 0
        else:
            print(f'{_filename} not exists...')
            self.exit = 1
            exit(1)

    def extract_zip(self, _filename, _path):
        """___extract zip archive___"""

        if Path(_filename).exists():
            zipo = zipfile.ZipFile(_filename)

            for member_info in zipo.namelist():
                print('Extracting: ' + member_info)
                zipo.extract(member_info, path=_path)

            zipo.close()
            print('Extraction_completed_successfully.')
            self.exit = 0
        else:
            print(f'{_filename} not exists...')
            self.exit = 1
            exit(1)


class SwExtractIcon:
    """Loads an executable from the given filename or data (raw bytes)."""

    def __init__(self, _filename=None, data=None):

        self._pefile = pefile.PE(name=_filename, data=data, fast_load=True)
        self._pefile.parse_data_directories(
                        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'])

        if not hasattr(self._pefile, 'DIRECTORY_ENTRY_RESOURCE'):
            self.rt_group_icon = None
            self.rt_icon = None
            print(f'{tc.RED}SW_EXTRACT_ICON: File has no icon{tc.END}')
        else:
            res = {r.id: r for r in reversed(self._pefile.DIRECTORY_ENTRY_RESOURCE.entries)}
            self.rt_group_icon = res.get(pefile.RESOURCE_TYPE['RT_GROUP_ICON'])
            self.rt_icon = res.get(pefile.RESOURCE_TYPE['RT_ICON'])

    def list_group_icons(self):
        """Returns all group icon entries as a list of (name, offset) tuples."""

        return [(e.struct.Name, e.struct.OffsetToData)
                for e in self.rt_group_icon.directory.entries]

    def _get_group_icon_entries(self, _num=0):
        """Returns the group icon entries for the specified group icon in the executable."""

        group_icon = self.rt_group_icon.directory.entries[_num]
        if group_icon.struct.DataIsDirectory:
            group_icon = group_icon.directory.entries[0]

        rva = group_icon.data.struct.OffsetToData
        size = group_icon.data.struct.Size
        data = self._pefile.get_data(rva, size)
        file_offset = self._pefile.get_offset_from_rva(rva)

        grp_icon_dir = self._pefile.__unpack_data__(ICON_DIR_FORMAT, data, file_offset)

        if grp_icon_dir.Reserved:
            raise RuntimeError(
                'Invalid group icon definition (got Reserved=%s instead of 0)' % hex(grp_icon_dir.Reserved))

        grp_icons = []
        icon_offset = grp_icon_dir.sizeof()
        for idx in range(grp_icon_dir.Count):
            grp_icon = self._pefile.__unpack_data__(
                ICON_DIR_ENTRY_FORMAT, data[icon_offset:], file_offset+icon_offset
            )
            icon_offset += grp_icon.sizeof()
            grp_icons.append(grp_icon)

        return grp_icons

    def _get_icon_data(self, icon_ids):
        """Return a list of raw icon images corresponding to the icon IDs given."""

        icons = []
        entry_list = {e.id: e for e in self.rt_icon.directory.entries}
        for idx in icon_ids:
            entry_lst = entry_list[idx]
            icon_entry = entry_lst.directory.entries[0]
            rva = icon_entry.data.struct.OffsetToData
            size = icon_entry.data.struct.Size
            data = self._pefile.get_data(rva, size)
            icons.append(data)

        return icons

    def _write_ico(self, fd, _num=0):
        """Writes ICO data to a file descriptor."""

        if not self.rt_group_icon or not self.rt_icon:
            print(f'{tc.RED}SW_EXTRACT_ICON: File has no group icon resources{tc.END}')
            return
        else:
            group_icons = self._get_group_icon_entries(_num=_num)
            icon_images = self._get_icon_data([g.ID for g in group_icons])
            icons = list(zip(group_icons, icon_images))
            assert len(group_icons) == len(icon_images)
            fd.write(b'\x00\x00')
            fd.write(struct.pack('<H', 1))
            fd.write(struct.pack('<H', len(icons)))

            data_offset = 6 + (len(icons) * 16)
            for i in icons:
                group_icon, icon_data = i
                fd.write(group_icon.__pack__()[:12])
                fd.write(struct.pack('<I', data_offset))
                data_offset += len(icon_data)

            for i in icons:
                group_icon, icon_data = i
                fd.write(icon_data)

    def extract_icon(self, fname, _num=0):
        """Writes ICO data of the requested group icon ID to fname."""

        with open(fname, 'wb') as fb:
            self._write_ico(fb, _num=_num)

    def get_icon(self, _num=0):
        """Returns ICO data as a BytesIO() instance, containing the requested group icon ID."""

        bio = io.BytesIO()
        self._write_ico(bio, _num=_num)
        return bio

    def save_to_png(self, fname):
        """Save ICO to PNG format."""

        if Path(fname).exists():
            parent_ico_path = Path(fname).parent
            ico_name = Path(fname).stem

            try:
                img = Image.open(Path(fname), mode='r')
            except (Exception,) as e:
                img = None
                shutil.copy2(fname, f'{parent_ico_path}/{ico_name}.png', follow_symlinks=False)
                print(e)
                print('Can not open ICO file...try copy...')
            else:
                img.save(f'{parent_ico_path}/{ico_name}.png', format='PNG', sizes=[(256, 256)])
                print('Save ICO file to PNG format')
        else:
            print('ICO file not exists...')


class SwHudSize:
    """Get font size for mangohud config."""
    def __init__(self):
        self.hud_size = None
        self.get_hud_size()

    def get_hud_size(self):
        """Get font size for mangohud config."""

        if os.getenv('MANGOHUD_FONT_SIZE_RATION') is not None:
            mh_ratio = int(os.getenv('MANGOHUD_FONT_SIZE_RATION'))
        else:
            mh_ratio = 55

        display = Gdk.Display().get_default()

        try:
            monitor = display.get_monitors()[0]
        except (Exception,):
            height = 720
        else:
            height = monitor.get_geometry().height

        self.hud_size = int(height / mh_ratio)
        print(self.hud_size)


def on_helper():
    """___Commandline help info___"""

    print('''
    ----------------------------------------------------------------------------
    StartWine Crier:
    It is a set of tools with dialog boxes, progress bars and others.

    ----------------------------------------------------------------------------
    Usage Crier: [crier] [option]

    ----------------------------------------------------------------------------
    Options:
    -h or '--help'                                          Show help and exit
    -i    'text message'                                    Info dialog window
    -e    'text message'                                    Error dialog window
    -w    'text message'                                    Warning dialog window
    -q    'text message' 'button_name1 'button_name2'       Question dialog window
    -t    'text or path to text file'                       Show text or open file in text editor
    -f    'path'                                            File chooser dialog window
    -d    'url' 'output_file'                               Download progress bar window
    -tar  'input_file, output_file'                         Tar archive extraction progress bar window
    -zip  'input_file, output_file'                         Zip archive extraction progress bar window
    -ico  'input_file, output_file'                         Ico extraction from DLL or EXE file
    -hud                                                    Print MangoHud font size
''')


if __name__ == '__main__':

    if len(argv) > 1:

        if len(argv) == 2:
            if str(argv[1]) == str('-h') or str(argv[1]) == str('--help'):
                on_helper()

            elif str(argv[1]) == str('-hud'):
                import os
                SwHudSize()
            else:
                on_helper()

        elif len(argv) == 3:

            if argv[1] == '-i':
                app = SwCrier(text_message=argv[2], message_type='INFO')
                try:
                    app.run()
                except KeyboardInterrupt:
                    app.quit()

            elif argv[1] == '-e':
                app = SwCrier(text_message=argv[2], message_type='ERROR')
                try:
                    app.run()
                except KeyboardInterrupt:
                    app.quit()

            elif argv[1] == '-w':
                app = SwCrier(text_message=argv[2], message_type='WARNING')
                try:
                    app.run()
                except KeyboardInterrupt:
                    app.quit()

            elif argv[1] == '-q':
                app = SwCrier(text_message=argv[2], message_type='QUESTION', response=None)
                try:
                    app.run()
                except KeyboardInterrupt:
                    app.quit()

            elif argv[1] == '-t':
                app = SwCrier(file=argv[2], message_type='TEXT')
                try:
                    app.run()
                except KeyboardInterrupt:
                    app.quit()

            elif argv[1] == '-f':
                app = SwCrier(file=argv[2], message_type='FILE')
                try:
                    app.run()
                except KeyboardInterrupt:
                    app.quit()

            elif str(argv[1]) == str('-p'):
                app = SwPathManager(argv[2])
                try:
                    app.run()
                except KeyboardInterrupt:
                    app.quit()
                run_menu()
            else:
                on_helper()

        elif len(argv) == 4:

            if str(argv[1]) == str('-d') or str(argv[1]) == str('--silent-download'):
                import os
                import multiprocessing as mp
                from threading import Thread

                url = str(argv[2])
                filename = str(argv[3])
                process = mp.Process(target=download, args=(url, filename))
                process.start()
                if str(argv[1]) == str('--silent-download'):
                    totalsize = get_total_size(url, filename)
                    data = [[filename, url, totalsize]]
                    queue = deque([], len(data))
                    Thread(target=download_progress, args=(data, queue)).start()
                else:
                    app = SwDownloadBar(url, filename)
                    try:
                        app.run()
                    except KeyboardInterrupt:
                        app.quit()

            elif str(argv[1]) == str('-tar') or str(argv[1]) == str('--silent-tar'):
                import tarfile
                from threading import Thread

                filename = str(argv[2])
                path = str(argv[3])
                if str(argv[1]) == str('--silent-tar'):
                    Thread(target=extract_tar, args=[filename, path]).start()
                else:
                    app = SwExtractBar(filename, path)
                    Thread(target=app.extract_tar, args=[filename, path]).start()
                    try:
                        app.run()
                    except KeyboardInterrupt:
                        app.quit()

            elif str(argv[1]) == str('-zip') or str(argv[1]) == str('--silent-zip'):
                import zipfile
                from threading import Thread

                filename = str(argv[2])
                path = str(argv[3])
                if str(argv[1]) == str('--silent-zip'):
                    Thread(target=extract_zip, args=[filename, path]).start()
                else:
                    app = SwExtractBar(filename, path)
                    Thread(target=app.extract_zip, args=[filename, path]).start()
                    try:
                        app.run()
                    except KeyboardInterrupt:
                        app.quit()

            elif str(argv[1]) == str('-ico'):

                input_file = str(argv[2])
                output_file = str(argv[3])
                num = 0
                app = SwExtractIcon(input_file)
                app.extract_icon(output_file, _num=num)
                app.save_to_png(output_file)
            else:
                on_helper()

        elif len(argv) == 5:

            if str(argv[1]) == str('-q'):
                response = [argv[3], argv[4]]
                app = SwCrier(text_message=argv[2], message_type='QUESTION', response=response)
                try:
                    app.run()
                except KeyboardInterrupt:
                    app.quit()
            else:
                on_helper()
        else:
            on_helper()
    else:
        on_helper()
