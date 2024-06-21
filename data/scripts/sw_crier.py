#!/usr/bin/env python3


import sys
from sys import argv, exit
from pathlib import Path
import shutil
from warnings import filterwarnings
import json
import urllib.request
from urllib.request import Request, urlopen, urlretrieve
from urllib.error import HTTPError
from subprocess import run
import itertools

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Gdk', '4.0')
from gi.repository import Gdk, Gio, GLib, Gtk, Gsk, Graphene, Pango, GdkPixbuf
import cairo
import io
from PIL import Image
from sw_data import Msg as msg
filterwarnings('ignore')

#############################___PATH_DATA___:

program_name = 'StartWine'
sw_scripts = Path(argv[0]).absolute().parent
sw_path = Path(sw_scripts).parent.parent
sw_default_path = Path(f'{Path.home()}/.local/share/StartWine')
sw_menu_json = Path(f'{sw_scripts}/sw_menu.json')
sw_css_dark = Path(f'{sw_path}/data/img/sw_themes/css/dark/gtk.css')
sw_css_light = Path(f'{sw_path}/data/img/sw_themes/css/light/gtk.css')
sw_css_custom = Path(f'{sw_path}/data/img/sw_themes/css/custom/gtk.css')
sw_logo = Path(f'{sw_path}/data/img/gui_icons/sw_large_light.svg')
icon_folder = f'{sw_path}/data/img/gui_icons/hicolor/symbolic/apps/folder-symbolic.svg'

############################___SET_CSS_STYLE___:

css_provider = Gtk.CssProvider()

if sw_menu_json.exists():

    menu_conf_read = open(sw_menu_json, 'r')
    dict_ini = json.load(menu_conf_read)

    if dict_ini['color_scheme'] == 'dark':

        css_provider.load_from_file(Gio.File.new_for_path(bytes(sw_css_dark)))
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            css_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )
    elif dict_ini['color_scheme'] == 'light':
        css_provider.load_from_file(Gio.File.new_for_path(bytes(sw_css_light)))
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            css_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )
    elif dict_ini['color_scheme'] == 'custom':
        css_provider.load_from_file(Gio.File.new_for_path(bytes(sw_css_custom)))
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            css_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )

    menu_conf_read.close()

class SwPathManager(Gtk.Application):

    def __init__(self, source_path):
        super().__init__(flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.source_path = source_path
        self.connect('activate', self.activate)

    def activate(self, app):

        self.window = Gtk.Window(
                        application=app,
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
        self.label_main =Gtk.Label(css_name='sw_label', label=msg.msg_dict['select_sw_path'])

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

    def _select_path(self, button):

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
        except GLib.GError as e:
            result = None
        else:
            self.entry_main.set_text(str(result.get_path()))

    def _accept_response(self, button):

        dest_path = Path(self.entry_main.get_text())

        if not str(dest_path).endswith('StartWine'):
            if dest_path.exists():
                dest_path = Path(f'{dest_path}/StartWine')
            else:
                self.label_main.add_css_class('warning')
                self.label_main.set_label(msg.msg_dict['correct_path'])

        if dest_path == Path(self.source_path):
            print('set default path...')
            self.window.close()
            print('run StartWine...')
            if not Path(f'{Path.home()}/.config').exists():
                Path(f'{Path.home()}/.config').mkdir(parents=True, exist_ok=True)
                with open(f'{Path.home()}/.config/swrc', 'w') as f:
                    f.write(f'{dest_path}')
                    f.close()
            else:
                with open(f'{Path.home()}/.config/swrc', 'w') as f:
                    f.write(f'{dest_path}')
                    f.close()
        else:
            if dest_path.exists():
                print('path exists, skip...')
                self.window.close()
                print('run StartWine...')
            else:
                self.window.close()
                if str(dest_path).endswith('StartWine'):
                    print('move StartWine...')
                    try:
                        shutil.move(self.source_path, dest_path)
                    except Exception as e:
                        print(e)
                    else:
                        if not Path(f'{Path.home()}/.config').exists():
                            Path(f'{Path.home()}/.config').mkdir(parents=True, exist_ok=True)
                            with open(f'{Path.home()}/.config/swrc', 'w') as f:
                                f.write(f'{dest_path}')
                                f.close()
                        else:
                            with open(f'{Path.home()}/.config/swrc', 'w') as f:
                                f.write(f'{dest_path}')
                                f.close()

def run_menu():

    if Path(f'{Path.home()}/.config/swrc').exists():
        with open(f'{Path.home()}/.config/swrc', 'r') as f:
            dest_path = f.read().splitlines()[0]
            f.close()
        run(f'{dest_path}/data/scripts/sw_menu.py', start_new_session=True)
    else:
        print(f'{Path.home()}/.config/swrc not found...')

#############################___APPLICATION___:

class SwCrier(Gtk.Application):
    '''Application for providing a set of dialog windows.'''
    def __init__(
                self, app=None, title=None, text_message=None, message_type=None,
                response=None, file=None, mime_types=None, *args, **kwargs
        ):
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

    def activate(self, _app):
        '''Activate application.'''

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
        '''Building the info dialog window.'''

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
        self.dialog = Gtk.Window(
                        css_name='sw_window',
                        application=self.app,
                        titlebar=header,
                        title=f'{program_name} {self.message_type}',
                        child=box_content,
                        default_height=120,
                        default_width=540,
        )
        self.dialog.remove_css_class('background')
        self.dialog.add_css_class('sw_background')
        box_content.append(label)
        header.pack_end(btn_ok)
        btn_ok.connect('clicked', self.cb_btn)
        btn_ok.grab_focus()
        self.dialog.set_default_size(540, 120)
        self.dialog.set_size_request(540, 120)
        self.dialog.set_resizable(False)
        self.dialog.present()

    def question(self):
        '''Building the question dialog window.'''

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
        self.dialog = Gtk.Window(
                        css_name='sw_window',
                        application=self.app,
                        titlebar=header,
                        title=f'{program_name} {self.message_type}',
                        child=box_content,
                        default_height=120,
                        default_width=540,
        )
        self.dialog.remove_css_class('background')
        self.dialog.add_css_class('sw_background')
        box_content.append(label)
        header.pack_end(btn_yes)
        header.pack_start(btn_no)
        btn_yes.connect('clicked', self.cb_btn)
        btn_yes.grab_focus()
        btn_no.connect('clicked', self.cb_btn_cancel)
        self.dialog.set_default_size(540, 120)
        self.dialog.set_size_request(540, 120)
        self.dialog.set_resizable(False)
        self.dialog.present()

    def text_editor(self):
        '''Building the text editor view.'''

        if Path(self.file).is_file():
            title = str(Path(self.file).stem)
            text = Path(self.file).read_text()
        else:
            title = str(self.file)
            text = str(self.file)

        header = Gtk.HeaderBar(
                            css_name='sw_header_top',
                            show_title_buttons=False
        )
        self.dialog = Gtk.Window(
                        css_name='sw_window',
                        application=app,
                        titlebar=header,
                        title=title,
        )
        self.dialog.remove_css_class('background')
        self.dialog.add_css_class('sw_background')
        self.dialog.set_default_size(960, 540)

        btn_save = Gtk.Button(
                        css_name='sw_button_accept',
                        label=msg.msg_dict['save'],
                        valign=Gtk.Align.CENTER,
        )
        btn_save.set_size_request(120, 16),

        btn_cancel = Gtk.Button(
                        css_name='sw_button_cancel',
                        label=msg.msg_dict['cancel'],
                        valign=Gtk.Align.CENTER,
        )
        btn_cancel.set_size_request(120, 16),

        textview = Gtk.TextView(
                        css_name='sw_textview',
                        vexpand=True,
                        hexpand=True,
                        wrap_mode=Gtk.WrapMode.WORD,
                        left_margin=16,
        )
        textview.remove_css_class('view')
        textview.add_css_class('text')
        self.buffer = Gtk.TextBuffer()
        textview.set_buffer(self.buffer)
        self.buffer.set_text(text)

        scrolled = Gtk.ScrolledWindow(
                                    css_name='sw_scrolledwindow',
                                    propagate_natural_height=True,
                                    propagate_natural_width=True,
        )
        btn_save.connect('clicked', self.cb_btn_save)
        btn_cancel.connect('clicked', self.cb_btn_cancel)
        header.pack_end(btn_save)
        header.pack_start(btn_cancel)
        scrolled.set_child(textview)
        self.dialog.set_child(scrolled)
        self.dialog.present()

    def file_selector(self, window=None, data=None, *args, **kwargs):
        '''Calling the file selection dialog window.'''

        if window is None:
            window = Gtk.Window(application=self, css_name='sw_window')

        path = self.file
        title = self.title
        mime_types = self.mime_types

        dialog = SwDialogDirectory(
                                path=path, title=title, mime_types=mime_types,
                                *args, **kwargs
        )
        if Path(path).is_file() or data is not None:
            dialog.open(
                        parent=window,
                        cancellable=Gio.Cancellable(),
                        callback=self.cb_select_file,
                        user_data=data,
        )
        elif Path(path).is_dir():
            dialog.select_folder(
                        parent=window,
                        cancellable=Gio.Cancellable(),
                        callback=self.cb_select_folder,
                        user_data=data,
        )

    def cb_select_file(self, dialog, res, data):
        '''Callback from the folder selection dialog.'''

        try:
            result = dialog.open_finish(res)
        except GLib.GError as e:
            path = '1'
            result = None
        else:
            path = result.get_path()
            if data is not None:
                Path(path).write_text(data)

        self.quit()
        print(path)
        return path

    def cb_select_folder(self, dialog, res, data):
        '''Callback from the folder selection dialog.'''

        try:
            result = dialog.select_folder_finish(res)
        except GLib.GError as e:
            path = '1'
        else:
            path = result.get_path()

        if path is None:
            path = '1'

        self.quit()
        print(path)
        return path

    def cb_btn(self, btn):
        '''Callback from the accept button.'''

        self.dialog.close()
        self.quit()
        p = '0'
        print(p)
        return p

    def cb_btn_save(self, btn):
        '''Callback from the save button.'''

        startIter, endIter = self.buffer.get_bounds()
        buffer_text = self.buffer.get_text(startIter, endIter, False)

        if Path(self.file).is_file():
            Path(self.file).write_text(buffer_text)
        else:
            self.file_selector(window=self.dialog, data=buffer_text)

        self.quit()
        p = '0'
        print(p)
        return p

    def cb_btn_cancel(self, btn):
        '''Callback from the cancel button.'''

        self.quit()
        p = '1'
        print(p)
        return p

class SwDialogEntry(Gtk.Widget):
    def __init__(
        self, app=None, title=None, text_message=None, response=None, func=None,
        num=None, string_list=None, *args, **kwargs
        ):
        super().__init__(*args, **kwargs)

        self.app = app
        self.title = title
        self.text_message = text_message
        self.response = response
        self.func = func
        self.num = num
        self.string_list = string_list
        self.window = self.app.get_windows()[0]
        self.dialog_entry()

    def get_child(self):
        return self.box

    def dialog_entry(self):
        '''___dialog window with entry row___'''

        headerbar = Gtk.HeaderBar(
                            css_name='sw_header_top',
                            show_title_buttons=False,
        )
        self.box = Gtk.Box(
                    css_name='sw_box',
                    orientation=Gtk.Orientation.HORIZONTAL,
        )
        dialog = Gtk.Window(
                            css_name='sw_window',
                            application=self.app,
                            transient_for=self.window,
                            modal=True,
                            titlebar=headerbar,
                            title=self.title,
                            child=self.box,
        )
        dialog.remove_css_class('background')
        dialog.add_css_class('sw_background')

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
            'clicked', cb_btn_response, self.window, dialog, self.func[0]
        )
        btn_cancel.connect(
            'clicked', cb_btn_response, self.window, dialog, self.func[1]
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
                'activate', cb_btn_response, self.window, dialog, self.func[0]
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

        dialog.set_size_request(540, 120)
        dialog.set_resizable(False)
        dialog.present()
        return dialog

class SwDialogQuestion(Gtk.Widget):
    def __init__(
        self, app=None, title=None, text_message=None, response=None, func=None,
        *args, **kwargs
        ):
        super().__init__(*args, **kwargs)

        self.app = app
        self.title = title
        self.text_message = text_message
        self.response = response
        self.func = func
        self.window = self.app.get_windows()[0]
        self.width = 540
        self.height = 120

        if self.title is None:
            self.title = ""

        if self.text_message is None:
            self.text_message = ['', '']

        self.dialog_question()

    def dialog_question(self):
        '''___dialog question window for text message___'''

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
        image = Gtk.Picture(
                        css_name='sw_picture',
                        content_fit=Gtk.ContentFit.CONTAIN,
        )
        box_image = Gtk.Box(
                        css_name='sw_box',
                        orientation=Gtk.Orientation.VERTICAL,
                        spacing=8,
                        halign=Gtk.Align.CENTER,
        )
        #image.set_filename(str(f'{sw_gui_icons}/{sw_logo_dark}'))
        #box_image.append(image)
        #box_image.set_size_request(240,32)

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

        dialog = Gtk.Window(
                            css_name='sw_window',
                            application=self.app,
                            titlebar=headerbar,
                            title=self.title,
                            modal=True,
                            transient_for=self.window,
                            child=box,
        )
        dialog.remove_css_class('background')
        dialog.add_css_class('sw_background')

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
                'clicked', cb_btn_response, self.window, dialog, self.func[0]
            )
            btn_no.connect(
                'clicked', cb_btn_response, self.window, dialog, self.func[1]
            )
            headerbar.pack_start(btn_no)
            headerbar.pack_end(btn_yes)
            btn_yes.grab_focus()
        else:
            count = -1
            for r, f in zip(self.response, self.func):
                count += 1
                if r == msg.msg_dict['cancel']:
                    btn = Gtk.Button(css_name='sw_button_cancel', label=r)
                else:
                    btn = Gtk.Button(css_name='sw_button', label=r)

                btn.set_name(str(count))
                btn.connect('clicked', cb_btn_response, self.window, dialog, f)
                box_btn.append(btn)

        dialog.set_size_request(self.width, self.height)
        dialog.set_resizable(False)
        dialog.present()

def cb_btn_response(self, parent_window, dialog, func):

    if not parent_window.get_visible():
        if (self.get_label() != msg.msg_dict['run']
            and self.get_label() != msg.msg_dict['cancel']):
                parent_window.set_hide_on_close(False)
                parent_window.set_visible(True)
                parent_window.unminimize()

    if func is not None:
        if isinstance(func, dict):
            dialog.close()
            f = list(func)[0]
            args = func[f]
            return f(*args)

        elif isinstance(func, tuple):
            dialog.close()
            f = func[0]
            args = func[1]
            return f(*args)

        elif isinstance(func, list):
            dialog.close()
            f = func[0]
            args = func
            args.remove(f)
            return f(*args)
        else:
            dialog.close()
            return func()
    else:
        return dialog.close()

class SwDialogDirectory(Gtk.FileDialog):
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
        '''___dialog window for choose directory___'''

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

class SwWidget(Gtk.Box):

    def __init__(self, background_color='#000000', shadow_color='#000000',
                border_color = '#000000', *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.filename = None
        self.effects = []
        self.blur = 50.0
        self.border = 10.0
        self.corner = 0.0
        self.bg = Gdk.RGBA()
        self.bg.parse(background_color)
        self.bd = Gdk.RGBA()
        self.bd.parse(border_color)
        self.sd = Gdk.RGBA()
        self.sd.parse(shadow_color)
        self.direct = list(range(10, 255))
        self.reverse = list(range(10, 255))
        self.reverse.reverse()
        self.iter_color = itertools.cycle(self.direct + self.reverse)
        self.tick = None
        self.transform = Gsk.Transform()
        self.texture = None
        self.flip_texture = None
        self.cairo_surface = None
        self.width = None
        self.height = None
        self.child = None
        self.check_tick_callback()

    def do_snapshot(self, snapshot):

        self.snapshot = snapshot

        x = self.width
        y = self.height

        rect_c = Graphene.Rect().init(0, 0, x, y)
        rrect_c = Gsk.RoundedRect()
        rrect_c.init_from_rect(rect_c, self.corner)

        #self.snapshot.pop()
        #self.snapshot.push_rounded_clip(rrect_c)
        

        if 'blur' in self.effects:
            self.snapshot.push_blur(30)

        if 'reverse' in self.effects:
            point = Graphene.Point()
            #y = (self.width/96) * 124
            point.x = x
            point.y = y
            self.snapshot.translate(point)
            #self.snapshot.scale(1.0, 1.0)
            self.snapshot.rotate(180.0)

        if self.filename is not None and self.texture is not None:
            trilinear_c = Gsk.ScalingFilter.TRILINEAR
            self.snapshot.append_scaled_texture(self.texture, trilinear_c, rect_c)

#        snapshot.append_inset_shadow(
#                            rrect_c, self.sd, 0, 0, 1.0 + self.border, self.blur
#        )
        builder = Gsk.PathBuilder.new()
        builder.add_rounded_rect(rrect_c)
        path = builder.to_path()
        snapshot.append_fill(path, Gsk.FillRule.WINDING, self.bg)


        self.snapshot.pop()
        self.snapshot_child(self.child, self.snapshot)

    def do_size_allocate(self, width, height, baseline):
        ''''''
        self.width = width
        self.height = height

    def set_filename(self, filename: str):

        self.filename = filename
        if self.filename is not None:
            self.texture = Gdk.Texture.new_from_filename(self.filename)
#            image = Image.open(self.filename)
#            image = image.transpose(Image.FLIP_LEFT_RIGHT)
#            byte_arr = io.BytesIO()
#            image.save(byte_arr, format='PNG')
#            byte_arr = byte_arr.getvalue()
#            self.texture = Gdk.Texture.new_from_bytes(GLib.Bytes.new(byte_arr))

        self.queue_draw()

    def set_effects(self, effects: list):
        self.effects = effects

    def set_content_fit(self, content_fit):
        self.content_fit = content_fit

    def _inset_shadow(self, snapshot, x, y):
        '''Shadow and border layouts'''

        rectt = Graphene.Rect().init(0, 0, x, y)
        rrect = Gsk.RoundedRect()
        rrect.init_from_rect(rectt, self.corner)
        snapshot.append_inset_shadow(
                            rrect, self.sd, 0, 0, 1.0 + self.border, self.blur
        )
        builder = Gsk.PathBuilder.new()
        builder.add_rounded_rect(rrect)
        path = builder.to_path()
        snapshot.append_fill(path, Gsk.FillRule.WINDING, self.bg)

    def _tick_callback(self, snapshot, frame_clock):
        ''''''
        self.width = self.get_width()
        self.height = self.get_height()
        self.child = self.get_first_child()
        #next_color = next(self.iter_color)
        #self.blur = float(next_color)
        self.queue_draw()
        return True

    def check_tick_callback(self):

        if self.tick is not None:
            self.remove_tick_callback(self.tick)

        self.tick = self.add_tick_callback(self._tick_callback)

    def shadow_pulse(self):
        self.check_tick_callback()
        self.queue_draw()
        return True

class SwProgressBar(Gtk.Widget):
    def __init__(
                self,
                color='#aaaaaa',
                background_color='#000000',
                shadow_color='#2080ff',
                border_color = '#2080ff',
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
                style = 'circle',
                css_provider=None,
                orientation = 'horizontal',
                *args, **kwargs
        ):
        super().__init__(
            *args, **kwargs,
            width_request=240, height_request=24)

        self.width = width
        self.height = height
        self.font_family = font_family
        self.font_size = font_size
        self.border = border
        self.corner = corner
        self.blur = 0.0

        self.counter = None
        self.tick = None
        self.max_count = 0
        self.text = text
        self.show_text = show_text
        self.fraction = fraction
        self.pulse_step = pulse_step

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
        '''Get current define colors from css provider'''

        css_list = self.css_provider.to_string().splitlines()
        define_colors = dict()
        for x in css_list:
            if '@define-color sw_' in x:
                if len([x.split(' ')[2].strip(';') ]) > 0:
                    define_colors[x.split(' ')[1]] = [x.split(' ')[2].strip(';') ][0]

        return define_colors

    def set_define_colors(self):

        dcolors = self.get_define_colors()

        if dcolors != {}:
            self.set_foreground(dcolors['sw_invert_bg_color'])
            self.set_background(dcolors['sw_bg_color'])
            self.set_progress_color(
                                    dcolors['sw_invert_progress_color'],
                                    dcolors['sw_accent_fg_color'],
            )
            self.set_border_color(dcolors['sw_accent_fg_color'])
            self.set_shadow_color(dcolors['sw_accent_bg_color'])

    def check_tick_callback(self):

        if self.tick is not None:
            self.remove_tick_callback(self.tick)

        if self.counter is not None or self.fraction is not None:
            self.tick = self.add_tick_callback(self._tick_callback)

    def do_snapshot(self, snapshot):
        '''Do snapshot of widget'''

        self.snapshot = snapshot
        self._bar(snapshot)

    def _text_layout(self, snapshot):
        '''Pango layout'''

        font = Pango.FontDescription.new()
        font.set_family(self.font_family)
        font.set_size(self.font_size * Pango.SCALE)
        context = self.get_pango_context()
        layout = Pango.Layout(context)
        layout.set_font_description(font)
        metrics = context.get_metrics(font, context.get_language())
        self.ch = metrics.get_height() / 1000

        return layout, metrics

    def _set_pango_layout(self, snapshot, layout, metrics, x, y):

        point = Graphene.Point()
        chr_w = metrics.get_approximate_char_width() / 1000
        dgt_w = metrics.get_approximate_digit_width() / 1000

        if self.text is not None:
            len_dgt = len([e for e in self.text if e.isdigit()])
            len_chr = len([e for e in self.text if e.isalpha()])
            point.x = x/2 - (len_chr * chr_w + len_dgt * dgt_w ) / 2
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
            point.x = x/2 - (len_chr * chr_w + len_dgt * dgt_w ) / 2
            point.y = 0
            layout.set_text(text)
            snapshot.save()
            snapshot.translate(point)
            snapshot.append_layout(layout, self.fg)
            snapshot.restore()

    def _set_shadow(self, snapshot, x, y):
        '''Shadow and border layouts'''

        rectt = Graphene.Rect().init(0, self.ch, x, y)
        rrect = Gsk.RoundedRect()
        rrect.init_from_rect(rectt, self.corner)
        snapshot.append_outset_shadow(
                            rrect, self.sd, 0, 0, 1.0 + self.border, self.blur
        )
        builder = Gsk.PathBuilder.new()
        builder.add_rounded_rect(rrect)
        path = builder.to_path()
        snapshot.append_fill(path, Gsk.FillRule.WINDING, self.bg)

        snapshot.append_border(
                        rrect,
                        [self.border, self.border, self.border, self.border],
                        [self.bd, self.bd, self.bd, self.bd]
        )

    def _bar(self, snapshot):
        '''Do snapshot of progressbar widget'''

        x = self.width
        y = self.height
        b = self.border
        mc = self.max_count + 2
        self.ch = 0
        rh = y/2 + self.ch
        rw = x/20
        self.path_list = list()
        self.rect_list = list()

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
                        x/3, y*(5*mc -9)/(5*mc) + self.ch - (i * y/mc), x/3, y/(2*mc)
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
                        x/2 - x/48, y*(5*mc -9)/(5*mc) + self.ch - (i * y/mc), x/24, y/48
                )
                _round.init_from_rect(_rect, self.corner)
                builder.add_rounded_rect(_round)

            path = builder.to_path()
            snapshot.append_fill(path, Gsk.FillRule.WINDING, self.p_bg)
            self.path_list.append(path)

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

    def do_size_allocate(self, width, height, baseline):
        ''''''

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
        ''''''
        self.check_tick_callback()
        self.fraction = fraction
        self.queue_draw()

    def get_fraction(self):
        ''''''
        return self.fraction

    def set_text(self, text: str):
        ''''''
        self.text = text

    def get_text(self):
        ''''''
        return self.text

    def set_show_text(self, show: bool):
        ''''''
        self.show_text = show

    def get_show_text(self):
        ''''''
        return self.show_text

    def set_pulse_step(self, step: int):
        ''''''
        self.pulse_step = step

    def get_pulse_step(self):
        ''''''
        return self.pulse_step

    def set_font_size(self, size: int):
        ''''''
        self.font_size = size

    def get_font_size(self):
        ''''''
        return self.font_size

    def set_foreground(self, color: str):
        ''''''
        self.color = color
        self.fg.parse(color)

    def get_foreground(self):
        ''''''
        return  self.fg.to_string()

    def set_background(self, background_color: str):
        ''''''
        self.background_color = background_color
        self.bg.parse(background_color)

    def get_background(self):
        ''''''
        return self.bg.to_string()

    def set_shadow_color(self, shadow_color: str):
        ''''''
        self.shadow_color = shadow_color
        self.sd.parse(shadow_color)

    def get_shadow_color(self):
        ''''''
        return self.sd.to_string()

    def set_border_color(self, border_color: str):
        ''''''
        self.border_color = border_color
        self.bd.parse(border_color)

    def get_border_color(self):
        ''''''
        return  self.bd.to_string()

    def set_progress_color(self, color: str, background_color: str):
        ''''''
        self.progress_foreground = color
        self.progress_background = background_color
        self.p_fg.parse(color)
        self.p_bg.parse(background_color)

    def get_progress_color(self):
        ''''''
        return  self.p_fg.to_string(), self.p_bg.to_string()

    def set_size(self, width: int, height: int):
        ''''''
        self.width = width
        self.height = height
        self.set_size_request(self.width, self.height)

    def get_size(self):
        ''''''
        return [self.get_width(), self.get_height()]

    def set_border(self, width: int):
        ''''''
        self.border = width

    def get_border(self):
        ''''''
        return self.border

    def set_corner(self, corner: int):
        ''''''
        self.corner = corner

    def get_corner(self):
        ''''''
        return self.corner

    def set_style(self, style: str):
        ''''''
        if style not in self.style_list:
            print(f'Value error: The style must be one of {self.style_list}')
        else:
            self.style = style

    def get_style(self):
        ''''''
        return self.style

    def set_orientation(self, orientation: str):

        if orientation in ['horizontal', 'vertical']:
            self.orientation = orientation
        else:
            print(f'Value error: The orientation must be on of {orientation_list}')

    def pulse(self):
        ''''''
        self.check_tick_callback()
        return self._update()

    def stop(self):
        ''''''
        GLib.Source.remove(self.timeout)
        self.counter = None
        self.queue_draw()

    def _update(self):
        ''''''
        self.fraction = 0.0
        if self.counter is None:
            self.counter = 0

        self.counter += 1
        if self.counter == self.max_count + 1:
            self.counter = 0

        self.queue_draw()
        return True

    def _tick_callback(self, snapshot, frame_clock):
        ''''''
        next_color = next(self.iter_color)
        self.blur = float(next_color / 5)
        self.queue_draw()
        return True

################################___DOWNLOAD___:

def download(url, filename):

    request_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101 Safari/537.36',
        'Accept-Language': 'fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Connection': 'keep-alive',
        'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
    }
    try:
        response = urlopen(Request(url, headers=request_headers))
    except HTTPError as e:
        print(e)
        try:
            urllib.request.urlretrieve(url, filename)
        except HTTPError as e:
            print(e)
            exit(1)
        else:
            exit(0)
    else:
        with response as res, open(filename, 'wb') as out:
            shutil.copyfileobj(res, out)
            res.close()
            exit(0)

class SwDownloadBar(Gtk.Application):

    def __init__(self, url, filename):
        super().__init__(
                        #application_id='ru.project.Crier',
                        flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        GLib.set_prgname(program_name)
        self.percent = 0
        self.exit = None
        self.url = url

        try:
            self.totalsize = urlopen(url).length
        except Exception as e:
            self.totalsize = None

        self.filename = filename
        self.program_name = f'StartWine'
        self.connect('activate', self.activate)
        GLib.timeout_add(1000, self.update)

    def activate(self, root):

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
        self.header = Gtk.HeaderBar(
                            css_name='sw_header_top',
                            show_title_buttons=False,
        )
        self.progressbar = SwProgressBar(
                                    css_name='sw_progressbar',
                                    hexpand=True,
                                    vexpand=True,
                                    margin_bottom=32,
                                    css_provider=css_provider,
        )
        self.progressbar.set_show_text(True)
        self.progressbar.set_size_request(420, 24)
        self.label = Gtk.Label(css_name='sw_label')
        self.name = str(list(filename.replace('/','\n').split())[-1])
        self.label.set_label(self.name)
        self.grid = Gtk.Grid(css_name='sw_message_box')
        self.grid.set_margin_start(32)
        self.grid.set_margin_end(32)
        self.grid.set_margin_bottom(8)
        self.grid.set_margin_top(8)
        self.grid.set_row_spacing(16)
        self.grid.attach(self.label, 0, 0, 1, 1)
        self.grid.attach(self.progressbar, 0, 1, 1, 1)
        self.window.set_titlebar(self.header)
        self.window.set_child(self.grid)
        self.add_window(self.window)
        self.window.grab_focus()
        self.window.present()

    def update(self):

        if self.totalsize is None:
            print(f'Impossible to determine total size. URL not found...')
            self.window.close()
            self.exit = self.quit()
            exit(1)

        if Path(self.filename).exists():
            current = Stat(self.filename).st_size
            self.percent = current / self.totalsize

            if self.exit is None:
                self.progressbar.set_fraction(self.percent)

            if self.percent >= 1:
                print(f'Download_completed_successfully.')
                self.window.close()
                self.exit = self.quit()

        return True

##############################___EXTRACTION___:

class SwExtractBar(Gtk.Application):

    def __init__(self, filename, path):
        super().__init__(
                        #application_id='ru.project.Crier',
                        flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        GLib.set_prgname(program_name)
        self.exit = None
        self.filename = filename
        self.path = path
        self.program_name = f'StartWine'
        self.connect('activate', self.activate)
        GLib.timeout_add(100, self.update)

    def activate(self, root):

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
                                    css_provider=css_provider,
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

        if self.exit is None:
            self.progressbar.pulse()
            return True
        else:
            self.window.close()
            self.quit()
            return False

    def extract_tar(self, filename, path):

        if Path(filename).exists():
            taro = tarfile.open(filename)

            for member_info in taro.getmembers():
                taro.extract(member_info, path=path)
                print('Extracting: ' + member_info.name)
            else:
                taro.close()
                print(f'Extraction_completed_successfully.')
                self.exit = 0
        else:
            print(f'{filename} not exists...')
            self.exit = 1
            exit(1)

    def extract_zip(self, filename, path):

        if Path(filename).exists():
            zipo = zipfile.ZipFile(filename)

            for member_info in zipo.namelist():
                print('Extracting: ' + member_info)
                zipo.extract(member_info, path=path)
            else:
                zipo.close()
                print(f'Extraction_completed_successfully.')
                self.exit = 0
        else:
            print(f'{filename} not exists...')
            self.exit = 1
            exit(1)

class SwExtractIcon():

    def __init__(self, filename=None, data=None):
        '''Loads an executable from the given filename or data (raw bytes).'''

        self._pefile = pefile.PE(name=filename, data=data, fast_load=True)
        self._pefile.parse_data_directories(pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'])

        if not hasattr(self._pefile, 'DIRECTORY_ENTRY_RESOURCE'):
            raise RuntimeError('File has no icon')

        res = {r.id: r for r in reversed(self._pefile.DIRECTORY_ENTRY_RESOURCE.entries)}

        self.rt_group_icon = res.get(pefile.RESOURCE_TYPE['RT_GROUP_ICON'])
        if not self.rt_group_icon:
            raise RuntimeError('File has no group icon resources')

        self.rt_icon = res.get(pefile.RESOURCE_TYPE['RT_ICON'])

    def list_group_icons(self):
        '''Returns all group icon entries as a list of (name, offset) tuples.'''

        return [(e.struct.Name, e.struct.OffsetToData)
                for e in self.rt_group_icon.directory.entries]

    def _get_group_icon_entries(self, num=0):
        '''Returns the group icon entries for the specified group icon in the executable.'''

        group_icon = self.rt_group_icon.directory.entries[num]
        if group_icon.struct.DataIsDirectory:
            group_icon = group_icon.directory.entries[0]

        rva = group_icon.data.struct.OffsetToData
        size = group_icon.data.struct.Size
        data = self._pefile.get_data(rva, size)
        file_offset = self._pefile.get_offset_from_rva(rva)

        grp_icon_dir = self._pefile.__unpack_data__(ICON_DIR_FORMAT, data, file_offset)

        if grp_icon_dir.Reserved:
            raise  RuntimeError('Invalid group icon definition (got Reserved=%s instead of 0)' % hex(grp_icon_dir.Reserved))

        grp_icons = []
        icon_offset = grp_icon_dir.sizeof()
        for idx in range(grp_icon_dir.Count):
            grp_icon = self._pefile.__unpack_data__(ICON_DIR_ENTRY_FORMAT, data[icon_offset:], file_offset+icon_offset)
            icon_offset += grp_icon.sizeof()
            grp_icons.append(grp_icon)

        return grp_icons

    def _get_icon_data(self, icon_ids):
        '''Return a list of raw icon images corresponding to the icon IDs given.'''

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

    def _write_ico(self, fd, num=0):
        '''Writes ICO data to a file descriptor.'''

        group_icons = self._get_group_icon_entries(num=num)
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

    def extract_icon(self, fname, num=0):
        '''Writes ICO data of the requested group icon ID to fname.'''

        with open(fname, 'wb') as f:
            self._write_ico(f, num=num)

    def get_icon(self, num=0):
        '''Returns ICO data as a BytesIO() instance, containing the requested group icon ID.'''

        f = io.BytesIO()
        self._write_ico(f, num=num)
        return f

class SwHudSize():
    '''Get font size for mangohud config.'''

    def __init__(self):
        self._get_hud_size()

    def _get_hud_size(self):
        '''Get font size for mangohud config.'''
        try:
            mh_ratio = int(os.getenv('MANGOHUD_FONT_SIZE_RATION'))
        except:
            mh_ratio = 55

        display = Gdk.Display().get_default()

        try:
            monitor = display.get_monitors()[0]
        except:
            height = 720
        else:
            height = monitor.get_geometry().height

        print(int(height / mh_ratio))

################___HELP_INFO___:

def on_helper():
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
'''
    )

##########################___SYSTEM_ARGUMENTS___:

if __name__ == '__main__':

    if len(argv) > 1:

        if len(argv) == 2:
            if str(argv[1]) == str('-h') or str(argv[1]) == str('--help'):
                on_helper()

            elif str(argv[1]) == str('-hud'):
                import psutil
                import os
                SwHudSize()
            else:
                on_helper()

        elif len(argv) == 3:

            if argv[1] == f'-i':
                app = SwCrier(text_message=argv[2], message_type='INFO')
                app.run()

            elif argv[1] == f'-e':
                app = SwCrier(text_message=argv[2], message_type='ERROR')
                app.run()

            elif argv[1] == f'-w':
                app = SwCrier(text_message=argv[2], message_type='WARNING')
                app.run()

            elif argv[1] == f'-q':
                app = SwCrier(text_message=argv[2], message_type='QUESTION', response=None)
                app.run()

            elif argv[1] == f'-t':
                app = SwCrier(file=argv[2], message_type='TEXT')
                app.run()

            elif argv[1] == f'-f':
                app = SwCrier(file=argv[2], message_type='FILE')
                app.run()

            elif str(argv[1]) == str('-p'):
                app = SwPathManager(argv[2])
                app.run()
                run_menu()
            else:
                on_helper()

        elif len(argv) == 4:

            if str(argv[1]) == str('-d'):
                import os
                from os import stat as Stat
                import multiprocessing as mp

                url = str(argv[2])
                filename = str(argv[3])
                process = mp.Process(target=download, args=[url, filename])
                process.start()
                app = SwDownloadBar(url, filename)
                app.run()

            elif str(argv[1]) == str('-tar'):
                import tarfile
                from threading import Thread

                filename = str(argv[2])
                path = str(argv[3])
                app = SwExtractBar(filename, path)
                Thread(target=app.extract_tar, args=[filename, path]).start()
                app.run()

            elif str(argv[1]) == str('-zip'):
                import zipfile
                from threading import Thread

                filename = str(argv[2])
                path = str(argv[3])
                app = SwExtractBar(filename, path)
                Thread(target=app.extract_zip, args=[filename, path]).start()
                app.run()

            elif str(argv[1]) == str('-ico'):
                import io
                import struct
                import pefile

                ICON_DIR_ENTRY_FORMAT = ('GRPICONDIRENTRY',
                    ('B,Width', 'B,Height','B,ColorCount','B,Reserved',
                     'H,Planes','H,BitCount','I,BytesInRes','H,ID')
                )
                ICON_DIR_FORMAT = ('GRPICONDIR', ('H,Reserved', 'H,Type','H,Count'))

                input_file = str(argv[2])
                output_file = str(argv[3])
                num = 0
                app = SwExtractIcon(input_file)
                app.extract_icon(output_file, num=num)

            else:
                on_helper()

        elif len(argv) == 5:

            if str(argv[1]) == str('-q'):
                response = [argv[3], argv[4]]
                app = SwCrier(text_message=argv[2], message_type='QUESTION', response=response)
                app.run()
            else:
                on_helper()

        else:
            on_helper()

    else:
        on_helper()

