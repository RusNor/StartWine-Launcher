#!/usr/bin/env python3

import os
from os import stat as Stat
import sys
from sys import argv, exit
from pathlib import Path
from time import time
import shutil
from warnings import filterwarnings
import json
import urllib.request
from urllib.request import Request, urlopen, urlretrieve
from urllib.error import HTTPError
from subprocess import run, Popen
from threading import Thread

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Gdk', '4.0')
from gi.repository import Gdk, Gio, GLib, Gtk

from sw_data import Msg as msg
filterwarnings("ignore")

#############################___PATH_DATA___:

program_name = 'StartWine'
sw_scripts = Path(argv[0]).absolute().parent
sw_path = Path(sw_scripts).parent.parent
sw_default_path = Path(f"{Path.home()}/.local/share/StartWine")
sw_menu_json = Path(f'{sw_scripts}/sw_menu.json')
sw_css_dark = Path(f'{sw_path}/data/img/sw_themes/css/dark/gtk.css')
sw_css_light = Path(f'{sw_path}/data/img/sw_themes/css/light/gtk.css')
sw_css_custom = Path(f'{sw_path}/data/img/sw_themes/css/custom/gtk.css')
sw_logo = Path(f'{sw_path}/data/img/gui_icons/sw_large_light.svg')
icon_folder = f'{sw_path}/data/img/gui_icons/hicolor/symbolic/apps/folder-symbolic.svg'

#############################___DISPLAY___:

display = Gdk.Display().get_default()
try:
    monitor = display.get_monitors()[0]
except:
    width = 1280
    height = 720
else:
    width = monitor.get_geometry().width
    height = monitor.get_geometry().height

############################___SET_CSS_STYLE___:

if sw_menu_json.exists():

    menu_conf_read = open(sw_menu_json, 'r')
    dict_ini = json.load(menu_conf_read)

    if dict_ini['color_scheme'] == 'dark':
        css_provider = Gtk.CssProvider()
        css_provider.load_from_file(Gio.File.new_for_path(bytes(sw_css_dark)))
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            css_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )
    elif dict_ini['color_scheme'] == 'light':
        css_provider = Gtk.CssProvider()
        css_provider.load_from_file(Gio.File.new_for_path(bytes(sw_css_light)))
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            css_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )
    elif dict_ini['color_scheme'] == 'custom':
        css_provider = Gtk.CssProvider()
        css_provider.load_from_file(Gio.File.new_for_path(bytes(sw_css_custom)))
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            css_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )

    menu_conf_read.close()

def media_play(media_file, samples, volume):
    '''___playing system event sounds___'''

    if isinstance(samples, str):
        media_file.set_filename(f'{samples}')
        media_file.set_volume(volume)
        media_file.play()

def dialog_entry(app, title, text_message, response, func, num, string_list):
    '''___dialog window with entry row___'''

    headerbar = Gtk.HeaderBar(
                        css_name='sw_header_top',
                        show_title_buttons=False,
    )
    box = Gtk.Box(
                css_name='sw_box',
                orientation=Gtk.Orientation.HORIZONTAL,
    )
    dialog = Gtk.Window(
                        css_name='sw_window',
                        application=app,
                        transient_for=app.get_windows()[0],
                        modal=True,
                        titlebar=headerbar,
                        title=title,
                        child=box,
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
                        label=response,
                        valign=Gtk.Align.CENTER,
    )
    btn_accept.set_size_request(120, 16)

    btn_accept.connect('clicked', cb_btn_response, dialog, func[0])
    btn_cancel.connect('clicked', cb_btn_response, dialog, func[1])
    headerbar.pack_start(btn_cancel)
    headerbar.pack_end(btn_accept)
    btn_accept.grab_focus()

    for i in range(num):
        entry = Gtk.Entry(
                        css_name='sw_entry',
                        margin_start=8,
                        margin_end=8,
                        hexpand=True,
                        valign=Gtk.Align.CENTER,
                        text=text_message[i]
        )
        box.append(entry)

    dropdown_menu = Gtk.DropDown(
                                css_name='sw_dropdown',
                                valign=Gtk.Align.CENTER,
                                margin_end=8,
                                show_arrow=True,
    )
    if string_list is not None:
        model = Gtk.StringList()
        for string in string_list:
            model.append(string)

        dropdown_menu.set_size_request(96, -1)
        dropdown_menu.set_model(model)
        box.append(dropdown_menu)

    dialog.set_default_size(500, 120)
    dialog.set_size_request(500, 120)
    dialog.set_resizable(False)
    dialog.present()
    return dialog

def dialog_question(app, title, text_message, response, func):
    '''___dialog question window for text message___'''

    if title is None:
        title = f"{program_name} Question"

    if text_message is None:
        text_message = ''

    label = Gtk.Label(
                    css_name='sw_label',
                    margin_top=8,
                    margin_bottom=8,
                    margin_start=8,
                    margin_end=8,
                    wrap=True,
                    natural_wrap_mode=True,
                    label=text_message,
    )
    scrolled = Gtk.ScrolledWindow(
                                css_name='sw_scrolledwindow',
                                vexpand=True,
                                hexpand=True,
                                propagate_natural_height=True,
                                propagate_natural_width=True,
                                max_content_width=width*0.33,
                                max_content_height=height*0.33,
                                child=label
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
                        application=app,
                        titlebar=headerbar,
                        title=title,
                        modal=True,
                        transient_for=app.get_windows()[0],
                        child=box,
    )
    dialog.remove_css_class('background')
    dialog.add_css_class('sw_background')

    if response is None:
        response = [msg.msg_dict['yes'], msg.msg_dict['no']]
        btn_yes = Gtk.Button(
                            css_name='sw_button_accept',
                            label=response[0],
                            valign=Gtk.Align.CENTER,
        )
        btn_yes.set_size_request(96, 16)
        btn_no = Gtk.Button(
                            css_name='sw_button_cancel',
                            label=response[1],
                            vexpand=True,
                            valign=Gtk.Align.CENTER,
        )
        btn_no.set_size_request(96, 16)
        btn_yes.connect('clicked', cb_btn_response, dialog, func[0])
        btn_no.connect('clicked', cb_btn_response, dialog, func[1])
        headerbar.pack_start(btn_no)
        headerbar.pack_end(btn_yes)
        btn_yes.grab_focus()
    else:
        count = -1
        for r, f in zip(response, func):
            count += 1
            if r == msg.msg_dict['cancel']:
                btn = Gtk.Button(css_name='sw_button_cancel', label=r)
            else:
                btn = Gtk.Button(css_name='sw_button', label=r)

            btn.set_name(str(count))
            btn.connect('clicked', cb_btn_response, dialog, f)
            box_btn.append(btn)

    dialog.set_size_request(width*0.25, height*0.15)
    dialog.set_resizable(False)
    dialog.present()

def cb_btn_response(self, dialog, func):

    if func is not None:
        if isinstance(func, dict):
            dialog.close()
            f = list(func)[0]
            args = func[f]
            return f(args)

        elif isinstance(func, tuple):
            dialog.close()
            f = func[0]
            args = func[1]
            return f(args)

        elif isinstance(func, list):
            dialog.close()
            f = func[0]
            args = func
            args.remove(f)
            return f(args)
        else:
            dialog.close()
            return func()
    else:
        return dialog.close()

def dialog_directory(app, title):
    '''___dialog window for choose directory___'''

    dialog = Gtk.FileDialog()
    dialog.set_accept_label('_OK')
    file_filter = Gtk.FileFilter()
    file_filter.set_name('folder')
    file_filter.add_mime_type('inode/directory')
    dialog.set_default_filter(file_filter)
    file = Gio.File.new_for_commandline_arg(bytes(Path.home()))
    dialog.set_initial_folder(file)
    dialog.set_modal(True)
    dialog.set_title(title)

    return dialog

def dialog_folder(app, parent, func, data):

    filechooser = Gtk.FileChooserDialog(
                                    application=app,
                                    title="Please choose a folder",
                                    action=Gtk.FileChooserAction.SELECT_FOLDER,
                                    )
    filechooser.set_transient_for(parent)
    filechooser.set_decorated(False)
    filechooser.add_buttons(
                        "_Cancel", Gtk.ResponseType.CANCEL,
                        "_Select", Gtk.ResponseType.ACCEPT
    )
    path = Gio.File.new_for_path(f'{Path.home()}')
    filechooser.set_current_folder(path)
    filechooser.present()
    filechooser.connect("response", func, data)

class StartPathManager(Gtk.Application):

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
        self.btn_ok.set_size_request(96, 16)
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

    def _select_path(self, button):

        title = msg.msg_dict['change_directory']
        dialog = dialog_directory(self, title)
        dialog.select_folder(
                    parent=self.window,
                    cancellable=Gio.Cancellable(),
                    callback=self._get_folder,
                    user_data=dialog,
        )

    def _get_folder(self, dialog, res, data):

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
        print(f'{Path.home()}/.config/swrc not found...exit')

#############################___APPLICATION___:

class Crier(Gtk.Application):

    def __init__(self, *args, **kwargs):
        super().__init__(*args,
                        #application_id="ru.project.Crier",
                        flags=Gio.ApplicationFlags.FLAGS_NONE,
                        **kwargs
        )
        GLib.set_prgname(program_name)
        try:
            if argv[1] == f"-i":
                self.connect('activate', info, argv[2], 'INFO')

            elif argv[1] == f"-e":
                self.connect('activate', info, argv[2], 'ERROR')

            elif argv[1] == f"-w":
                response = [msg.msg_dict['accept'], msg.msg_dict['cancel']]
                self.connect('activate', question, argv[2], 'WARNING', response)

            elif argv[1] == f"-q":
                if len(argv) == 4:
                    response = argv[3].split(',')
                else:
                    response = None

                self.connect('activate', question, argv[2], 'QUESTION', response)

            elif argv[1] == f"-t":
                self.connect('activate', text_info, Path(argv[2]))

            elif argv[1] == f"-fl":
                self.connect('activate', on_file)

            elif argv[1] == f"-fd":
                self.connect('activate', on_folder)
        except:
            on_helper()

###########################___INFO___:

def info(app, text_message, message_type):

    def cb_btn_ok(self):
        p = print(0)
        dialog.close()
        return p

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
                    label=text_message,
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
    btn_ok.set_size_request(96, 16)
    box_content = Gtk.Box(
                    css_name='sw_box',
                    orientation=Gtk.Orientation.VERTICAL,
                    spacing=8,
    )
    dialog = Gtk.Window(
                    css_name='sw_window',
                    application=app,
                    titlebar=header,
                    title=f'{program_name} {message_type}',
                    child=box_content,
                    default_height=120,
                    default_width=420,
    )
    dialog.remove_css_class('background')
    dialog.add_css_class('sw_background')
    box_content.append(label)
    header.pack_end(btn_ok)
    btn_ok.connect('clicked', cb_btn_ok)
    btn_ok.grab_focus()
    dialog.set_default_size(420, 120)
    dialog.set_size_request(420, 120)
    dialog.set_resizable(False)
    dialog.present()

def alert(app, text_message):

    window = Gtk.Window(css_name='sw_window', application=app)
    window.remove_css_class('background')
    window.add_css_class('sw_background')
    dialog = Gtk.AlertDialog(
                            buttons=('_OK', '_Cancel'),
                            message=f"{program_name} INFO",
                            detail=text_message,
                            modal=False,
                            )

    dialog.set_default_button(0)
    dialog.set_cancel_button(1)

    def on_choose(self, res):
        '''______'''
        res = self.choose_finish(res)
        print(res)
        window.destroy()

    dialog.choose(
                parent=window,
                cancellable=Gio.Cancellable(),
                callback=on_choose
                )

#######################___QUESTION___:

def question(app, text_message, message_type, response):

    def cb_btn_yes(self):
        dialog.close()
        p = print("0")
        return p

    def cb_btn_no(self):
        dialog.close()
        p = print("1")
        return p

    if response is None:
        response = [msg.msg_dict['yes'], msg.msg_dict['no']]

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
                    label=text_message,
    )
    btn_yes = Gtk.Button(
                    css_name='sw_button_accept',
                    label=response[0],
                    valign=Gtk.Align.CENTER,
                    margin_start=4,
                    margin_end=4,
                    margin_bottom=4,
                    margin_top=4,
    )
    btn_yes.set_size_request(96, 16)

    btn_no = Gtk.Button(
                    css_name='sw_button_cancel',
                    label=response[1],
                    valign=Gtk.Align.CENTER,
                    margin_start=4,
                    margin_end=4,
                    margin_bottom=4,
                    margin_top=4,
    )
    btn_no.set_size_request(96, 16)

    box_content = Gtk.Box(
                    css_name='sw_box',
                    orientation=Gtk.Orientation.VERTICAL,
                    spacing=8,
    )
    dialog = Gtk.Window(
                    css_name='sw_window',
                    application=app,
                    titlebar=header,
                    title=f'{program_name} {message_type}',
                    child=box_content,
                    default_height=120,
                    default_width=420,
    )
    dialog.remove_css_class('background')
    dialog.add_css_class('sw_background')
    box_content.append(label)
    header.pack_end(btn_yes)
    header.pack_start(btn_no)
    btn_yes.connect('clicked', cb_btn_yes)
    btn_yes.grab_focus()
    btn_no.connect('clicked', cb_btn_no)
    dialog.set_default_size(420, 120)
    dialog.set_size_request(420, 120)
    dialog.set_resizable(False)
    dialog.present()

########################___TEXT_INFO___:

def text_info(app, text_edit_name):

    def cb_btn_save(self):

        startIter, endIter = buffer.get_bounds()
        get_text = buffer.get_text(startIter, endIter, False)
        Path(text_edit_name).write_text(get_text)
        p = print("0")
        return p

    def cb_btn_cancel(self):
        p = print("1")
        dialog.close()
        return p

    header = Gtk.HeaderBar(
                        css_name='sw_header_top',
                        show_title_buttons=False
    )
    dialog = Gtk.Window(
                    css_name='sw_window',
                    application=app,
                    titlebar=header,
                    title=str(Path(text_edit_name).stem),
    )
    dialog.remove_css_class('background')
    dialog.add_css_class('sw_background')
    dialog.set_default_size(960, 540)

    btn_save = Gtk.Button(
                    css_name="sw_button_accept",
                    label=msg.msg_dict['save'],
                    valign=Gtk.Align.CENTER,
    )
    btn_save.set_size_request(120, 16),

    btn_cancel = Gtk.Button(
                    css_name="sw_button_cancel",
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
    text = Path(text_edit_name).read_text()
    buffer = Gtk.TextBuffer()
    textview.set_buffer(buffer)
    buffer.set_text(text)

    scrolled = Gtk.ScrolledWindow(
                                css_name='sw_scrolledwindow',
                                propagate_natural_height=True,
                                propagate_natural_width=True,
    )
    btn_save.connect('clicked', cb_btn_save)
    btn_cancel.connect('clicked', cb_btn_cancel)
    header.pack_end(btn_save)
    header.pack_start(btn_cancel)
    scrolled.set_child(textview)
    dialog.set_child(scrolled)
    dialog.present()

#####################___FILE_CHOOSER_WINDOW___:

def on_file(self):

    def add_filters(dialog):

        filter_text = Gtk.FileFilter()
        filter_text.set_name("Exe files")
        filter_text.add_mime_type("application/x-ms-dos-executable")
        filechooser.add_filter(filter_text)

        filter_text = Gtk.FileFilter()
        filter_text.set_name("Text files")
        filter_text.add_mime_type("text/plain")
        filechooser.add_filter(filter_text)

        filter_py = Gtk.FileFilter()
        filter_py.set_name("Python files")
        filter_py.add_mime_type("text/x-python")
        filechooser.add_filter(filter_py)

        filter_any = Gtk.FileFilter()
        filter_any.set_name("Any files")
        filter_any.add_pattern("*")
        filechooser.add_filter(filter_any)

    parent = Gtk.Window(css_name='sw_window')
    parent.remove_css_class('background')
    parent.add_css_class('sw_background')
    filechooser = Gtk.FileChooserDialog(
                                    application=app,
                                    title="Please choose a file",
                                    action=Gtk.FileChooserAction.OPEN
                                    )
    filechooser.set_transient_for(parent)
    filechooser.set_decorated(False)
    filechooser.add_buttons(
                        "_Cancel", Gtk.ResponseType.CANCEL,
                        "_Open", Gtk.ResponseType.ACCEPT
                        )

    add_filters(filechooser)
    path = Gio.File.new_for_commandline_arg(argv[2])
    filechooser.set_current_folder(path)
    filechooser.present()

    def on_buttons(self, response):

        if response == Gtk.ResponseType.ACCEPT:
            app_path = filechooser.get_file().get_path()
            filechooser.destroy()
            return app_path

        elif response == Gtk.ResponseType.CANCEL:
            app_path = None
            filechooser.destroy()
            return app_path

    filechooser.connect("response", on_buttons)

def on_folder(self):

    path = text_message
    parent = Gtk.Window(css_name='sw_window')
    parent.remove_css_class('background')
    parent.add_css_class('sw_background')

    filechooser = Gtk.FileChooserDialog(
                                    application=app,
                                    title="Please choose a folder",
                                    action=Gtk.FileChooserAction.SELECT_FOLDER,
                                    )
    filechooser.set_transient_for(parent)
    filechooser.set_decorated(False)
    filechooser.add_buttons(
                        "_Cancel", Gtk.ResponseType.CANCEL,
                        "_Select", Gtk.ResponseType.ACCEPT
    )

    path = Gio.File.new_for_commandline_arg(argv[2])
    filechooser.set_current_folder(path)
    filechooser.present()

    def on_buttons(self, response):

        if response == Gtk.ResponseType.OK:
            app_folder = filechooser.get_file().get_path()
            filechooser.destroy()
            return app_folder

        elif response == Gtk.ResponseType.CANCEL:
            app_folder = ''
            filechooser.destroy()
            return app_folder

    filechooser.connect("response", on_buttons)

################################___DOWNLOAD___:

def download(url, filename):

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
            exit(1)
        else:
            exit(0)
    else:
        with response as res, open(filename, 'wb') as out:
            shutil.copyfileobj(res, out)
            res.close()
            exit(0)

class ProgressBar(Gtk.Application):

    def __init__(self, url, filename):
        super().__init__(
                        #application_id="ru.project.Crier",
                        flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        GLib.set_prgname(program_name)
        self.percent = 0
        self.quit = None
        self.url = url

        try:
            self.totalsize = urlopen(url).length
        except Exception as e:
            self.totalsize = None

        self.filename = filename
        self.program_name = f"StartWine"
        self.connect('activate', self.activate)
        GLib.timeout_add(1000, self.update)

    def activate(self, root):

        self.window = Gtk.Window(
                            css_name='sw_window',
                            application=self,
                            default_height=80,
                            default_width=320
                            )
        self.window.remove_css_class('background')
        self.window.add_css_class('sw_background')
        self.window.set_title(f"{self.program_name}")
        self.header = Gtk.HeaderBar(
                            css_name='sw_header_top',
                            show_title_buttons=False,
                            )
        self.progressbar = Gtk.ProgressBar(
                                    css_name='sw_progressbar',
                                    show_text=True
                                    )
        self.progressbar.set_hexpand(True)
        self.progressbar.set_vexpand(True)
        self.progressbar.set_margin_bottom(32)
        self.label = Gtk.Label(css_name='sw_label')
        self.name = str(list(filename.replace('/','\n').split())[-1])
        self.label.set_label(self.name)
        self.grid = Gtk.Grid()
        self.grid.set_margin_start(8)
        self.grid.set_margin_end(8)
        self.grid.set_margin_bottom(8)
        self.grid.set_margin_top(8)
        self.grid.set_row_spacing(8)
        self.grid.attach(self.label, 0, 0, 1, 1)
        self.grid.attach(self.progressbar, 0, 1, 1, 1)
        self.window.set_titlebar(self.header)
        self.window.set_child(self.grid)
        self.add_window(self.window)
        self.window.present()

    def update(self):

        if self.totalsize is None:
            print(f'Impossible to determine total size. URL not found...Exit')
            self.quit = self.window.close()
            exit(1)

        if Path(self.filename).exists():
            current = Stat(self.filename).st_size
            self.percent = current / self.totalsize

            if self.quit is None:
                self.progressbar.set_fraction(self.percent)

            if self.percent >= 1:
                print(f'Download_completed_successfully.')
                self.quit = self.window.close()

        return True

##############################___EXTRACTION___:

class ExtractBar(Gtk.Application):

    def __init__(self, filename, path):
        super().__init__(
                        #application_id="ru.project.Crier",
                        flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        GLib.set_prgname(program_name)
        self.quit = None
        self.filename = filename
        self.path = path
        self.program_name = f"StartWine"
        self.connect('activate', self.activate)
        GLib.timeout_add(100, self.update)

    def activate(self, root):

        self.window = Gtk.Window(
                            css_name='sw_window',
                            application=self,
                            default_height=80,
                            default_width=320
                            )
        self.window.remove_css_class('background')
        self.window.add_css_class('sw_background')
        self.window.set_title(f"{self.program_name}")
        self.header = Gtk.HeaderBar(
                            css_name='sw_header_top',
                            show_title_buttons=False,
                            )
        self.progressbar = Gtk.ProgressBar(
                                    css_name='sw_progressbar',
                                    show_text=True
                                    )
        self.progressbar.set_hexpand(True)
        self.progressbar.set_vexpand(True)
        self.progressbar.set_margin_bottom(32)
        self.progressbar.set_show_text(True)
        self.progressbar.set_text(Path(self.filename).name)
        self.label = Gtk.Label(css_name='sw_label')
        self.name = str('Extraction...')
        self.label.set_label(self.name)
        self.grid = Gtk.Grid()
        self.grid.set_margin_start(8)
        self.grid.set_margin_end(8)
        self.grid.set_margin_bottom(8)
        self.grid.set_margin_top(8)
        self.grid.set_row_spacing(8)
        self.grid.attach(self.label, 0, 0, 1, 1)
        self.grid.attach(self.progressbar, 0, 1, 1, 1)
        self.window.set_titlebar(self.header)
        self.window.set_child(self.grid)
        self.add_window(self.window)
        self.window.present()

    def update(self):

        if self.quit is None:
            self.progressbar.pulse()
            return True
        else:
            self.window.close()
            return False

    def extract_tar(self, filename, path):

        if Path(filename).exists():
            taro = tarfile.open(filename)

            for member_info in taro.getmembers():
                taro.extract(member_info, path=path)
                print("Extracting: " + member_info.name)
            else:
                taro.close()
                print(f'Extraction_completed_successfully.')
                self.quit = 0
        else:
            print(f'{filename} not exists...Exit.')
            self.quit = 1
            exit(1)

    def extract_zip(self, filename, path):

        if Path(filename).exists():
            zipo = zipfile.ZipFile(filename)

            for member_info in zipo.namelist():
                print("Extracting: " + member_info)
                zipo.extract(member_info, path=path)
            else:
                zipo.close()
                print(f'Extraction_completed_successfully.')
                self.quit = 0
        else:
            print(f'{filename} not exists...Exit.')
            self.quit = 1
            exit(1)

class ExtractIcon():

    def __init__(self, filename=None, data=None):
        '''Loads an executable from the given filename or data (raw bytes).'''

        self._pefile = pefile.PE(name=filename, data=data, fast_load=True)
        self._pefile.parse_data_directories(pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'])

        if not hasattr(self._pefile, 'DIRECTORY_ENTRY_RESOURCE'):
            raise RuntimeError("File has no icon")

        res = {r.id: r for r in reversed(self._pefile.DIRECTORY_ENTRY_RESOURCE.entries)}

        self.rt_group_icon = res.get(pefile.RESOURCE_TYPE["RT_GROUP_ICON"])
        if not self.rt_group_icon:
            raise RuntimeError("File has no group icon resources")

        self.rt_icon = res.get(pefile.RESOURCE_TYPE["RT_ICON"])

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
            raise  RuntimeError("Invalid group icon definition (got Reserved=%s instead of 0)" % hex(grp_icon_dir.Reserved))

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
        fd.write(b"\x00\x00")
        fd.write(struct.pack("<H", 1))
        fd.write(struct.pack("<H", len(icons)))

        data_offset = 6 + (len(icons) * 16)
        for i in icons:
            group_icon, icon_data = i
            fd.write(group_icon.__pack__()[:12])
            fd.write(struct.pack("<I", data_offset))
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

class HudSize():
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
    -h    '--help'                                 Show help info
    -i    'text'                                   Info dialog window
    -e    'text'                                   Error dialog window
    -w    'text'                                   Warning dialog window
    -q    'text' 'button_name1,button_name2'       Question dialog window
    -t    'file'                                   Open text file in dialog window
    -fl   'path'                                   File chooser dialog window
    -fd   'path'                                   Directory chooser dialog window
    -d    'url' 'filename'                         Download progressbar window
    -tar  'filename, path'                         Extraction tar archive progressbar window
    -zip  'filename, path'                         Extraction zip archive progressbar window
    -ico  'input_file, output_file'                Extraction ico from dll or exe file
    -hud                                           Show mangohud font size
'''
    )

##########################___SYSTEM_ARGUMENTS___:

if __name__ == "__main__":
    app = Crier()

    if len(argv) > 1:
        if str(argv[1]) == str("-d"):
            import multiprocessing as mp
            url = str(argv[2])
            filename = str(argv[3])
            process = mp.Process(target=download, args=[url, filename])
            process.start()
            app = ProgressBar(url, filename)
            app.run()

        elif str(argv[1]) == str("-tar"):
            import tarfile
            from threading import Thread

            filename = str(argv[2])
            path = str(argv[3])
            app = ExtractBar(filename, path)
            Thread(target=app.extract_tar, args=[filename, path]).start()
            app.run()

        elif str(argv[1]) == str("-zip"):
            import zipfile
            from threading import Thread

            filename = str(argv[2])
            path = str(argv[3])
            app = ExtractBar(filename, path)
            Thread(target=app.extract_zip, args=[filename, path]).start()
            app.run()

        elif str(argv[1]) == str("-ico"):
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
            app = ExtractIcon(input_file)
            app.extract_icon(output_file, num=num)

        elif str(argv[1]) == str("-hud"):
            import psutil
            HudSize()

        elif str(argv[1]) == str("-p"):
            if len(argv) > 2:
                path = argv[2]
            else:
                path = sw_default_path

            app = StartPathManager(path)
            app.run()
            run_menu()

        elif str(argv[1]) == str("-py"):
            run_menu()

        elif str(argv[1]) == str("-h") or str(argv[1]) == str("--help"):
            on_helper()

        elif len(argv) >= 3:
            text_message = argv[2]
            app.run()
        else:
            on_helper()
