#!/usr/bin/env python3

import os
import sys
import gi
gi.require_version('Gtk', '3.0')
gi.require_version('Gdk', '3.0')
from gi.repository import Gdk, GdkPixbuf, Gio, GLib, GObject, Gtk
from pathlib import Path
import subprocess
from subprocess import run
import threading
from threading import Thread, Event
import urllib.request
from urllib.request import Request, urlopen, urlretrieve
from urllib.error import HTTPError
import time
import tarfile
import zipfile
import shutil

try:
    from OpenGL.GL import *
    from OpenGL.GL import shaders
    import numpy as np
    from PIL import Image
except:
    pass

sw_path = Path(os.path.dirname(os.path.abspath(__file__))).parent.parent
sw_scripts = f"{sw_path}/data/scripts"
sw_icon = f"{sw_path}/data/img"
sw_app_config = f"{sw_path}/data/app_config"
sw_css = f"{sw_icon}/sw_themes/css"
sw_rsh = Path(f"{sw_scripts}/sw_run.sh")
crier_title = f"StartWine"

themes = ['black','grey','white', 'blue','purple','red','green','yellow','brown']

window = None
dialog = None
view = None
filechooser = None

try:
    m = str(sys.argv[1])
except IndexError as e:
    print('<< start_sw_crier_default >>')
    m = str("")

def get_out():

    app_path = str(sw_rsh.read_text()).split('" ')[-1].replace('\n', '').replace('%F', '').replace(' ', '_')
    app_name = app_path.split('/')[-1].split('.exe')[0]
    return app_name

def get_arg(arg):

    return arg

def get_css(css_name):

    css = css_name
    screen = Gdk.Screen.get_default()
    provider = Gtk.CssProvider()
    style_context = Gtk.StyleContext()
    style_context.add_provider_for_screen(
        screen, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
    )
    provider.load_from_path(css)

def get_gradient_css(window, dialog, view, filechooser):

    proc_vga = run(f"lspci | grep VGA", shell=True, stdout=subprocess.PIPE, encoding='UTF-8')
    grep_vga = str(proc_vga.stdout[0:]).replace('\n', '')

    if not str('NVIDIA') in grep_vga:

        try:
            gc = Path(f"{sw_app_config}/.default")
            gcread = gc.read_text().split('\n')

            for line in gcread:
                sw_theme = line.replace('export SW_USE_THEME=', '')
                if sw_theme in themes:
                    css_name = f"{sw_css}/{sw_theme}/gtk-3.0/toggle.css"
        except:
            pass

        if not window is None:
            provider_window = Gtk.CssProvider()
            provider_window.load_from_path(css_name)
            window.get_style_context().add_provider(
                provider_window, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
                )

        if not view is None:
            provider_view = Gtk.CssProvider()
            provider_view.load_from_path(css_name)
            view.get_style_context().add_provider(
                provider_view, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
                )

        if not dialog is None:
            provider_dialog = Gtk.CssProvider()
            provider_dialog.load_from_path(css_name)
            dialog.get_style_context().add_provider(
                provider_dialog, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
                )

        if not filechooser is None:
            provider_filechooser = Gtk.CssProvider()
            provider_filechooser.load_from_path(css_name)
            filechooser.get_style_context().add_provider(
                provider_filechooser, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
                )

def on_theme():

    try:
        gc = Path(f"{sw_app_config}/.default")
        gcread = gc.read_text().split('\n')

        for line in gcread:
            sw_theme = line.replace('export SW_USE_THEME=', '')
            if sw_theme in themes:
                css_name = f"{sw_css}/{sw_theme}/gtk-3.0/gtk.css"
                get_css(css_name)
    except:
        pass

on_theme()

class sw_crier():

###################___INFO___:

    def on_info(i):

        text_info = i
        dialog = Gtk.MessageDialog(
            flags=0,
            message_type=Gtk.MessageType.INFO,
            buttons=Gtk.ButtonsType.OK,
            text=f"{crier_title} INFO",
        )
        get_gradient_css(window, dialog, view, filechooser)

        dialog.format_secondary_text(
            text_info
        )
        dialog.set_default_size(320, 120)
        dialog.run()
        print('<< INFO_dialog_closed >>')

        dialog.destroy()

    if m == str("-i"):
        i = str(sys.argv[2])
        on_info(i)

####################___ERROR___:

    def on_error(e):
        text_error = e
        dialog = Gtk.MessageDialog(
            flags=0,
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.CANCEL,
            text=f"{crier_title} ERROR",
        )
        get_gradient_css(window, dialog, view, filechooser)

        dialog.format_secondary_text(
            text_error
        )
        dialog.set_default_size(320, 120)
        dialog.run()
        print('<< ERROR_dialog_closed >>')

        dialog.destroy()

    if m == str("-e"):
        e = str(sys.argv[2])
        on_error(e)

###################___WARNING___:

    def on_warn(w):
        text_warn = w
        dialog = Gtk.MessageDialog(
            flags=0,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.OK_CANCEL,
            text=f"{crier_title} WARNING",
        )
        get_gradient_css(window, dialog, view, filechooser)

        dialog.format_secondary_text(
            text_warn
        )
        dialog.set_default_size(320, 120)
        response = dialog.run()

        if response == Gtk.ResponseType.OK:
            p = print("0")
            return p
        elif response == Gtk.ResponseType.CANCEL:
            p = print("1")
            return p

        dialog.destroy()

    if m == str("-w"):
        w = str(sys.argv[2])
        on_warn(w)

#######################___QUESTION___:

    def on_question(q):
        text_quest = q
        dialog = Gtk.MessageDialog(
            flags=0,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.YES_NO,
            text=f"{crier_title} QUESTION",
        )
        get_gradient_css(window, dialog, view, filechooser)

        dialog.format_secondary_text(
            text_quest
        )
        dialog.set_default_size(320, 120)
        response = dialog.run()

        if response == Gtk.ResponseType.YES:
            p = print("0")
            request = "0"
            dialog.destroy()
            return request
        elif response == Gtk.ResponseType.NO:
            p = print("1")
            request = "1"
            dialog.destroy()
            return request

        dialog.destroy()

    if m == str("-q"):
        q = str(sys.argv[2])
        on_question(q)

#######################___TEXT_INFO___:

    def text_info(text_edit_name):

        def on_response(dialog, response):

            if response == Gtk.ResponseType.OK:
                p = print("0")
                startIter, endIter = buffer.get_bounds()
                get_text = buffer.get_text(startIter, endIter, False)
                text_edit_name.write_text(get_text)
                return p
            else:
                print('<< Text_Info_closed >>')

        dialog = Gtk.Dialog()
        get_title = str(Path(text_edit_name.stem))
        dialog.set_title(get_title)
        dialog.set_default_size(960, 540)
        dialog.add_button("_SAVE", Gtk.ResponseType.OK)
        dialog.connect("response", on_response)
        view = Gtk.TextView()
        view.set_top_margin(16)
        view.set_left_margin(16)
        view.set_right_margin(16)
        view.set_bottom_margin(16)
        text = text_edit_name.read_text()
        buffer = view.get_buffer()
        buffer.set_text(text)
        view.set_vexpand(True)
        view.set_hexpand(True)
        scrolled = Gtk.ScrolledWindow()
        scrolled.add(view)
        dialog.vbox.add(scrolled)
        dialog.connect("destroy", Gtk.main_quit)
        dialog.show_all()
        get_gradient_css(window, dialog, view, filechooser)
        Gtk.main()

    if m == str("-t"):
        text_edit_name = Path(sys.argv[2])
        text_info(text_edit_name)

####################___FILE_CHOOSER_WINDOW___:

    def on_file(fl):

        path = fl

        def add_filters(filechooser):

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

        filechooser = Gtk.FileChooserDialog(
            title = f"{crier_title}",
            action=Gtk.FileChooserAction.OPEN
            )
        filechooser.add_buttons(
            Gtk.STOCK_CANCEL,
            Gtk.ResponseType.CANCEL,
            Gtk.STOCK_OPEN,
            Gtk.ResponseType.OK
            )

        get_gradient_css(window, dialog, view, filechooser)

        add_filters(filechooser)
        filechooser.set_current_folder(path)
        filechooser.set_default_size(960, 540)

        response = filechooser.run()

        if response == Gtk.ResponseType.OK:
            app_path = filechooser.get_filename()
            filechooser.destroy()
            return app_path

        elif response == Gtk.ResponseType.CANCEL:
            app_path = None
            filechooser.destroy()
            return app_path

        filechooser.destroy()

    if m == str("-fl"):
        fl = str(sys.argv[2])
        on_file(fl)

    def on_folder(fd):

        path = fd

        def add_filters(filechooser):
            filter_text = Gtk.FileFilter()
            filter_text.set_name("Any files")
            filter_text.add_mime_type("*")
            filechooser.add_filter(filter_text)

        filechooser = Gtk.FileChooserDialog(
            title = f"{crier_title}",
            action=Gtk.FileChooserAction.SELECT_FOLDER
            )
        filechooser.add_buttons(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, "Select", Gtk.ResponseType.OK
            )
        filechooser.set_current_folder(path)

        get_gradient_css(window, dialog, view, filechooser)

        response = filechooser.run()

        if response == Gtk.ResponseType.OK:
            app_folder = filechooser.get_filename()
            filechooser.destroy()
            return app_folder
        elif response == Gtk.ResponseType.CANCEL:
            app_folder = ''
            filechooser.destroy()
            return app_folder

    if m == str("-fd"):
        fd = str(sys.argv[2])
        on_folder(fd)

############################___DOWNLOAD___:

    def download(url, filename):
        window = progressbar = label = quit = None
        event = Event()
        def reporthook(blocknum, blocksize, totalsize):
            nonlocal quit
            if blocknum == 0:
                def guiloop():
                    nonlocal window, progressbar, label
                    window = Gtk.Window(default_height=80, default_width=320)
                    window.set_title(f"{crier_title}")
                    window.set_role('task_dialog')
                    progressbar = Gtk.ProgressBar(show_text=True)
                    progressbar.set_hexpand(True)
                    label = Gtk.Label()
                    name = str(list(filename.replace('/','\n').split())[-1])
                    label.set_label(name)
                    box1 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
                    box1.pack_start(label, False, True, 16)
                    box2 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
                    box2.pack_start(progressbar, False, True, 16)
                    grid = Gtk.Grid()
                    grid.set_row_spacing(16)
                    grid.attach(box1, 0, 0, 1, 1)
                    grid.attach(box2, 0, 1, 1, 1)
                    window.add(grid)
                    window.connect("destroy", Gtk.main_quit)
                    window.show_all()
                    event.set()
                    get_gradient_css(window, dialog, view, filechooser)
                    Gtk.main()
                Thread(target=guiloop).start()
            event.wait(1)

            percent = blocknum * blocksize / totalsize

            if quit is None:
                def bar():
                    if blocksize == 0:
                        progressbar.set_show_text(False)
                        progressbar.pulse()
                        return True
                    else:
                        progressbar.set_fraction(percent)
                GLib.timeout_add(50, bar)
            if percent >= 1:
                print(f'<< download_completed_successfully >>')
                quit = GLib.timeout_add(100, Gtk.main_quit)

        try:
            urllib.request.urlretrieve(url, filename, reporthook)

        except IOError as e:
            print(e)

            try:
                urllib.request.urlretrieve(url, filename, reporthook)

            except HTTPError as e:
                print(e)
                print(f'<< try_sending_a_request_with_headers >>')

                url_rq = Request(url, headers={"User-Agent": "Mozilla/5.0"})

                with urllib.request.urlopen(url_rq) as response, open(filename, 'wb') as out_file:

                    totalsize = response.length
                    blocknum = 0
                    blocksize = 0
                    tmp_file = filename

                    reporthook(blocknum, blocksize, totalsize)
                    shutil.copyfileobj(response, out_file)

                    print(f'<< download_completed_successfully >>')

                    quit = GLib.timeout_add(100, Gtk.main_quit)

    if m == str("-d"):
        url = str(sys.argv[2])
        filename = str(sys.argv[3])

        try:
            download(url, filename)
        except HTTPError as e:
            print(e)

##############################___EXTRACTION___:

############___extract_tar___:

    def extract_tar(filename, path):
        window = progressbar = label = quit = None
        event = Event()

        def tar_file():
            nonlocal quit
            if Path(filename).exists():
                taro = tarfile.open(filename)

                def guiloop():
                    nonlocal window, progressbar, label
                    window = Gtk.Window(default_height=80, default_width=320)
                    window.set_title(f"{crier_title}")
                    window.set_role('task_dialog')
                    progressbar = Gtk.ProgressBar(show_text=True)
                    progressbar.set_hexpand(True)
                    label = Gtk.Label()
                    name = str("Extracting...")
                    label.set_label(name)
                    box1 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
                    box1.pack_start(label, False, True, 16)
                    box2 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
                    box2.pack_start(progressbar, False, True, 16)
                    grid = Gtk.Grid()
                    grid.set_row_spacing(16)
                    grid.attach(box1, 0, 0, 1, 1)
                    grid.attach(box2, 0, 1, 1, 1)
                    window.add(grid)
                    window.connect("destroy", Gtk.main_quit)
                    window.show_all()
                    get_gradient_css(window, dialog, view, filechooser)
                    event.set()
                    Gtk.main()
                Thread(target=guiloop).start()
            event.wait(1)

            if quit is None:

                def bar():
                    progressbar.pulse()
                    return True
                GLib.timeout_add(100, bar)

            def tar_info():
                try:
                    progressbar.set_show_text(True)
                    progressbar.set_text(filename)
                    for member_info in taro.getmembers():
                        print('<< extracting >>' + member_info.name)
                        taro.extract(member_info, path=path)
                    taro.close()
                    print(f'<< extraction_completed_successfully >>')
                    quit = GLib.timeout_add(100, Gtk.main_quit)
                except:
                    quit = GLib.timeout_add(100, Gtk.main_quit)
            Thread(target=tar_info).start()
        return tar_file()

    if m == str("-tar"):
        filename = str(sys.argv[2])
        path = str(sys.argv[3])
        extract_tar(filename, path)

############___extract_zip___:

    def extract_zip(filename, path):
        window = progressbar = label = quit = None
        event = Event()

        def zip_file():
            nonlocal quit
            if Path(filename).exists():
                zipo = zipfile.ZipFile(filename)

                def guiloop():
                    nonlocal window, progressbar, label
                    window = Gtk.Window(default_height=80, default_width=320)
                    window.set_title(f"{crier_title}")
                    progressbar = Gtk.ProgressBar(show_text=True)
                    progressbar.set_hexpand(True)
                    label = Gtk.Label()
                    name = str("Extracting...")
                    label.set_label(name)
                    box1 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
                    box1.pack_start(label, False, True, 16)
                    box2 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
                    box2.pack_start(progressbar, False, True, 16)
                    grid = Gtk.Grid()
                    grid.set_row_spacing(16)
                    grid.attach(box1, 0, 0, 1, 1)
                    grid.attach(box2, 0, 1, 1, 1)
                    window.add(grid)
                    window.connect("destroy", Gtk.main_quit)
                    window.show_all()
                    get_gradient_css(window, dialog, view, filechooser)
                    event.set()
                    Gtk.main()
                Thread(target=guiloop).start()
            event.wait(1)

            if quit is None:

                def bar():
                    progressbar.pulse()
                    return True
                GLib.timeout_add(200, bar)

            def zip_info():
                try:
                    progressbar.set_show_text(True)
                    progressbar.set_text(filename)
                    for member_info in zipo.namelist():
                        print('<< extracting >>' + member_info)
                        zipo.extract(member_info, path=path)
                    zipo.close()
                    print(f'<< extraction_completed_successfully >>')
                    quit = GLib.timeout_add(100, Gtk.main_quit)
                except:
                    quit = GLib.timeout_add(100, Gtk.main_quit)
            Thread(target=zip_info).start()
        return zip_file()

    if m == str("-zip"):
        filename = str(sys.argv[2])
        path = str(sys.argv[3])

        extract_zip(filename, path)

    def gl_main():

        vertices = (
            (0.4, -0.4, -0.4),
            (0.4, 0.4, -0.4),
            (-0.4, 0.4, -0.4),
            (-0.4, -0.4, -0.4),
            (0.4, -0.4, 0.4),
            (0.4, 0.4, 0.4),
            (-0.4, -0.4, 0.4),
            (-0.4, 0.4, 0.4)
            )

        edges = (
            (0,1),(0,3),(0,4),(2,1),(2,3),(2,7),
            (6,3),(6,4),(6,7),(5,1),(5,4),(5,7)
            )

        colors = (
            (0.1, 0.1, 0.8),
            (0.2, 0.2, 0.8),
            (0.1, 0.2, 0.8),
            (0.2, 0.1, 0.8),
            (0.8, 0.1, 0.1),
            (0.8, 0.2, 0.2),
            (0.8, 0.1, 0.2),
            (0.8, 0.2, 0.1),
            (0.1, 0.8, 0.1),
            (0.2, 0.8, 0.2),
            (0.1, 0.8, 0.2),
            (0.2, 0.8, 0.1),
            )

        surfaces = (
            (0,1,2,3),(3,2,7,6),(6,7,5,4),
            (4,5,1,0),(1,5,7,2),(4,0,3,6)
            )

        normals = [
            ( 0,  0, -1),  # surface 0
            (-1,  0,  0),  # surface 1
            ( 0,  0,  1),  # surface 2
            ( 1,  0,  0),  # surface 3
            ( 0,  1,  0),  # surface 4
            ( 0, -1,  0)   # surface 5
            ]

        textureCoordinates = ((0, 0), (0, 1), (1, 1), (1, 0))

        ##############################___OPENGL_AREA_FUNC___:

        def on_realize(gl_area):

            ctx = gl_area.get_context()
            gues = gl_area.get_use_es()
            print('realized', ctx)
            print('realized', gues)

        def on_render(gl_area, ctx):

            ctx.make_current()
            glClearColor(0.05, 0.05, 0.05, 1.0)
            glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)
            glRotatef(4, 1, 0, 1)

            num = 1
            new_vertices = []

            for vert in vertices:
                new_vert = []
                x = vert[0] * num
                y = vert[1] * num
                z = vert[2] * num
                new_vert.append(x)
                new_vert.append(y)
                new_vert.append(z)
                new_vertices.append(new_vert)

            colored_cube(vertices)
#            textured_cube(vertices)

        def textured_cube(vertices):

            image = Image.open(f'{sw_scripts}/image.png')
            data = np.array(list(image.getdata()), np.uint8)

            texture = glGenTextures(1)
            glBindTexture(GL_TEXTURE_2D, texture)
            glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, image.width, image.height, 0, GL_RGBA, GL_UNSIGNED_BYTE, data)
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR)
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR)
            glEnable(GL_TEXTURE_2D)

            glColor3f(1, 1, 1)

            glBegin(GL_QUADS)

            for i_surface, surface in enumerate(surfaces):
                x = 0
                glNormal3fv(normals[i_surface])
                for i_vertex, vertex in enumerate(surface):
                    x+=1
                    glTexCoord2fv(textureCoordinates[i_vertex])
                    glVertex3fv(vertices[vertex])
            glEnd()

            glColor3fv(colors[0])

            glBegin(GL_LINES)

            for edge in edges:
                for vertex in edge:
                    glVertex3fv(vertices[vertex])
            glEnd()

        def colored_cube(vertices):

            glBegin(GL_LINES)
            for edge in edges:
                x = 0
                for vertex in edge:
                    x += 1
                    glColor3fv(colors[x])
                    glVertex3fv(vertices[vertex])
            glEnd()

            glBegin(GL_QUADS)
            for surface in surfaces:
                x = 0
                for vertex in surface:
                    x += 2
                    glColor3fv(colors[x])
                    glVertex3fv(vertices[vertex])
            glEnd()

        ######################___REFRESH_AREA___:

        def refresh_gl_area():

            glClear(GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT)
            gl_area.queue_draw()
            return True

        GLib.timeout_add(1, refresh_gl_area)

        def on_hide(widget, event):
            global gl_switch
            if event.keyval and event.keyval != Gdk.KEY_Escape:
                gl_switch = 'hide'
                gl_window.close()
            else:
                gl_window.stop_emission_by_name("close")
                gl_switch = 'hide'
                gl_window.close()
                return True

        #######################___BUILDER___:
        gl_window = Gtk.Dialog()
        gl_window.set_title("Preview")
        gl_window.set_default_size(640, 640)
        gl_window.set_decorated(False)
        gl_window.set_modal(True)
        gl_area = Gtk.GLArea()
        gl_area.set_use_es(-1)
        gl_area.set_auto_render(True)
        gl_area.set_has_depth_buffer(True)
        gl_area.set_has_stencil_buffer(True)
        gl_area.set_hexpand(True)
        gl_area.set_vexpand(True)
        gl_window.vbox.add(gl_area)
        gl_area.connect("render", on_render)
        gl_area.connect("realize", on_realize)
        gl_window.connect("key-press-event", on_hide)
        gl_window.show_all()
        gl_window.connect("destroy", Gtk.main_quit)
        Gtk.main()

    if m == str("-opengl"):
        try:
            from OpenGL.GL import shaders
        except:
            e = "python3 opengl, numpy, pillow packages required"
            on_error(e)
        else:
            gl_main()

    def helper():
        print("-i    'text'                                   Info dialog window\n"
            "-e    'text'                                   Error dialog window\n"
            "-w    'text'                                   Warning dialog window\n"
            "-q    'text'                                   Question dialog window\n"
            "-t    'path to text file'                      Text dialog window\n"
            "-fl   'path to directory'                      File chooser dialog window\n"
            "-fd   'path to directory'                      Directory chooser dialog window\n"
            "-d    'url' 'filename'                         Download progressbar window\n"
            "-tar  'file name, path'                        Extraction tar archive progressbar window\n"
            "-zip  'file name, path'                        Extraction zip archive progressbar window\n"
            "-opengl                                        Rotating cube in OpenGL window,\n"
            "                                               press (Ctrl_L + q) for exit or any key for hide"
            )

    if m == str("-h") or m == str("--help"):
        helper()

