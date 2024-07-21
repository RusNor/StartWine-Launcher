#!/usr/bin/env python3
######################

import os
from os import environ, getenv
from subprocess import run, PIPE

ls_gpu_in_use = "lspci -nnk | grep -i vga -A3 | grep 'in use' | cut -d ' ' -f5-100"
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
    environ['PYOPENGL_PLATFORM'] = 'posix'
    environ['GDK_DEBUG'] = 'gl-glx'
    environ['GDK_BACKEND'] = 'x11'
    environ['GSK_RENDERER'] = 'opengl'

import sys
from sys import argv
from pathlib import Path
import time
import json
from array import array

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Gdk', '4.0')
gi.require_version('GL', '1.0')
from gi.repository import Gtk, Gdk, Gio, GLib, GdkPixbuf

from OpenGL.GL import *
from OpenGL.GL import shaders
from OpenGL.GL.shaders import compileProgram, compileShader

link = f"{sys.argv[0]}"
sw_scripts = Path(link).parent
sw_path = Path(sw_scripts).parent.parent
sw_menu_json = Path(f'{sw_scripts}/sw_menu.json')
sw_css_dark = Path(f'{sw_path}/data/img/sw_themes/css/dark/gtk.css')
sw_css_light = Path(f'{sw_path}/data/img/sw_themes/css/light/gtk.css')
sw_css_custom = Path(f'{sw_path}/data/img/sw_themes/css/custom/gtk.css')

if Path(f'{sw_path}/data/img').exists():
    sw_cube_icon = Path(f'{sw_path}/data/img/gui_icons/cube.png')
    image = GdkPixbuf.Pixbuf.new_from_file(f'{sw_cube_icon}')

elif Path(f'{sw_scripts.parent}/share/icons/cube.png').exists():
    sw_cube_icon = Path(f'{sw_scripts.parent}/share/icons/cube.png')
    image = GdkPixbuf.Pixbuf.new_from_file(f'{sw_cube_icon}')

elif Path(f'{sw_scripts}/cube.png').exists():
    sw_cube_icon = Path(f'{sw_scripts}/cube.png')
    image = GdkPixbuf.Pixbuf.new_from_file(f'{sw_cube_icon}')

elif Path('/usr/share/sw/gui_icons/cube.png').exists():
    sw_cube_icon = Path('/usr/share/sw/gui_icons/cube.png')
    image = GdkPixbuf.Pixbuf.new_from_file(f'{sw_cube_icon}')

elif Path('/usr/share/icons/cube.png').exists():
    sw_cube_icon = Path('/usr/share/icons/cube.png')
    image = GdkPixbuf.Pixbuf.new_from_file(f'{sw_cube_icon}')

else:
    image = None

#############################___SET_PROGRAM_NAME___:

program_name = GLib.set_prgname('Cube')
application_name = GLib.set_application_name('Cube')

#############################___APPLICATION___:

vertex_src = """
# version 410

layout(location = 0) in vec3 position;
layout(location = 1) in vec3 color;
layout(location = 2) in vec2 texture;

//uniform vec3 iResolution;
uniform float iTime;

out vec3 vColor;
out vec2 fragCoord;

mat4 rotX( in float angle ) {

    float c = cos(angle);
    float s = sin(angle);

    return mat4(1.0, 0, 0, 0,
                0, c, -s, 0,
                0, s, c, 0,
                0, 0, 0, 1);
}

mat4 rotY( in float angle ) {
    
    float c = cos(angle);
    float s = sin(angle);
    
    return mat4( c, 0, s, 0,
                0, 1.0, 0, 0,
                -s, 0, c, 0,
                0, 0, 0, 1);
}

mat4 rotZ( in float angle ) {
    float c = cos(angle);
    float s = sin(angle);

    return mat4(c, -s, 0, 0,
                s, c, 0, 0,
                0, 0, 1, 0,
                0, 0, 0, 1);
}

void main()
{
    gl_Position = rotX(iTime *0.5) * rotZ(iTime * 0.5) * vec4(position, 1.0);
    // gl_Position = vec4(position, 1.0);
    vColor = color;
    fragCoord = texture;
}
"""

fragment_src = """
# version 410

uniform vec3      iResolution;
uniform float     iTime;
uniform float     iTimeDelta;
uniform int       iFrame;
uniform float     iFrameRate;
uniform float     iChannelTime[4];
uniform vec3      iChannelResolution[4];
uniform vec4      iMouse;
uniform sampler2D iChannel0;
uniform sampler2D iChannel1;
uniform sampler2D iChannel2;
uniform sampler2D iChannel3;
uniform vec4      iDate;
uniform float     iSampleRate;

in vec2 fragCoord;
in vec3 vColor;

uniform sampler2D sTexture;
out vec4 fragColor;

void main()
{
    fragColor = texture(sTexture, fragCoord);
}
"""
vertices = [-0.5, -0.5,  0.5,  1.0, 0.0, 0.0,  0.0, 0.0,
             0.5, -0.5,  0.5,  0.0, 1.0, 0.0,  1.0, 0.0,
             0.5,  0.5,  0.5,  0.0, 0.0, 1.0,  1.0, 1.0,
            -0.5,  0.5,  0.5,  1.0, 1.0, 1.0,  0.0, 1.0,

            -0.5, -0.5, -0.5,  1.0, 0.0, 0.0,  0.0, 0.0,
             0.5, -0.5, -0.5,  0.0, 1.0, 0.0,  1.0, 0.0,
             0.5,  0.5, -0.5,  0.0, 0.0, 1.0,  1.0, 1.0,
            -0.5,  0.5, -0.5,  1.0, 1.0, 1.0,  0.0, 1.0,

             0.5, -0.5, -0.5,  1.0, 0.0, 0.0,  0.0, 0.0,
             0.5,  0.5, -0.5,  0.0, 1.0, 0.0,  1.0, 0.0,
             0.5,  0.5,  0.5,  0.0, 0.0, 1.0,  1.0, 1.0,
             0.5, -0.5,  0.5,  1.0, 1.0, 1.0,  0.0, 1.0,

            -0.5,  0.5, -0.5,  1.0, 0.0, 0.0,  0.0, 0.0,
            -0.5, -0.5, -0.5,  0.0, 1.0, 0.0,  1.0, 0.0,
            -0.5, -0.5,  0.5,  0.0, 0.0, 1.0,  1.0, 1.0,
            -0.5,  0.5,  0.5,  1.0, 1.0, 1.0,  0.0, 1.0,

            -0.5, -0.5, -0.5,  1.0, 0.0, 0.0,  0.0, 0.0,
             0.5, -0.5, -0.5,  0.0, 1.0, 0.0,  1.0, 0.0,
             0.5, -0.5,  0.5,  0.0, 0.0, 1.0,  1.0, 1.0,
            -0.5, -0.5,  0.5,  1.0, 1.0, 1.0,  0.0, 1.0,

             0.5,  0.5, -0.5,  1.0, 0.0, 0.0,  0.0, 0.0,
            -0.5,  0.5, -0.5,  0.0, 1.0, 0.0,  1.0, 0.0,
            -0.5,  0.5,  0.5,  0.0, 0.0, 1.0,  1.0, 1.0,
             0.5,  0.5,  0.5,  1.0, 1.0, 1.0,  0.0, 1.0]

indices = [0,  1,  2,  2,  3,  0,
           4,  5,  6,  6,  7,  4,
           8,  9, 10, 10, 11,  8,
          12, 13, 14, 14, 15, 12,
          16, 17, 18, 18, 19, 16,
          20, 21, 22, 22, 23, 20]

vertices = array('f', vertices)
indices = array('I', indices)

global first_frame, first_frame_time, dif_time, x_mouse, y_mouse
first_frame_time = 0
first_frame = 0
dif_time = 0
x_mouse = 0
y_mouse = 0

#############################___SET_CSS_STYLE___:

def init_css_style():

    if sw_menu_json.exists():
        with open(sw_menu_json, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
            dict_ini = json_data

            sw_color_scheme = dict_ini['color_scheme']

            if sw_color_scheme == 'dark':
                css_provider = Gtk.CssProvider()
                css_provider.load_from_file(Gio.File.new_for_path(bytes(sw_css_dark)))
                Gtk.StyleContext.add_provider_for_display(
                    Gdk.Display.get_default(),
                    css_provider,
                    Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
                    )

            elif sw_color_scheme == 'light':
                css_provider = Gtk.CssProvider()
                css_provider.load_from_file(Gio.File.new_for_path(bytes(sw_css_light)))
                Gtk.StyleContext.add_provider_for_display(
                    Gdk.Display.get_default(),
                    css_provider,
                    Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
                    )

            else:
                css_provider = Gtk.CssProvider()
                css_provider.load_from_file(Gio.File.new_for_path(bytes(sw_css_custom)))
                Gtk.StyleContext.add_provider_for_display(
                    Gdk.Display.get_default(),
                    css_provider,
                    Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
                    )
            f.close()

class Cube(Gtk.Application):
    def __init__(self, *args, **kwargs):
        super().__init__(*args,
                        application_id="ru.project.Cube",
                        flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
                        **kwargs
        )
        self.connect('activate', self.on_activate)

    def on_activate(self, app):

        self.gl_window = Gtk.Window(
                            application=app,
                            css_name='sw_window',
                            resizable=False,
                            decorated=False,
        )
        self.gl_window.remove_css_class('background')
        self.gl_window.add_css_class('sw_background')
        self.gl_window.set_title("Hud preview")
        self.gl_window.set_default_size(720, 720)

        self.wc_close = Gtk.Button(css_name='sw_wc_close')
        self.wc_close.set_valign(Gtk.Align.CENTER)
        self.wc_close.connect('clicked', self.on_parent_close)

        self.wc_minimize = Gtk.Button(css_name='sw_wc_minimize')
        self.wc_minimize.set_valign(Gtk.Align.CENTER)
        self.wc_minimize.connect('clicked', self.on_parent_minimize)

        self.wc_maximize = Gtk.Button(css_name='sw_wc_maximize')
        self.wc_maximize.set_valign(Gtk.Align.CENTER)
        self.wc_maximize.connect('clicked', self.on_parent_maximize)

        self.headerbar_end_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.headerbar_end_box.append(self.wc_minimize)
        self.headerbar_end_box.append(self.wc_maximize)
        self.headerbar_end_box.append(self.wc_close)

        self.gl_headerbar = Gtk.HeaderBar(css_name='sw_header_top')
        self.gl_headerbar.set_size_request(-1,46)
        self.gl_headerbar.set_show_title_buttons(False)
        self.gl_headerbar.pack_end(self.headerbar_end_box)

        self.gl_area = Gtk.GLArea()
        self.gl_area.set_auto_render(True)
        self.gl_area.set_has_depth_buffer(True)
        self.gl_area.set_has_stencil_buffer(True)
        self.gl_area.set_hexpand(True)
        self.gl_area.set_vexpand(True)

        self.gl_area.add_tick_callback(self.on_frame_clock)
        self.gl_area.connect("resize", self.on_resize)
        self.gl_area.connect("render", self.on_render)
        self.gl_area.connect("realize", self.on_realize)

        self.ctrl_key = Gtk.EventControllerKey()
        self.ctrl_key.connect('key_pressed', self.on_key_event, self.gl_window)
        self.ctrl_gl_motion = Gtk.EventControllerMotion()
        self.ctrl_gl_motion.connect('motion', self.on_ctrl_gl_motion)

        self.gl_window.add_controller(self.ctrl_gl_motion)
        self.gl_window.add_controller(self.ctrl_key)
        self.gl_window.set_child(self.gl_area)
        #self.gl_window.set_titlebar(self.gl_headerbar)
        self.add_window(self.gl_window)
        self.gl_window.present()

    def on_realize(self, gl_area):

        context = gl_area.get_context()
        api = gl_area.get_api()
        auto_render = gl_area.get_auto_render()
        depth_buffer = gl_area.get_has_depth_buffer()
        stensil_buffer = gl_area.get_has_stencil_buffer()

        print("<< context realized >>", context)
        print("<< use OpenGL API >>", api)
        print("<< auto render >>", auto_render)
        print("<< depth buffer >>", depth_buffer)
        print("<< stensil buffer >>", stensil_buffer)

        if gl_area.get_error():
            return True

    def on_resize(self, gl_area, width, height):

        global gl_resolution
        width = gl_area.get_width()
        height = gl_area.get_height()
        gl_resolution = [width, height, 1.0]

        glViewport(0,0, width, height)

    def on_render(self, gl_area, context):
        """___create render program___"""

        if gl_area.get_error() is not None:
            return False

        else:
            glClearColor (0.024, 0.032, 0.04, 1.0);
            glClear (GL_COLOR_BUFFER_BIT);

            if fragment_src is not None:
                self.on_draw(fragment_src)
                glFlush()

                return True
            else:
                return False

    def on_draw(self, fragment_src):

        global dif_time, timedelta, frame, x_mouse, y_mouse, gl_resolution

        # create shaders
        v = compileShader(vertex_src, GL_VERTEX_SHADER)
        f = compileShader(fragment_src, GL_FRAGMENT_SHADER)

        # shader program
        shader = glCreateProgram()
        glAttachShader(shader, v)
        glAttachShader(shader, f)
        glLinkProgram(shader)

        # Vertex Arrays Object
        VAO = glGenVertexArrays(1)
        glBindVertexArray(VAO)

        # Vertex Buffer Object
        VBO = glGenBuffers(1)
        glBindBuffer(GL_ARRAY_BUFFER, VBO)
        glBufferData(
                    GL_ARRAY_BUFFER,
                    len(vertices.tobytes()),
                    vertices.tobytes(),
                    GL_STATIC_DRAW
        )
        # Element Buffer Object
        EBO = glGenBuffers(1)
        glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, EBO)
        glBufferData(
                    GL_ELEMENT_ARRAY_BUFFER,
                    len(indices.tobytes()),
                    indices.tobytes(),
                    GL_STATIC_DRAW
        )
        glVertexAttribPointer(
                            0,
                            3,
                            GL_FLOAT,
                            GL_FALSE,
                            vertices.itemsize * 8,
                            ctypes.c_void_p(0)
        )
        glEnableVertexAttribArray(0)

        glVertexAttribPointer(
                            1,
                            3,
                            GL_FLOAT,
                            GL_FALSE,
                            vertices.itemsize * 8,
                            ctypes.c_void_p(12)
        )
        glEnableVertexAttribArray(1)

        glVertexAttribPointer(
                            2,
                            2,
                            GL_FLOAT,
                            GL_FALSE,
                            vertices.itemsize * 8,
                            ctypes.c_void_p(24)
        )
        glEnableVertexAttribArray(2)

        # Generate Textures
        texture = glGenTextures(1)
        glBindTexture(GL_TEXTURE_2D, texture)

        # Set the texture wrapping parameters
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT)
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT)

        # Set texture filtering parameters
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR)
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR)

        # Load Image
        if image is not None:
            data = image.get_pixels()
            glTexImage2D(
                        GL_TEXTURE_2D,
                        0,
                        GL_RGBA,
                        image.get_width(),
                        image.get_height(),
                        0,
                        GL_RGBA,
                        GL_UNSIGNED_BYTE,
                        data
            )
        # Use Shader Program
        glUseProgram(shader)
        glClearColor(0.0, 0.0, 0.0, 0.5)
        glClear(GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT)
        glEnable(GL_DEPTH_TEST)
        glEnable(GL_BLEND)
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA)

        resolution_location = glGetUniformLocation(shader, "iResolution")
        time_location = glGetUniformLocation(shader, "iTime")
        mouse_location = glGetUniformLocation(shader, "iMouse");
        timedelta_location = glGetUniformLocation(shader, "iTimeDelta");
        frame_location = glGetUniformLocation(shader, "iFrame");
        sample_rate_location = glGetUniformLocation(shader, "iSampleRate");
        date_location = glGetUniformLocation(shader, "iDate");

        if resolution_location != -1:
            glUniform3fv(resolution_location, 1, gl_resolution)

        if time_location != -1:
            glUniform1f(time_location, dif_time)

        if date_location != -1:
            pass    #glUniform1i(date_location, 1, int(T))

        if mouse_location != -1:
            try:
                glUniform4f(mouse_location, float(x_mouse), float(y_mouse), 1.0, 1.0)
            except:
                pass

        if timedelta_location != -1:
            glUniform1f(timedelta_location, time_delta);

        if frame_location != -1:
            glUniform1i(frame_location, frame);

        if sample_rate_location != -1:
            pass    #glUniform1i(sample_rate_location, samp);

        # Draw elements
        glDrawElements(
                    GL_TRIANGLES,
                    len(indices),
                    GL_UNSIGNED_INT,
                    None
                    )

        # Disable program
        glBindVertexArray(0)
        glDisableVertexAttribArray(0)
        glBindBuffer(GL_ARRAY_BUFFER, 0)
        glUseProgram(0)

        # delete shaders
        glDetachShader(shader, v)
        glDetachShader(shader, f)
        glDeleteShader(v)
        glDeleteShader(f)

        # delete buffers, textures and vertex
        glBindVertexArray(0)
        glDisableVertexAttribArray(0)
        glDisableVertexAttribArray(1)
        glDisableVertexAttribArray(2)
        glDeleteBuffers(1, VBO)
        glDeleteBuffers(1, EBO)
        glDeleteVertexArrays(1, VAO)
        glDeleteTextures(1, texture)
        glDeleteProgram(shader)

    def on_key_event(self, ctrl_key_press, keyval, keycode, state, gl_window):
        '''___window_close_when_press_escape___'''

        if ((state & Gdk.MODIFIER_MASK) == Gdk.ModifierType.SUPER_MASK
            and keyval == Gdk.KEY_Escape):
                self.gl_window.close()

        if keyval == Gdk.KEY_Escape:
            self.gl_window.close()

        if keyval == Gdk.KEY_Return:
            self.gl_window.close()

        if keyval == Gdk.KEY_space:
            self.gl_window.close()

        if ((state & Gdk.MODIFIER_MASK) == Gdk.ModifierType.SHIFT_MASK
            and keyval == Gdk.KEY_F11):
                self.gl_window.queue_draw()

    def on_ctrl_gl_motion(self, ctrl_gl_motion, x, y):
        '''___cursor position signal handler___'''

        global x_mouse, y_mouse
        x_mouse = x
        y_mouse = y

        self.gl_area.queue_render()
        return True

    def on_frame_clock(self, gl_area, frame_clock):
        '''___update frames and redraw widget___'''

        global first_frame, first_frame_time, dif_time, time_delta, frame

        frame_time = frame_clock.get_frame_time()
        frame = frame_clock.get_frame_counter()

        if first_frame_time == 0:
            first_frame_time = frame_time
            first_frame = frame
            previous_time = 0
        else:
            previous_time = dif_time

        dif_time = (frame_time - first_frame_time) / float(1000000.0)
        frame = frame - first_frame
        time_delta = dif_time - previous_time

        self.gl_area.queue_render()
        return True

    def on_parent_close(self, button):
        '''___window_close___'''

        self.gl_window.close()

    def on_parent_minimize(self, button):
        '''___window_minimize___'''

        self.gl_window.minimize()

    def on_parent_maximize(self, button):
        '''___window_maximize___'''

        if self.gl_window.is_maximized() is True:
            self.gl_window.unmaximize()
        else:
            self.gl_window.maximize()

if __name__ == "__main__":

    environ["MANGOHUD_LOG_LEVEL"] = 'off'
    environ["MANGOHUD"] = '1'

    MANGOHUD_CONFIG = "fps_color_change,round_corners=10,cpu_load_change,\
        gpu_load_change,core_load_change,background_alpha=0.2,\
        background_color=020202,toggle_fps_limit=Shift_L+F1,position=top-right,\
        toggle_hud=Shift_R+F12,toggle_hud_position=R_Shift+F11,core_load,\
        offset_y=42,font_size=14"

    MESA_OVERLAY_CONFIG = "position=top-left"

    GALLIUM_HUD_CONFIG = ".d.w320fps+.d.w320frametime+.d.w320cpu+\
        .d.w320GPU-load+.d.w320memory-clock+.d.w320VRAM-usage+.d.w320temperature"

    if getenv('MANGOHUD_CONFIG') is None:
        environ["MANGOHUD_CONFIG"] = MANGOHUD_CONFIG

    if getenv('SW_USE_MESA_OVERLAY_HUD') == '1':
        environ['VK_LAYER_MESA_OVERLAY_CONFIG'] = MESA_OVERLAY_CONFIG
        environ['VK_INSTANCE_LAYERS'] = f"$VK_INSTANCE_LAYERS:VK_LAYER_MESA_overlay"

    if getenv('SW_USE_GALLIUM_HUD') == '1':
        environ['GALLIUM_HUD_PERIOD'] = '0.1'
        environ['GALLIUM_HUD'] = GALLIUM_HUD_CONFIG

    if len(argv) > 1:
        if argv[1] == '-v' or argv[1] == '--vulkan':
            if getenv('XDG_SESSION_TYPE') == 'wayland':
                if gpu_in_use == 'nvidia':
                    environ['GSK_RENDERER'] = 'opengl'
                else:
                    environ['GSK_RENDERER'] = 'vulkan'
            else:
                environ['GSK_RENDERER'] = 'vulkan'

        elif argv[1] == '-o' or argv[1] == '--opengl':
            environ['GSK_RENDERER'] = 'opengl'
        else:
            environ['GSK_RENDERER'] = 'opengl'
    else:
        environ['GSK_RENDERER'] = 'opengl'

    init_css_style()
    app = Cube()
    app.run()

