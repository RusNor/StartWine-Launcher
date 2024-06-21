#!/usr/bin/env python3

####___Core modules___.
from os import environ, getenv
from sys import argv
from pathlib import Path
from datetime import datetime, date
from array import array
import time as clock
start_time = clock.time()

####___Third party modules___.
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Gdk', '4.0')
from gi.repository import Gtk, Gdk, Gio, GLib, GdkPixbuf
from OpenGL.GL import *
from OpenGL.GL import shaders
from OpenGL.GL.shaders import compileShader

####___Local data modules___.
from sw_shaders import Shaders as sdr
from sw_data import TermColors as tc

link = f"{argv[0]}"
sw_scripts = Path(link).absolute().parent
sw_path = Path(sw_scripts).parent.parent
sw_img = Path(f'{sw_path}/data/img')
sw_themes = f"{sw_img}/sw_themes"
fragments_list = [s.value for s in list(sdr)]

vertex_src = '''
#version 450

uniform vec3 iResolution;
in vec2 position;
out vec2 fragCoord;

void main() {
    gl_Position = vec4(position, 0.0, 1.0);
    fragCoord = (gl_Position.xy + vec2(1.0)) / vec2(2.0) * iResolution.xy;
}
'''

fragment_prefix = '''
    #version 450

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

    out vec4 fragColor;
    in vec2 fragCoord;
'''

fragment_main = '''
    out vec4 vFragColor;

    void main() {
        vec4 c;
        mainImage(c, fragCoord);
        vFragColor = c;
    }
'''

img_vertex_src = '''
#version 450

layout(location = 0) in vec3 position;
layout(location = 1) in vec2 texture;
out vec3 vColor;
out vec2 fragCoord;

void main()
{
    gl_Position = vec4(position, 1.0);
    fragCoord = 1 - texture;
}
'''

img_fragment_src = '''
#version 450

in vec2 fragCoord;
uniform sampler2D sTexture;
out vec4 fragColor;

void main()
{
    fragColor = texture(sTexture, fragCoord);
}
'''

vertices = [
    -1.0, -1.0, 0.0, 1.0,
    -1.0,  1.0, 0.0, 1.0,
    1.0,  1.0, 0.0, 1.0,
    -1.0, -1.0, 0.0, 1.0,
    1.0,  1.0, 0.0, 1.0,
    1.0, -1.0, 0.0, 1.0,
]

img_vertices = [
    -1.0, -1.0,  0.5,  1.0, 0.0, 0.0,  0.0, 0.0,
    1.0, -1.0,  0.5,  0.0, 1.0, 0.0,  1.0, 0.0,
    1.0,  1.0,  0.5,  0.0, 0.0, 1.0,  1.0, 1.0,
    -1.0,  1.0,  0.5,  1.0, 1.0, 1.0,  0.0, 1.0,
]

img_indices = [
    0,  1,  2,  2,  3,  0,
    4,  5,  6,  6,  7,  4,
    8,  9, 10, 10, 11,  8,
    12, 13, 14, 14, 15, 12,
    16, 17, 18, 18, 19, 16,
    20, 21, 22, 22, 23, 20
]
vertices = array('f', vertices)
img_verts = array('f', img_vertices)
img_inds = array('I', img_indices)

class RenderArea(Gtk.GLArea):

    def __init__(self, parent, image):
        super().__init__(
                        css_name='sw_gl_area',
                        name='gl_area',
                        auto_render=True,
                        has_depth_buffer=True,
                        has_stencil_buffer=True,
                        hexpand=True,
                        vexpand=True
        )
        self.parent = parent
        self.image = image
        self.first_frame_time = 0
        self.gl_resolution = 0
        self.first_frame = 0
        self.time_delta = 0
        self.x_mouse = 0.0
        self.y_mouse = 0.0
        self.dif_time = 0
        self.frame = 0

        if getenv('SW_OPENGL') == '1':
            self.f_num = getenv('FRAGMENT_NUM')
            self.fragment_src = (
                            fragment_prefix
                            + fragments_list[int(self.f_num)]
                            + fragment_main
            )
        else:
            self.f_num = 0
            self.fragment_src = None

        self.connect('realize', self.on_realize)
        self.connect('resize', self.on_resize)
        self.connect('render', self.on_render)
        self.add_tick_callback(self.on_frame_clock)
        ctrl_gl_motion = Gtk.EventControllerMotion()
        ctrl_gl_motion.connect('motion', self.on_ctrl_gl_motion)
        self.parent.add_controller(ctrl_gl_motion)

        if getenv('SW_CYCLE_OPENGL') == '1':
            GLib.timeout_add(3000, self.get_cycle_source)
        else:
            GLib.timeout_add(1000, self.get_source_next_boot)

    def get_cycle_source(self):
        '''Cyclically load the shader fragment source from the fragment list.'''

        if getenv('SW_OPENGL') == '1':
            timer = clock.time() - start_time

            if round(timer) < len(fragments_list) * 3:
                self.fragment_src = (
                                fragment_prefix
                                + fragments_list[round((timer/3)-1)]
                                + fragment_main
                )
                return True
            else:
                return False
        else:
            self.fragment_src = None

        return True

    def get_source_next_boot(self):
        '''Update the shader fragment source after implementing boot shader.'''

        if getenv('SW_OPENGL') == '1':
            timer = clock.time() - start_time
            f_num = getenv('FRAGMENT_NUM')

            if round(timer) >= 3:
                self.fragment_src = (
                                fragment_prefix
                                + fragments_list[int(f_num)]
                                + fragment_main
                )
        else:
            self.fragment_src = None

        return True

    def on_realize(self, gl_area):
        '''Opengl context implementation state.'''

        context = self.get_context()
        api = self.get_api()
        auto_render = self.get_auto_render()
        depth_buffer = self.get_has_depth_buffer()
        stensil_buffer = self.get_has_stencil_buffer()
        error = self.get_error()

        print(tc.SELECTED + tc.RED2
            + "\n--------------< OPENGL_CONTEXT >--------------\n"
            + tc.END, "\n",
            tc.VIOLET2 + "CONTEXT_REALIZED: ", tc.GREEN, str(type(context)), "\n",
            tc.VIOLET2 + "OPENGL_API:       ", tc.GREEN, api, "\n",
            tc.VIOLET2 + "AUTO_RENDER:      ", tc.GREEN, auto_render, "\n",
            tc.VIOLET2 + "DEPTH_BUFFER:     ", tc.GREEN, depth_buffer, "\n",
            tc.VIOLET2 + "STENSIL_BUFFER:   ", tc.GREEN, stensil_buffer, "\n",
            tc.VIOLET2 + "CONTEXT_ERROR:    ", tc.GREEN, error, "\n",
            tc.END
            )

    def on_resize(self, gl_area, width, height):
        '''Opengl area resizing signal handler.'''

        width = self.get_width()
        height = self.get_height()
        self.gl_resolution = [width, height, 1.0]

        if getenv('SW_OPENGL') == '1':
            glViewport(0,0, width, height)

    def on_render(self, gl_area, context):
        '''Rendering signal handler in opengl area.'''

        if self.get_error() is not None:
            return False

        elif self.fragment_src is None:
            return True

        elif getenv('SW_OPENGL') == '0':
            glClearColor (0.02, 0.02, 0.02, 0.02)
            glClear(GL_COLOR_BUFFER_BIT)
            glFlush()
            return True
        else:
            glClearColor (0.02, 0.02, 0.02, 0.02)
            glClear(GL_COLOR_BUFFER_BIT)

            if self.image is None:
                self.on_draw()
            else:
                self.on_image_draw()

            glFlush()

        return True

    def on_image_draw(self):
        '''Compiling a shader program and rendering in opengl area.'''

        # Create shaders.
        v = compileShader(img_vertex_src, GL_VERTEX_SHADER)
        f = compileShader(img_fragment_src, GL_FRAGMENT_SHADER)

        # Shader program.
        shader = glCreateProgram()
        glAttachShader(shader, v)
        glAttachShader(shader, f)
        glLinkProgram(shader)

        # Vertex Arrays Object.
        VAO = glGenVertexArrays(1)
        glBindVertexArray(VAO)

        # Vertex Buffer Object.
        VBO = glGenBuffers(1)
        glBindBuffer(GL_ARRAY_BUFFER, VBO)
        glBufferData(
                    GL_ARRAY_BUFFER, len(img_verts.tobytes()),
                    img_verts.tobytes(), GL_STATIC_DRAW
        )
        # Element Buffer Object.
        EBO = glGenBuffers(1)
        glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, EBO)
        glBufferData(
                    GL_ELEMENT_ARRAY_BUFFER, len(img_inds.tobytes()),
                    img_inds.tobytes(), GL_STATIC_DRAW
        )
        # Vertex Attributes Pointers.
        glVertexAttribPointer(
            0, 3, GL_FLOAT, GL_FALSE, img_verts.itemsize * 8, ctypes.c_void_p(0)
        )
        glEnableVertexAttribArray(0)

        glVertexAttribPointer(
            1, 2, GL_FLOAT, GL_FALSE, img_verts.itemsize * 8, ctypes.c_void_p(24)
        )
        glEnableVertexAttribArray(1)

        # Generate Textures.
        texture = glGenTextures(1)
        glBindTexture(GL_TEXTURE_2D, texture)

        # Set the texture wrapping parameters.
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT)
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT)

        # Set texture filtering parameters.
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR)
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR)

        # Load Image.
        data = self.image.get_pixels()
        glTexImage2D(
            GL_TEXTURE_2D, 0, GL_RGB, self.image.get_width(),
            self.image.get_height(), 0, GL_RGB, GL_UNSIGNED_BYTE, data
        )
        # Use Shader Program.
        glUseProgram(shader)
        glClearColor(0.02, 0.02, 0.02, 0.02)
        glClear(GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT)
        glEnable(GL_DEPTH_TEST)
        glEnable(GL_BLEND)
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA)

        # Draw elements.
        glDrawElements(
                    GL_TRIANGLES,
                    len(img_inds),
                    GL_UNSIGNED_INT,
                    None
                    )

        # Disable program.
        glBindVertexArray(0)
        glDisableVertexAttribArray(0)
        glBindBuffer(GL_ARRAY_BUFFER, 0)
        glUseProgram(0)

        # delete shaders.
        glDetachShader(shader, v)
        glDetachShader(shader, f)
        glDeleteShader(v)
        glDeleteShader(f)

        # delete program, buffers, textures and vertex.
        glBindVertexArray(0)
        glDisableVertexAttribArray(0)
        glDisableVertexAttribArray(1)
        glDeleteBuffers(1, VBO)
        glDeleteBuffers(1, EBO)
        glDeleteVertexArrays(1, VAO)
        glDeleteTextures(1, texture)
        glDeleteProgram(shader)

    def on_draw(self):
        '''Compiling a shader program and rendering in opengl area.'''

        # Compile shaders.
        v = compileShader(vertex_src, GL_VERTEX_SHADER)
        f = compileShader(self.fragment_src, GL_FRAGMENT_SHADER)

        # Shader program.
        shader = glCreateProgram()
        glAttachShader(shader, v)
        glAttachShader(shader, f)
        glLinkProgram(shader)

        # Vertex Arrays Object.
        VAO = glGenVertexArrays(1)
        glBindVertexArray(VAO)

        # Vertex Buffer Object.
        VBO = glGenBuffers(1)
        glBindBuffer(GL_ARRAY_BUFFER, VBO)
        glBufferData(
                    GL_ARRAY_BUFFER,
                    len(vertices.tobytes()),
                    vertices.tobytes(),
                    GL_STATIC_DRAW
        )
        glVertexAttribPointer (
                            0, 4, GL_FLOAT, GL_FALSE,
                            0,
                            ctypes.c_void_p(0)
        )
        glEnableVertexAttribArray(0)

        # Use Shader Program.
        glUseProgram(shader)

        glClearColor(0.024, 0.032, 0.04, 1.0)
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
            glUniform3fv(resolution_location, 1, self.gl_resolution)

        if time_location != -1:
            glUniform1f(time_location, self.dif_time)

        if date_location != -1:
            pass    #glUniform1i(date_location, 1, int(T))

        if mouse_location != -1:
            try:
                glUniform4f(mouse_location, float(self.x_mouse), float(self.y_mouse), 1.0, 1.0)
            except:
                pass

        if timedelta_location != -1:
            glUniform1f(timedelta_location, self.time_delta);

        if frame_location != -1:
            glUniform1i(frame_location, self.frame);

        if sample_rate_location != -1:
            pass    #glUniform1i(sample_rate_location, samp);

        glDrawArrays(GL_TRIANGLES, 0, 6)

        # Disable program
        glBindVertexArray(0)
        glDisableVertexAttribArray(0)
        glBindBuffer(GL_ARRAY_BUFFER, 0)
        glUseProgram(0)

       # Delete shaders.
        glDetachShader(shader, v)
        glDetachShader(shader, f)
        glDeleteShader(v)
        glDeleteShader(f)

        # Delete program, buffers and vertex.
        glDeleteBuffers(1, VBO)
        glDeleteVertexArrays(1, VAO)
        glDeleteProgram(shader)

    def on_ctrl_gl_motion(self, ctrl_gl_motion, x, y):
        '''Mouse position signal handler.'''

        self.x_mouse = x
        self.y_mouse = y

    def on_frame_clock(self, gl_area, frame_clock):
        '''Update frames and redraw widget.'''

        frame_time = frame_clock.get_frame_time()
        self.frame = frame_clock.get_frame_counter()

        if self.first_frame_time == 0:
            self.first_frame_time = frame_time
            self.first_frame = self.frame
            previous_time = 0
        else:
            previous_time = self.dif_time

        self.dif_time = (frame_time - self.first_frame_time) / float(1000000.0)
        self.frame = self.frame - self.first_frame
        self.time_delta = self.dif_time - previous_time

        self.queue_render()
        return True

