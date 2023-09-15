#!/usr/bin/env python3

import os
import sys
from pathlib import Path
import time
import gi
gi.require_version('Gtk', '3.0')
gi.require_version('Gdk', '3.0')
from gi.repository import Gtk, Gdk, GLib

sw_path = Path(os.path.dirname(os.path.abspath(__file__))).parent.parent
sw_scripts = f"{sw_path}/data/scripts"

sw_icon = Path(f"{sw_path}/data/img")

from OpenGL.GL import *
from OpenGL.GL.shaders import compileProgram, compileShader
import numpy as np
import pyrr
from PIL import Image

vertex_src = """
# version 330

layout(location = 0) in vec3 a_position;
layout(location = 1) in vec3 a_color;
layout(location = 2) in vec2 a_texture;

uniform mat4 rotation;

out vec3 v_color;
out vec2 v_texture;

void main()
{
    gl_Position = rotation * vec4(a_position, 1.0);
    v_color = a_color;
    v_texture = vec2(a_texture.s, 1 - a_texture.t);
}
"""

fragment_src = """
# version 330

in vec3 v_color;
in vec2 v_texture;

out vec4 out_color;

uniform sampler2D s_texture;

void main()
{
    out_color = texture(s_texture, v_texture); // * vec4(v_color, 1.0f);
}
"""

def gl_main():

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

    vertices = np.array(vertices, dtype=np.float32)
    indices = np.array(indices, dtype=np.uint32)

    def on_create_context(gl_area):

        ctx = gl_area.get_context()
        gues = gl_area.get_use_es()
        print("Opengl Context:", ctx)
        print("OpenGL ES enable:", gues)
        ctx.make_current()
        error = gl_area.get_error()
        if error != None:
            print(error)
            return

        glBindRenderbuffer(GL_RENDERBUFFER, 0)
        glBindFramebuffer(GL_FRAMEBUFFER, 0)
        ctx.clear_current()

    def on_render(gl_area, ctx):

        # shader program
        shader = compileProgram(
                                compileShader(vertex_src, GL_VERTEX_SHADER),
                                compileShader(fragment_src, GL_FRAGMENT_SHADER)
                                )

        # Vertex Arrays Object
        VAO = glGenVertexArrays(1)
        glBindVertexArray(VAO)

        # Vertex Buffer Object
        VBO = glGenBuffers(1)
        glBindBuffer(GL_ARRAY_BUFFER, VBO)
        glBufferData(
                    GL_ARRAY_BUFFER,
                    vertices.nbytes,
                    vertices, GL_STATIC_DRAW
                    )

        # Element Buffer Object
        EBO = glGenBuffers(1)
        glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, EBO)
        glBufferData(
                    GL_ELEMENT_ARRAY_BUFFER,
                    indices.nbytes, indices,
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
        image = Image.open(f"{sw_icon}/gui_icons/cube.png")
        img_data = image.convert("RGBA").tobytes()
        glTexImage2D(
                    GL_TEXTURE_2D,
                    0,
                    GL_RGBA,
                    image.width,
                    image.height,
                    0,
                    GL_RGBA,
                    GL_UNSIGNED_BYTE,
                    img_data
                    )

        # Use Shader Program
        glUseProgram(shader)
        glClearColor(0.05, 0.05, 0.05, 1)
        glClear(GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT)
        glEnable(GL_DEPTH_TEST)
        glEnable(GL_BLEND)
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA)

        # Rotation
        rotation_loc = glGetUniformLocation(shader, "rotation")
        rot_x = pyrr.Matrix44.from_x_rotation(1.0 * time.time())
        rot_y = pyrr.Matrix44.from_y_rotation(1.0 * time.time())
        glUniformMatrix4fv(
                        rotation_loc,
                        1,
                        GL_FALSE,
                        pyrr.matrix44.multiply(rot_x, rot_y)
                        )

        # Draw elements
        glDrawElements(
                    GL_TRIANGLES,
                    len(indices),
                    GL_UNSIGNED_INT,
                    None
                    )

        # clear buffers
        glBindVertexArray(0)
        glDisableVertexAttribArray(0)
        glDisableVertexAttribArray(1)
        glDisableVertexAttribArray(2)
        glDeleteBuffers(1, VBO)
        glDeleteBuffers(1, EBO)
        glDeleteVertexArrays(1, vertices)
        glDeleteVertexArrays(1, VAO)
        glDeleteTextures(1, texture)
        glDeleteProgram(shader)
        gl_window.queue_draw()

    def on_window_redraw(widget, event):
        if gl_window.get_visible() is True:
            gl_window.queue_draw()

    def on_window_btn_event(widget, event):
        if event.type == Gdk.EventType.BUTTON_RELEASE:
            gl_window.destroy()

############################

    gl_window = Gtk.Dialog()
    gl_window.set_decorated(False)
    gl_window.set_modal(True)
    gl_window.set_title("Preview")
    gl_window.set_default_size(720, 640)
    gl_area = Gtk.GLArea()
    gl_area.set_use_es(False)
    gl_area.set_auto_render(True)
    gl_area.set_has_depth_buffer(True)
    gl_area.set_has_stencil_buffer(True)
    gl_area.set_hexpand(True)
    gl_area.set_vexpand(True)
    gl_area.connect("render", on_render)
    gl_area.connect("realize", on_create_context)
    gl_window.vbox.add(gl_area)
    gl_window.show_all()
    gl_window.connect("destroy", Gtk.main_quit)
    #gl_window.connect("draw", on_window_redraw)
    gl_window.connect("event", on_window_btn_event)
    Gtk.main()

gl_main()

