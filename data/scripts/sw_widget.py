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
from pathlib import Path
import itertools

from PIL import Image
import psutil
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
from gi.repository import Gtk, Gdk, Gio, GLib, Pango, Gsk, Graphene

from sw_data import Msg as msg
from sw_data import IconPath
from sw_data import (
    key_group, navi_hotkey, navi_hotkey_desc, game_hotkey, game_hotkey_desc,
    page_hotkey, page_hotkey_desc, file_hotkey, file_hotkey_desc, hotpad_dict,
    controller_icons, progress_dict, str_title_hotkeys, str_sw_use_pfx,
    sw_app_config, sw_app_hicons, sw_app_default_icons, sw_shortcuts,
)
from sw_func import get_out
program_name = 'StartWine'


class SourceSelectionWindow(Gtk.Application):
    """___Dialog window for selecting source to capture___"""
    def __init__(self, app=None, mon_dict=dict(), xid_dict=dict(), callback=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        GLib.set_prgname(program_name)
        self.app = app
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

    def factory_setup(self, _, item_list):
        """______"""

        label = Gtk.Label(
            css_name='sw_box_view', xalign=0, ellipsize=Pango.EllipsizeMode.END
        )
        box = Gtk.Box(css_name='sw_box', hexpand=True)
        box.append(label)
        item_list.set_child(box)

    def factory_bind(self, _, item_list):
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

    def terminate(self, _):
        """______"""
        if self.callback:
            self.callback(None, None, None)


class SwDialogEntry(Gtk.Widget):
    """___Custom dialog widget with entry row___"""
    def __init__(
            self, app: Gtk.Application = None, title=None, text_message=None,
            response=None, func=None, num=None, string_list=None, *args, **kwargs
        ):
        super().__init__(*args, **kwargs)
        self.app = app
        self.title = title
        self.text_message = text_message if text_message else []
        self.response = response
        self.func = func
        self.num = num if num else 0
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

        if self.func:
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
            if self.func:
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

    def key_pressed(self, _, keyval, _keycode, _state, _dialog):
        if keyval == Gdk.KEY_Escape:
            return self.dialog.close()


class SwDialogQuestion(Gtk.Widget):
    """___custom dialog question widget for text message___"""
    def __init__(
            self, _app: Gtk.Application = None,
            title=None,
            icon=None,
            text_message=None,
            response=None,
            func=None,
            *args,
            **kwargs
        ):
        super().__init__(*args, **kwargs)
        self.app = _app
        self.title = title
        self.icon = icon if Path(str(icon)).exists() else None
        self.text_message = text_message if text_message else ['', '']
        self.response = response
        self.func = func
        self.window = self.app.get_windows()[0]
        self.dialog: Gtk.Window = None
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
                        # margin_top=8,
                        # margin_bottom=8,
                        # margin_start=8,
                        # margin_end=8,
                        wrap=True,
                        natural_wrap_mode=True,
                        label=self.text_message[0],
        )
        image = Gtk.Image(css_name='sw_image')

        if self.icon:
            image.set_from_file(f'{self.icon}')
            image.set_pixel_size(64)

        label = Gtk.Label(
                        css_name='sw_label_desc',
                        # margin_top=8,
                        # margin_bottom=8,
                        # margin_start=8,
                        # margin_end=8,
                        wrap=True,
                        natural_wrap_mode=True,
                        label=self.text_message[1],
        )
        box_message = Gtk.Box(
                        css_name='sw_message_box',
                        orientation=Gtk.Orientation.VERTICAL,
                        margin_top=8,
                        margin_bottom=8,
                        margin_start=8,
                        margin_end=8,
                        spacing=8,
        )
        box_message.append(image)
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
                        margin_top=0,
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

            if self.func:
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
            if self.func:
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

    def key_pressed(self, _, keyval, _keycode, _state, _dialog):
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
            fn = func
            args = None

        dialog.close()

        if args is None:
            fn()
        else:
            fn(*args)
    else:
        dialog.close()


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

    def do_size_allocate(self, width, height, _):
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

    def _tick_callback(self, _, _frame_clock):
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

        define_colors = {}
        if self.css_provider:
            css_list = self.css_provider.to_string().splitlines()
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

    def _text_layout(self, _):
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
            len_spc = len([e for e in self.text if e.isspace()])
            len_text = (len_chr * chr_w) + (len_dgt * dgt_w) + (len_spc * chr_w * 2)
            point.x = (x / 2) - (len_text / 2)
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
                if self.snapshot:
                    self.snapshot.append_fill(
                        self.path_list[i], Gsk.FillRule.WINDING, self.p_fg)

        if self.fraction is not None:
            count = round(int(self.fraction * self.max_count))
            for i in range(0, count):
                if self.snapshot:
                    self.snapshot.append_fill(
                        self.path_list[i], Gsk.FillRule.WINDING, self.p_fg)

    def do_size_allocate(self, width, height, _):
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

    def _tick_callback(self, _, _frame_clock):
        """..."""
        next_color = next(self.iter_color)
        self.blur = float(next_color / 5)
        self.queue_draw()
        return True


class AppConfReplace:
    """___Application selection window for transferring settings___"""

    def __init__(self, app: Gtk.Application = None, data: list[str] = []):
        self.app = app
        self.data = data
        self.list_apps_store = Gio.ListStore()
        self.check_header = Gtk.CheckButton()
        self.win = Gtk.Window()
        self.ctrl_key = Gtk.EventControllerKey()

    def run(self):
        self.activate()

    def factory_apps_setup(self, _, items):
        """___setup application config list___"""

        image = Gtk.Picture(
            css_name="sw_picture",
            hexpand=True,
            halign=Gtk.Align.FILL,
            content_fit=Gtk.ContentFit.COVER,
        )
        image.add_css_class("gridview")
        image.set_size_request(196, 96)

        pic = Gtk.Picture(
            css_name="sw_uncheck",
            hexpand=True,
            halign=Gtk.Align.START,
            content_fit=Gtk.ContentFit.SCALE_DOWN,
            vexpand=True,
            valign=Gtk.Align.END,
        )
        pic.set_size_request(32, 32)

        label = Gtk.Label(
            css_name="sw_label_view",
            xalign=0,
            ellipsize=Pango.EllipsizeMode.END,
            lines=2,
            wrap=True,
            natural_wrap_mode=True,
            hexpand=True,
            halign=Gtk.Align.FILL,
            vexpand=True,
            valign=Gtk.Align.CENTER,
        )
        check = Gtk.CheckButton(
            css_name="sw_checkbutton",
            halign=Gtk.Align.START,
            vexpand=True,
            valign=Gtk.Align.CENTER,
        )
        check.get_first_child().set_visible(False)
        check.set_child(pic)

        box = Gtk.Box(
            css_name="sw_box_overlay",
            orientation=Gtk.Orientation.HORIZONTAL,
            spacing=8,
            hexpand=True,
            vexpand=True,
            valign=Gtk.Align.END,
        )
        box.append(check)
        box.append(label)

        child_overlay = Gtk.Overlay(
            css_name="sw_box_view",
            margin_start=8,
            margin_end=8,
            margin_top=8,
            margin_bottom=8,
        )
        child_overlay.set_child(image)
        child_overlay.add_overlay(box)

        items.set_child(child_overlay)

    def factory_apps_bind(self, _, items):
        """___bind application config list___"""

        item = items.get_item()
        child_overlay = items.get_child()
        image = child_overlay.get_first_child()
        box = child_overlay.get_last_child()
        check = box.get_first_child()
        label = check.get_next_sibling()
        pic = check.get_child()
        path = item.get_path()

        n = "".join([x for x in Path(path).stem if x.isalnum()])
        p = str(sw_app_hicons.joinpath(f"{n}"))

        try:
            image.set_filename(
                f"{sw_app_default_icons.joinpath(Path(path).stem, '_x256.png')}"
            )
        except (Exception,):
            pass
        else:
            label.set_label(Path(path).stem)

        for x in sw_app_hicons.iterdir():
            if p in str(x):
                image.set_filename(str(x))
                label.set_label(str(x.stem.split("_")[-2]))
                break

        check.set_name(item.get_path())
        check.connect("toggled", self.cb_check, pic)

        if self.check_header.get_active():
            pic.set_filename(IconPath.icon_checked)
            check.set_active(True)
        else:
            pic.set_filename(None)
            self.data.clear()

    def update_apps_view(self):
        """___update application config list store___"""

        self.list_apps_store.remove_all()
        for s in sw_shortcuts.iterdir():
            for c in sw_app_config.iterdir():
                if c.stem == s.stem:
                    f = Gio.File.new_for_path(f"{c}")
                    self.list_apps_store.append(f)

    def cb_check(self, btn, pic):
        """___toggle choosed item in view___"""

        if btn.get_active():
            pic.set_filename(IconPath.icon_checked)
            self.data.append(btn.get_name())
        else:
            pic.set_filename(None)
            self.data.remove(btn.get_name())

    def cb_check_all(self, btn, pic):
        """___toggle all item in view___"""

        if btn.get_active():
            pic.set_filename(IconPath.icon_checked)
        else:
            pic.set_filename(None)

        return self.update_apps_view()

    def cb_btn_ok_choose(self, _):
        """___moving settings after confirmation from the user___"""

        if self.data is not None:
            if len(self.data) > 0:
                self.data = list(set(self.data))
                for x in self.data:
                    self.on_move_settings(x)
                else:
                    self.win.close()
            else:
                self.win.close()
        else:
            self.win.close()

    def on_move_settings(self, x_conf):
        """___moving current settings to other prefix___"""

        app_name = get_out()
        src_conf = sw_app_config.joinpath(f"{app_name}")
        dst_conf = Path(x_conf)
        src_lst = src_conf.read_text().splitlines()
        dst_lst = dst_conf.read_text().splitlines()
        print(dst_conf)
        for s, d in zip(src_lst, dst_lst):
            if not f"{str_sw_use_pfx}=" in s:
                dst = dst_conf.read_text()
                dst_conf.write_text(dst.replace(d, s))

    def key_pressed(self, _, keyval, _keycode, _state, _widget):
        """___key event handler___"""
        if keyval == Gdk.KEY_Escape:
            return self.win.close()

    def cb_close(self, _):
        """___close window___"""

        self.win.close()

    def activate(self):
        """___building and present window___"""

        self.list_apps_store = Gio.ListStore()
        apps_model = Gtk.SingleSelection.new(self.list_apps_store)

        apps_factory = Gtk.SignalListItemFactory()
        apps_factory.connect("setup", self.factory_apps_setup)
        apps_factory.connect("bind", self.factory_apps_bind)

        apps_view = Gtk.GridView(css_name="sw_gridview")
        apps_view.set_model(apps_model)
        apps_view.set_factory(apps_factory)

        label_header = Gtk.Label(
            css_name="sw_label",
            label=str(msg.ctx_dict["select_all"][0]),
        )
        pic_header = Gtk.Picture(
            css_name="sw_uncheck",
            hexpand=True,
            halign=Gtk.Align.FILL,
            content_fit=Gtk.ContentFit.COVER,
        )
        pic_header.set_size_request(32, 32)

        self.check_header = Gtk.CheckButton(
            css_name="sw_checkbutton",
            child=pic_header,
        )
        self.check_header.get_first_child().set_visible(False)
        self.check_header.connect("toggled", self.cb_check_all, pic_header)

        apps_header = Gtk.Box(
            css_name="sw_box_view",
            orientation=Gtk.Orientation.HORIZONTAL,
            hexpand=True,
        )
        apps_header.append(self.check_header)
        apps_header.append(label_header)

        scrolled = Gtk.ScrolledWindow(
            css_name="sw_scrolledwindow",
            child=apps_view,
            propagate_natural_height=True,
            vexpand=True,
        )
        apps_grid = Gtk.Grid(
            css_name="sw_pref_box",
            vexpand=True,
        )
        apps_grid.attach(apps_header, 0, 0, 1, 1)
        apps_grid.attach(scrolled, 0, 1, 1, 1)

        ok = Gtk.Button(
            css_name="sw_button_accept",
            valign=Gtk.Align.CENTER,
            label=msg.msg_dict["ok"],
        )
        ok.set_size_request(160, -1)
        ok.connect("clicked", self.cb_btn_ok_choose)

        cancel = Gtk.Button(
            css_name="sw_button_cancel",
            valign=Gtk.Align.CENTER,
            label=msg.msg_dict["cancel"],
        )
        cancel.set_size_request(160, -1)
        cancel.connect("clicked", self.cb_close)

        headerbar = Gtk.HeaderBar(
            css_name="sw_header_top", show_title_buttons=False
        )
        title = Gtk.Label(
            css_name="sw_label",
            label=msg.msg_dict["choose_app"],
            margin_start=8,
            margin_end=8,
            ellipsize=Pango.EllipsizeMode.END,
        )
        headerbar.set_title_widget(title)
        headerbar.pack_start(cancel)
        headerbar.pack_end(ok)

        self.win = Gtk.Window(
            css_name="sw_window",
            application=self.app,
            titlebar=headerbar,
            modal=True,
            child=apps_grid,
            transient_for=self.app.get_active_window(),
        )
        self.ctrl_key.connect("key_pressed", self.key_pressed, self.win)
        self.win.remove_css_class("background")
        self.win.add_css_class("sw_background")
        self.win.set_default_size(1248, 688)
        self.win.add_controller(self.ctrl_key)
        self.update_apps_view()
        self.win.present()


class HotkeySettings:
    """___Application hotkey settings window___"""

    def __init__(self, app: Gtk.Application = None, data=None):
        self.app = app
        self.data = data
        self.stack = Gtk.Stack(
            css_name="sw_stack",
            transition_duration=250,
            transition_type=Gtk.StackTransitionType.SLIDE_LEFT_RIGHT,
        )
        self.stack_switcher = Gtk.StackSwitcher(
            css_name="sw_stackswitcher", stack=self.stack
        )
        self.root = self.app.get_active_window()
        self.win = Gtk.Window(css_name="sw_window", application=self.app)
        self.ctrl_key = Gtk.EventControllerKey()

    def run(self):
        self.activate()

    def activate(self):
        keys_flow = Gtk.FlowBox(
            css_name="sw_box",
            margin_bottom=16,
            column_spacing=8,
            row_spacing=8,
            min_children_per_line=2,
            max_children_per_line=4,
        )
        hotkey_groups = [
            (key_group[0], navi_hotkey, navi_hotkey_desc),
            (key_group[1], game_hotkey, game_hotkey_desc),
            (key_group[2], page_hotkey, page_hotkey_desc),
            (key_group[3], file_hotkey, file_hotkey_desc),
        ]
        for group, hotkeys, descriptions in hotkey_groups:
            title_label = Gtk.Label(
                css_name="sw_label_view",
                xalign=0,
                label=group,
            )
            title_label.add_css_class("font_size_14")
            box = Gtk.Box(
                css_name="sw_box", orientation=Gtk.Orientation.VERTICAL, spacing=8
            )
            grid_key = Gtk.Grid(css_name="sw_grid", hexpand=True)
            grid_key.set_column_spacing(4)
            box.append(title_label)
            box.append(grid_key)
            keys_flow_child = Gtk.FlowBoxChild(css_name="sw_box_view")
            keys_flow_child.set_child(box)

            for row in range(len(hotkeys)):
                for column, key in enumerate(hotkeys[row]):
                    label_key = Gtk.Label(css_name="sw_label_desc", label=key)
                    label_key.add_css_class("left_padding_4")
                    label_key.add_css_class("right_padding_4")
                    if key == "":
                        grid_key.attach(label_key, column, row, 1, 1)
                    else:
                        key_btn = Gtk.Button(css_name="sw_action_row")
                        key_btn.add_css_class("key")
                        key_btn.add_css_class("padding_0")
                        key_btn.add_css_class("margin_2")
                        key_btn.set_sensitive(False)
                        key_btn.set_child(label_key)
                        grid_key.attach(key_btn, column, row, 1, 1)

                label_desc_x = Gtk.Label(
                    css_name="sw_label_desc",
                    label=descriptions[row].capitalize(),
                    xalign=0,
                    wrap=True,
                    natural_wrap_mode=True,
                )
                grid_key.attach(label_desc_x, 5, row, 1, 1)

            keys_flow.append(keys_flow_child)

        keyboard_scrolled = Gtk.ScrolledWindow(
            css_name="sw_scrolledwindow", child=keys_flow, vexpand=True
        )
        pad_flow = Gtk.FlowBox(
            css_name="sw_box",
            margin_bottom=16,
            column_spacing=8,
            homogeneous=True,
            min_children_per_line=2,
            max_children_per_line=4,
        )
        count = -1
        for pad, desc in hotpad_dict.items():
            count += 1
            grid = Gtk.Grid(
                css_name="sw_grid",
                column_spacing=8,
                vexpand=False,
                valign=Gtk.Align.START,
            )
            image_mod = Gtk.Picture(css_name="sw_image")
            image_mod.set_size_request(32, 32)
            image_mod.set_filename(controller_icons.get(pad[0]))

            grid.attach(image_mod, 0, count, 1, 1)

            if len(pad) >= 2:
                label_plus0 = Gtk.Label(css_name="sw_label_view", label="+")
                image_pad0 = Gtk.Picture(css_name="sw_image")
                image_pad0.set_size_request(32, 32)
                icon = controller_icons.get(pad[1])
                image_pad0.set_filename(icon)

                grid.attach(label_plus0, 1, count, 1, 1)
                grid.attach(image_pad0, 2, count, 1, 1)

            if len(pad) >= 3:
                label_plus1 = Gtk.Label(css_name="sw_label_view", label="+")
                image_pad1 = Gtk.Picture(css_name="sw_image")
                image_pad1.set_size_request(32, 32)
                icon = controller_icons.get(pad[2])
                image_pad1.set_filename(icon)

                grid.attach(label_plus1, 3, count, 1, 1)
                grid.attach(image_pad1, 4, count, 1, 1)

            label_desc = Gtk.Label(
                css_name="sw_label_desc",
                label=desc.capitalize(),
                xalign=0,
                wrap=True,
                natural_wrap_mode=True,
            )
            grid.attach(label_desc, 5, count, 1, 1)

            pad_flow_child = Gtk.FlowBoxChild(css_name="sw_box_view")
            pad_flow_child.set_child(grid)
            pad_flow.append(pad_flow_child)

        controller_scrolled = Gtk.ScrolledWindow(
            css_name="sw_scrolledwindow", child=pad_flow, vexpand=True
        )
        self.stack.add_titled(
            keyboard_scrolled, "hotkeys", msg.tt_dict["keyboard"]
        )
        self.stack.add_titled(
            controller_scrolled, "controller", msg.tt_dict["controller"]
        )
        hotkey_box = Gtk.Box(
            css_name="sw_popover",
            orientation=Gtk.Orientation.VERTICAL,
            vexpand=True,
            margin_start=16,
            margin_end=16,
            margin_bottom=16,
        )
        hotkey_box.append(self.stack_switcher)
        hotkey_box.append(self.stack)

        close = Gtk.Button(css_name="sw_wc_close", valign=Gtk.Align.CENTER)
        close.connect("clicked", self.cb_btn_close)

        title_widget = Gtk.Label(css_name="sw_label", label=str_title_hotkeys)
        headerbar = Gtk.HeaderBar(
            css_name="sw_header_top", show_title_buttons=False
        )
        headerbar.set_title_widget(title_widget)
        headerbar.pack_end(close)

        self.win.remove_css_class("background")
        self.win.add_css_class("sw_background")
        self.win.set_titlebar(headerbar)
        self.win.set_default_size(1248, 688)
        self.win.set_transient_for(self.root)
        self.win.set_modal(True)
        self.win.set_child(hotkey_box)
        self.ctrl_key.connect("key_pressed", self.key_pressed, self.win)
        self.win.add_controller(self.ctrl_key)
        self.win.present()

    def cb_btn_close(self, _):
        """___close hotkeys settings window___"""
        self.win.close()

    def key_pressed(self, _, keyval, _keycode, state, _widget):
        """___key event handler___"""
        all_mask = (
            Gdk.ModifierType.CONTROL_MASK
            | Gdk.ModifierType.SHIFT_MASK
            | Gdk.ModifierType.ALT_MASK
            | Gdk.ModifierType.SUPER_MASK
        )
        if keyval == Gdk.KEY_Escape:
            return self.win.close()
        if (state & all_mask) == Gdk.ModifierType.ALT_MASK and keyval == Gdk.KEY_Right:
            self.stack.set_visible_child_name("controller")
        if (state & all_mask) == Gdk.ModifierType.ALT_MASK and keyval == Gdk.KEY_Left:
            self.stack.set_visible_child_name("hotkeys")


class UpdateContentWindow:
    def __init__(
        self,
        app: Gtk.Application = None,
        icon=None,
        cover=None,
        title=None,
        text=None,
        font_size=None,
        data=None,
        width=None,
        height=None,
    ):
        self.app = app
        self.icon = icon
        self.cover = cover
        self.title = title if title else ""
        self.text = text if text else progress_dict["update"].capitalize()
        self.font_size = font_size if font_size else 12
        self.data = data
        self.suspended = False
        self.width = width if width else 768
        self.height = height if height else self.get_height()
        self.activate()

    def activate(self):
        image = Gtk.Image(css_name="sw_picture", halign=Gtk.Align.CENTER)
        image.set_pixel_size(64)
        image.set_from_file(self.icon)
        image.set_size_request(64, 64)
        image.add_css_class("margin_8")

        background = Gtk.Picture(css_name="sw_picture")
        background.set_content_fit(Gtk.ContentFit.COVER)
        if self.cover:
            background.set_filename(self.cover)

        title_label = Gtk.Label(css_name="sw_label_title", label=self.title)
        subtitle_label = Gtk.Label(css_name="sw_label", label=self.text)
        self.progress = SwProgressBar(
            css_name="sw_progressbar",
            valign=Gtk.Align.CENTER,
            halign=Gtk.Align.CENTER,
            hexpand=True,
            vexpand=True,
            margin_bottom=48,
            font_size=self.font_size,
            color="#ffffff",
        )
        self.progress.add_css_class("text_bold")
        self.progress.set_size_request(576, 20)
        self.set_define_colors()

        header_label = Gtk.Label(css_name="sw_label_title")

        image_cancel = Gtk.Image(css_name="sw_image")
        image_cancel.set_from_file(IconPath.icon_clear)

        btn_cancel = Gtk.Button(css_name="sw_button", child=image_cancel)
        btn_cancel.set_tooltip_markup(msg.msg_dict["cancel"])
        btn_cancel.connect("clicked", self.cancel)

        self.image_control = Gtk.Image(css_name="sw_image")
        self.image_control.set_from_file(IconPath.icon_pause)

        btn_control = Gtk.Button(css_name="sw_button", child=self.image_control)
        btn_control.set_tooltip_markup(msg.msg_dict["stop"])
        btn_control.connect("clicked", self.control)

        box_control = Gtk.Box(
            css_name="sw+box",
            orientation=Gtk.Orientation.HORIZONTAL,
            spacing=8,
            valign=Gtk.Align.CENTER,
        )
        box_control.add_css_class("margin_8")
        box_control.append(btn_control)
        box_control.append(btn_cancel)
        if not self.data:
            btn_control.set_visible(False)
            btn_cancel.set_visible(False)

        header = Gtk.HeaderBar(
            css_name="sw_box",
            show_title_buttons=False,
            title_widget=header_label,
        )
        header.pack_start(image)
        header.pack_end(box_control)

        progress_box = Gtk.Box(
            css_name="sw+box",
            orientation=Gtk.Orientation.VERTICAL,
            spacing=8,
            valign=Gtk.Align.END,
        )
        progress_box.append(title_label)
        progress_box.append(subtitle_label)
        progress_box.append(self.progress)

        grid = Gtk.Grid(css_name="sw_box")
        grid.set_row_spacing(8)
        grid.attach(header, 0, 0, 1, 1)
        grid.attach(progress_box, 0, 1, 1, 1)
        grid.add_css_class("darkened")
        grid.add_css_class("shadow_2")

        overlay = Gtk.Overlay(css_name="sw_overlay")
        overlay.set_child(background)
        overlay.add_overlay(grid)

        self.window = Gtk.Window(
            css_name="sw_window",
            application=self.app,
            child=overlay,
            transient_for=self.app.get_active_window(),
            resizable=False,
            decorated=False,
        )
        self.window.remove_css_class("background")
        self.window.add_css_class("sw_background")
        self.window.set_default_size(self.width, self.height)
        self.window.present()

    def get_height(self):
        height = int(self.width / 3)
        if self.cover:
            img = Image.open(self.cover)
            w = img.width
            h = img.height
            ratio = self.width / w
            height = int(h * ratio)
            if (self.width / height) < 2:
                height = self.width / 2

        return height

    def set_define_colors(self):
        dcolors = dict()
        css_provider = self.app.css_provider
        if css_provider:
            css_list = css_provider.to_string().splitlines()
            for x in css_list:
                if "@define-color sw_" in x:
                    if len([x.split(" ")[2].strip(";")]) > 0:
                        dcolors[x.split(" ")[1]] = [x.split(" ")[2].strip(";")][0]

        bg_color = dcolors.get("sw_header_bg_color")
        invert_progress_color = dcolors.get("sw_invert_progress_color")
        accent_fg_color = dcolors.get("sw_accent_fg_color")

        if bg_color:
            self.progress.set_background(bg_color)

        if invert_progress_color and accent_fg_color:
            self.progress.set_progress_color(invert_progress_color, accent_fg_color)
            self.progress.set_border_color(accent_fg_color)
            self.progress.set_shadow_color(accent_fg_color)

    def pulse(self):
        GLib.timeout_add(100, self.progress.pulse)

    def set_fraction(self, fraction=0):
        self.progress.set_fraction(fraction)

    def set_text(self, text):
        self.progress.set_show_text(True)
        self.progress.set_text(text)

    def control(self, btn):
        if self.suspended:
            self.image_control.set_from_file(IconPath.icon_pause)
            btn.set_tooltip_markup(msg.msg_dict["stop"])
            self.resume()
        else:
            self.image_control.set_from_file(IconPath.icon_start)
            btn.set_tooltip_markup(msg.msg_dict["run"])
            self.suspend()
        self.suspended = not self.suspended

    def suspend(self):
        if self.data:
            pid = self.data.pid
            proc = psutil.Process(pid)
            children = proc.children(True)
            for p in children:
                p.suspend()
                print(f"Process {p.pid} {p.name()} {p.status()}")
            proc.suspend()
            print(f"Process {proc.pid} {proc.name()} {proc.status()}")

    def resume(self):
        if self.data:
            pid = self.data.pid
            proc = psutil.Process(pid)
            children = proc.children(True)
            for p in children:
                p.resume()
                print(f"Process {p.pid} {p.name()} {p.status()}")
            proc.resume()
            print(f"Process {proc.pid} {proc.name()} {proc.status()}")

    def cancel(self, _):
        if self.data:
            pid = self.data.pid
            proc = psutil.Process(pid)
            children = proc.children(True)
            for p in children:
                p.terminate()
                print(f"Process {p.pid} {p.name()} {p.status()} terminate")
            proc.terminate()
            print(f"Process {proc.pid} {proc.name()} {proc.status()} terminate")
        self.close()

    def close(self):
        self.window.close()

