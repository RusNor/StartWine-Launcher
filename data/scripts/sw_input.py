#!/usr/bin/env python3

"""
#define BTN_JOYSTICK    0x120
#define BTN_TRIGGER	    0x120
#define BTN_THUMB       0x121
#define BTN_THUMB2      0x122
#define BTN_TOP         0x123
#define BTN_TOP2        0x124
#define BTN_PINKIE      0x125
#define BTN_BASE        0x126
#define BTN_BASE2       0x127
#define BTN_BASE3       0x128
#define BTN_BASE4       0x129
#define BTN_BASE5       0x12a
#define BTN_BASE6       0x12b
#define BTN_DEAD        0x12f
#define BTN_GAMEPAD     0x130
#define BTN_SOUTH       0x130
#define BTN_A           BTN_SOUTH
#define BTN_EAST        0x131
#define BTN_B           BTN_EAST
#define BTN_C           0x132
#define BTN_NORTH       0x133
#define BTN_X           BTN_NORTH
#define BTN_WEST        0x134
#define BTN_Y           BTN_WEST
#define BTN_Z           0x135
#define BTN_TL          0x136
#define BTN_TR          0x137
#define BTN_TL2         0x138
#define BTN_TR2         0x139
#define BTN_SELECT      0x13a
#define BTN_START       0x13b
#define BTN_MODE        0x13c
#define BTN_THUMBL      0x13d
#define BTN_THUMBR      0x13e
#define ABS_X           0x00
#define ABS_Y           0x01
#define ABS_Z           0x02
#define ABS_RX          0x03
#define ABS_RY          0x04
#define ABS_RZ          0x05
#define ABS_THROTTLE    0x06
#define ABS_RUDDER      0x07
#define ABS_WHEEL       0x08
#define ABS_GAS         0x09
#define ABS_BRAKE       0x0a
#define ABS_HAT0X       0x10
#define ABS_HAT0Y       0x11
#define ABS_HAT1X       0x12
#define ABS_HAT1Y       0x13
#define ABS_HAT2X       0x14
#define ABS_HAT2Y       0x15
#define ABS_HAT3X       0x16
#define ABS_HAT3Y       0x17
#define ABS_PRESSURE    0x18
#define ABS_DISTANCE    0x19
#define ABS_TILT_X      0x1a
#define ABS_TILT_Y      0x1b
#define ABS_TOOL_WIDTH  0x1c
"""

import sys
from sys import argv
import time
from pathlib import Path
import evdev
from evdev import UInput, AbsInfo, InputDevice, ecodes, categorize, ff, list_devices
from threading import Thread
import multiprocessing as mp
import asyncio
import signal
from select import select
import math

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Gdk', '4.0')
from gi.repository import Gtk, Gdk, Gio, GLib
from sw_data import (
    str_gc_title, str_gc_subtitle, str_not_set, str_press_any_key, sw_css_dark,
    default_app_bind_profile, default_gui_bind_profile, app_bind_profile,
    controller_icons, IconPath, write_json_data, Msg as msg, vl_dict, sw_input_json
)
from sw_func import check_alive


dev_except = [
    'POWERBUTTON', 'SPEAKER', 'HDA', 'CONSUMERCONTROL', 'SYSTEMCONTROL',
    'MOUSEKEYBOARD', 'LIDSWITCH', 'VIDEOBUS', 'HDAUDIO', 'SWKEYPAD'
]
KEYBOARD = 'keyboard'
GAMEPAD = 'gamepad'
KEYPAD = 'keypad'
MOUSEPAD = 'mousepad'
Display = Gdk.Display().get_default()


def get_device_list(device_type=None):
    """Get filtered list of connected input devices."""

    if device_type == GAMEPAD:
        _dev_except = dev_except + ['MOUSE', 'KEYBOARD', 'HOTKEY', 'TOUCHPAD' ]

    elif device_type == KEYPAD:
        _dev_except = dev_except

    elif device_type == MOUSEPAD:
        _dev_except = dev_except + ['KEYBOARD', 'HOTKEY', 'TOUCHPAD']

    elif device_type == KEYBOARD:
        _dev_except = dev_except + ['MOUSE', 'HOTKEY', 'TOUCHPAD']
    else:
        _dev_except = []

    dev_list = [InputDevice(dev) for dev in evdev.list_devices()]
    dev_fltr = list()

    for d in dev_list:
        n = ''.join([x for x in d.name if x.isalnum()])
        for e in _dev_except:
            if e.lower() in n.lower():
                if d not in dev_fltr:
                    dev_fltr.append(d)

    for d in dev_fltr:
        if d in dev_list:
            dev_list.remove(d)

    dev_list.reverse()
    return dev_list


def get_key_dict(dev_name, dev_type):
    """Get device capabilities dictionaries."""

    key_dict = {}
    abs_dict = {}
    device_dict = {dev.name: dev for dev in get_device_list(dev_type)}
    if device_dict.get(dev_name):
        dev_caps = device_dict.get(dev_name).capabilities(verbose=True)

        try:
            ev_key = dev_caps[('EV_KEY', 1)]
        except KeyError as e:
            ev_key = []
        try:
            ev_abs = dev_caps[('EV_ABS', 3)]
        except KeyError as e:
            ev_abs = []

        for k in ev_key:
            x = k[0]
            if isinstance(k[0], list):
                x = x[0]
            key_dict[x] = k[1]

        for k in ev_abs:
            x = k[0]
            if isinstance(k[0], tuple):
                x = x[0]
            abs_dict[x] = k[1]

    return key_dict, abs_dict


def bind_device_key(device, key_name, bind_dict):
    """Create dicrionary with key bindings from commandline."""

    key_bind = None
    mouse_bind = None
    mouse_list = get_device_list(MOUSEPAD)
    keyboard_list = get_device_list(KEYBOARD)

    inp = []
    while inp == []:
        inp = input(f'press Enter to configure the {device.name}: ')
        print(f'Press any key to bind {key_name}')

    bind_key(key_name, bind_dict)


def bind_key(key_name, bind_dict):
    """Create dicrionary with key bindings."""

    key_bind = None
    mouse_bind = None
    mouse_list = get_device_list(MOUSEPAD)
    keyboard_list = get_device_list(KEYBOARD)
    key = (
        key_name.replace('_LEFT', '').replace('_RIGHT', '')
        .replace('_UP', '').replace('_DOWN', '')
    )
    bind_list = bind_dict[key]

    while True:
        for keyboard in keyboard_list:
            keyboard_event = keyboard.read_one()
            if keyboard_event:
                if keyboard_event.type == ecodes.EV_KEY:
                    key_bind = ecodes.bytype[ecodes.EV_KEY][keyboard_event.code]

        for mouse in mouse_list:
            mouse_event = mouse.read_one()
            if mouse_event:
                if mouse_event.type == ecodes.EV_KEY:
                    mouse_bind = ecodes.bytype[ecodes.EV_KEY][mouse_event.code]
                elif mouse_event.type == ecodes.EV_REL:
                    mouse_bind = ecodes.bytype[ecodes.EV_REL][mouse_event.code]

        if key_bind:
            if isinstance(key_bind, list):
                key_bind = key_bind[0]

            if '_RIGHT' in key_name:
                bind_list.pop(0)
                bind_list.insert(0, key_bind)

            elif '_LEFT' in key_name:
                bind_list.pop(1)
                bind_list.insert(1, key_bind)

            elif '_DOWN' in key_name:
                bind_list.pop(0)
                bind_list.insert(0, key_bind)

            elif '_UP' in key_name:
                bind_list.pop(1)
                bind_list.insert(1, key_bind)
            else:
                bind_list = [key_bind]

            bind_dict[key] = bind_list
            print('Set binding:', key_name, bind_list)
            break

        if mouse_bind:
            if isinstance(mouse_bind, list):
                mouse_bind = mouse_bind[0]

            if '_RIGHT' in key_name:
                bind_list.pop(0)
                bind_list.insert(0, mouse_bind)

            elif '_LEFT' in key_name:
                bind_list.pop(1)
                bind_list.insert(1, mouse_bind)

            elif '_DOWN' in key_name:
                bind_list.pop(0)
                bind_list.insert(0, mouse_bind)

            elif '_UP' in key_name:
                bind_list.pop(1)
                bind_list.insert(1, mouse_bind)
            else:
                bind_list = [mouse_bind]

            bind_dict[key] = bind_list
            print('Set binding:', key_name, bind_list)
            break


class DeviceRedirection:
    """Redirecting user input events to another device."""

    def __init__(self, device=None, data=None, *args, **kwargs):

        self.monitor = Display.get_monitors()[0]
        self.width = self.monitor.get_geometry().width
        self.height = self.monitor.get_geometry().height
        self.device = device
        self.name = self.device.name if self.device else None
        self.data = data if data else app_bind_profile
        self.mouse = get_device_list(MOUSEPAD)
        self.keyboard = get_device_list(KEYBOARD)
        self.key_dict, self.abs_dict = get_key_dict(self.name, GAMEPAD)
        if self.mouse and self.keyboard:
            self.ui = UInput.from_device(*self.mouse, *self.keyboard, name='SwKeyPad')
        else:
            self.ui = None

        self.rumble = ff.Rumble(strong_magnitude=0x0000, weak_magnitude=0xffff)
        self.effect_type = ff.EffectType(ff_rumble_effect=self.rumble)
        self.duration = 500
        self.effect = ff.Effect(
            ecodes.FF_RUMBLE, -1, 0, ff.Trigger(0, 0), ff.Replay(self.duration, 0),
            self.effect_type
        )

    def run(self):
        """Running device redirection."""

        for cap in self.device.capabilities():
            if ecodes.EV_FF == cap:
                self.effect_id = self.device.upload_effect(self.effect)
                self.device.write(ecodes.EV_FF, self.effect_id, 1)
                time.sleep(self.duration / 1000)
                self.device.erase_effect(self.effect_id)

        if self.ui:
            print(f'{self.name} redirection is running...')
            self._async_read()
        else:
            print('The devices required for redirection were not found...')

    def terminate(self):
        """Terminate reading device events."""

        sys.exit(0)

    def _async_read(self):
        """Running async reading device events."""

        self.rx = list()
        self.ry = list()
        self.lx = list()
        self.ly = list()

        for event in self.device.async_read_loop():

            if self.data.get('bind_profile'):
                bind_dict = self.data.get('bind_profile')

            if self.data.get('controller_active'):
                key_name = None
                abs_name = None
                binding = None

                if event.type == ecodes.EV_KEY:
                    key_name = ecodes.bytype[ecodes.EV_KEY][event.code]
                    if isinstance(key_name, list) or isinstance(key_name, tuple):
                        key_name = key_name[0]

                if event.type == ecodes.EV_ABS:
                    abs_name = ecodes.bytype[ecodes.EV_ABS][event.code]
                    if isinstance(abs_name, list) or isinstance(abs_name, tuple):
                        abs_name = abs_name[0]

                if key_name and bind_dict.get(key_name):

                    if isinstance(bind_dict[key_name], list):
                        binding = bind_dict[key_name][0]
                        self._ev_key_write(event, 1, binding)

                if abs_name and bind_dict.get(abs_name) and self.abs_dict.get(abs_name):

                    abs_bind = None
                    abs_bind0 = None
                    abs_bind1 = None
                    max_ = self.abs_dict[abs_name].max
                    min_ = self.abs_dict[abs_name].min

                    if isinstance(bind_dict[abs_name], list) and len(bind_dict[abs_name]) == 1:
                        abs_bind = bind_dict[abs_name][0]

                    if isinstance(bind_dict[abs_name], list) and len(bind_dict[abs_name]) > 1:
                        abs_bind0 = bind_dict[abs_name][0]
                        abs_bind1 = bind_dict[abs_name][1]

                    if abs_bind and 'REL_' in abs_bind:

                        if event.code == ecodes.ABS_RX:
                            tx = time.time_ns()

                            if event.value > max_ * 0.05:
                                self.rx.append(event.value)

                            elif event.value < min_ * 0.05:
                                self.lx.append(event.value)

                            elif min_ * 0.05 <= event.value <= max_* 0.05:
                                self.rx.clear()
                                self.lx.clear()

                            self._translate_xy(event, min_, max_, tx)

                        elif event.code == ecodes.ABS_RY:
                            ty = time.time_ns()

                            if event.value > max_ * 0.05:
                                self.ry.append(event.value)

                            elif event.value < min_ * 0.05:
                                self.ly.append(event.value)

                            elif min_ * 0.05 <= event.value <= max_* 0.05:
                                self.ry.clear()
                                self.ly.clear()

                            self._translate_xy(event, min_, max_, ty)
                        else:
                            self._ev_rel_write(event, min_, max_, abs_bind)

                    elif abs_bind and ('KEY_' in abs_bind or 'BTN_' in abs_bind):
                        self._ev_key_write(event, max_, abs_bind)

                    elif abs_bind0 and abs_bind1 and 'KEY_' in abs_bind0 and 'KEY_' in abs_bind1:
                        self._ev_keys_write(event, min_, max_, abs_bind0, abs_bind1)

    def _ev_key_write(self, event, max_, binding):
        """Write uinput key press event."""

        if event.value > max_ * 0.1:
            print(categorize(event))
            self.ui.write(ecodes.EV_KEY, ecodes.ecodes[binding], 1)
            self.ui.syn()
        else:
            self.ui.write(ecodes.EV_KEY, ecodes.ecodes[binding], 0)
            self.ui.syn()

    def _ev_keys_write(self, event, min_, max_, bind0, bind1):
        """Write uinput key press event."""

        if event.value > max_ * 0.1:
            print(categorize(event))
            self.ui.write(ecodes.EV_KEY, ecodes.ecodes[bind0], 1)
            self.ui.syn()

        elif event.value < min_ * 0.1:
            print(categorize(event))
            self.ui.write(ecodes.EV_KEY, ecodes.ecodes[bind1], 1)
            self.ui.syn()

        elif min_ * 0.1 <= event.value <= max_ * 0.1:
            self.ui.write(ecodes.EV_KEY, ecodes.ecodes[bind0], 0)
            self.ui.write(ecodes.EV_KEY, ecodes.ecodes[bind1], 0)
            self.ui.syn()

    def _ev_rel_write(self, event, min_, max_, abs_bind):
        """Write the X and Y axis movement event"""

        if event.value > max_ * 0.1:
            print(categorize(event))

            if event.code == ecodes.ABS_X:
                self.ui.write(ecodes.EV_REL, ecodes.ecodes[abs_bind], -1)
                self.ui.syn()

            elif event.code == ecodes.ABS_Y:
                self.ui.write(ecodes.EV_REL, ecodes.ecodes[abs_bind], -1)
                self.ui.syn()

        elif event.value < min_ * 0.1:
            print(categorize(event))

            if event.code == ecodes.ABS_X:
                self.ui.write(ecodes.EV_REL, ecodes.ecodes[abs_bind], 1)
                self.ui.syn()

            elif event.code == ecodes.ABS_Y:
                self.ui.write(ecodes.EV_REL, ecodes.ecodes[abs_bind], 1)
                self.ui.syn()

    def _translate_xy(self, event, min_, max_, st):
        """Sorting movement events along the X and Y axes."""

        vx = vy = px = py = sx = sy = 0

        if event.value > max_ * 0.05:

            if event.code == ecodes.ABS_RX:
                vx = event.value
                sx = self.rx[0] if self.rx else 0
                px = self.rx[-1] if self.rx else 0
                if len(self.rx) > 1:
                    px = self.rx[-2]

            elif  event.code == ecodes.ABS_RY:
                vy = event.value
                sy = self.ry[0] if self.ry else 0
                py = self.ry[-1] if self.ry else 0
                if len(self.ry) > 1:
                    py = self.ry[-2]

        elif event.value < min_ * 0.05:

            if event.code == ecodes.ABS_RX:
                vx = event.value
                sx = self.lx[0] if self.lx else 0
                px = self.lx[-1] if self.lx else 0
                if len(self.lx) > 1:
                    px = self.lx[-2]

            elif event.code == ecodes.ABS_RY:
                vy = event.value
                sy = self.ly[0] if self.ly else 0
                py = self.ly[-1] if self.ly else 0
                if len(self.ly) > 1:
                    py = self.ly[-2]

        if event.value == max_ and event.value != 0:
            t_rx = Thread(target=self.x_hold_max, args=(1, max_,))
            t_rx.start()
            t_ry = Thread(target=self.y_hold_max, args=(1, max_,))
            t_ry.start()

        elif event.value == min_ and event.value != 0:
            t_lx = Thread(target=self.x_hold_max, args=(-1, min_,))
            t_lx.start()
            t_ly = Thread(target=self.y_hold_max, args=(-1, min_,))
            t_ly.start()
        else:
            self._move_xy(vx, vy, px, py, sx, sy, st)

    def _move_xy(self, vx, vy, px, py, sx, sy, st):
        """Сalculating the speed of movement along the x and y axes."""

        w = self.width / 2
        dsx = (vx/w - sx/w)
        etx = time.time_ns()
        dtx = etx - st
        val_x = int((dsx/dtx) * 1000)
        dsy = (vy/w - sy/w)
        ety = time.time_ns()
        dty = ety - st
        val_y = int((dsy/dty) * 1000)

        if val_x != 0:
            self.ui.write(ecodes.EV_REL, ecodes.REL_X, val_x)

        if val_y != 0:
            self.ui.write(ecodes.EV_REL, ecodes.REL_Y, val_y)

        self.ui.syn()

    def x_hold_max(self, value, _max):
        """Write motion at maximum X-axis deviation."""

        if self.rx:
            while self.rx[-1] == _max:
                time.sleep(0.0006)
                self.ui.write(ecodes.EV_REL, ecodes.REL_X, value)

        if self.lx:
            while self.lx[-1] == _max:
                time.sleep(0.0006)
                self.ui.write(ecodes.EV_REL, ecodes.REL_X, value)

    def y_hold_max(self, value, _max):
        """Write motion at maximum Y-axis deviation."""

        if self.ry:
            while self.ry[-1] == _max:
                time.sleep(0.0006)
                self.ui.write(ecodes.EV_REL, ecodes.REL_Y, value)

        if self.ly:
            while self.ly[-1] == _max:
                time.sleep(0.0006)
                self.ui.write(ecodes.EV_REL, ecodes.REL_Y, value)


class SwKeyController:
    """Shortcut controller and device input event handler."""

    def __init__(self, _dict={}):

        self.is_active = True
        self.type = KEYPAD
        self.devices = get_device_list(self.type)
        self.dict = _dict
        self.dev = {dev.fd: dev for dev in self.devices}

    def run(self):
        """"Running event loop."""

        try:
            asyncio.run(self.controller())
        except (Exception,) as e:
            print(e)
            sys.exit(0)

    def quit(self):
        """close all reading devices."""

        self.is_active = False

    async def controller(self):
        """"Running input device event handler."""

        args = (self.handle_device_event(device) for device in self.devices)
        await asyncio.gather(*args)
        return

    async def handle_device_event(self, device):
        """"Handling input events from the device."""

        evc = 0
        while self.is_active:
            r, w, x = select(self.dev, [], [])
            for fd in r:
                for event in self.dev[fd].read():
                    if event.type == ecodes.EV_KEY:
                        key_name = ecodes.bytype[ecodes.EV_KEY][event.code]

                        if key_name and event.value == 1:
                            evc += 1
                            if evc < 4:
                                self.dict[evc] = key_name

                        if key_name and event.value == 0:
                            evc = 0
                            self.dict.clear()

                    if event.type == ecodes.EV_ABS:
                        abs_dict = {a[0]: a[1] for a in self.dev[fd].capabilities()[3]}
                        abs_name = ecodes.bytype[ecodes.EV_ABS][event.code]
                        min_ = abs_dict[event.code].min
                        max_ = abs_dict[event.code].max

                        if min_ * 0.25 <= event.value <= max_ * 0.25:
                            evc = 0
                            self.dict.clear()
                        else:
                            evc += 1
                            if evc < 4:
                                self.dict[evc] = abs_name
                    if evc > 3:
                        evc = 0
        device.close()
        print(f'stop reading {device}')


class SwDeviceRedirectionSettings(Gtk.Widget):
    """Device redirection settings widget."""

    def __init__(self, _app=None, bind_dict=None, data=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.app = _app
        self.is_active = True
        self.bind_dict = bind_dict if bind_dict else dict()
        self.data = data
        self.widget_list = list()
        self.dev_type = KEYPAD
        self.devices = get_device_list(self.dev_type)
        self.controllers = get_device_list(GAMEPAD)
        self.dev = {dev.fd: dev for dev in self.devices}
        self.selected_device = None
        self.activate()
        self.run_device()

    def run_device(self):
        """Running device event handler."""

        t = Thread(target=asyncio.run, args=(self.listen_devices(),))
        t.start()

    def activate(self):
        """Building settings menu."""

        self.gc_settings = Gtk.Box(
            css_name='sw_flowbox', orientation=Gtk.Orientation.VERTICAL
        )
        self.gc_pref_group_title = Gtk.Label(
            css_name='sw_label_title', label=str_gc_title,
            xalign=0.0
        )
        self.gc_pref_group_subtitle = Gtk.Label(
            css_name='sw_label_desc',
            label= str_gc_subtitle,
            xalign=0.0, wrap=True, natural_wrap_mode=True
        )
        self.gc_pref_group_box = Gtk.Box(
                                css_name='sw_box_view',
                                orientation=Gtk.Orientation.VERTICAL
        )
        self.gc_pref_group_box.append(self.gc_pref_group_title)
        self.gc_pref_group_box.append(self.gc_pref_group_subtitle)

        self.gc_list_model = Gtk.StringList()
        self.gc_list_store = Gio.ListStore()
        self.gc_selection_model = Gtk.SingleSelection.new(self.gc_list_store)

        self.gc_dropdown = Gtk.DropDown(
                                css_name='sw_dropdown',
                                hexpand=True,
                                valign=Gtk.Align.CENTER,
                                halign=Gtk.Align.END,
                                show_arrow=True,
        )
        self.gc_dropdown.set_size_request(240,-1)
        self.gc_dropdown.set_model(self.gc_list_model)
        self.gc_dropdown.connect('notify::selected-item', self.gc_dropdown_activate)

        self.pref_group_gc_title_grid = Gtk.Grid()
        self.pref_group_gc_title_grid.attach(self.gc_pref_group_box, 0,0,1,1)
        self.pref_group_gc_title_grid.attach(self.gc_dropdown, 1,0,1,1)

        self.gc_view = Gtk.GridView(css_name='sw_gridview')
        self.gc_view.set_enable_rubberband(False)
        self.gc_view.set_min_columns(1)
        self.gc_view.set_max_columns(8)
        self.gc_view.set_single_click_activate(True)

        self.gc_factory = Gtk.SignalListItemFactory()
        self.gc_factory.connect('setup', self.gc_factory_setup)
        self.gc_factory.connect('bind', self.gc_factory_bind)

        self.gc_view.set_factory(self.gc_factory)
        self.gc_view.set_model(self.gc_selection_model)
        self.gc_view.connect('activate', self.gc_item_activate)

        for dev in self.controllers:
            self.gc_list_model.append(dev.name)

        self.scrolled_gc_settings = Gtk.ScrolledWindow(
                                        css_name='sw_scrolledwindow',
                                        vexpand=True,
                                        hexpand=True,
                                        valign=Gtk.Align.FILL,
                                        halign=Gtk.Align.FILL,
                                        child=self.gc_view,
        )
        self.gc_pref_group_flow = Gtk.Box(
                                css_name='sw_pref_box',
                                orientation=Gtk.Orientation.VERTICAL,
        )
        self.save = Gtk.Button(
                        css_name='sw_button_accept',
                        valign=Gtk.Align.CENTER,
                        label=msg.msg_dict['save'],
        )
        self.save.set_size_request(160, -1)
        self.save.connect('clicked', self.write_controller_settings)

        self.cancel = Gtk.Button(
                        css_name='sw_button_cancel',
                        valign=Gtk.Align.CENTER,
                        label=msg.msg_dict['cancel'],
        )
        self.cancel.set_size_request(160, -1)
        self.cancel.connect('clicked', self.close)

        self.title_widget = Gtk.Label(
            css_name='sw_label_title', label=vl_dict['gc_settings']
        )
        self.headerbar = Gtk.HeaderBar(
            css_name='sw_header_top', show_title_buttons=False
        )
        self.headerbar.set_title_widget(self.title_widget)
        self.headerbar.pack_start(self.cancel)
        self.headerbar.pack_end(self.save)

        self.gc_pref_group_flow.append(self.pref_group_gc_title_grid)
        self.gc_pref_group_flow.append(self.scrolled_gc_settings)

        self.gc_settings.append(self.gc_pref_group_flow)

        self.parent = Gtk.Window(
                                application=self.app, css_name='sw_window',
                                titlebar=self.headerbar,
                                modal=True,
        )
        self.parent.remove_css_class('background')
        self.parent.add_css_class('sw_background')
        self.parent.set_default_size(1248, 688)
        self.parent.set_resizable(True)
        self.parent.set_child(self.gc_settings)
        self.parent.connect('close-request', self.close)
        self.parent.present()

    def close(self, _btn):
        """Close controller settings window."""

        self.data['controller_active'] = True
        self.is_active = False
        self.parent.close()

    def write_controller_settings(self, _btn):
        """Write controller settings to json data."""

        write_json_data(sw_input_json, self.bind_dict)
        print(f'{sw_input_json} saved...done')

        self.is_active = False
        self.parent.close()

    def gc_item_activate(self, gc_view, position):
        """Activate item by user."""

        key_name = gc_view.get_model().get_item(position).get_string()
        key_widget = next(self.get_key_name_widget(key_name))
        self.gc_item_bind_key(key_name, key_widget)

    def get_key_name_widget(self, key_name):
        """Get widget by key name."""

        if '_LEFT' in key_name:
            suffix = '_LEFT'

        elif '_RIGHT' in key_name:
            suffix = '_RIGHT'

        elif '_UP' in key_name:
            suffix = '_UP'

        elif '_DOWN' in key_name:
            suffix = '_DOWN'
        else:
            suffix = ''

        for w in self.widget_list:
            w_name = str(w.get_name()) + suffix
            if w_name == key_name:
                yield w

    def gc_item_bind_key(self, key_name, key_widget):

        if key_widget and key_widget.get_visible_child_name() == 'box':
            key_widget.set_visible_child_name('label')

            t = Thread(target=bind_key, args=(key_name, self.bind_dict))
            t.start()
            f = self.update_item
            q = (key_name, key_widget)
            timeout = GLib.timeout_add(100, check_alive, t, f, q, None)

    def update_item(self, key_name, key_widget):
        """Update item of binding list."""

        box = key_widget.get_first_child()
        label = box.get_last_child()
        key = (
            key_name.replace('_LEFT', '').replace('_RIGHT', '')
            .replace('_UP', '').replace('_DOWN', '')
        )
        if self.bind_dict.get(key):
            if '_RIGHT' in key_name or '_DOWN' in key_name:
                name = self.bind_dict.get(key)[0]
            elif '_LEFT' in key_name or '_UP' in key_name:
                name = self.bind_dict.get(key)[1]
            else:
                name = self.bind_dict.get(key)[0]

            label.set_label(name)

        key_widget.set_visible_child_name('box')

    def gc_factory_setup(self, factory, item_list):
        """Controller item factory setup."""

        image_key_name = Gtk.Image(css_name='sw_action_row', margin_start=4)
        image_key_name.set_pixel_size(32)
        image_key_name.set_sensitive(False)
        image_key_name.add_css_class('key')

        label_key_name = Gtk.Label(
            css_name='sw_label_view', wrap=True, natural_wrap_mode=True,
            xalign=0, width_request=128,
        )
        label_key_binding = Gtk.Label(
            css_name='sw_entry', wrap=True, natural_wrap_mode=True, xalign=0,
            hexpand=True, halign=Gtk.Align.END, width_request=192,
        )
        label_key_press = Gtk.Label(
            css_name='sw_label_view', wrap=True, natural_wrap_mode=True,
            xalign=0, margin_start=8, label=str_press_any_key
        )
        box = Gtk.Box(
            css_name='sw_box_view', spacing=8, hexpand=True,
            orientation=Gtk.Orientation.HORIZONTAL,
        )
        box.append(image_key_name)
        box.append(label_key_name)
        box.append(label_key_binding)

        stack = Gtk.Stack(
            css_name='sw_stack', transition_duration=350,
            transition_type=Gtk.StackTransitionType.SLIDE_LEFT_RIGHT,
        )
        stack.add_named(box, 'box')
        stack.add_named(label_key_press, 'label')

        item_list.set_child(stack)

    def gc_factory_bind(self, factory, item_list):
        """Controller item factory bind,"""

        item = item_list.get_item()
        name = (
            item.get_string().replace('_LEFT', '').replace('_RIGHT', '')
            .replace('_UP', '').replace('_DOWN', '')
        )
        stack = item_list.get_child()
        stack.set_name(name)
        box = stack.get_first_child()
        image_key_name = box.get_first_child()
        label_key_name = image_key_name.get_next_sibling()
        label_key_binding = label_key_name.get_next_sibling()
        cap_var = item.get_string()

        if controller_icons.get(name):
            image_key_name.set_from_file(controller_icons.get(name))
            text = self.bind_dict.get(name) if self.bind_dict[name] else str_not_set
            if isinstance(text, list):
                text = text[0]

        elif '_RIGHT' in cap_var:
            image_key_name.set_from_file(controller_icons.get(name+'rt'))
            text = self.bind_dict.get(name) if self.bind_dict[name] else str_not_set
            if text and isinstance(text, list):
                text = text[0]

        elif '_LEFT' in cap_var:
            image_key_name.set_from_file(controller_icons.get(name+'lt'))
            text = self.bind_dict.get(name) if self.bind_dict[name] else str_not_set
            if text and isinstance(text, list):
                if len(text) == 1:
                    text = text[0]
                elif len(text) > 1:
                    text = text[1]

        elif '_DOWN' in cap_var:
            image_key_name.set_from_file(controller_icons.get(name+'dn'))
            text = self.bind_dict.get(name) if self.bind_dict[name] else str_not_set
            if text and isinstance(text, list):
                text = text[0]

        elif '_UP' in cap_var:
            image_key_name.set_from_file(controller_icons.get(name+'up'))
            text = self.bind_dict.get(name) if self.bind_dict[name] else str_not_set
            if text and isinstance(text, list):
                if len(text) == 1:
                    text = text[0]
                elif len(text) > 1:
                    text = text[1]
        else:
            image_key_name.set_from_file(IconPath.icon_unknown_button)
            text = str_not_set

        label_key_name.set_label(cap_var)
        label_key_name.set_name(cap_var)
        label_key_binding.set_label(str(text))
        self.widget_list.append(stack)

    def update_gc_view(self):
        """Update controller settings view."""

        self.widget_list.clear()
        self.gc_list_store.remove_all()

        double_x = [
            'ABS_X', 'ABS_RX', 'ABS_HAT0X', 'ABS_HAT1X', 'ABS_HAT2X', 'ABS_HAT3X'
        ]
        double_y = [
            'ABS_Y', 'ABS_RY','ABS_HAT0Y', 'ABS_HAT1Y', 'ABS_HAT2Y', 'ABS_HAT3Y',
        ]
        for dev in self.controllers:
            if self.gc_dropdown.get_selected_item().get_string() == dev.name:
                key_dict, abs_dict = get_key_dict(dev.name, self.dev_type)

                for k, v in key_dict.items():
                    if not 'BTN_TRIGGER_HAPPY' in k:
                        string = Gtk.StringObject.new(str(k))
                        self.gc_list_store.append(string)

                for k, v in abs_dict.items():

                    if k in double_x:
                        string_rt = Gtk.StringObject.new(str(k) + '_RIGHT')
                        string_lt = Gtk.StringObject.new(str(k) + '_LEFT')
                        self.gc_list_store.append(string_rt)
                        self.gc_list_store.append(string_lt)

                    elif k in double_y:
                        string_dn = Gtk.StringObject.new(str(k) + '_DOWN')
                        string_up = Gtk.StringObject.new(str(k) + '_UP')
                        self.gc_list_store.append(string_dn)
                        self.gc_list_store.append(string_up)
                    else:
                        string = Gtk.StringObject.new(str(k))
                        self.gc_list_store.append(string)

    def gc_dropdown_activate(self, gc_dropdown, gparam):
        """Building settings list of selected controller."""

        self.selected_device = gc_dropdown.get_selected_item().get_string()
        self.update_gc_view()

    async def listen_devices(self):
        asyncio.gather(*(self.listen_event(d) for d in self.devices))

    async def listen_event(self, device):
        """Listen input events from the device."""

        while self.widget_list == []:
            time.sleep(1)
        else:
            while self.is_active:
                try:
                    codes = [ecodes.ecodes[x.get_name()] for x in self.widget_list]
                except:
                    codes = []

                r, w, x = select(self.dev, [], [])
                for fd in r:
                    for event in self.dev[fd].read():
                        if self.dev[fd].name == self.selected_device:
                            for w, c in zip(self.widget_list, codes):
                                if int(event.code) == int(c):
                                    key_name = None
                                    if event.type == ecodes.EV_KEY:
                                        key_name = ecodes.bytype[ecodes.EV_KEY][event.code]
                                        if isinstance(key_name, list) or isinstance(key_name, tuple):
                                            key_name = key_name[0]

                                    abs_name = None
                                    if event.type == ecodes.EV_ABS:
                                        abs_name = ecodes.bytype[ecodes.EV_ABS][event.code]
                                        if isinstance(abs_name, list) or isinstance(abs_name, tuple):
                                            abs_name = abs_name[0]

                                    if w.get_name() == key_name:
                                        if event.value == 0:
                                            if w.has_css_class('bind'):
                                                w.remove_css_class('bind')
                                        else:
                                            if not w.has_css_class('bind'):
                                                print(categorize(event))
                                                w.add_css_class('bind')
                                        break

                                    if w.get_name() == abs_name:
                                        abs_dict = {a[0]: a[1] for a in self.dev[fd].capabilities()[3]}
                                        min_ = abs_dict[event.code].min
                                        max_ = abs_dict[event.code].max

                                        if min_ * 0.1 <= event.value <= max_ * 0.1:
                                            if w.has_css_class('bind'):
                                                w.remove_css_class('bind')
                                        else:
                                            if not w.has_css_class('bind'):
                                                print(categorize(event))
                                                w.add_css_class('bind')
                                        break

                if not self.parent.get_visible():
                    print(f'stop listening to the {device}, exit...')
                    break


class SwDeviceRedirectionApp(Gtk.Application):
    """Device redirection settings menu."""

    def __init__(self, bind_dict=None, *args, **kwargs):
        super().__init__(*args, **kwargs, application_id="ru.launcher.StartWine",
                        flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        GLib.set_prgname('GamepadController')
        GLib.set_application_name('GamepadController')
        self.display = Gdk.Display().get_default()
        self.sw_css_dark = sw_css_dark
        self.css_provider = Gtk.CssProvider()
        self.window = None
        self.bind_dict = bind_dict if bind_dict else dict()
        self.css_provider.load_from_file(Gio.File.new_for_path(bytes(self.sw_css_dark)))
        Gtk.StyleContext.add_provider_for_display(
            self.display, self.css_provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )
        self.connect('activate', self.activate)

    def activate(self, app):
        """Building settings menu."""

        self.window = SwDeviceRedirectionSettings(app, self.bind_dict)

    def terminate(self):
        """Shut down the application."""

        self.window.close(None)
        self.quit()


def run_device_event_monitoring(device, key_dict, abs_dict):
    """Start monitoring of device input events."""

    for event in device.async_read_loop():

        if event.type == ecodes.EV_KEY:
            print(categorize(event), event.value)

        if event.type == ecodes.EV_ABS:
            print(categorize(event), event.value)

        if event.type == ecodes.EV_REL:
            print(categorize(event), event.value)


def run_device_redirection_settings():
    """Running device redirection settings."""

    app = SwDeviceRedirectionApp(bind_dict=app_bind_profile)
    try:
        app.run()
    except KeyboardInterrupt as e:
        print('Exit...')
        app.terminate()


def run_device_redirection(device, data):
    """Running device event redirection."""

    while True:
        time.sleep(0.5)
        dev_connected = {
            InputDevice(dev).name: dev for dev in evdev.list_devices()
        }
        if dev_connected.get(device.name):
            device = InputDevice(dev_connected.get(device.name))
            data['device_connected'] = device.name
            redirection = DeviceRedirection(device, data)
            print(f'{device.name} connected')
            try:
                redirection.run()
            except (KeyboardInterrupt, OSError) as e:
                data['device_connected'] = ''
                print(f'{device.name} disconnected')


def run_zero_device_redirection(event, data):
    """Running redirection for first device in device list."""

    gamepad = None
    devices = get_device_list('gamepad')
    for dev in devices:
        caps = dev.capabilities()
        for x in caps:
            if ecodes.EV_FF == x:
                gamepad = dev
                break

    if not gamepad:
        print('No connected devices found...')

    while not gamepad:
        devices = get_device_list('gamepad')
        for dev in devices:
            caps = dev.capabilities()
            for x in caps:
                if ecodes.EV_FF == x:
                    gamepad = dev
                    break
        time.sleep(0.5)
    else:
        data['device_connected'] = devices[0].name
        try:
            run_device_redirection(devices[0], data)
        except (KeyboardInterrupt, OSError) as e:
            sys.exit(0)


def run_commandline(run_type, dev_type=None):
    """Running with commandline args."""

    bind_dict = dict()
    devices = get_device_list(dev_type)

    if devices == []:
        print('No connected devices found...')
    else:
        for n, d in enumerate(devices):
            print(n, d.name)

        try:
            dev_num = input('Input device number: ')
        except KeyboardInterrupt as e:
            sys.exit(0)

        try:
            dev_num = eval(dev_num)
        except (SyntaxError, NameError) as e:
            print('Invalid value! Must be a number of device')
            sys.exit(1)

        if isinstance(dev_num, int) and dev_num < len(devices):
            device = devices[dev_num]
            key_dict, abs_dict = get_key_dict(device.name, dev_type)

        if run_type == 'default':
            data = dict()
            data['bind_profile'] = default_app_bind_profile
            data['controller_active'] = True
            try:
                run_device_redirection(device, data)
            except KeyboardInterrupt as e:
                sys.exit(0)

        elif run_type == 'custom':
            for k, v in key_dict.items():
                try:
                    bind_device_key(device, k, bind_dict)
                except KeyboardInterrupt as e:
                    sys.exit(0)
            else:
                data = dict()
                data['bind_profile'] = bind_dict
                data['controller_active'] = True
                try:
                    run_device_redirection(device, data)
                except KeyboardInterrupt as e:
                    sys.exit(0)

        elif run_type == 'monitoring':
            try:
                run_device_event_monitoring(device, key_dict, abs_dict)
            except KeyboardInterrupt as e:
                print('Exit...')
                sys.exit(0)

        elif run_type == 'keys':
            dev_caps = device.capabilities(verbose=True, absinfo=True)
            print(dev_caps)

        else:
            print('Wrong redirection type, must be "default" or "custom".')
            sys.exit(0)


def helper():
    """___Commandline help info___"""

    print('''
    ----------------------------------------------------------------------------
    StartWine Input:
    It is a set of tools for handling input devices, redirecting input
    and keybinding.
    ----------------------------------------------------------------------------
    Usage Input: [module] [option]
    ----------------------------------------------------------------------------
    Options:
    -h  '--help'                Show help and exit
    -g  '--gui-settings'        Device redirection settings (graphical interface).
    -r  '--redirection'         Gamepad or joystick redirection (default bindings).
    -c  '--custom-redirection'  Custom configuration for device redirection.
    -m  '--monitoring'          Monitoring input events from the device.
    -l  '--list'                Print a list of all input devices.
    -k  '--keys'                Print out the dictionary of the input device keys.
''')

if __name__ == '__main__':

    if len(argv) == 1:
        helper()

    elif len(argv) == 2:
        if argv[1] == '-g' or argv[1] == '--gui-settings':
            run_device_redirection_settings()

        elif argv[1] == '-r' or argv[1] == '--redirection':
            run_commandline('default', GAMEPAD)

        elif argv[1] == '-c' or argv[1] == '--custom-redirection':
            run_commandline('custom', GAMEPAD)

        elif argv[1] == '-m' or argv[1] == '--monitoring':
            run_commandline('monitoring', KEYPAD)

        elif argv[1] == '-l' or argv[1] == '--list':
            devices = [InputDevice(dev) for dev in evdev.list_devices()]
            for num, dev in enumerate(devices):
                print(f'{num}:\t{dev} {dev.name}')

        elif argv[1] == '-k' or argv[1] == '--keys':
            run_commandline('keys')
        else:
            helper()
    else:
        helper()

