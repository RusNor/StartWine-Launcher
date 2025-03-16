#!/usr/bin/python3

import os
import time
from os import environ, getenv
from sys import argv, stdout, stderr
from pathlib import Path
from threading import Thread
from subprocess import Popen, run, check_output, PIPE

import dbus
from dbus.mainloop.glib import DBusGMainLoop
import gi
gi.require_version('Gst', '1.0')
from gi.repository import GObject, Gst, GLib
import pulsectl
import pychromecast
from pychromecast.controllers.media import MediaController
from sw_input import SwKeyController

"""
-------------
Video formats
-------------
mp4:
    video_enc: vaapih264enc h264parse, x264enc
    audio_enc: faac, lamemp3enc, avenc_mp2, avenc_alac
    muxer: mp4mux

mkv: 
    video_enc: x264enc, vaapih264enc
    audio_enc: faac, avenc_mp2, opusenc, vorbisenc, flacenc, pcm
    muxer: matroskamux

ts:
    video_enc: x264enc, vaapih264enc, vaapih265enc
    audio_enc: avenc_mp2, faac, opusenc
    muxer: mpegtsmux

flv:
    video_enc: x264enc, vaapih264enc
    audio_enc: faac
    muxer: flvmux

-------------
Audio formats
-------------
mp4: faac
mp3: lamemp3enc
mp2: avenc_mp2
flac: flacenc
alac: avenc_alac
opus: opusenc
vorbis: vorbisenc
pcm:

---------------
Encoder options
---------------
cabac=0 ref=1 deblock=0:0:0 analyse=0:0 me=dia subme=0 psy=1 psy_rd=1.00:0.00
mixed_ref=0 me_range=16 chroma_me=1 trellis=0 8x8dct=0 cqm=0 deadzone=21,11
fast_pskip=1 chroma_qp_offset=6 threads=17 lookahead_threads=16 sliced_threads=1
slices=17 nr=0 decimate=1 interlaced=0 bluray_compat=0 constrained_intra=0
bframes=0 weightp=0 keyint=250 keyint_min=25 scenecut=0 intra_refresh=0 rc=crf
mbtree=0 crf=20.0 qcomp=0.60 qpmin=0 qpmax=69 qpstep=4 ip_ratio=1.40 aq=0
rate-control={cqp, vbr, cbr}
"""

sw_data = Path(__file__).parent.parent
sw_icon = Path(f'{sw_data}/img/gui_icons/sw_icon.png')

venc_dict = {
    'buff': '! queue max-size-buffers=0 max-size-time=0 max-size-bytes=0',
    'h264': '! videoconvert ! queue ! vaapih264enc rate-control=cqp tune=high-compression ! h264parse',
    'h265': '! videoconvert ! queue ! vaapih265enc rate-control=cqp ! h265parse',
    'x264': '! videoconvert ! queue ! x264enc interlaced=true pass=quant quantizer=18 speed-preset=ultrafast byte-stream=true',
    'x264raw': '! videoconvert ! queue ! x264enc interlaced=true pass=quant quantizer=0 speed-preset=ultrafast byte-stream=true',
}
aenc_dict = {
    'raw': '! audio/x-raw,format=F32LE,channels=2,rate=48000',
    'mp4': '! audioconvert ! queue ! audioresample ! queue ! faac bitrate=320000',
    'mp3': '! audioconvert ! queue ! audioresample ! queue ! lamemp3enc bitrate=320',
    'mp2': '! audioconvert ! queue ! audioresample ! queue ! avenc_mp2',
    'opus': '! audioconvert ! queue ! audioresample ! queue ! opusenc bitrate=32000',
    'flac': '! audioconvert ! queue ! audioresample ! queue ! flacenc',
    'pcm': '! audioconvert ! queue ! audioresample ! queue ! audio/x-raw,format=F32LE,channels=2,rate=48000',
    'alac': '! audioconvert ! queue ! audioresample ! queue ! avenc_alac',
}
muxer_dict = {
    'mp4mux': 'mp4mux name=mux reserved-bytes-per-sec=100 reserved-max-duration=20184000000000 reserved-moov-update-period=100000000',
    'matroskamux': 'matroskamux name=mux min-index-interval=1000000000',
    'mpegtsmux': 'mpegtsmux name=mux',
    'flvmux': 'flvmux name=mux',
}


def get_screen_dict():
    """___Get X11 screen dictionary___"""

    gi.require_version('Gdk', '4.0')
    from gi.repository import Gdk
    screen_dict = dict()
    display = Gdk.Display().get_default()
    monitors = display.get_monitors()

    for num, mon in enumerate(monitors):
        name = mon.get_manufacturer()
        port = mon.get_connector()
        model = mon.get_model()
        x = mon.get_geometry().x
        y = mon.get_geometry().y
        width = mon.get_geometry().width
        height = mon.get_geometry().height
        screen_dict[num] = {
            'monitor': mon, 'name': name, 'model': model, 'x': x, 'y': y,
            'width': width, 'height': height, 'connector': port
        }

    return screen_dict


def get_xprop_list():
    """___Get X11 window xid dictionary___"""

    xid_list = list()
    xid_dict = dict()
    x_prop = f"xprop -root _NET_CLIENT_LIST | sed 's/.*# //'"
    out = run(x_prop, shell=True, stdout=PIPE, encoding='utf-8').stdout
    xid_list = out.replace(',', '').replace('\n', '').split(' ')
    for xid in xid_list:
        cmd = f'xprop -id {xid} _NET_WM_NAME'
        out = run(cmd, shell=True, stdout=PIPE, encoding='utf-8').stdout
        name = out.splitlines()[0].split('=')[1].strip().strip('"')
        xid_dict[xid] = name

    return xid_dict


def get_xid_dict():
    """___Get X11 window xid dictionary___"""

    try:
        from Xlib.display import Display
    except ImportError as e:
        return None
    try:
        from Xlib.X import AnyPropertyType
    except ImportError as e:
        return None

    xid_dict = dict()
    display = Display()
    root = display.screen().root
    width = display.screen().width_in_pixels
    height = display.screen().height_in_pixels
    _NET_CLIENT_LIST = display.get_atom('_NET_CLIENT_LIST')
    _NET_WM_NAME = display.get_atom('_NET_WM_NAME')

    client_list = root.get_full_property(
        _NET_CLIENT_LIST,
        property_type=AnyPropertyType,
    ).value

    for xid in client_list:
        window = display.create_resource_object('window', xid)
        name = window.get_full_property(
            _NET_WM_NAME,
            property_type=AnyPropertyType,
        ).value
        xid_dict[xid] = str(name, encoding='utf-8')

    return xid_dict


class SwScreenCast:
    """A tool for capture, broadcast and recording screen"""

    def __init__(
            self, preview=None, record=None, stream=None, chromecast=None,
            v_enc=None, v_fmt=None, a_enc=None, output=None, key_mod=None, keys=[],
            mode=None, a_dev=None, volume=None):

        DBusGMainLoop(set_as_default=True)
        Gst.init(None)

        if getenv('WAYLAND_DISPLAY') or getenv('XDG_SESSION_TYPE') == 'wayland':
            self.session_type = 'wayland'
        else:
            self.session_type = 'x11'

        self.id = 'ru.launcher.StartWine'
        self.loop = GLib.MainLoop()
        self.bus = dbus.SessionBus()
        self.mode = mode
        self.preview = preview
        self.record = record
        self.stream = stream
        self.chromecast = chromecast
        self.v_enc = v_enc if v_enc and v_enc in venc_dict.keys() else 'h264'
        self.a_enc = a_enc if a_enc and a_enc in aenc_dict.keys() else 'mp4'
        self.muxer = v_fmt if v_fmt and v_fmt in muxer_dict.keys() else 'matroskamux'
        self.time = time.strftime('%Y%M%d%S')
        self.ext = str(
            self.muxer.replace('matroskamux', 'mkv').rstrip('mux') if self.muxer else 'mkv'
        )
        output = output if output else Path.home()

        if output == Path.home():
            self.output = f'{Path.home()}/video_{self.time}.{self.ext}'

        elif Path(output).suffix():
            self.output = output

        elif Path(output).exist() and Path(output).is_dir():
            self.output = f'{output}/video_{self.time}.{self.ext}'
        else:
            self.output = f'{Path.home()}/video_{self.time}.{self.ext}'

        self.key_mod = key_mod
        self.keys = keys
        self.pipelines = []
        self.session_handle = None
        self.request_token_counter = 0
        self.session_token_counter = 0
        self.sender_name = str(self.bus.get_unique_name()[1:]).replace('.', '_')
        self.audio_device = a_dev
        self.volume = volume

        if not self.audio_device:
            self.audio_device, self.volume = self.pulseaudio_default_sink()

        self.screencast = 'org.freedesktop.portal.ScreenCast'
        self.notify = 'org.freedesktop.portal.Notification'
        self.desktop_object = 'org.freedesktop.portal.Desktop'
        self.desktop_path = '/org/freedesktop/portal/desktop'
        self.request_object = 'org.freedesktop.portal.Request'
        self.request_root = '/org/freedesktop/portal/desktop/request'
        self.session_root = '/org/freedesktop/portal/desktop/session'
        self.portal = self.bus.get_object(self.desktop_object, self.desktop_path)
        self.session_path, self.session_token = self.get_session_path()
        self.controller_dict = {}
        self.title = 'Screencast'
        self.message = 'Session is active...'
        self.icon = open(sw_icon, 'r').fileno()
        self.notify_dict = {
            'title': f'{self.title}',
            'body': f'{self.message}',
            'icon': f'(file-descriptor, {self.icon})',
            #'buttons': [{'label': dbus.types.Struct(), 'action': dbus.types.Struct()}],
            #'category': 'call.incoming'
        }

    def run(self):
        """___Run glib main loop___"""

        self.controller = SwKeyController(self.controller_dict)
        self.activate()
        self.loop.run()

    def activate(self):
        """___Create new screencast session___"""

        if self.session_type == 'wayland':
            self.gdbus_call(
                self.portal.CreateSession, self.create_session_response,
                options={'session_handle_token': self.session_token}, interface=self.screencast
            )
            t = Thread(target=self.controller.run)
            t.start()
            GLib.timeout_add(100, self.controller_callback)
        else:
            scr = get_screen_dict()
            xid = get_xid_dict()

            if not xid:
                xid = get_xprop_list()

            if not self.mode:
                self.select_x11_source(scr, xid)

    def select_x11_source(self, screen_data, xid_data):
        """___Running dilaog window for selecting x11 source to capture___"""

        from sw_crier import SourceSelectionWindow
        dialog = SourceSelectionWindow(
                                        mon_dict=screen_data, xid_dict=xid_data,
                                        callback=self.selected_source
        )
        try:
            dialog.run()
        except KeyboardInterrupt:
            self.terminate()
        else:
            t = Thread(target=self.controller.run)
            t.start()
            GLib.timeout_add(100, self.controller_callback)

    def selected_source(self, xid, source_name, data):
        """___Callback selected x11 source___"""

        if xid and source_name:
            print(xid, source_name, data)
            self.run_stream(xid, data)
        else:
            return None

    def controller_callback(self):
        """___Callback dictionary of key controller event handler"""

        count = 0
        if len(self.controller_dict) > 0:
            mod = self.controller_dict.get(1)
            key0 = self.controller_dict.get(2)
            key1 = self.controller_dict.get(3)

            if ('KEY_LEFTCTRL' in str(mod) and 'KEY_LEFTSHIFT' in str(key0)
                    and 'KEY_END' in str(key1)):
                print(f'Event pressed: {mod} {key0} {key1}')
                count += 1
                if count == 1:
                    self.controller_dict.clear()
                    self.terminate()
                    return False
        return True

    def bus_message(self, bus, message):
        """___Gstreamer message handler___"""

        t = message.type
        if t == Gst.MessageType.EOS:
            stdout.write("End-of-stream\n")
            return self.terminate()

        elif t == Gst.MessageType.ERROR:
            err, debug = message.parse_error()
            stderr.write("Error: %s: %s\n" % (err, debug))
            return self.terminate()

        return True

    def run_stream(self, node_id, data=None):
        """___Open remote for playing or record stream by gstreamer___"""

        if self.session_handle:
            db_dict = dbus.Dictionary(signature="sv")
            fd_object = self.portal.OpenPipeWireRemote(
            self.session_handle, db_dict, dbus_interface=self.screencast
            )
            fd = fd_object.take()

        buff = venc_dict['buff']
        raw = aenc_dict.get('raw')
        opus = aenc_dict.get('opus')
        h264 = venc_dict.get('h264')
        venc = venc_dict.get(self.v_enc)
        aenc = aenc_dict.get(self.a_enc)
        muxer = muxer_dict.get(self.muxer)
        out = self.output

        if self.preview:
            if self.session_type == 'wayland':
                pipeline0 = Gst.parse_launch(
                    f'pipewiresrc fd={fd} path={node_id} ! videoconvert ! queue ! vaapisink'
                )
            else:
                xid = f'xid={node_id}'
                sx = sy = ex = ey = ''
                w = h = None
                x_pos = y_pos = None

                if isinstance(data, dict):
                    xid = ''
                    w = data.get('width')
                    h = data.get('height')
                    x_pos = data.get('x')
                    y_pos = data.get('y')

                    if w and h and x_pos is not None and y_pos is not None:
                        sx = f'startx={x_pos}'
                        sy = f'starty={y_pos}'
                        ex = f'endx={int(x_pos) + int(w)-1}'
                        ey = f'endy={int(y_pos) + int(h)-1}'

                pipeline0 = Gst.parse_launch(
                    f'ximagesrc {xid} {sx} {sy} {ex} {ey}  use-damage=0 '
                    +f'! videoscale method=0 ! videoconvert ! queue ! vaapisink'
                )

            self.pipelines.append(pipeline0)
            pipeline0.set_state(Gst.State.PLAYING)
            pipeline0.get_bus().connect('message', self.bus_message)

        if self.record:
            if self.session_type == 'wayland':
                pipeline1 = Gst.parse_launch(
                    f'pipewiresrc fd={fd} path={node_id} '
                    + f'{buff} {venc} ! progressreport update-freq=1 ! queue ! mux. '
                    + f'pulsesrc device="{self.audio_device}.monitor" volume={self.volume} '
                    + f'{buff} {raw} {aenc} ! queue ! mux. {muxer} '
                    + f'! filesink location={out}'
                )
            else:
                xid = f'xid={node_id}'
                sx = sy = ex = ey = ''
                w = h = None
                x_pos = y_pos = None
                if isinstance(data, dict):
                    w = data.get('width')
                    h = data.get('height')
                    x_pos = data.get('x')
                    y_pos = data.get('y')
                    xid = ''
                    if w and h and x_pos is not None and y_pos is not None:
                        sx = f'startx={x_pos}'
                        sy = f'starty={y_pos}'
                        ex = f'endx={int(x_pos) + int(w)-1}'
                        ey = f'endy={int(y_pos) + int(h)-1}'

                pipeline1 = Gst.parse_launch(
                    f'ximagesrc {xid} {sx} {sy} {ex} {ey} '
                    + f'{buff} {venc} ! progressreport update-freq=1 ! queue ! mux. '
                    + f'pulsesrc device="{self.audio_device}.monitor" volume={self.volume} '
                    + f'{buff} {raw} {aenc} ! queue ! mux. {muxer} '
                    + f'! filesink location={out}'
                )

            pipeline1.set_state(Gst.State.PLAYING)
            self.pipelines.append(pipeline1)

            bus = pipeline1.get_bus()
            bus.add_signal_watch()
            bus.connect('message', self.bus_message)

        if self.stream:
            pipeline2 = Gst.parse_launch(
                f'pipewiresrc fd={fd} path={node_id} '
                + f'{h264} ! rtph264pay config-interval=1 pt=96 ! udpsink host=127.0.0.1 port=5000 '
                #+ f'pulsesrc device="{self.audio_device}.monitor" '
                #+ f'{raw} {opus} ! queue ! rtpopuspay pt=97 ! udpsink host=127.0.0.1 port=5002'
            )
            pipeline2.set_state(Gst.State.PLAYING)
            pipeline2.get_bus().connect('message', self.bus_message)
            self.pipelines.append(pipeline2)

        if self.chromecast:
            self.chromecast_stream(fd, node_id, h264, muxer)

    def chromecast_stream(fd, node_id, venc, mp4mux):
        """___Start a chromecast stream using gstreamer___"""

        cast = find_chromecasts()
        mc = cast.media_controller
        host = cast.cast_info.host
        port = cast.cast_info.port
        stream_url = f"tcp://{host}:{port}"

        print("Casting to: ", f"tcp://{host}:{port}")
        print(f"Setting transmission to {cast.cast_info.friendly_name}")

        if self.session_type == 'wayland':
            pipeline3 = Gst.parse_launch(
                f'pipewiresrc fd={fd} path={node_id} '
                f'{h264} ! rtph264pay config-interval=1 pt=96 ! udpsink host=127.0.0.1 port=5000 '
                + f'pulsesrc device="{self.audio_device}.monitor" '
                + f'{raw} {opus} ! queue ! rtpopuspay pt=97 ! udpsink host=127.0.0.1 port=5002'
            )
            pipeline3.set_state(Gst.State.PLAYING)
            self.pipelines.append(pipeline3)
            pipeline3.get_bus().connect('message', self.bus_message)

            print("Starting chromecast transmission with gstreamer...")
            mc.play_media(f"tcp://{host}:{port}", 'video/mp4')
            mc.block_until_active()
        else:
            #TODO
            print('x11 session chromecast...')

    def get_request_path(self):
        """___Get new request path and token___"""

        self.request_token_counter = self.request_token_counter + 1
        token = f'swtoken_{self.request_token_counter}'
        path = f'{self.request_root}/{self.sender_name}/{token}'
        return path, token

    def get_session_path(self):
        """___Get new session path and token___"""

        self.session_token_counter = self.session_token_counter + 1
        token = f'swtoken_{self.session_token_counter}'
        path = f'{self.session_root}/{self.sender_name}/{token}'
        return path, token

    def gdbus_call(self, method, callback, *args, options={}, interface):
        """___Gdbus call screencast interface___"""

        request_path, request_token = self.get_request_path()
        options['handle_token'] = request_token
        self.bus.add_signal_receiver(
            callback, 'Response', self.request_object, self.desktop_object, request_path,
        )
        method(*(args + (options,)), dbus_interface=interface)

    def gdbus_notify(self, method, notification, interface):
        """___Gdbus call notification interface___"""

        if notification:
            method(self.id, notification , dbus_interface=self.notify)
        else:
            method(self.id, dbus_interface=self.notify)

    def send_notify(self, title, message):

        self.notify_dict['title'] = title if title else self.title
        self.notify_dict['body'] = message if message else self.message
        self.gdbus_notify(
            self.portal.AddNotification, notification=self.notify_dict, interface=self.notify
        )
        to = Thread(target=self.timeout)
        to.start()

    def start_response(self, response, result):
        """___Start a pipewire stream and play it using gstreamer___"""

        if response == 0:
            for (node_id, stream_properties) in result['streams']:
                print(f"stream {node_id}")
                self.run_stream(node_id)
                self.send_notify(None, 'is started...')
        else:
            print(f'Failed to start: {response}')
            self.terminate()
            return

    def select_sources_response(self, response, result):
        """___Start screencast when source is selected___"""

        if response == 0:
            print(f'start session {self.session_handle}')
            self.gdbus_call(self.portal.Start, self.start_response, self.session_handle, '', interface=self.screencast)
        else:
            print(f'Failed to select sources: {response}')
            self.terminate()
            return

    def create_session_response(self, response, result):
        """___Select source for created session___"""

        print(response, result)
        if response == 0:
            self.session_handle = result['session_handle']
            print(f'create session {self.session_handle}')
            self.gdbus_call(
                    self.portal.SelectSources, self.select_sources_response, self.session_handle,
                    options={'multiple': False, 'types': dbus.UInt32(1|2)}, interface=self.screencast
            )
        else:
            print(f'Failed to create session: {response}')
            self.terminate()
            return

    def pulseaudio_default_sink(self):
        """___Get pulse audio default sink name and volune value___"""

        pa = pulsectl.Pulse('SwSourceCapture')
        pa_default_sink = pa.server_info().default_sink_name
        volume = 1.0
        try:
            pa.sink_info(0)
        except IndexError as e:
            pass
        else:
            volume = round(pa.sink_info(0).volume.values[0], 2)
        print(
            f'Audio sink: {pa_default_sink}\n'
            +f'Volume: {volume*100}%'
        )
        return pa_default_sink, volume

    def get_audio_devices(self):
        """___Get available audio devices___"""

        devmon = Gst.DeviceMonitor.new()
        devmon.start()
        devices = devmon.get_devices()

        for i, d in enumerate(devices):
            props = d.get_properties()
            #print(props)
            if props['alsa.card']:
                data = {
                    '\tnode.nick': props['node.nick'],
                    '\tobject.path': props['object.path'],
                    '\tcard_name': props['alsa.card_name'],
                    '\tmixer_name': props['alsa.mixer_name'],
                    '\talsa.name': props['alsa.name'],
                    '\tresolution': props['alsa.resolution_bits'],
                    '\talsa.path': props['api.alsa.path'],
                    '\tpcm.stream': props['api.alsa.pcm.stream'],
                    '\tchannels': props['audio.channels'],
                    '\tposition':props['audio.position'],
                }
                print(
                '''------------------------------------------------------------------------''')
                print(f"\t{props['node.description']}:")
                print(
                '''------------------------------------------------------------------------''')
                print(f"\t{props['alsa.card']}: {props['node.name']}")
                for k, v in data.items():
                    print(f'\t{k}:\t{v}')
        devmon.stop()

    def get_monitors(self):
        """___Get dictionary of connected x11 monitors___"""

        monitors = {}
        xrandr_output = check_output(["xrandr", "--listactivemonitors"]).decode()
        for num, line in enumerate(xrandr_output.splitlines()):
            if line.strip():
                if len(line.split()) == 4:
                    c = line.split()[0].strip(':')
                    r = line.split()[2]
                    n = line.split()[3]
                    monitors[int(c)] = {'name': n, 'resolution': r}
        return monitors

    def find_chromecasts(self):
        """___Searching and selecting available chromecast devices___"""

        print("Searching Chromecast devices...")
        chromecasts, browser = pychromecast.get_chromecasts()
        if not chromecasts:
            print("Not found.")
            return None

        print("Chromecast devices availble:")
        for i, cc in enumerate(chromecasts):
            print(f"{i}: {cc.cast_info.friendly_name}")

        selection = int(input("Select Chromecast device: "))
        cast = chromecasts[selection]
        print(f"Connected to {cast.cast_info.friendly_name}")
        cast.wait()
        return cast

    def get_bus_service(self):
        """___Get system and session bus services___"""

        for service in dbus.SystemBus().list_names():
            print(service)

        for service in dbus.SessionBus().list_names():
            print(service)

    def timeout(self):
        count = 0
        while count < 3:
            count += 1
            time.sleep(1)
        else:
            self.gdbus_notify(
                self.portal.RemoveNotification, None, interface=self.notify
            )

    def terminate(self):
        """___Stop gstreamer and exit main loop___"""

        if len(self.pipelines) > 0:
            for pipeline in self.pipelines:
                print(f'terminate {pipeline}')
                pipeline.set_state(Gst.State.NULL)
                pipeline.get_state(Gst.CLOCK_TIME_NONE)

        self.send_notify(None, 'is ended...')
        print('\nEnd sceencast session...')
        self.controller.quit()
        self.loop.quit()


def print_encoder_list():

    f = ['mp4', 'mkv', 'ts', 'flv']
    m = {k: v for k, v in zip(muxer_dict.keys(), f)}
    v = venc_dict
    a = aenc_dict
    del v['buff']

    print('''
    ------------------------------------------------------------------------
    Video formats:''')
    print(f'\t({str(m)[1:-1]})')
    print('''
    ------------------------------------------------------------------------
    Video encoders:''')
    print(f'\t{tuple(v.keys())}')
    print('''
    ------------------------------------------------------------------------
    Audio encoders:''')
    print(f'\t{tuple(a.keys())}')
    print('''
    ------------------------------------------------------------------------
    ''')


def print_audio_devices():

    #pa = pulsectl.Pulse('SwSourceCapture')
    #pa_info = pa.server_info()
    #print(pa_info.default_sink_name)
    #print(pa_info.default_source_name)

    app = SwScreenCast()
    app.get_audio_devices()


def main(args):

    app = SwScreenCast(**args)
    try:
        app.run()
    except KeyboardInterrupt:
        app.terminate()


def helper():
    """___Commandline help info___"""

    print('''
    ------------------------------------------------------------------------
    StartWine ScreenCast:
    A tool for capture, broadcast and recording screen

    ------------------------------------------------------------------------
    Usage ScreenCast: [sw_cast] [general option] [option]

    ------------------------------------------------------------------------
    General options:
    -h or --help            Show help and exit
    -r or --record          Capture and record selected screen or window
    -p or --preview         Сapture selected source for preview
    -c or --chromecast      Connect to Chromecast device over local network
    -s or --stream          Start stream over the network
    -l or --list            List of available encoders and formats
    -a or --audio-devices   List of available audio devices

    ------------------------------------------------------------------------
    Record options:
    --v_fmt="format"        set video format, see --list option (default mkv)
    --v_enc="encoder"       set video encoder (default h264)
    --a_enc="encoder"       set audio encoder (default mp4)
    --a_dev="device"        set audio device for capture (default output)
    --volume="volume"       set volume of audio device (range 0.0 to 1.0)
    --output="output"       path to the output file (default $HOME)

    ------------------------------------------------------------------------
    Stream options:

    ------------------------------------------------------------------------
    Chromecast options:

    ------------------------------------------------------------------------
    ''')


if __name__ == '__main__':

    args = {}

    if len(argv) == 1:
        args['record'] = True

    elif len(argv) == 2:

        if argv[1] == '-h' or argv[1] == '--help':
            helper()

        elif argv[1] == '-r' or argv[1] == '--record':
            args['record'] = True

        elif argv[1] == '-p' or argv[1] == '--preview':
            args['preview'] = True

        elif argv[1] == '-c' or argv[1] == '--chromecast':
            args['chromecast'] = True

        elif argv[1] == '-s' or argv[1] == '--stream':
            args['stream'] = True

        elif argv[1] == '-l' or argv[1] == '--list-encoders':
            print_encoder_list()

        elif argv[1] == '-a' or argv[1] == '--audio-devices':
            print_audio_devices()

        else:
            helper()

    elif len(argv) > 2:

        if argv[1] == '-r':
            args['record'] = True

            for arg in argv:
                if '--v_fmt=' in arg:
                    args['v_fmt'] = str(arg.split('=')[1])

                if '--v_enc=' in arg:
                    args['v_enc'] = str(arg.split('=')[1])

                if '--a_enc=' in arg:
                    args['a_enc'] = str(arg.split('=')[1])

                if '--audio_device=' in arg:
                    args['a_dev'] = str(arg.split('=')[1])

                if '--volume=' in arg:
                    args['volume'] = str(arg.split('=')[1])

                if '--output=' in arg:
                    args['output'] = str(arg.split('=')[1])

            if not args:
                helper()

        elif argv[1] == '-s':
            print('Oops! Stream options in development, nothing to do...')

        elif argv[1] == '-c':
            print('Oops! Chromecast options in development, nothing to do...')

        else:
            helper()
    else:
        helper()

    if args:
        main(args)

