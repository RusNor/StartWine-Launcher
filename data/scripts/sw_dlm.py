# coding: utf-8
"""
This is modified part of Legendary.
https://github.com/derrod/legendary

Legendary is free software: you can redistribute it and/or modify it 
under the terms of the GNU General Public License as published by the Free 
Software Foundation, either version 3 of the License, or (at your option) any 
later version.

Legendary is distributed in the hope that it will be useful, but 
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with 
Legendary. If not, see http://www.gnu.org/licenses/.
"""

from __future__ import annotations
import logging
import os
import time
from collections import Counter, defaultdict, deque
from logging.handlers import QueueHandler
from multiprocessing import cpu_count, Process, Queue as MPQueue
from multiprocessing.shared_memory import SharedMemory
from queue import Empty
from sys import exit
from threading import Condition, Thread
import requests
from requests.adapters import HTTPAdapter, DEFAULT_POOLBLOCK
from enum import Flag, auto
from dataclasses import dataclass
from typing import Optional
import json
from copy import deepcopy
import hashlib
from hashlib import sha1
import struct
import zlib
from uuid import uuid4
from base64 import b64encode
from io import BytesIO

logger = logging.getLogger('Manifest')
hash_poly = 0xC96C5795D7870F42
hash_table = []


def read_fstring(bio):
    length = struct.unpack('<i', bio.read(4))[0]
    if length < 0:
        length *= -2
        s = bio.read(length - 2).decode('utf-16')
        bio.seek(2, 1)
    elif length > 0:
        s = bio.read(length - 1).decode('ascii')
        bio.seek(1, 1)
    else:
        s = ''
    return s


def write_fstring(bio, string):
    if not string:
        bio.write(struct.pack('<i', 0))
        return

    try:
        s = string.encode('ascii')
        bio.write(struct.pack('<i', len(string) + 1))
        bio.write(s)
        bio.write(b'\x00')
    except UnicodeEncodeError:
        s = string.encode('utf-16le')
        bio.write(struct.pack('<i', -(len(string) + 1)))
        bio.write(s)
        bio.write(b'\x00\x00')


def get_chunk_dir(version):
    if version >= 15:
        return 'ChunksV4'
    elif version >= 6:
        return 'ChunksV3'
    elif version >= 3:
        return 'ChunksV2'
    else:
        return 'Chunks'


def _init():
    for i in range(256):
        for _ in range(8):
            if i & 1:
                i >>= 1
                i ^= hash_poly
            else:
                i >>= 1
        hash_table.append(i)


def get_hash(data):
    if not hash_table:
        _init()

    h = 0
    for i in range(len(data)):
        h = ((h << 1 | h >> 63) ^ hash_table[data[i]]) & 0xffffffffffffffff
    return h


def blob_to_num(in_str):
    """
    The JSON manifest use a rather strange format for storing numbers.
    It's essentially %03d for each char concatenated to a string.
    ...instead of just putting the fucking number in the JSON...
    Also it's still little endian so we have to bitshift it.
    """
    num = 0
    shift = 0
    for i in range(0, len(in_str), 3):
        num += (int(in_str[i:i + 3]) << shift)
        shift += 8
    return num


def guid_from_json(in_str):
    return struct.unpack('>IIII', bytes.fromhex(in_str))


class Chunk:
    header_magic = 0xB1FE3AA2

    def __init__(self):
        self.header_version = 3
        self.header_size = 0
        self.compressed_size = 0
        self.hash = 0
        self.stored_as = 0
        self.guid = struct.unpack('>IIII', uuid4().bytes)
        self.hash_type = 0
        self.sha_hash = b''
        self.uncompressed_size = 1024 * 1024
        self._guid_str = ''
        self._guid_num = 0
        self._bio = BytesIO()
        self._data = b''

    @property
    def data(self):
        if self._data:
            return self._data

        if self.compressed:
            self._data = zlib.decompress(self._bio.read())
        else:
            self._data = self._bio.read()

        self._bio.close()
        self._bio = BytesIO()

        return self._data

    @data.setter
    def data(self, value: bytes):
        if len(value) > 1024*1024:
            raise ValueError('Provided data is too large (> 1 MiB)!')
        if self.compressed:
            self.stored_as ^= 0x1
        if len(value) < 1024 * 1024:
            value += b'\x00' * (1024 * 1024 - len(value))
        self.hash = get_hash(value)
        self.sha_hash = sha1(value).digest()
        self.hash_type = 0x3
        self._data = value

    @property
    def guid_str(self):
        if not self._guid_str:
            self._guid_str = '-'.join('{:08x}'.format(g) for g in self.guid)
        return self._guid_str

    @property
    def guid_num(self):
        if not self._guid_num:
            self._guid_num = self.guid[3] + (self.guid[2] << 32) + (self.guid[1] << 64) + (self.guid[0] << 96)
        return self._guid_num

    @property
    def compressed(self):
        return self.stored_as & 0x1

    @classmethod
    def read_buffer(cls, data):
        _sio = BytesIO(data)
        return cls.read(_sio)

    @classmethod
    def read(cls, bio):
        head_start = bio.tell()

        if struct.unpack('<I', bio.read(4))[0] != cls.header_magic:
            raise ValueError('Chunk magic doesn\'t match!')

        _chunk = cls()
        _chunk._bio = bio
        _chunk.header_version = struct.unpack('<I', bio.read(4))[0]
        _chunk.header_size = struct.unpack('<I', bio.read(4))[0]
        _chunk.compressed_size = struct.unpack('<I', bio.read(4))[0]
        _chunk.guid = struct.unpack('<IIII', bio.read(16))
        _chunk.hash = struct.unpack('<Q', bio.read(8))[0]
        _chunk.stored_as = struct.unpack('B', bio.read(1))[0]

        if _chunk.header_version >= 2:
            _chunk.sha_hash = bio.read(20)
            _chunk.hash_type = struct.unpack('B', bio.read(1))[0]

        if _chunk.header_version >= 3:
            _chunk.uncompressed_size = struct.unpack('<I', bio.read(4))[0]

        if bio.tell() - head_start != _chunk.header_size:
            raise ValueError('Did not read entire chunk header!')

        return _chunk

    def write(self, fp=None, compress=True):
        bio = fp or BytesIO()

        self.uncompressed_size = self.compressed_size = len(self.data)
        if compress or self.compressed:
            self._data = zlib.compress(self.data)
            self.stored_as |= 0x1
            self.compressed_size = len(self._data)

        bio.write(struct.pack('<I', self.header_magic))
        bio.write(struct.pack('<I', 3))
        bio.write(struct.pack('<I', 66))
        bio.write(struct.pack('<I', self.compressed_size))
        bio.write(struct.pack('<IIII', *self.guid))
        bio.write(struct.pack('<Q', self.hash))
        bio.write(struct.pack('<B', self.stored_as))
        bio.write(self.sha_hash)
        bio.write(struct.pack('B', self.hash_type))
        bio.write(struct.pack('<I', self.uncompressed_size))
        bio.write(self._data)

        return bio.tell() if fp else bio.getvalue()


class Manifest:
    header_magic = 0x44BEC00C
    default_serialisation_version = 17

    def __init__(self):
        self.header_size = 41
        self.size_compressed = 0
        self.size_uncompressed = 0
        self.sha_hash = b''
        self.stored_as = 0
        self.version = 18
        self.data = b''
        self.meta: Optional[ManifestMeta] = None
        self.chunk_data_list: Optional[CDL] = None
        self.file_manifest_list: Optional[FML] = None
        self.custom_fields: Optional[CustomFields] = None

    @property
    def compressed(self):
        return self.stored_as & 0x1

    @classmethod
    def read_all(cls, data):
        _m = cls.read(data)
        _tmp = BytesIO(_m.data)

        _m.meta = ManifestMeta.read(_tmp)
        _m.chunk_data_list = CDL.read(_tmp, _m.meta.feature_level)
        _m.file_manifest_list = FML.read(_tmp)
        _m.custom_fields = CustomFields.read(_tmp)

        if unhandled_data := _tmp.read():
            logger.warning(f'Did not read {len(unhandled_data)} remaining bytes in manifest! '
                           f'This may not be a problem.')

        _tmp.close()
        del _tmp
        _m.data = b''

        return _m

    @classmethod
    def read(cls, data):
        bio = BytesIO(data)
        if struct.unpack('<I', bio.read(4))[0] != cls.header_magic:
            raise ValueError('No header magic!')

        _manifest = cls()
        _manifest.header_size = struct.unpack('<I', bio.read(4))[0]
        _manifest.size_uncompressed = struct.unpack('<I', bio.read(4))[0]
        _manifest.size_compressed = struct.unpack('<I', bio.read(4))[0]
        _manifest.sha_hash = bio.read(20)
        _manifest.stored_as = struct.unpack('B', bio.read(1))[0]
        _manifest.version = struct.unpack('<I', bio.read(4))[0]

        if bio.tell() != _manifest.header_size:
            logger.warning(f'Did not read entire header {bio.tell()} != {_manifest.header_size}! '
                           f'Header version: {_manifest.version}, please report this on '
                           f'GitHub along with a sample of the problematic manifest!')
            bio.seek(_manifest.header_size)

        data = bio.read()
        if _manifest.compressed:
            _manifest.data = zlib.decompress(data)
            dec_hash = hashlib.sha1(_manifest.data).hexdigest()
            if dec_hash != _manifest.sha_hash.hex():
                raise ValueError('Hash does not match!')
        else:
            _manifest.data = data

        return _manifest

    def write(self, fp=None, compress=True):
        body_bio = BytesIO()
        bio = fp or BytesIO()

        if (self.meta and self.file_manifest_list
                and self.chunk_data_list and self.custom_fields
            ):
            target_version = max(self.default_serialisation_version, self.meta.feature_level)

            if self.meta.data_version == 2:
                target_version = max(21, target_version)
            elif self.file_manifest_list.version == 2:
                target_version = max(20, target_version)
            elif self.file_manifest_list.version == 1:
                target_version = max(19, target_version)
            elif self.meta.data_version == 1:
                target_version = max(18, target_version)

            if target_version > 21:
                logger.warning(f'Trying to serialise an unknown target version: {target_version},'
                            f'clamping to 21.')
                target_version = 21

            self.meta.feature_level = target_version
            self.meta.write(body_bio)
            self.chunk_data_list.write(body_bio)
            self.file_manifest_list.write(body_bio)
            self.custom_fields.write(body_bio)
            self.data = body_bio.getvalue()
            self.size_uncompressed = self.size_compressed = len(self.data)
            self.sha_hash = hashlib.sha1(self.data).digest()

            if self.compressed or compress:
                self.stored_as |= 0x1
                self.data = zlib.compress(self.data)
                self.size_compressed = len(self.data)

            bio.write(struct.pack('<I', self.header_magic))
            bio.write(struct.pack('<I', self.header_size))
            bio.write(struct.pack('<I', self.size_uncompressed))
            bio.write(struct.pack('<I', self.size_compressed))
            bio.write(self.sha_hash)
            bio.write(struct.pack('B', self.stored_as))
            bio.write(struct.pack('<I', target_version))
            bio.write(self.data)

        return bio.tell() if fp else bio.getvalue()

    def apply_delta_manifest(self, delta_manifest: Manifest):
        added = set()

        if (self.file_manifest_list
                and self.chunk_data_list and self.custom_fields
            ):
            man_fml = delta_manifest.file_manifest_list
            if man_fml:
                for idx, file_elem in enumerate(self.file_manifest_list.elements):
                    try:
                        delta_file = man_fml.get_file_by_path(file_elem.filename)
                        self.file_manifest_list.elements[idx] = delta_file
                        added.add(delta_file.filename)
                    except ValueError:
                        pass

                for delta_file in man_fml.elements:
                    if delta_file.filename not in added:
                        self.file_manifest_list.elements.append(delta_file)

                self.file_manifest_list.count = len(self.file_manifest_list.elements)
                self.file_manifest_list._path_map = dict()

                try:
                    self.chunk_data_list.get_chunk_by_guid(0)
                except ValueError:
                    pass

                guids = self.chunk_data_list._guid_int_map
                if guids:
                    existing_chunk_guids = guids.keys()

                    cdl = delta_manifest.chunk_data_list
                    if cdl:
                        for chunk in cdl.elements:
                            if chunk.guid_num not in existing_chunk_guids:
                                self.chunk_data_list.elements.append(chunk)

                self.chunk_data_list.count = len(self.chunk_data_list.elements)
                self.chunk_data_list._guid_map = None
                self.chunk_data_list._guid_int_map = None
                self.chunk_data_list._path_map = None


class ManifestMeta:
    def __init__(self):
        self.meta_size = 0
        self.data_version = 0
        self.feature_level = 18
        self.is_file_data = False
        self.app_id = 0
        self.app_name = ''
        self.build_version = ''
        self.launch_exe = ''
        self.launch_command = ''
        self.prereq_ids = []
        self.prereq_name = ''
        self.prereq_path = ''
        self.prereq_args = ''
        self.uninstall_action_path = ''
        self.uninstall_action_args = ''
        self._build_id = ''

    @property
    def build_id(self):
        if self._build_id:
            return self._build_id

        s = hashlib.sha1()
        s.update(struct.pack('<I', self.app_id))
        s.update(self.app_name.encode('utf-8'))
        s.update(self.build_version.encode('utf-8'))
        s.update(self.launch_exe.encode('utf-8'))
        s.update(self.launch_command.encode('utf-8'))
        self._build_id = b64encode(
            s.digest()
        ).decode('ascii').replace('+', '-').replace('/', '_').replace('=', '')
        return self._build_id

    @classmethod
    def read(cls, bio):
        _meta = cls()

        _meta.meta_size = struct.unpack('<I', bio.read(4))[0]
        _meta.data_version = struct.unpack('B', bio.read(1))[0]
        _meta.feature_level = struct.unpack('<I', bio.read(4))[0]
        _meta.is_file_data = struct.unpack('B', bio.read(1))[0] == 1
        _meta.app_id = struct.unpack('<I', bio.read(4))[0]
        _meta.app_name = read_fstring(bio)
        _meta.build_version = read_fstring(bio)
        _meta.launch_exe = read_fstring(bio)
        _meta.launch_command = read_fstring(bio)

        entries = struct.unpack('<I', bio.read(4))[0]
        for _ in range(entries):
            _meta.prereq_ids.append(read_fstring(bio))

        _meta.prereq_name = read_fstring(bio)
        _meta.prereq_path = read_fstring(bio)
        _meta.prereq_args = read_fstring(bio)

        if _meta.data_version >= 1:
            _meta._build_id = read_fstring(bio)

        if _meta.data_version >= 2:
            _meta.uninstall_action_path = read_fstring(bio)
            _meta.uninstall_action_args = read_fstring(bio)

        if (size_read := bio.tell()) != _meta.meta_size:
            logger.warning(f'Did not read entire manifest metadata! Version: {_meta.data_version}, '
                           f'{_meta.meta_size - size_read} bytes missing, skipping...')
            bio.seek(_meta.meta_size - size_read, 1)
            _meta.data_version = 0

        return _meta

    def write(self, bio):
        meta_start = bio.tell()
        bio.write(struct.pack('<I', 0))
        bio.write(struct.pack('B', self.data_version))
        bio.write(struct.pack('<I', self.feature_level))
        bio.write(struct.pack('B', self.is_file_data))
        bio.write(struct.pack('<I', self.app_id))
        write_fstring(bio, self.app_name)
        write_fstring(bio, self.build_version)
        write_fstring(bio, self.launch_exe)
        write_fstring(bio, self.launch_command)

        bio.write(struct.pack('<I', len(self.prereq_ids)))
        for preqre_id in self.prereq_ids:
            write_fstring(bio, preqre_id)

        write_fstring(bio, self.prereq_name)
        write_fstring(bio, self.prereq_path)
        write_fstring(bio, self.prereq_args)

        if self.data_version >= 1:
            write_fstring(bio, self.build_id)
        if self.data_version >= 2:
            write_fstring(bio, self.uninstall_action_path)
            write_fstring(bio, self.uninstall_action_args)

        meta_end = bio.tell()
        bio.seek(meta_start)
        bio.write(struct.pack('<I', meta_end - meta_start))
        bio.seek(meta_end)


class CDL:
    def __init__(self):
        self.version = 0
        self.size = 0
        self.count = 0
        self.elements = []
        self._manifest_version = 18
        self._guid_map = None
        self._guid_int_map = None
        self._path_map = None

    def get_chunk_by_path(self, path):
        if not self._path_map:
            self._path_map = dict()
            for index, chunk in enumerate(self.elements):
                self._path_map[chunk.path] = index

        index = self._path_map.get(path, None)
        if index is None:
            raise ValueError(f'Invalid path! "{path}"')
        return self.elements[index]

    def get_chunk_by_guid(self, guid):
        """
        Get chunk by GUID string or number, creates index of chunks on first call
        Integer GUIDs are usually faster and require less memory, use those when possible.
        :param guid:
        :return:
        """
        if isinstance(guid, int):
            return self.get_chunk_by_guid_num(guid)
        else:
            return self.get_chunk_by_guid_str(guid)

    def get_chunk_by_guid_str(self, guid):
        if not self._guid_map:
            self._guid_map = dict()
            for index, chunk in enumerate(self.elements):
                self._guid_map[chunk.guid_str] = index

        index = self._guid_map.get(guid.lower(), None)
        if index is None:
            raise ValueError(f'Invalid GUID! {guid}')
        return self.elements[index]

    def get_chunk_by_guid_num(self, guid_int):
        if not self._guid_int_map:
            self._guid_int_map = dict()
            for index, chunk in enumerate(self.elements):
                self._guid_int_map[chunk.guid_num] = index

        index = self._guid_int_map.get(guid_int, None)
        if index is None:
            raise ValueError(f'Invalid GUID! {hex(guid_int)}')
        return self.elements[index]

    @classmethod
    def read(cls, bio, manifest_version=18):
        cdl_start = bio.tell()
        _cdl = cls()
        _cdl._manifest_version = manifest_version

        _cdl.size = struct.unpack('<I', bio.read(4))[0]
        _cdl.version = struct.unpack('B', bio.read(1))[0]
        _cdl.count = struct.unpack('<I', bio.read(4))[0]

        for _ in range(_cdl.count):
            _cdl.elements.append(ChunkInfo(manifest_version=manifest_version))

        for chunk in _cdl.elements:
            chunk.guid = struct.unpack('<IIII', bio.read(16))

        for chunk in _cdl.elements:
            chunk.hash = struct.unpack('<Q', bio.read(8))[0]

        for chunk in _cdl.elements:
            chunk.sha_hash = bio.read(20)

        for chunk in _cdl.elements:
            chunk.group_num = struct.unpack('B', bio.read(1))[0]

        for chunk in _cdl.elements:
            chunk.window_size = struct.unpack('<I', bio.read(4))[0]

        for chunk in _cdl.elements:
            chunk.file_size = struct.unpack('<q', bio.read(8))[0]

        if (size_read := bio.tell() - cdl_start) != _cdl.size:
            logger.warning(f'Did not read entire chunk data list! Version: {_cdl.version}, '
                           f'{_cdl.size - size_read} bytes missing, skipping...')
            bio.seek(_cdl.size - size_read, 1)
            _cdl.version = 0

        return _cdl

    def write(self, bio):
        cdl_start = bio.tell()
        bio.write(struct.pack('<I', 0))
        bio.write(struct.pack('B', self.version))
        bio.write(struct.pack('<I', len(self.elements)))

        for chunk in self.elements:
            bio.write(struct.pack('<IIII', *chunk.guid))
        for chunk in self.elements:
            bio.write(struct.pack('<Q', chunk.hash))
        for chunk in self.elements:
            bio.write(chunk.sha_hash)
        for chunk in self.elements:
            bio.write(struct.pack('B', chunk.group_num))
        for chunk in self.elements:
            bio.write(struct.pack('<I', chunk.window_size))
        for chunk in self.elements:
            bio.write(struct.pack('<q', chunk.file_size))

        cdl_end = bio.tell()
        bio.seek(cdl_start)
        bio.write(struct.pack('<I', cdl_end - cdl_start))
        bio.seek(cdl_end)


class ChunkInfo:
    def __init__(self, manifest_version=18):
        self.guid = tuple()
        self.hash = 0
        self.sha_hash = b''
        self.window_size = 0
        self.file_size = 0
        self._manifest_version = manifest_version
        self._group_num = None
        self._guid_str = None
        self._guid_num = None

    def __repr__(self):
        return '<ChunkInfo (guid={}, hash={}, sha_hash={}, group_num={}, window_size={}, file_size={})>'.format(
            self.guid_str, self.hash, self.sha_hash.hex(), self.group_num, self.window_size, self.file_size
        )

    @property
    def guid_str(self):
        if not self._guid_str:
            self._guid_str = '-'.join('{:08x}'.format(g) for g in self.guid)

        return self._guid_str

    @property
    def guid_num(self):
        if not self._guid_num:
            self._guid_num = self.guid[3] + (self.guid[2] << 32) + (self.guid[1] << 64) + (self.guid[0] << 96)
        return self._guid_num

    @property
    def group_num(self):
        if self._guid_num is not None:
            return self._group_num

        self._group_num = (zlib.crc32(
            struct.pack('<I', self.guid[0]) +
            struct.pack('<I', self.guid[1]) +
            struct.pack('<I', self.guid[2]) +
            struct.pack('<I', self.guid[3])
        ) & 0xffffffff) % 100
        return self._group_num

    @group_num.setter
    def group_num(self, value):
        self._group_num = value

    @property
    def path(self):
        return '{}/{:02d}/{:016X}_{}.chunk'.format(
            get_chunk_dir(self._manifest_version), self.group_num,
            self.hash, ''.join('{:08X}'.format(g) for g in self.guid))


class FML:
    def __init__(self):
        self.version = 0
        self.size = 0
        self.count = 0
        self.elements = []

        self._path_map = dict()

    def get_file_by_path(self, path):
        if not self._path_map:
            self._path_map = dict()
            for index, fm in enumerate(self.elements):
                self._path_map[fm.filename] = index

        index = self._path_map.get(path, None)
        if index is None:
            raise ValueError(f'Invalid path! {path}')
        return self.elements[index]

    @classmethod
    def read(cls, bio):
        fml_start = bio.tell()
        _fml = cls()
        _fml.size = struct.unpack('<I', bio.read(4))[0]
        _fml.version = struct.unpack('B', bio.read(1))[0]
        _fml.count = struct.unpack('<I', bio.read(4))[0]

        for _ in range(_fml.count):
            _fml.elements.append(FileManifest())

        for fm in _fml.elements:
            fm.filename = read_fstring(bio)

        for fm in _fml.elements:
            fm.symlink_target = read_fstring(bio)

        for fm in _fml.elements:
            fm.hash = bio.read(20)

        for fm in _fml.elements:
            fm.flags = struct.unpack('B', bio.read(1))[0]

        for fm in _fml.elements:
            _elem = struct.unpack('<I', bio.read(4))[0]
            for _ in range(_elem):
                fm.install_tags.append(read_fstring(bio))

        for fm in _fml.elements:
            _elem = struct.unpack('<I', bio.read(4))[0]
            _offset = 0
            for _ in range(_elem):
                chunkp = ChunkPart()
                _start = bio.tell()
                _size = struct.unpack('<I', bio.read(4))[0]
                chunkp.guid = struct.unpack('<IIII', bio.read(16))
                chunkp.offset = struct.unpack('<I', bio.read(4))[0]
                chunkp.size = struct.unpack('<I', bio.read(4))[0]
                chunkp.file_offset = _offset
                fm.chunk_parts.append(chunkp)
                _offset += chunkp.size
                if (diff := (bio.tell() - _start - _size)) > 0:
                    logger.warning(f'Did not read {diff} bytes from chunk part!')
                    bio.seek(diff)

        if _fml.version >= 1:
            for fm in _fml.elements:
                _has_md5 = struct.unpack('<I', bio.read(4))[0]
                if _has_md5 != 0:
                    fm.hash_md5 = bio.read(16)

            for fm in _fml.elements:
                fm.mime_type = read_fstring(bio)

        if _fml.version >= 2:
            for fm in _fml.elements:
                fm.hash_sha256 = bio.read(32)

        for fm in _fml.elements:
            fm.file_size = sum(c.size for c in fm.chunk_parts)

        if (size_read := bio.tell() - fml_start) != _fml.size:
            logger.warning(f'Did not read entire file data list! Version: {_fml.version}, '
                           f'{_fml.size - size_read} bytes missing, skipping...')
            bio.seek(_fml.size - size_read, 1)
            _fml.version = 0

        return _fml

    def write(self, bio):
        fml_start = bio.tell()
        bio.write(struct.pack('<I', 0))
        bio.write(struct.pack('B', self.version))
        bio.write(struct.pack('<I', len(self.elements)))

        for fm in self.elements:
            write_fstring(bio, fm.filename)
        for fm in self.elements:
            write_fstring(bio, fm.symlink_target)
        for fm in self.elements:
            bio.write(fm.hash)
        for fm in self.elements:
            bio.write(struct.pack('B', fm.flags))
        for fm in self.elements:
            bio.write(struct.pack('<I', len(fm.install_tags)))
            for tag in fm.install_tags:
                write_fstring(bio, tag)

        for fm in self.elements:
            bio.write(struct.pack('<I', len(fm.chunk_parts)))
            for cp in fm.chunk_parts:
                bio.write(struct.pack('<I', 28))
                bio.write(struct.pack('<IIII', *cp.guid))
                bio.write(struct.pack('<I', cp.offset))
                bio.write(struct.pack('<I', cp.size))

        if self.version >= 1:
            for fm in self.elements:
                has_md5 = 1 if fm.hash_md5 else 0
                bio.write(struct.pack('<I', has_md5))
                if has_md5:
                    bio.write(fm.hash_md5)

            for fm in self.elements:
                write_fstring(bio, fm.mime_type)

        if self.version >= 2:
            for fm in self.elements:
                bio.write(fm.hash_sha256)

        fml_end = bio.tell()
        bio.seek(fml_start)
        bio.write(struct.pack('<I', fml_end - fml_start))
        bio.seek(fml_end)


class FileManifest:
    def __init__(self):
        self.filename = ''
        self.symlink_target = ''
        self.hash = b''
        self.flags = 0
        self.install_tags = []
        self.chunk_parts = []
        self.file_size = 0
        self.hash_md5 = b''
        self.mime_type = ''
        self.hash_sha256 = b''

    @property
    def read_only(self):
        return self.flags & 0x1

    @property
    def compressed(self):
        return self.flags & 0x2

    @property
    def executable(self):
        return self.flags & 0x4

    @property
    def sha_hash(self):
        return self.hash

    def __repr__(self):
        if len(self.chunk_parts) <= 20:
            cp_repr = ', '.join(repr(c) for c in self.chunk_parts)
        else:
            _cp = [repr(cp) for cp in self.chunk_parts[:20]]
            _cp.append('[...]')
            cp_repr = ', '.join(_cp)

        return '<FileManifest (filename="{}", symlink_target="{}", hash={}, flags={}, ' \
               'install_tags=[{}], chunk_parts=[{}], file_size={})>'.format(
                    self.filename, self.symlink_target, self.hash.hex(), self.flags,
                    ', '.join(self.install_tags), cp_repr, self.file_size
               )


class ChunkPart:
    def __init__(self, guid=tuple(), offset=0, size=0, file_offset=0):
        self.guid = guid
        self.offset = offset
        self.size = size
        self.file_offset = file_offset
        self._guid_str = None
        self._guid_num = None

    @property
    def guid_str(self):
        if not self._guid_str:
            self._guid_str = '-'.join('{:08x}'.format(g) for g in self.guid)
        return self._guid_str

    @property
    def guid_num(self):
        if not self._guid_num:
            self._guid_num = self.guid[3] + (self.guid[2] << 32) + (self.guid[1] << 64) + (self.guid[0] << 96)
        return self._guid_num

    def __repr__(self):
        guid_readable = '-'.join('{:08x}'.format(g) for g in self.guid)
        return '<ChunkPart (guid={}, offset={}, size={}, file_offset={})>'.format(
            guid_readable, self.offset, self.size, self.file_offset)


class CustomFields:
    def __init__(self):
        self.size = 0
        self.version = 0
        self.count = 0

        self._dict = dict()

    def __getitem__(self, item):
        return self._dict.get(item, None)

    def __setitem__(self, key, value):
        self._dict[key] = value

    def __str__(self):
        return str(self._dict)

    def items(self):
        return self._dict.items()

    def keys(self):
        return self._dict.keys()

    def values(self):
        return self._dict.values()

    @classmethod
    def read(cls, bio):
        _cf = cls()

        cf_start = bio.tell()
        _cf.size = struct.unpack('<I', bio.read(4))[0]
        _cf.version = struct.unpack('B', bio.read(1))[0]
        _cf.count = struct.unpack('<I', bio.read(4))[0]

        _keys = [read_fstring(bio) for _ in range(_cf.count)]
        _values = [read_fstring(bio) for _ in range(_cf.count)]
        _cf._dict = dict(zip(_keys, _values))

        if (size_read := bio.tell() - cf_start) != _cf.size:
            logger.warning(f'Did not read entire custom fields part! Version: {_cf.version}, '
                           f'{_cf.size - size_read} bytes missing, skipping...')
            bio.seek(_cf.size - size_read, 1)
            _cf.version = 0

        return _cf

    def write(self, bio):
        cf_start = bio.tell()
        bio.write(struct.pack('<I', 0))
        bio.write(struct.pack('B', self.version))
        bio.write(struct.pack('<I', len(self._dict)))

        for key in self.keys():
            write_fstring(bio, key)

        for value in self.values():
            write_fstring(bio, value)

        cf_end = bio.tell()
        bio.seek(cf_start)
        bio.write(struct.pack('<I', cf_end - cf_start))
        bio.seek(cf_end)


class ManifestComparison:
    def __init__(self):
        self.added = set()
        self.removed = set()
        self.changed = set()
        self.unchanged = set()

    @classmethod
    def create(cls, manifest, old_manifest=None):
        comp = cls()

        if not old_manifest:
            comp.added = set(fm.filename for fm in manifest.file_manifest_list.elements)
            return comp

        old_files = {fm.filename: fm.hash for fm in old_manifest.file_manifest_list.elements}

        for fm in manifest.file_manifest_list.elements:
            if old_file_hash := old_files.pop(fm.filename, None):
                if fm.hash == old_file_hash:
                    comp.unchanged.add(fm.filename)
                else:
                    comp.changed.add(fm.filename)
            else:
                comp.added.add(fm.filename)

        if old_files:
            comp.removed = set(old_files.keys())

        return comp


class JSONManifest(Manifest):
    """
    Manifest-compatible reader for JSON based manifests
    """
    def __init__(self):
        super().__init__()
        self.json_data = None

    @classmethod
    def read_all(cls, data):
        _m = cls.read(data)
        _tmp = deepcopy(_m.json_data)
        _m.meta = JSONManifestMeta.read(_tmp)
        _m.chunk_data_list = JSONCDL.read(_tmp, manifest_version=_m.version)
        _m.file_manifest_list = JSONFML.read(_tmp)
        _m.custom_fields = CustomFields()
        if _tmp:
            _m.custom_fields._dict = _tmp.pop('CustomFields', dict())
            if _tmp.keys():
                print(f'Did not read JSON keys: {_tmp.keys()}!')

        _m.data = b''
        _m.json_data = None

        return _m

    @classmethod
    def read(cls, data):
        _manifest = cls()
        _manifest.data = data
        _manifest.json_data = json.loads(data.decode('utf-8'))
        _manifest.stored_as = 0  # never compressed
        _manifest.version = blob_to_num(_manifest.json_data.get('ManifestFileVersion', '013000000000'))

        return _manifest

    def write(self, *args, **kwargs):
        """
        The version here only matters for the manifest header,
        the feature level in meta determines chunk folders etc.
        So all that's required for successful serialization is
        setting it to something high enough to be a binary manifest
        """
        self.version = 18
        return super().write(*args, **kwargs)


class JSONManifestMeta(ManifestMeta):
    def __init__(self):
        super().__init__()

    @classmethod
    def read(cls, bio):
        _meta = cls()
        _meta.feature_level = blob_to_num(bio.pop('ManifestFileVersion', '013000000000'))
        _meta.is_file_data = bio.pop('bIsFileData', False)
        _meta.app_id = blob_to_num(bio.pop('AppID', '000000000000'))
        _meta.app_name = bio.pop('AppNameString', '')
        _meta.build_version = bio.pop('BuildVersionString', '')
        _meta.launch_exe = bio.pop('LaunchExeString', '')
        _meta.launch_command = bio.pop('LaunchCommand', '')
        _meta.prereq_ids = bio.pop('PrereqIds', list())
        _meta.prereq_name = bio.pop('PrereqName', '')
        _meta.prereq_path = bio.pop('PrereqPath', '')
        _meta.prereq_args = bio.pop('PrereqArgs', '')

        return _meta


class JSONCDL(CDL):
    def __init__(self):
        super().__init__()

    @classmethod
    def read(cls, bio, manifest_version=13):
        _cdl = cls()
        _cdl._manifest_version = manifest_version
        _cdl.count = len(bio['ChunkFilesizeList'])
        cfl = bio.pop('ChunkFilesizeList')
        chl = bio.pop('ChunkHashList')
        csl = bio.pop('ChunkShaList')
        dgl = bio.pop('DataGroupList')
        _guids = list(cfl.keys())

        for guid in _guids:
            _ci = ChunkInfo(manifest_version=manifest_version)
            _ci.guid = guid_from_json(guid)
            _ci.file_size = blob_to_num(cfl.pop(guid))
            _ci.hash = blob_to_num(chl.pop(guid))
            _ci.sha_hash = bytes.fromhex(csl.pop(guid))
            _ci.group_num = blob_to_num(dgl.pop(guid))
            _ci.window_size = 1024*1024
            _cdl.elements.append(_ci)

        for _dc in (cfl, chl, csl, dgl):
            if _dc:
                print(f'Non-consumed CDL stuff: {_dc}')

        return _cdl


class JSONFML(FML):
    def __init__(self):
        super().__init__()

    @classmethod
    def read(cls, bio):
        _fml = cls()
        _fml.count = len(bio['FileManifestList'])

        for _fmj in bio.pop('FileManifestList'):
            _fm = FileManifest()
            _fm.filename = _fmj.pop('Filename', '')
            _fm.hash = blob_to_num(_fmj.pop('FileHash')).to_bytes(160//8, 'little')
            _fm.flags |= int(_fmj.pop('bIsReadOnly', False))
            _fm.flags |= int(_fmj.pop('bIsCompressed', False)) << 1
            _fm.flags |= int(_fmj.pop('bIsUnixExecutable', False)) << 2
            _fm.file_size = 0
            _fm.chunk_parts = []
            _fm.install_tags = _fmj.pop('InstallTags', list())

            _offset = 0
            for _cpj in _fmj.pop('FileChunkParts'):
                _cp = ChunkPart()
                _cp.guid = guid_from_json(_cpj.pop('Guid'))
                _cp.offset = blob_to_num(_cpj.pop('Offset'))
                _cp.size = blob_to_num(_cpj.pop('Size'))
                _cp.file_offset = _offset
                _fm.file_size += _cp.size
                if _cpj:
                    print(f'Non-read ChunkPart keys: {_cpj.keys()}')
                _fm.chunk_parts.append(_cp)
                _offset += _cp.size

            if _fmj:
                print(f'Non-read FileManifest keys: {_fmj.keys()}')

            _fml.elements.append(_fm)

        return _fml

################################################################################

@dataclass
class SharedMemorySegment:
    """
    Segment of the shared memory used for one Chunk
    """
    offset: int
    end: int

    @property
    def size(self):
        return self.end - self.offset


@dataclass
class DownloaderTask:
    """
    Task submitted to the download worker
    """
    url: str
    chunk_guid: int
    shm: SharedMemorySegment


@dataclass
class DownloaderTaskResult(DownloaderTask):
    """
    Result of DownloaderTask provided by download workers
    """
    success: bool
    size_downloaded: Optional[int] = None
    size_decompressed: Optional[int] = None


@dataclass
class ChunkTask:
    """
    A task describing a single read of a (partial) chunk from memory or an existing file
    """
    chunk_guid: int
    chunk_offset: int = 0
    chunk_size: int = 0
    # Whether this chunk can be removed from memory/disk after having been written
    cleanup: bool = False
    # Path to the file the chunk is read from (if not from memory)
    chunk_file: Optional[str] = None


class TaskFlags(Flag):
    NONE = 0
    OPEN_FILE = auto()
    CLOSE_FILE = auto()
    DELETE_FILE = auto()
    CREATE_EMPTY_FILE = auto()
    RENAME_FILE = auto()
    RELEASE_MEMORY = auto()
    MAKE_EXECUTABLE = auto()
    SILENT = auto()


@dataclass
class FileTask:
    """
    A task describing some operation on the filesystem
    """
    filename: str
    flags: TaskFlags
    old_file: Optional[str] = None


@dataclass
class WriterTask:
    """
    Task for FileWriter worker process, describing an operation on the filesystem
    """
    filename: str
    flags: TaskFlags
    chunk_offset: int = 0
    chunk_size: int = 0
    chunk_guid: Optional[int] = None
    shared_memory: Optional[SharedMemorySegment] = None
    old_file: Optional[str] = None
    cache_file: Optional[str] = None


@dataclass
class WriterTaskResult(WriterTask):
    """
    Result from the FileWriter worker
    """
    success: bool = False
    size: int = 0


@dataclass
class UIUpdate:
    """
    Status update object sent from the manager to the CLI/GUI to update status indicators
    """
    progress: float
    download_speed: float
    write_speed: float
    read_speed: float
    memory_usage: float
    current_filename: Optional[str] = None


@dataclass
class AnalysisResult:
    """
    Result of processing a manifest for downloading
    """
    dl_size: int = 0
    uncompressed_dl_size: int = 0
    install_size: int = 0
    disk_space_delta: int = 0
    reuse_size: int = 0
    biggest_file_size: int = 0
    unchanged_size: int = 0
    biggest_chunk: int = 0
    min_memory: int = 0
    num_chunks: int = 0
    num_chunks_cache: int = 0
    num_files: int = 0
    removed: int = 0
    added: int = 0
    changed: int = 0
    unchanged: int = 0
    manifest_comparison: Optional[ManifestComparison] = None


@dataclass
class ConditionCheckResult:
    """
    Result of install condition checks
    """
    failures: Optional[set] = None
    warnings: Optional[set] = None


class TerminateWorkerTask:
    """
    Universal task to signal a worker to exit
    """
    pass


class BindingHTTPAdapter(HTTPAdapter):
    def __init__(self, addr):
        self.__attrs__.append('addr')
        self.addr = addr
        super().__init__()

    def init_poolmanager(
            self, connections, maxsize, block=DEFAULT_POOLBLOCK, **pool_kwargs
    ):
        pool_kwargs['source_address'] = (self.addr, 0)
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)


class DLWorker(Process):
    def __init__(self, name, queue, out_queue, shm, max_retries=7,
                 logging_queue=None, dl_timeout=10, bind_addr=None):
        super().__init__(name=name)
        self.q = queue
        self.o_q = out_queue
        self.session = requests.session()
        self.session.headers.update({
            'User-Agent': 'EpicGamesLauncher/11.0.1-14907503+++Portal+Release-Live Windows/10.0.19041.1.256.64bit'
        })
        self.max_retries = max_retries
        self.shm = SharedMemory(name=shm)
        self.log_level = logging.getLogger().level
        self.logging_queue = logging_queue
        self.dl_timeout = float(dl_timeout) if dl_timeout else 10.0
        if bind_addr:
            adapter = BindingHTTPAdapter(bind_addr)
            self.session.mount('https://', adapter)
            self.session.mount('http://', adapter)

    def run(self):
        _root = logging.getLogger()
        _root.handlers = []
        if self.logging_queue:
            _root.addHandler(QueueHandler(self.logging_queue))

        logger = logging.getLogger(self.name)
        logger.setLevel(self.log_level)
        logger.debug(f'Download worker reporting for duty!')

        empty = False
        while True:
            try:
                job: DownloaderTask = self.q.get(timeout=10.0)
                empty = False
            except Empty:
                if not empty:
                    logger.debug('Queue Empty, waiting for more...')
                empty = True
                continue

            if isinstance(job, TerminateWorkerTask):
                print('Worker received termination signal, shutting down...')
                break

            tries = 0
            compressed = 0
            chunk = None

            while tries < self.max_retries:
                if tries > 1:
                    sleep_time = 2**(tries-1)
                    logger.info(f'Sleeping {sleep_time} seconds before retrying.')
                    time.sleep(sleep_time)

                logger.debug(f'Downloading {job.url}')
                try:
                    r = self.session.get(job.url, timeout=self.dl_timeout)
                    r.raise_for_status()
                except Exception as e:
                    print(f'Chunk download for {job.chunk_guid} failed: ({e!r}), retrying...')
                    continue

                if r.status_code != 200:
                    print(f'Chunk download for {job.chunk_guid} failed: status {r.status_code}, retrying...')
                    continue
                else:
                    compressed = len(r.content)
                    chunk = Chunk.read_buffer(r.content)
                    break
            else:
                print('Max retries reached')
                logger.error(f'Job for {job.chunk_guid} failed! Fetching next one...')
                self.o_q.put(DownloaderTaskResult(success=False, **job.__dict__))

            if not chunk:
                print('Chunk somehow None?')
                self.o_q.put(DownloaderTaskResult(success=False, **job.__dict__))
                continue

            data = chunk.data
            size = len(data)
            if size > job.shm.size:
                logger.fatal('Downloaded chunk is longer than SharedMemorySegment!')

            self.shm.buf[job.shm.offset:job.shm.offset + size] = data
            del chunk
            self.o_q.put(
                DownloaderTaskResult(
                    success=True,
                    size_decompressed=size,
                    size_downloaded=compressed,
                    **job.__dict__
                )
            )
        self.shm.close()


class FileWorker(Process):
    def __init__(self, queue, out_queue, base_path, shm, cache_path=None, logging_queue=None):
        super().__init__(name='FileWorker')
        self.q = queue
        self.o_q = out_queue
        self.base_path = base_path
        self.cache_path = cache_path or os.path.join(base_path, '.cache')
        self.shm = SharedMemory(name=shm)
        self.log_level = logging.getLogger().level
        self.logging_queue = logging_queue

    def run(self):
        _root = logging.getLogger()
        _root.handlers = []
        if self.logging_queue:
            _root.addHandler(QueueHandler(self.logging_queue))

        logger = logging.getLogger(self.name)
        logger.setLevel(self.log_level)
        logger.debug('Download worker reporting for duty!')

        last_filename = ''
        current_file = None

        while True:
            try:
                j: WriterTask = self.q.get(timeout=10.0)
            except Empty:
                print('Writer queue empty!')
                continue

            if isinstance(j, TerminateWorkerTask):
                if current_file:
                    current_file.close()
                logger.debug('Worker received termination signal, shutting down...')
                self.o_q.put(TerminateWorkerTask())
                break

            path = os.path.split(j.filename)[0]
            if not os.path.exists(os.path.join(self.base_path, path)):
                os.makedirs(os.path.join(self.base_path, path))

            full_path = os.path.join(self.base_path, j.filename)

            if j.flags & TaskFlags.CREATE_EMPTY_FILE:
                open(full_path, 'a').close()
                self.o_q.put(WriterTaskResult(success=True, **j.__dict__))
                continue

            elif j.flags & TaskFlags.OPEN_FILE:
                if current_file:
                    print(f'Opening new file {j.filename} without closing previous! {last_filename}')
                    current_file.close()
                current_file = open(full_path, 'wb')
                last_filename = j.filename
                self.o_q.put(WriterTaskResult(success=True, **j.__dict__))
                continue

            elif j.flags & TaskFlags.CLOSE_FILE:
                if current_file:
                    current_file.close()
                    current_file = None
                else:
                    print(f'Asking to close file that is not open: {j.filename}')
                self.o_q.put(WriterTaskResult(success=True, **j.__dict__))
                continue

            elif j.flags & TaskFlags.RENAME_FILE:
                if current_file:
                    print('Trying to rename file without closing first!')
                    current_file.close()
                    current_file = None
                if j.flags & TaskFlags.DELETE_FILE:
                    try:
                        os.remove(full_path)
                    except OSError as e:
                        logger.error(f'Removing file failed: {e!r}')
                        self.o_q.put(WriterTaskResult(success=False, **j.__dict__))
                        continue
                try:
                    os.rename(os.path.join(self.base_path, str(j.old_file)), full_path)
                except OSError as e:
                    logger.error(f'Renaming file failed: {e!r}')
                    self.o_q.put(WriterTaskResult(success=False, **j.__dict__))
                    continue
                self.o_q.put(WriterTaskResult(success=True, **j.__dict__))
                continue

            elif j.flags & TaskFlags.DELETE_FILE:
                if current_file:
                    print('Trying to delete file without closing first!')
                    current_file.close()
                    current_file = None
                try:
                    os.remove(full_path)
                except OSError as e:
                    if not j.flags & TaskFlags.SILENT:
                        logger.error(f'Removing file failed: {e!r}')
                self.o_q.put(WriterTaskResult(success=True, **j.__dict__))
                continue

            elif j.flags & TaskFlags.MAKE_EXECUTABLE:
                if current_file:
                    print('Trying to chmod file without closing first!')
                    current_file.close()
                    current_file = None
                try:
                    st = os.stat(full_path)
                    os.chmod(full_path, st.st_mode | 0o111)
                except OSError as e:
                    if not j.flags & TaskFlags.SILENT:
                        logger.error(f'chmod\'ing file failed: {e!r}')
                self.o_q.put(WriterTaskResult(success=True, **j.__dict__))
                continue

            if current_file:
                try:
                    if j.shared_memory:
                        shm_offset = j.shared_memory.offset + j.chunk_offset
                        shm_end = shm_offset + j.chunk_size
                        current_file.write(self.shm.buf[shm_offset:shm_end])
                    elif j.cache_file:
                        with open(os.path.join(self.cache_path, j.cache_file), 'rb') as f:
                            if j.chunk_offset:
                                f.seek(j.chunk_offset)
                            current_file.write(f.read(j.chunk_size))
                    elif j.old_file:
                        with open(os.path.join(self.base_path, j.old_file), 'rb') as f:
                            if j.chunk_offset:
                                f.seek(j.chunk_offset)
                            current_file.write(f.read(j.chunk_size))
                except Exception as e:
                    print(f'Something in writing a file failed: {e!r}')
                    self.o_q.put(WriterTaskResult(success=False, size=j.chunk_size, **j.__dict__))
                else:
                    self.o_q.put(WriterTaskResult(success=True, size=j.chunk_size, **j.__dict__))


class DLManager(Process):
    def __init__(self, download_dir, base_url, cache_dir=None, status_q=None,
                 max_workers=0, update_interval=1.0, dl_timeout=10, resume_file=None,
                 max_shared_memory=1024 * 1024 * 1024, bind_ip=None):
        super().__init__(name='DLManager')
        self.log = logging.getLogger('DLM')
        self.proc_debug = False
        self.base_url = base_url
        self.dl_dir = download_dir
        self.cache_dir = cache_dir or os.path.join(download_dir, '.cache')
        self.logging_queue = None
        self.dl_worker_queue = None
        self.writer_queue = None
        self.dl_result_q = None
        self.writer_result_q = None
        self.max_workers = max_workers or min(cpu_count() * 2, 16)
        self.dl_timeout = dl_timeout
        self.bind_ips = [] if not bind_ip else bind_ip.split(',')
        self.analysis = None
        self.tasks = deque()
        self.chunks_to_dl = deque()
        self.chunk_data_list = None
        self.max_shared_memory = max_shared_memory
        self.sms = deque()
        self.shared_memory = None
        self.update_interval = update_interval
        self.status_queue = status_q
        self.resume_file = resume_file
        self.hash_map = dict()
        self.running = True
        self.active_tasks = 0
        self.children = []
        self.threads = []
        self.conditions = []
        self.bytes_downloaded_since_last = 0
        self.bytes_decompressed_since_last = 0
        self.bytes_written_since_last = 0
        self.bytes_read_since_last = 0
        self.num_processed_since_last = 0
        self.num_tasks_processed_since_last = 0

    def run_analysis(self, manifest: Manifest, old_manifest: Manifest | None = None,
                     patch=True, resume=True, file_prefix_filter=None,
                     file_exclude_filter=None, file_install_tag=None,
                     processing_optimization=False) -> AnalysisResult:
        """
        Run analysis on manifest and old manifest (if not None) and return a result
        with a summary resources required in order to install the provided manifest.
        :param manifest: Manifest to install
        :param old_manifest: Old manifest to patch from (if applicable)
        :param patch: Patch instead of redownloading the entire file
        :param resume: Continue based on resume file if it exists
        :param file_prefix_filter: Only download files that start with this prefix
        :param file_exclude_filter: Exclude files with this prefix from download
        :param file_install_tag: Only install files with the specified tag
        :param processing_optimization: Attempt to optimize processing order and RAM usage
        :return: AnalysisResult
        """
        analysis_res = AnalysisResult()
        man_fml = manifest.file_manifest_list
        man_cdl = manifest.chunk_data_list
        if man_fml and man_cdl:
            analysis_res.install_size = sum(fm.file_size for fm in man_fml.elements)
            analysis_res.biggest_chunk = max(c.window_size for c in man_cdl.elements)
            analysis_res.biggest_file_size = max(f.file_size for f in man_fml.elements)
            is_1mib = analysis_res.biggest_chunk == 1024 * 1024
            self.log.debug(
                f'Biggest chunk size: {analysis_res.biggest_chunk} bytes (== 1 MiB? {is_1mib})'
            )
            self.log.debug(f'Creating manifest comparison...')
            mc = ManifestComparison.create(manifest, old_manifest)
            analysis_res.manifest_comparison = mc

            if resume and self.resume_file and os.path.exists(self.resume_file):
                self.log.info(
                    'Found previously interrupted download. '
                    'Download will be resumed if possible.'
                )
                missing = 0
                mismatch = 0
                completed_files = set()

                for line in open(self.resume_file, encoding='utf-8').readlines():
                    file_hash, _, filename = line.strip().partition(':')
                    _p = os.path.join(self.dl_dir, filename)
                    if not os.path.exists(_p):
                        self.log.debug(
                            f'File does not exist but is in resume file: "{_p}"'
                        )
                        missing += 1
                    elif file_hash != man_fml.get_file_by_path(filename).sha_hash.hex():
                        mismatch += 1
                    else:
                        completed_files.add(filename)

                if missing:
                    self.log.warning(
                        f'{missing} previously completed file(s) are missing, '
                        'they will be redownloaded.'
                    )
                if mismatch:
                    self.log.warning(
                        f'{mismatch} existing file(s) have been changed and will be '
                        'redownloaded.'
                    )
                mc.added -= completed_files
                mc.changed -= completed_files
                mc.unchanged |= completed_files
                self.log.info(
                    f'Skipping {len(completed_files)} files based on resume data.'
                )

            elif resume:
                missing_files = set()

                for fm in man_fml.elements:
                    if fm.filename in mc.added:
                        continue

                    local_path = os.path.join(self.dl_dir, fm.filename)
                    if not os.path.exists(local_path):
                        missing_files.add(fm.filename)

                self.log.info(f'Found {len(missing_files)} missing files.')
                mc.added |= missing_files
                mc.changed -= missing_files
                mc.unchanged -= missing_files

            additional_deletion_tasks = []
            if file_install_tag is not None:
                if isinstance(file_install_tag, str):
                    file_install_tag = [file_install_tag]

                files_to_skip = set(i.filename for i in man_fml.elements
                                    if not any((fit in i.install_tags) or (not fit and not i.install_tags)
                                            for fit in file_install_tag))
                self.log.info(f'Found {len(files_to_skip)} files to skip based on install tag.')
                mc.added -= files_to_skip
                mc.changed -= files_to_skip
                mc.unchanged |= files_to_skip
                for fname in sorted(files_to_skip):
                    additional_deletion_tasks.append(FileTask(fname, flags=TaskFlags.DELETE_FILE | TaskFlags.SILENT))

            if file_exclude_filter:
                if isinstance(file_exclude_filter, str):
                    file_exclude_filter = [file_exclude_filter]

                file_exclude_filter = [f.lower() for f in file_exclude_filter]
                files_to_skip = set(i.filename for i in man_fml.elements if
                                    any(i.filename.lower().startswith(pfx) for pfx in file_exclude_filter))
                self.log.info(f'Found {len(files_to_skip)} files to skip based on exclude prefix.')
                mc.added -= files_to_skip
                mc.changed -= files_to_skip
                mc.unchanged |= files_to_skip

            if file_prefix_filter:
                if isinstance(file_prefix_filter, str):
                    file_prefix_filter = [file_prefix_filter]

                file_prefix_filter = [f.lower() for f in file_prefix_filter]
                files_to_skip = set(i.filename for i in man_fml.elements if not
                                    any(i.filename.lower().startswith(pfx) for pfx in file_prefix_filter))
                self.log.info(f'Found {len(files_to_skip)} files to skip based on include prefix(es)')
                mc.added -= files_to_skip
                mc.changed -= files_to_skip
                mc.unchanged |= files_to_skip

            if file_prefix_filter or file_exclude_filter or file_install_tag:
                self.log.info(f'Remaining files after filtering: {len(mc.added) + len(mc.changed)}')
                analysis_res.install_size = sum(fm.file_size for fm in man_fml.elements
                                                if fm.filename in mc.added)

            if mc.removed:
                analysis_res.removed = len(mc.removed)
                self.log.debug(f'{analysis_res.removed} removed files')
            if mc.added:
                analysis_res.added = len(mc.added)
                self.log.debug(f'{analysis_res.added} added files')
            if mc.changed:
                analysis_res.changed = len(mc.changed)
                self.log.debug(f'{analysis_res.changed} changed files')
            if mc.unchanged:
                analysis_res.unchanged = len(mc.unchanged)
                self.log.debug(f'{analysis_res.unchanged} unchanged files')

            if processing_optimization and len(man_fml.elements) > 100_000:
                self.log.warning('Manifest contains too many files, processing optimizations will be disabled.')
                processing_optimization = False
            elif processing_optimization:
                self.log.info('Processing order optimization is enabled, analysis may take a few seconds longer...')

            references = Counter()
            fmlist = sorted(man_fml.elements,
                            key=lambda a: a.filename.lower())

            current_tmp_size = 0
            for fm in fmlist:
                self.hash_map[fm.filename] = fm.sha_hash.hex()

                if fm.filename in mc.unchanged:
                    analysis_res.unchanged += fm.file_size
                    continue

                for cp in fm.chunk_parts:
                    references[cp.guid_num] += 1

                if fm.filename in mc.added:
                    current_tmp_size += fm.file_size
                    analysis_res.disk_space_delta = max(current_tmp_size, analysis_res.disk_space_delta)

                elif fm.filename in mc.changed:
                    current_tmp_size += fm.file_size
                    analysis_res.disk_space_delta = max(current_tmp_size, analysis_res.disk_space_delta)
                    if old_manifest:
                        old_man_fml = old_manifest.file_manifest_list
                        if old_man_fml:
                            current_tmp_size -= old_man_fml.get_file_by_path(fm.filename).file_size

            self.log.debug(f'Disk space delta: {analysis_res.disk_space_delta/1024/1024:.02f} MiB')

            if processing_optimization:
                s_time = time.time()
                min_overlap = 4
                cp_threshold = 5
                remaining_files = {
                    fm.filename: {cp.guid_num for cp in fm.chunk_parts}
                    for fm in fmlist if fm.filename not in mc.unchanged
                }
                _fmlist = []

                for fm in fmlist:
                    if fm.filename not in remaining_files:
                        continue

                    _fmlist.append(fm)
                    f_chunks = remaining_files.pop(fm.filename)
                    if len(f_chunks) < cp_threshold:
                        continue

                    best_overlap, match = 0, None
                    for fname, chunks in remaining_files.items():
                        if len(chunks) < cp_threshold:
                            continue
                        overlap = len(f_chunks & chunks)
                        if overlap > min_overlap and overlap > best_overlap:
                            best_overlap, match = overlap, fname

                    if match:
                        _fmlist.append(man_fml.get_file_by_path(match))
                        remaining_files.pop(match)

                fmlist = _fmlist
                opt_delta = time.time() - s_time
                self.log.debug(f'Processing optimizations took {opt_delta:.01f} seconds.')

            re_usable = defaultdict(dict)
            if old_manifest and mc.changed and patch:
                self.log.debug('Analyzing manifests for re-usable chunks...')
                for changed in mc.changed:
                    old_man_fml = old_manifest.file_manifest_list
                    if old_man_fml:
                        old_file = old_man_fml.get_file_by_path(changed)
                        new_file = man_fml.get_file_by_path(changed)

                        existing_chunks = defaultdict(list)
                        off = 0
                        for cp in old_file.chunk_parts:
                            existing_chunks[cp.guid_num].append((off, cp.offset, cp.offset + cp.size))
                            off += cp.size

                        for cp in new_file.chunk_parts:
                            key = (cp.guid_num, cp.offset, cp.size)
                            for file_o, cp_o, cp_end_o in existing_chunks[cp.guid_num]:
                                if cp_o <= cp.offset and (cp.offset + cp.size) <= cp_end_o:
                                    references[cp.guid_num] -= 1
                                    re_usable[changed][key] = file_o + (cp.offset - cp_o)
                                    analysis_res.reuse_size += cp.size
                                    break

            last_cache_size = current_cache_size = 0
            cached = set()
            chunks_in_dl_list = set()
            dl_cache_guids = set()
            self.log.debug('Creating filetasks and chunktasks...')

            for current_file in fmlist:
                if current_file.filename in mc.unchanged:
                    continue
                elif not current_file.chunk_parts:
                    self.tasks.append(FileTask(current_file.filename, flags=TaskFlags.CREATE_EMPTY_FILE))
                    continue

                existing_chunks = re_usable.get(current_file.filename, None)
                chunk_tasks = []
                reused = 0

                for cp in current_file.chunk_parts:
                    ct = ChunkTask(cp.guid_num, cp.offset, cp.size)

                    if existing_chunks and (cp.guid_num, cp.offset, cp.size) in existing_chunks:
                        reused += 1
                        ct.chunk_file = current_file.filename
                        ct.chunk_offset = existing_chunks[(cp.guid_num, cp.offset, cp.size)]
                    else:
                        if cp.guid_num not in chunks_in_dl_list:
                            self.chunks_to_dl.append(cp.guid_num)
                            chunks_in_dl_list.add(cp.guid_num)

                        if references[cp.guid_num] > 1 or cp.guid_num in cached:
                            references[cp.guid_num] -= 1

                            if references[cp.guid_num] < 1:
                                current_cache_size -= analysis_res.biggest_chunk
                                cached.remove(cp.guid_num)
                                ct.cleanup = True

                            elif cp.guid_num not in cached:
                                dl_cache_guids.add(cp.guid_num)
                                cached.add(cp.guid_num)
                                current_cache_size += analysis_res.biggest_chunk
                        else:
                            ct.cleanup = True

                    chunk_tasks.append(ct)

                if reused:
                    self.log.debug(
                        f' + Reusing {reused} chunks from: {current_file.filename}'
                    )
                    self.tasks.append(
                        FileTask(
                            current_file.filename + u'.tmp',
                            flags=TaskFlags.OPEN_FILE
                        )
                    )
                    self.tasks.extend(chunk_tasks)
                    self.tasks.append(
                        FileTask(
                            current_file.filename + u'.tmp',
                            flags=TaskFlags.CLOSE_FILE
                        )
                    )
                    self.tasks.append(
                        FileTask(
                            current_file.filename,
                            old_file=current_file.filename + u'.tmp',
                            flags=TaskFlags.RENAME_FILE | TaskFlags.DELETE_FILE
                        )
                    )
                else:
                    self.tasks.append(
                        FileTask(current_file.filename, flags=TaskFlags.OPEN_FILE)
                    )
                    self.tasks.extend(chunk_tasks)
                    self.tasks.append(
                        FileTask(current_file.filename, flags=TaskFlags.CLOSE_FILE)
                    )
                if current_file.executable:
                    self.tasks.append(
                        FileTask(current_file.filename, flags=TaskFlags.MAKE_EXECUTABLE)
                    )
                if current_cache_size > last_cache_size:
                    self.log.debug(
                        f' * New maximum cache size: {current_cache_size / 1024 / 1024:.02f} MiB'
                    )
                    last_cache_size = current_cache_size

            self.log.debug(f'Final cache size requirement: {last_cache_size / 1024 / 1024} MiB.')

            analysis_res.min_memory = last_cache_size + (1024 * 1024 * 32)
            if analysis_res.min_memory > self.max_shared_memory:
                shared_mib = f'{self.max_shared_memory / 1024 / 1024:.01f} MiB'
                required_mib = f'{analysis_res.min_memory / 1024 / 1024:.01f} MiB'
                # suggested_mib = round(
                #     self.max_shared_memory / 1024 / 1024 +
                #     (analysis_res.min_memory - self.max_shared_memory) / 1024 / 1024 + 32
                # )
                raise MemoryError(
                    f'Current shared memory cache is smaller than required: {shared_mib} < {required_mib}.'
                )

            analysis_res.dl_size = sum(
                c.file_size for c in man_cdl.elements if c.guid_num in chunks_in_dl_list
            )
            analysis_res.uncompressed_dl_size = sum(
                c.window_size for c in man_cdl.elements if c.guid_num in chunks_in_dl_list
            )
            for fname in mc.removed:
                self.tasks.append(FileTask(fname, flags=TaskFlags.DELETE_FILE))

            self.tasks.extend(additional_deletion_tasks)
            analysis_res.num_chunks_cache = len(dl_cache_guids)
            self.chunk_data_list = man_cdl
            self.analysis = analysis_res

        return analysis_res

    def download_job_manager(self, task_cond: Condition, shm_cond: Condition):
        while self.chunks_to_dl and self.running:
            while self.active_tasks < self.max_workers * 2 and self.chunks_to_dl:
                try:
                    sms = self.sms.popleft()
                    no_shm = False
                except IndexError:
                    no_shm = True
                    break

                c_guid = self.chunks_to_dl.popleft()
                if self.chunk_data_list and self.dl_worker_queue:
                    chunk = self.chunk_data_list.get_chunk_by_guid(c_guid)
                    self.log.debug(f'Adding {chunk.guid_num} (active: {self.active_tasks})')
                    try:
                        self.dl_worker_queue.put(
                            DownloaderTask(
                                url=self.base_url + '/' + chunk.path,
                                chunk_guid=c_guid, shm=sms
                            ),
                            timeout=1.0
                        )
                    except Exception as e:
                        self.log.warning(f'Failed to add to download queue: {e!r}')
                        self.chunks_to_dl.appendleft(c_guid)
                        break
                    self.active_tasks += 1
            else:
                with task_cond:
                    self.log.debug('Waiting for download tasks to complete..')
                    task_cond.wait(timeout=1.0)
                    continue
            if no_shm:
                with shm_cond:
                    self.log.debug('Waiting for more shared memory...')
                    shm_cond.wait(timeout=1.0)

        self.log.debug('Download Job Manager quitting...')

    def dl_results_handler(self, task_cond: Condition):
        in_buffer = dict()

        try:
            task = self.tasks.popleft()
        except IndexError:
            return

        current_file = ''

        while task and self.running:
            if isinstance(task, FileTask):
                try:
                    if self.writer_queue:
                        self.writer_queue.put(WriterTask(**task.__dict__), timeout=1.0)
                        if task.flags & TaskFlags.OPEN_FILE:
                            current_file = task.filename
                except Exception as e:
                    self.tasks.appendleft(task)
                    self.log.warning(f'Adding to queue failed: {e!r}')
                    continue

                try:
                    task = self.tasks.popleft()
                except IndexError:
                    break
                continue

            while (task.chunk_guid in in_buffer) or task.chunk_file:
                res_shm = None
                if not task.chunk_file:
                    res_shm = in_buffer[task.chunk_guid].shm
                try:
                    self.log.debug(f'Adding {task.chunk_guid} to writer queue')
                    if self.writer_queue:
                        self.writer_queue.put(WriterTask(
                            filename=current_file, shared_memory=res_shm,
                            chunk_offset=task.chunk_offset, chunk_size=task.chunk_size,
                            chunk_guid=task.chunk_guid, old_file=task.chunk_file,
                            flags=TaskFlags.RELEASE_MEMORY if task.cleanup else TaskFlags.NONE
                        ), timeout=1.0)
                except Exception as e:
                    self.log.warning(f'Adding to queue failed: {e!r}')
                    break

                if task.cleanup and not task.chunk_file:
                    del in_buffer[task.chunk_guid]

                try:
                    task = self.tasks.popleft()
                    if isinstance(task, FileTask):
                        break
                except IndexError:
                    task = None
                    break
            else:
                if self.dl_result_q:
                    try:
                        res = self.dl_result_q.get(timeout=1)
                        self.active_tasks -= 1
                        with task_cond:
                            task_cond.notify()

                        if res.success:
                            self.log.debug(f'Download for {res.chunk_guid} succeeded, adding to in_buffer...')
                            in_buffer[res.chunk_guid] = res
                            self.bytes_downloaded_since_last += res.size_downloaded
                            self.bytes_decompressed_since_last += res.size_decompressed
                        else:
                            self.log.error(f'Download for {res.chunk_guid} failed, retrying...')
                            if self.dl_worker_queue:
                                try:
                                    self.dl_worker_queue.put(res, timeout=1.0)
                                    self.active_tasks += 1
                                except Exception as e:
                                    self.log.warning(f'Failed adding retry task to queue! {e!r}')
                                    self.chunks_to_dl.appendleft(res.chunk_guid)
                    except Empty:
                        pass
                    except Exception as e:
                        self.log.warning(f'Unhandled exception when trying to read download result queue: {e!r}')

        self.log.debug('Download result handler quitting...')

    def fw_results_handler(self, shm_cond: Condition):
        while self.running:
            if self.writer_result_q:
                try:
                    res = self.writer_result_q.get(timeout=1.0)

                    if isinstance(res, TerminateWorkerTask):
                        self.log.debug('Got termination command in FW result handler')
                        break

                    self.num_tasks_processed_since_last += 1

                    if res.flags & TaskFlags.CLOSE_FILE and self.resume_file and res.success:
                        if res.filename.endswith('.tmp'):
                            res.filename = res.filename[:-4]

                        file_hash = self.hash_map[res.filename]
                        with open(self.resume_file, 'a', encoding='utf-8') as rf:
                            rf.write(f'{file_hash}:{res.filename}\n')

                    if not res.success:
                        self.log.fatal(f'Writing for {res.filename} failed!')

                    if res.flags & TaskFlags.RELEASE_MEMORY:
                        self.sms.appendleft(res.shared_memory)
                        with shm_cond:
                            shm_cond.notify()

                    if res.chunk_guid:
                        self.bytes_written_since_last += res.size

                        if not res.shared_memory:
                            self.bytes_read_since_last += res.size

                        self.num_processed_since_last += 1
                except Empty:
                    continue

                except Exception as e:
                    self.log.warning(f'Exception when trying to read writer result queue: {e!r}')

        self.log.debug('Writer result handler quitting...')

    def run(self):
        if not self.analysis:
            raise ValueError('Did not run analysis before trying to run download!')

        _root = logging.getLogger()
        _root.setLevel(logging.DEBUG if self.proc_debug else logging.INFO)
        if self.logging_queue:
            _root.handlers = []
            _root.addHandler(QueueHandler(self.logging_queue))

        self.log = logging.getLogger('DLManager')
        self.log.info(f'Download Manager running with process-id: {os.getpid()}')

        try:
            self.run_real()
        except KeyboardInterrupt:
            self.log.warning('Immediate exit requested!')
            self.running = False

            for cond in self.conditions:
                with cond:
                    cond.notify()

            for t in self.threads:
                t.join(timeout=5.0)
                if t.is_alive():
                    self.log.warning(f'Thread did not terminate! {repr(t)}')

            for child in self.children:
                child.join(timeout=5.0)
                if child.exitcode is None:
                    child.terminate()
            names = (
                'Download jobs',
                'Writer jobs',
                'Download results',
                'Writer results'
            )
            queues = (
                self.dl_worker_queue,
                self.writer_queue,
                self.dl_result_q,
                self.writer_result_q
            )
            for name, q in zip(names, queues):
                self.log.debug(f'Cleaning up queue "{name}"')
                if q:
                    try:
                        while True:
                            _ = q.get_nowait()
                    except Empty:
                        q.close()
                        q.join_thread()

    def run_real(self):
        self.shared_memory = SharedMemory(create=True, size=self.max_shared_memory)
        self.log.debug(
            'Created shared memory of size: '
            f'{self.shared_memory.size / 1024 / 1024:.02f} MiB'
        )
        if self.analysis:
            for i in range(int(self.shared_memory.size / self.analysis.biggest_chunk)):
                _sms = SharedMemorySegment(
                    offset=i * self.analysis.biggest_chunk,
                    end=i * self.analysis.biggest_chunk + self.analysis.biggest_chunk
                    )
                self.sms.append(_sms)

        self.log.debug(f'Created {len(self.sms)} shared memory segments.')

        self.dl_worker_queue = MPQueue(-1)
        self.writer_queue = MPQueue(-1)
        self.dl_result_q = MPQueue(-1)
        self.writer_result_q = MPQueue(-1)

        self.log.info(f'Starting download workers...')

        bind_ip = None
        for i in range(self.max_workers):
            if self.bind_ips:
                bind_ip = self.bind_ips[i % len(self.bind_ips)]

            w = DLWorker(f'DLWorker {i + 1}', self.dl_worker_queue, self.dl_result_q,
                         self.shared_memory.name, logging_queue=self.logging_queue,
                         dl_timeout=self.dl_timeout, bind_addr=bind_ip)
            self.children.append(w)
            w.start()

        self.log.info('Starting file writing worker...')
        writer_p = FileWorker(self.writer_queue, self.writer_result_q, self.dl_dir,
                              self.shared_memory.name, self.cache_dir, self.logging_queue)
        self.children.append(writer_p)
        writer_p.start()

        num_chunk_tasks = sum(isinstance(t, ChunkTask) for t in self.tasks)
        num_dl_tasks = len(self.chunks_to_dl)
        num_tasks = len(self.tasks)
        num_shared_memory_segments = len(self.sms)
        self.log.debug(
            f'Chunks to download: {num_dl_tasks}, File tasks: {num_tasks}, '
            f'Chunk tasks: {num_chunk_tasks}'
        )
        self.active_tasks = 0
        processed_chunks = 0
        processed_tasks = 0
        total_dl = 0
        total_write = 0

        shm_cond = Condition()
        task_cond = Condition()
        self.conditions = [shm_cond, task_cond]

        s_time = time.time()
        self.threads.append(Thread(target=self.download_job_manager, args=(task_cond, shm_cond)))
        self.threads.append(Thread(target=self.dl_results_handler, args=(task_cond,)))
        self.threads.append(Thread(target=self.fw_results_handler, args=(shm_cond,)))

        for t in self.threads:
            t.start()

        last_update = time.time()

        while processed_tasks < num_tasks:
            delta = time.time() - last_update
            if not delta:
                time.sleep(self.update_interval)
                continue

            processed_chunks += self.num_processed_since_last
            processed_tasks += self.num_tasks_processed_since_last

            total_dl += self.bytes_downloaded_since_last
            total_write += self.bytes_written_since_last

            dl_speed = self.bytes_downloaded_since_last / delta
            dl_unc_speed = self.bytes_decompressed_since_last / delta
            w_speed = self.bytes_written_since_last / delta
            r_speed = self.bytes_read_since_last / delta
            # c_speed = self.num_processed_since_last / delta

            self.bytes_read_since_last = self.bytes_written_since_last = 0
            self.bytes_downloaded_since_last = self.num_processed_since_last = 0
            self.bytes_decompressed_since_last = self.num_tasks_processed_since_last = 0
            last_update = time.time()

            perc = (processed_chunks / num_chunk_tasks) * 100
            runtime = time.time() - s_time
            total_avail = len(self.sms)
            biggest_chunk = self.analysis.biggest_chunk if self.analysis else 0
            total_used = (num_shared_memory_segments - total_avail) * (biggest_chunk / 1024 / 1024)

            if runtime and processed_chunks:
                average_speed = processed_chunks / runtime
                estimate = (num_chunk_tasks - processed_chunks) / average_speed
                hours, estimate = int(estimate // 3600), estimate % 3600
                minutes, seconds = int(estimate // 60), int(estimate % 60)

                rt_hours, runtime = int(runtime // 3600), runtime % 3600
                rt_minutes, rt_seconds = int(runtime // 60), int(runtime % 60)
            else:
                hours = minutes = seconds = 0
                rt_hours = rt_minutes = rt_seconds = 0

            self.log.info(f'= Progress: {perc:.02f}% ({processed_chunks}/{num_chunk_tasks}), '
                          f'Running for {rt_hours:02d}:{rt_minutes:02d}:{rt_seconds:02d}, '
                          f'ETA: {hours:02d}:{minutes:02d}:{seconds:02d}')
            self.log.info(f' - Downloaded: {total_dl / 1024 / 1024:.02f} MiB, '
                          f'Written: {total_write / 1024 / 1024:.02f} MiB')
            self.log.info(f' - Cache usage: {total_used:.02f} MiB, active tasks: {self.active_tasks}')
            self.log.info(f' + Download\t- {dl_speed / 1024 / 1024:.02f} MiB/s (raw) '
                          f'/ {dl_unc_speed / 1024 / 1024:.02f} MiB/s (decompressed)')
            self.log.info(f' + Disk\t- {w_speed / 1024 / 1024:.02f} MiB/s (write) / '
                          f'{r_speed / 1024 / 1024:.02f} MiB/s (read)')

            if self.status_queue:
                try:
                    self.status_queue.put(UIUpdate(
                        progress=perc, download_speed=dl_unc_speed, write_speed=w_speed, read_speed=r_speed,
                        memory_usage=total_used * 1024 * 1024
                    ), timeout=1.0)
                except Exception as e:
                    self.log.warning(f'Failed to send status update to queue: {e!r}')

            time.sleep(self.update_interval)

        for i in range(self.max_workers):
            self.dl_worker_queue.put_nowait(TerminateWorkerTask())

        self.log.info('Waiting for installation to finish...')
        self.writer_queue.put_nowait(TerminateWorkerTask())

        writer_p.join(timeout=10.0)
        if writer_p.exitcode is None:
            self.log.warning(f'Terminating writer process, no exit code!')
            writer_p.terminate()

        for child in self.children:
            if child.exitcode is None:
                child.terminate()

        for t in self.threads:
            t.join(timeout=5.0)
            if t.is_alive():
                self.log.warning(f'Thread did not terminate! {repr(t)}')

        if self.resume_file:
            try:
                os.remove(self.resume_file)
            except OSError as e:
                self.log.warning(f'Failed to remove resume file: {e!r}')

        self.shared_memory.close()
        self.shared_memory.unlink()
        self.shared_memory = None

        self.log.info('All done! Download manager quitting...')
        exit(0)
