#!/usr/bin/env python3
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

import os
import sys
from sys import argv, exit
from pathlib import Path
import shutil
import multiprocessing as mp
from threading import Thread
from collections import deque
import urllib.request
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import zipfile
import tarfile

END: str = "\33[0m"
RED: str = "\33[31m"
GREEN: str = "\33[32m"
YELLOW: str = "\33[33m"
VIOLET: str = "\33[35m"


def download(_url, _filename):
    """___download content from url___"""

    headers = {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, '
            'like Gecko) Chrome/30.0.1599.101 Safari/537.36'
        ),
        'Accept-Language': 'ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Connection': 'keep-alive',
        'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
    }
    try:
        _response = urlopen(Request(_url, headers=headers), timeout=10.0)
    except (Exception, HTTPError, URLError, ConnectionError) as e:
        print(RED, e, END)
        try:
            urllib.request.urlretrieve(_url, _filename)
        except (Exception, HTTPError, URLError) as e:
            print(e)
            return e
        else:
            exit(0)
    else:
        with _response as res, open(_filename, 'wb') as out:
            try:
                shutil.copyfileobj(res, out)
            except (Exception,) as e:
                print(RED, "CopyFileObjectError:", e, END)
                _filename.unlink()
                return e
            else:
                print(GREEN, f"Download to {_filename} comlete", END)
        exit(0)


def download_progress(data, queue, bar_len=50):
    """___download progress bar___"""
    while True:
        for x in data:
            filename = x[0]
            totalsize = x[2]
            if Path(filename).exists():
                current = os.stat(filename).st_size
                if totalsize is None:
                    percent = 1.0
                    progress = '~' * bar_len
                    string = f'\r{GREEN}[ {progress} ] {YELLOW}[unknown]% {VIOLET}{Path(filename).name}{END}'
                else:
                    pac = "\u15E7"
                    percent = current / totalsize
                    block = int(round(bar_len * percent))
                    progress = '\u2501' * block + f'{pac}' + ('\u2022' * (bar_len - block))
                    string = f'\r{GREEN}[ {progress} ] {YELLOW}{round(percent*100)}% {VIOLET}{Path(filename).name}{END}'

                queue.append([string, percent])
        else:
            for i in range(len(queue)):
                sys.stdout.write('\x1b[1A\x1b[2K')
            else:
                for i in range(len(queue)):
                    sys.stdout.write(queue[i][0] + '\n')

            if sum([q[1] for q in queue]) == len(data):
                print('Done')
                return False


def get_total_size(_url, _filename):
    """___get download content total size___"""
    totalsize = None
    try:
        totalsize = int(urlopen(_url).info().get(name='Content-Length'))
    except (Exception,):
        totalsize = None

    if totalsize is None:
        try:
            with urlopen(_url) as u:
                totalsize = u.length
        except (URLError, HTTPError):
            totalsize = None

    sys.stdout.write(f'Total size: {totalsize}\t{Path(_filename).name}\n')
    return totalsize


def extract_tar(filename, path):
    """___extract tar archive___"""

    if Path(filename).exists():
        taro = tarfile.open(filename)

        for member_info in taro.getmembers():
            taro.extract(member_info, path=path)
            print('Extracting: ' + member_info.name)

        taro.close()
        print('Extraction_completed_successfully.')
        exit(0)
    else:
        print(f'{filename} not exists...')
        exit(1)


def extract_zip(filename, path):
    """___extract zip archive___"""

    if Path(filename).exists():
        zipo = zipfile.ZipFile(filename)

        for member_info in zipo.namelist():
            print('Extracting: ' + member_info)
            zipo.extract(member_info, path=path)

        zipo.close()
        print('Extraction_completed_successfully.')
        exit(0)
    else:
        print(f'{filename} not exists...')
        exit(1)


def on_helper():
    """___Commandline help info___"""
    print('''
    ----------------------------------------------------------------------------
    StartWine PacUrl:
    It is a tool for download content from url with console progress bar.

    ----------------------------------------------------------------------------
    Usage: [pacurl] [option] [arguments]

    ----------------------------------------------------------------------------
    Options:
    -h
    --help                                  Show help and exit
    -d 'url' 'output_file'
    --download 'url' 'output_file'          Download content with progress bar
    --tar  'input_file, output_file'        Tar archive extraction
    --zip  'input_file, output_file'        Zip archive extraction
''')


if __name__ == "__main__":

    if len(argv) == 1 or '-h' in argv or '--help' in argv:
        on_helper()

    if len(argv) >= 4:
        if (str(argv[1]) == str('-d') or str(argv[1]) == str('--download')
                or str(argv[1]) == str('--silent-download')):

            url = str(argv[2])
            filename = str(argv[3])
            size = 50
            process = mp.Process(target=download, args=(url, filename))
            process.start()
            totalsize = get_total_size(url, filename)
            data = [[filename, url, totalsize]]
            queue = deque([], len(data))
            Thread(target=download_progress, args=(data, queue, size)).start()

        elif str(argv[1]) == str('--tar') or str(argv[1]) == str('--silent-tar'):
            filename = str(argv[2])
            path = str(argv[3])
            Thread(target=extract_tar, args=[filename, path]).start()

        elif str(argv[1]) == str('--zip') or str(argv[1]) == str('--silent-zip'):
            filename = str(argv[2])
            path = str(argv[3])
            Thread(target=extract_zip, args=[filename, path]).start()

