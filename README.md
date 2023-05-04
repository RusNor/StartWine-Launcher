![sw_image1](/doc/image/sw_image1.svg)

> StartWine is a launcher that allows you to quickly and easily launch Windows applications on Linux operating systems

# **StartWine Guide**
**English** - [Русский](doc/README-RU.md)

## Review

1. [Preparing for installation](#preparing-for-installation)
2. [Installation (new)](#installation-new)
3. [Installation (old)](#installation-old)
4. [Interface](#interface)
5. [Initial setup](#initial-setup)
6. [How to run games and programs](#how-to-run-games-and-programs)
7. [About](#about)


## Preparing for installation


To get started, download SrartWine itself from the discord server in the sw_releases section or from the GitHub page

Discord: [Click](https://discord.gg/jjY3auVdfm)

GitHub: [Click](https://github.com/RusNor/StartWine-Launcher/releases)

or the command
```bash
wget -c -t 5 -T 5 "https://github.com/RusNor/StartWine-Launcher/releases/download/StartWine_v376/StartWine_v376" --output-document="${HOME}/StartWine_v376" && chmod +x StartWine_v376 && ./StartWine_v376
```

If you downloaded and launched StartWine via the wget command, you can simply skip the item below

Once you have downloaded the file, first of all right-click, properties, rights (or any other similar item in the properties), check the "Is executable" or "Allow to run as a program" box.

![sw_image2](/doc/image/sw_image2.png)

or you can enter the command in the terminal:
```bash
chmod +x StartWine_v*
```

## Installation (new)
starting from version [3.6.4](https://github.com/RusNor/StartWine-Launcher/releases/tag/StartWine_v364) the graphic has been removed, so the installation has changed slightly

now just drag the file from the folder where you downloaded StartWine into the terminal and press enter

if you want to from the terminal:
```bash
./StartWine_v369
```

## Installation (old)


If you use a work environment [xfce](https://en.wikipedia.org/wiki/Xfce), then enter this command in the terminal (if suddenly the installer does not work):
```bash
xfconf-query --channel thunar --property /misc-exec-shell-scripts-by-default --create --type bool --set true && thunar -q 
```

Run the file in two mouse clicks and see the installer itself. Click on the Install button and wait for the installation to finish (you can make tea ☕ )

![sw_image3](/doc/image/sw_image3.png)

If you want to install other versions of wine along with the star twine, then the Advanced Options item you can select the option you need (I recommend putting wine in the intermediate and Proton language).

![sw_image4](/doc/image/sw_image4.png)

After installation, the StartWine-install-Manager program will appear in your startup, with its help you can update or delete StartWine.

![sw_image5](/doc/image/sw_image5.png)


## Interface


Now let 's briefly go through the menu of the StartWine

![sw_image6](/doc/image/sw_image6.png)

* **Shortcuts** - Application Catalog.
* **Create shortcuts** - Creating a shortcut .the exe file along with the prefix and recommended libs.
* **Prefix tools** - Managing the prefix from which you started the game.
* **Wine tools** - Management and settings of the wine that is currently used in the prefix.
* **Download wine** - Here you can download wine-staging, wine-steam-proton, wine-proton-ge, wine-lutris, wine-lutris-ge, wine-custom it is used to install third-party wine from various resources.
* **Settings** - Setting up the StartWine.
* **Debug** - Launching a file with a prefix in debug mode.
* **Stop** - Stopping processes wine.

If you don't like the StartWine background theme you can change it by clicking on the icon shown in the screenshot below 

![sw_image20](/doc/image/sw-image20.png)

Since version [3.6.0](https://github.com/RusNor/StartWine-Launcher/releases/tag/StartWine_v360), StartWine has added mangohud and vkbasalt settings  

![sw_image17](/doc/image/sw-image17.png)

![sw_image18](/doc/image/sw-image18.png)

You can view changes to mangohud and vkbasalt settings by clicking on the preview button
to exit the preview, press the Enter key

![sw_image19](/doc/image/sw-image19.png)

## Initial setup


To get started, go to the Download wine item and download the following there (if you have previously installed wine from the list below in the installer, you can skip this item):
wine-staging,
wine-steam-proton,
wine-proton-ge.

![sw_image7](/doc/image/sw_image7.png)

There's nothing else to do :)


## How to run games and programs


There are two ways to install the game in StartWine
1. You can install your games using the launcher in the install launchers section.

   ![sw_image8](/doc/image/sw_image8.png)

2. If you downloaded the game from other sources or somewhere else, then first you will need to install the game (I will show you the example of the game [Yuppie Psycho](https://store.steampowered.com/app/597760/Yuppie_Psycho_Executive_Edition/)).
How to run the .exe file installer? yes, it's easy, we launch it in two clicks on the left mouse button or just on the right mouse button

   ![sw_image9](/doc/image/sw_image9.png)

In the window that appears, click on the beckoning START button :) and wait until it starts.
Next, select the language, and here we will stop a little, first select the installation location and then where the selected area is just below, remove all the ticks! (Don't pay attention that I have a game here Сuphead, this is for example)

![sw_image10](/doc/image/sw_image10.png)

If you did as it was written above, then you will be a good chef 👨‍🍳 (the last one is a joke)

The Council!

* In some cases, it may turn out that the installation is going, but the percentages are not going, and the culprit is in my or maybe you have it [NTFS](https://en.wikipedia.org/wiki/NTFS) the partition of the disk from which you started the installer. The fact is that if you have a so-called [dualbut](https://en.wikipedia.org/wiki/Multi-booting) or multi-boot, call it as you like, then if you have not booted from Windows, then Windows will safely take away your rights to any actions on files.
What should I do in this case?
* Option 1: Just take and reboot into Windows, it is not necessary to log in to the account, then reboot into your Linux distribution.
* Option 2: In the folder where you have the files with the game installer, copy it and transfer it to the Linux partition, preferably in the /home/$USER/ (where $USER should be your username) section.

Now back to the game. After the game has been installed, go to the folder with the game and look for the .exe file to run the game.

![sw_image11](/doc/image/sw_image11.png)

Run the file, click on the button Create shortcut.
Here is the advice from Wine to choose Proton-ge

![sw_image12](/doc/image/sw_image12.png)

StartWine will ask you: do you want to create a prefix? Here I recommend pressing the yes button

![sw_image13](/doc/image/sw_image13.png)

During the creation of the prefix, StratWine will prompt you to install the recommended libs, the simplest language will be to install DirectX, visual c++ libraries in your prefix for the game, etc. What we click on the yes button is also not necessary, of course, but in most cases it is necessary.

![sw_image14](/doc/image/sw_image14.png)

As a result, this picture should turn out.

![sw_image15](/doc/image/sw_image15.png)

Now you can start the game

![sw_image16](/doc/image/sw_image16.png)

Have a nice game :)

## About


Author of the manual: [Lintech](https://www.youtube.com/c/Lintech8)

The creators of StartWine: [Normatov R.R.](https://github.com/RusNor) and [Maslov N.G.](https://github.com/nix-on-nix) 

Helpers in creating a manual:
[Normatov R.R.](https://github.com/RusNor) [Maslov N.G.](https://github.com/nix-on-nix) [Norz3n](https://github.com/vellynproduction) Huskysoul#6112

If you have any questions, go to the server: [Discord](https://discord.gg/jjY3auVdfm)

Telegram channel: [StartWine](https://t.me/StartWine)


## License


[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Copyright (C) Maslov N.G. Normatov R.R.

This file is part of StartWine-Launcher.

StartWine-Launcher is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

StartWine-Launcher is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with StartWine-Launcher.  If not, see <http://www.gnu.org/licenses/>.
____
