StartWine
Guide
Review
Preparing for installation
Installation
Interface
Initial setup
How to run games and programs
About
Preparing for installation
To get started, download SrartWine itself from the discord server in the sw_releases section or from the GitHub page
Discord: https://discord.gg/jjY3auVdfm
GitHub: https://github.com/RusNor/StartWine-Launcher
After you have downloaded the file, first of all right-click, properties, rights (or any other similar item in the properties), put a check mark on "Is executable" or “Allow to execute as a program"

or you can enter the command in the terminal:
chmod -x StartWine-(version) 



Installation
The Council. If the file does not start or does not work correctly, then enter the commands in the terminal

Ubuntu/Debian
sudo apt update -y || echo 'Pass' &&
sudo apt install software-properties-common -y || echo 'Pass' &&
sudo dpkg --add-architecture i386 || echo 'Pass' &&
sudo apt update -y || echo 'Pass' &&
sudo apt install zstd -y || echo 'Pass' &&
sudo apt install cabextract -y || echo 'Pass' &&
sudo apt install icoutils -y || echo 'Pass' &&
sudo apt install wine -y || echo 'Pass' &&
sudo apt install gir1.2-appindicator3-0.1 -y || echo 'Pass' &&
sudo apt install gir1.2-ayatanaappindicator3-0.1 -y || echo 'Pass' &&
sudo apt install imagemagick -y || echo 'Pass' &&
sudo apt install gir1.2-vte-2.91 -y || echo 'Pass' &&
sudo apt install vulkan-tools -y || echo 'Pass' &&
sudo apt install squashfs-tools -y || echo 'Pass' &&
sudo apt install libnotify4 -y || echo 'Pass'
Arch/Manjaro
sudo pacman -Sy -y || echo 'Pass' &&
sudo pacman -S zstd --noconfirm || echo 'Pass' &&
sudo pacman -S cabextract --noconfirm || echo 'Pass' &&
sudo pacman -S icoutils --noconfirm || echo 'Pass' &&
sudo pacman -S wine-staging --noconfirm || echo 'Pass' &&
sudo pacman -S imagemagick --noconfirm || echo 'Pass' &&
sudo pacman -S vte3 python-gobject --noconfirm || echo 'Pass' &&
sudo pacman -S squashfs-tools --noconfirm || echo 'Pass' &&
sudo pacman -S vulkan-tools --noconfirm || echo 'Pass' &&
sudo pacman -S libappindicator-gtk3 --noconfirm || echo 'Pass' &&
sudo pacman -S libindicator-gtk3 --noconfirm || echo 'Pass' &&
sudo pacman -S libnotify --noconfirm || echo 'Pass'
Red Hat Enterprise/Fedora
sudo dnf install zstd -y || echo 'Pass' &&
sudo dnf install cabextract -y || echo 'Pass' &&
sudo dnf install icoutils -y || echo 'Pass' &&
sudo dnf install wine -y || echo 'Pass' &&
sudo dnf install libappindicator-gtk3 -y || echo 'Pass' &&
sudo dnf install libindicator-gtk3 -y || echo 'Pass' &&
sudo dnf install ImageMagick -y || echo 'Pass' &&
sudo dnf install vulkan-tools -y || echo 'Pass' &&
sudo dnf install squashfs-tools -y || echo 'Pass' &&
sudo dnf install vte291 -y || echo 'Pass' &&
sudo dnf install libnotify -y || echo 'Pass'
openSUSE
sudo zypper ref || echo 'Pass' &&
sudo zypper in --no-confirm zstd || echo 'Pass' &&
sudo zypper in --no-confirm cabextract || echo 'Pass' &&
sudo zypper in --no-confirm icoutils || echo 'Pass' &&
sudo zypper in --no-confirm wine || echo 'Pass' &&
sudo zypper in --no-confirm ImageMagick || echo 'Pass' &&
sudo zypper in --no-confirm typelib-1_0-Vte-2.91 || echo 'Pass' &&
sudo zypper in --no-confirm libvte-2_91-0 || echo 'Pass' &&
sudo zypper in --no-confirm squashfs || echo 'Pass' &&
sudo zypper in --no-confirm vulkan-tools || echo 'Pass' &&
sudo zypper in --no-confirm libappindicator3-1 || echo 'Pass' &&
sudo zypper in --no-confirm typelib-1_0-AppIndicator3-0_1 || echo 'Pass' &&
sudo zypper in --no-confirm libnotify-tools || echo 'Pass'


If you use a work environment xfce, then enter this command in the terminal (if suddenly the installer does not work):
xfconf-query --channel thunar --property /misc-exec-shell-scripts-by-default --create --type bool --set true && thunar -q 

Run the file in two mouse clicks and see the installer itself. Click on the Install button and wait for the installation to finish (you can make tea ☕ )

Interface
Now let 's briefly go through the menu of the StartWine

Shortcuts - Application Catalog
Create shortcuts - Creating a shortcut .the exe file along with the prefix and recommended libs
Prefix tools - Managing the prefix from which you started the game
Wine tools - Management and settings of the wine that is currently used in the prefix
Download wine - Here you can download wine-staging, wine-steam-proton, wine-proton-ge, wine-lutris, wine-lutris-ge, wine-custom it is used to install third-party wine from various resources
Settings - Setting up the StartWine
Debug - Launching a file with a prefix in debug mode
Stop - Stopping processes wine
Initial setup
To get started, go to the Download wine item and download the following there:
wine-staging
wine-steam-proton
wine-proton-ge

There's nothing else to do :)
How to run games and programs
There are two ways to install the game in StartWine
1. You can install your games using the launcher in the install launchers section.

2. If you downloaded the game from other sources or somewhere else, then first you will need to install the game (I will show you the example of the game Yuppie Psycho).
How to run the .exe file installer? yes, it's easy, we launch it in two clicks on the left mouse button or just on the right mouse button

In the window that appears, click on the beckoning START button :) and wait until it starts.
Next, select the language, and here we will stop a little, first select the installation location and then where the selected area is just below, remove all the ticks! (Don't pay attention that I have a game here Сuphead, this is for example)

If you did as it was written above, then you will be a good chef 👨‍🍳 (the last one is a joke)

The Council.
In some cases, it may turn out that the installation is going, but the percentages are not going, and the culprit is in my or maybe you have it NTFS the partition of the disk from which you started the installer. The fact is that if you have a so-called dualbut or multi-boot, call it as you like, then if you have not booted from Windows, then Windows will safely take away your rights to any actions on files.
What should I do in this case?
Option 1: Just take and reboot into Windows, it is not necessary to log in to the account, then reboot into your Linux distribution.
Option 2: In the folder where you have the files with the game installer, copy it and transfer it to the Linux partition, preferably in the /home/$USER/ (where $USER should be your username) section.

Now back to the game. After the game has been installed, go to the folder with the game and look for the .exe file to run the game.
Run the file, click on the button Create shortcut.
Here is the advice from Wine to choose Proton-ge

StartWine will ask you: do you want to create a prefix? Here I recommend pressing the yes button

During the creation of the prefix, StratWine will prompt you to install the recommended libs, the simplest language will be to install DirectX, visual c++ libraries in your prefix for the game, etc. What we click on the yes button is also not necessary, of course, but in most cases it is necessary.

As a result, this picture should turn out.

Now you can start the game

Have a nice game :)
About
Author of the manual: Lintech
Helpers in creating a manual:
Normatov R.R. Maslov N.G.
The creators of StartWine: Maslov N.G. and Normatov R.R.
If you have any questions, go to the server: https://discord.gg/jjY3auVdfm




