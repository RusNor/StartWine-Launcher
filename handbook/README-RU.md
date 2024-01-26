![sw_image1](/handbook/sw_logo.svg)

> StartWine - это программа запуска, которая позволяет быстро и легко запускать приложения Windows в операционных системах Linux
# **Руководство StartWine**

## Навигация
1. [Установка](#установка)
2. [Интерфейс](#интерфейс)
3. [Cоздание ярлыков и запуск игр](#cоздание-ярлыков-и-запуск-игр)
4. [Что используется в StartWine?](#что-используется-в-startwine)
5. [Благодарность!](#благодарность)
6. [Полезные ссылки](#полезные-ссылки)
7. [Лицензия](#лицензия)

## Установка
Чтобы начать пользоваться программой, загрузите сам SrartWine со страницы GitHub в разделе sw_releases или со сервера discord

GitHub > [Click](https://github.com/RusNor/StartWine-Launcher/releases)

AUR > [I use Arch :p](https://aur.archlinux.org/packages/startwine)

Discord > [Click](https://discord.gg/jjY3auVdfm)

Сделайте файл исполняемым и запусте с двойным кликом

Если у вас не запускается StartWine, введите данные команды
```bash
sudo sh -c 'echo kernel.pid_max=4194304 >> /etc/sysctl.d/98-pid_max.conf'
sudo sh -c 'echo 4194304 > /proc/sys/kernel/pid_max'
```

## Интерфейс

Видео демнстарция интерфейса StartWine

https://github.com/RusNor/StartWine-Launcher/assets/81373196/d3b1bafd-8feb-40b0-aed3-062345d1ee45

Если вам надо быстрый доступ к папкам или добавить в закладку свою папку, то нажиме на соответсвующий значок как показано в видеодемонстариции

https://github.com/RusNor/StartWine-Launcher/assets/81373196/54c14c12-05f8-48e2-86db-83a62c573054

Скришоты StartWine (Сомнительно, но окееей)

![sw_image1](/handbook/ru/sw_image1.png)
![sw_image2](/handbook/ru/sw_image2.png)
![sw_image3](/handbook/ru/sw_image3.png)
![sw_image4](/handbook/ru/sw_image4.png)
![sw_image5](/handbook/ru/sw_image5.png)
![sw_image6](/handbook/ru/sw_image6.png)
![sw_image7](/handbook/ru/sw_image7.png)
![sw_image8](/handbook/ru/sw_image8.png)
![sw_image9](/handbook/ru/sw_image9.png)
![sw_image10](/handbook/ru/sw_image10.png)

## Cоздание ярлыков и запуск игр
Если нажать кнопку "НЕТ" в выборе создания префикса для .exe и других виндовых форматов, по умолчанию будет использоваться дефолтный префикс для ярлыка.

В ином случае просто нажимайте кнопку "Пуск" и игра запустится

https://github.com/RusNor/StartWine-Launcher/assets/81373196/75562e00-94e6-439d-aee9-eca7ce4a12a5

Обратите внимание, что у StartWine помимо обычного ярлыка с интерфейсом существует ```StartWine-Run.desktop``` который по умолчанию используется в файловых менеджерах таких, как [dolphin](https://ru.wikipedia.org/wiki/Dolphin_(%D1%84%D0%B0%D0%B9%D0%BB%D0%BE%D0%B2%D1%8B%D0%B9_%D0%BC%D0%B5%D0%BD%D0%B5%D0%B4%D0%B6%D0%B5%D1%80)), [Nautilus](https://ru.wikipedia.org/wiki/GNOME_Files) и т.д для запуска .exe файла без интерфейса StartWine

Совет!

* В некоторых случаях может оказаться, что установка идет, но проценты не идут, и виновник находится в моем или, может быть, у вас есть [NTFS](https://ru.wikipedia.org/wiki/NTFS ) раздел диска, с которого вы запустили программу установки. Дело в том, что если у вас есть так называемый [дуалбут](https://ru.wikipedia.org/wiki/Мультизагрузка) или мультизагрузка, называйте это как хотите, тогда, если вы не загрузились из Windows, то Windows благополучно отберет у вас права на любые действия с файлами.
Что мне следует делать в этом случае?
* Вариант 1: Просто возьмите и перезагрузитесь в Windows, не обязательно входить в учетную запись, затем перезагрузитесь в свой дистрибутив Linux. Или после того как загрузились в Windows отключите режим гибернации. Как это делать? смотрите в интернете.
* Вариант 2: В папке, где у вас есть файлы с установщиком игры, скопируйте его и перенесите в раздел Linux, предпочтительно в раздел /home/$USER/ (где $USER должно быть вашим именем пользователя).

## Что используется в StartWine?
StartWine был написан с нуля, но с использованием уже готовых компонентов без которых сама программа не появилась
> Список 

[GTK 4](https://www.gtk.org/)

[Wine](https://www.winehq.org/)

[Wine-Staging](https://github.com/Kron4ek/Wine-Builds)

[Wine GE](https://github.com/GloriousEggroll/wine-ge-custom)

[Proton GE](https://github.com/GloriousEggroll/proton-ge-custom)

[Steam Proton](https://github.com/ValveSoftware/Proton)

[Lutris](https://github.com/lutris/wine)

[Lutris GE](https://github.com/GloriousEggroll/proton-ge-custom)

[DXVK](https://github.com/doitsujin/dxvk)

[DXVK GE](https://github.com/GloriousEggroll/wine-ge-custom)

[VK3D](https://github.com/HansKristian-Work/vkd3d-proton)

[VK3D GE](https://github.com/GloriousEggroll/wine-ge-custom)

[MangoHud](https://github.com/flightlessmango/MangoHud) (Спасибо [VHSgunzo](https://github.com/VHSgunzo) за патч для работы на видеокарт Nvidia!)

[vkBasalt](https://github.com/DadSchoorse/vkBasalt)

[gamemode](https://github.com/FeralInteractive/gamemode)

[Mesa](https://www.mesa3d.org/)

[Runimage](https://github.com/VHSgunzo/runimage)

[Runimage nvidia drivers](https://github.com/VHSgunzo/runimage-nvidia-drivers)

[AMD FSR](https://github.com/GPUOpen-Effects/FidelityFX-FSR2)

[dgVoodoo2](http://dege.freeweb.hu/dgVoodoo2/dgVoodoo2/)

[DLSS](https://www.nvidia.com/en-us/geforce/technologies/dlss/)

## Благодарность!

> **Разработчики**

[Рустам Норматов](https://github.com/RusNor)
[Никита Маслов](https://github.com/nix-on-nix)

> **Создавали и помогали в написании кода**

[Рустам Норматов](https://github.com/RusNor)
[Никита Маслов](https://github.com/nix-on-nix)
[Максим Тарасов](https://github.com/VHSgunzo)

> **Участники проекта**

StartWine Community
Андрей
3y6HuK
Alexandrdrdr
Huskysoul
kazbek
Kot41ru
Fanchji (Виталий)
Survolog
Lex
Lintech
LinuxShef
Sheridan
Wilk

> **Дизайн проекта**

Дизайнерская социалистическая партия StartWine

Спасибо всем кто принимал участие в тестировании и разработки StartWine, а так же в поддержке своим энтузиазмом и большим терпением ❤️

## Полезные ссылки

Автор руководства > [Lintech](https://www.youtube.com/c/Lintech8)

Веб-сайт > [Клик](https://startwine-project.ru/)

Телеграм > [Telegram](https://t.me/StartWine) + [чат](https://t.me/StartWineChat)

Дискорд сервер > [Discord](https://discord.gg/jjY3auVdfm)

## Лицензия

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Copyright (C) Maslov N.G. Normatov R.R.

Этот файл является частью StartWine-Launcher.

StartWine-Launcher - это свободное программное обеспечение: вы можете распространять его и/или изменять
на условиях Стандартной общественной лицензии GNU, опубликованной
Фондом свободного программного обеспечения, либо версии 3 Лицензии, либо
(по вашему выбору) любой более поздней версии.

StartWine-Launcher распространяется в надежде, что он будет полезен,
но БЕЗ КАКИХ-ЛИБО ГАРАНТИЙ; даже без подразумеваемых гарантий
товарности или пригодности для определенной цели. См.
Стандартную общественную лицензию GNU для получения более подробной информации.

Вы должны были получить копию Стандартной общественной лицензии GNU
вместе с StartWine-Launcher.  Если нет, смотрите <http://www.gnu.org/licenses/>.
