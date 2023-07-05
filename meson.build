project('StartWine',
	version : '378',
	license : 'GPL-3.0'
)

# Convert .po to .mo for make opensource happy
ru_mo = meson.current_source_dir() / 'data' / 'scripts' / 'locale' / 'ru' / 'LC_MESSAGES' / 'StartWine.mo'
ru_po = meson.current_source_dir() / 'data' / 'scripts' / 'locale' / 'ru' / 'LC_MESSAGES' / 'ru.po'
convert_po = [find_program('msgfmt'), ru_po, '-o', ru_mo]
run_command(convert_po)

# Install icon
install_data('data/img/gui_icons/SW_Launcher_x256.png',
	install_dir: join_paths(get_option('datadir'), 'pixmaps'),
	rename: 'startwine.png'
)

# Prepare and install start file
configure_file(input: 'data/startwine.in',
	output: 'startwine',
	install_dir: join_paths(get_option('bindir')),
	install: true,
	install_mode: 'rwxr-xr-x',
	configuration: {
		'VERSION': meson.project_version(),
	}
)

# Install desktop file
configure_file(input: 'data/StartWine.desktop.in',
	output: 'StartWine.desktop',
	install_dir: join_paths(get_option('datadir'), 'applications'),
	install: true,
	install_mode: 'rw-r--r--',
	configuration: {}
)

# Install program data
install_subdir('data',
	install_dir: join_paths(get_option('datadir'), 'startwine'),
	exclude_files: ['startwine.in', 'StartWine.desktop.in']
)
