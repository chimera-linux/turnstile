# dinit backend

if get_option('dinit').enabled()
    install_data(
        'dinit',
        install_dir: join_paths(get_option('libexecdir'), 'turnstile'),
        install_mode: 'rwxr-xr-x'
    )

    install_data(
        'dinit.conf',
        install_dir: join_paths(get_option('sysconfdir'), 'turnstile/backend'),
        install_mode: 'rw-r--r--'
    )
endif
