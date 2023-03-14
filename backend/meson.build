# dinit backend

if have_dinit
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
