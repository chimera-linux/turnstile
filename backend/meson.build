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

# runit backend

if have_runit
    install_data(
        'runit',
        install_dir: join_paths(get_option('libexecdir'), 'turnstile'),
        install_mode: 'rwxr-xr-x'
    )

    install_data(
        'runit.conf',
        install_dir: join_paths(get_option('sysconfdir'), 'turnstile/backend'),
        install_mode: 'rw-r--r--'
    )

    configure_file(
        input: 'turnstile-update-runit-env.in',
        output: 'turnstile-update-runit-env',
        configuration: conf_data,
        install: true,
        install_dir: get_option('bindir'),
        install_mode: 'rwxr-xr-x'
    )
endif
