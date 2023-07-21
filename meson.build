project(
    'turnstile',
    ['cpp'],
    version: '0.1.6',
    default_options: [
        'cpp_std=c++17', 'warning_level=3', 'buildtype=debugoptimized',
    ],
    license: 'BSD-2-Clause'
)

cpp = meson.get_compiler('cpp')

pam_dep = dependency('pam', required: true)
# could be openpam, in which case pam_misc is not present
pam_misc_dep = dependency('pam_misc', required: false)
rt_dep = cpp.find_library('rt', required: false)

scdoc_dep = dependency(
    'scdoc', version: '>=1.10',
    required: get_option('man'),
    native: true
)

have_dinit = get_option('dinit').enabled()

conf_data = configuration_data()
conf_data.set_quoted('RUN_PATH', get_option('rundir'))
conf_data.set_quoted('CONF_PATH', join_paths(
    get_option('prefix'), get_option('sysconfdir'), 'turnstile'
))
conf_data.set10('MANAGE_RUNDIR', get_option('manage_rundir'))

conf_data.set('HAVE_PAM_MISC', pam_misc_dep.found())

statepath = join_paths(
    get_option('prefix'), get_option('localstatedir'),
    get_option('statedir')
)
lingerpath = join_paths(statepath, 'linger')

conf_data.set_quoted('STATE_PATH', statepath)
conf_data.set_quoted('LINGER_PATH', lingerpath)
conf_data.set_quoted('LIBEXEC_PATH', join_paths(
    get_option('prefix'), get_option('libexecdir'), 'turnstile'
))

configure_file(output: 'config.hh', configuration: conf_data)

extra_inc = [include_directories('src')]

add_project_arguments('-D_BSD_SOURCE', language: 'cpp')

daemon_sources = [
    'src/turnstiled.cc',
    'src/fs_utils.cc',
    'src/cfg_utils.cc',
    'src/exec_utils.cc',
    'src/utils.cc',
]

daemon = executable(
    'turnstiled', daemon_sources,
    include_directories: extra_inc,
    install: true,
    dependencies: [rt_dep, pam_dep, pam_misc_dep],
    gnu_symbol_visibility: 'hidden'
)

pam_moddir = get_option('pam_moddir')

if pam_moddir == ''
    pam_moddir = join_paths(
        pam_dep.get_variable('libdir', default_value: get_option('libdir')),
        'security'
    )
    message('Detected PAM module directory:', pam_moddir)
endif

pam_mod = shared_module(
    'pam_turnstile', ['src/pam_turnstile.cc', 'src/utils.cc'],
    include_directories: extra_inc,
    install: true,
    install_dir: pam_moddir,
    name_prefix: '',
    dependencies: [pam_dep],
    gnu_symbol_visibility: 'hidden'
)

if have_dinit
    install_data(
        'data/dinit/turnstiled',
        install_dir: join_paths(get_option('sysconfdir'), 'dinit.d'),
        install_mode: 'rw-r--r--'
    )
endif

install_data(
    'data/pam/turnstiled',
    install_dir: join_paths(get_option('sysconfdir'), 'pam.d'),
    install_mode: 'rw-r--r--'
)

# decide the default backend
if have_dinit
    default_backend = 'dinit'
else
    default_backend = 'none'
endif

uconf_data = configuration_data()

uconf_data.set('RUN_PATH', get_option('rundir'))
uconf_data.set('LINGER_PATH', lingerpath)
uconf_data.set('DEFAULT_BACKEND', default_backend)

if get_option('manage_rundir')
    uconf_data.set('MANAGE_RUNDIR', 'yes')
else
    uconf_data.set('MANAGE_RUNDIR', 'no')
endif

configure_file(
    input: 'turnstiled.conf.in',
    output: 'turnstiled.conf',
    configuration: uconf_data,
    install: true,
    install_dir: join_paths(get_option('sysconfdir'), 'turnstile'),
    install_mode: 'rw-r--r--'
)

cscd = configure_file(
    input: 'turnstiled.conf.5.scd.in',
    output: 'turnstiled.conf.5.scd',
    configuration: uconf_data
)

if get_option('man')
    scdoc_prog = find_program(
        scdoc_dep.get_pkgconfig_variable('scdoc'),
        native: true
    )
    sh = find_program('sh', native: true)
    mandir = get_option('mandir')

    man_files = [
        'src/turnstiled.8.scd',
        'src/pam_turnstile.8.scd',
        cscd,
    ]

    foreach filename: man_files
        section = '@0@'.format(filename).split('.')[-2]
        output = '@0@'.format(filename).split('/')[-1].replace('.scd', '')

        custom_target(
            output,
            input: filename,
            capture: true,
            output: output,
            command: [
                sh, '-c', '@0@ < @INPUT@'.format(scdoc_prog.path())
            ],
            install: true,
            install_dir: '@0@/man@1@'.format(mandir, section)
        )
    endforeach
endif

subdir('backend')
