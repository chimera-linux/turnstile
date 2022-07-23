project(
    'dinit-userservd',
    ['cpp'],
    version: '0.1.0',
    default_options: [
        'cpp_std=c++17', 'warning_level=3', 'buildtype=debugoptimized',
        'cpp_eh=none', 'cpp_rtti=false',
    ],
    license: 'BSD-2-Clause'
)

cpp = meson.get_compiler('cpp')

pam_dep = dependency('pam', required: true)
rt_dep = cpp.find_library('rt', required: false)

conf_data = configuration_data()
conf_data.set_quoted('RUN_PATH', get_option('rundir'))
conf_data.set_quoted('CONF_PATH', join_paths(
    get_option('prefix'), get_option('sysconfdir')
))

configure_file(output: 'config.hh', configuration: conf_data)

extra_inc = [include_directories('.')]

daemon_sources = [
    'dinit-userservd.cc',
    'fs_utils.cc',
    'cfg_utils.cc',
]

daemon = executable(
    'dinit-userservd', daemon_sources,
    include_directories: extra_inc,
    install: true,
    dependencies: [rt_dep],
    gnu_symbol_visibility: 'hidden'
)

pam_mod = shared_module(
    'pam_dinit_userservd', 'pam_dinit_userservd.cc',
    include_directories: extra_inc,
    install: true,
    install_dir: join_paths(get_option('libdir'), 'security'),
    name_prefix: '',
    dependencies: [pam_dep],
    gnu_symbol_visibility: 'hidden'
)

install_data(
    'dinit-userservd',
    install_dir: join_paths(get_option('sysconfdir'), 'dinit.d'),
    install_mode: 'rw-r--r--'
)

uconf_data = configuration_data()
uconf_data.set('RUN_PATH', get_option('rundir'))

configure_file(
    input: 'dinit-userservd.conf.in',
    output: 'dinit-userservd.conf',
    configuration: uconf_data,
    install: true,
    install_dir: get_option('sysconfdir'),
    install_mode: 'rw-r--r--'
)
