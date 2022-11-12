project(
    'dinit-userservd',
    ['cpp'],
    version: '0.91.0',
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
conf_data.set10('MANAGE_RUNDIR', get_option('manage_rundir'))

statepath = join_paths(
    get_option('prefix'), get_option('localstatedir'),
    get_option('statedir')
)
lingerpath = join_paths(statepath, 'linger')

conf_data.set_quoted('STATE_PATH', statepath)
conf_data.set_quoted('LINGER_PATH', lingerpath)

configure_file(output: 'config.hh', configuration: conf_data)

extra_inc = [include_directories('src')]

daemon_sources = [
    'src/dinit-userservd.cc',
    'src/fs_utils.cc',
    'src/cfg_utils.cc',
    'src/dinit_utils.cc',
]

daemon = executable(
    'dinit-userservd', daemon_sources,
    include_directories: extra_inc,
    install: true,
    dependencies: [rt_dep],
    gnu_symbol_visibility: 'hidden'
)

pam_mod = shared_module(
    'pam_dinit_userservd', 'src/pam_dinit_userservd.cc',
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
uconf_data.set('LINGER_PATH', lingerpath)

if get_option('manage_rundir')
    uconf_data.set('MANAGE_RUNDIR', 'yes')
else
    uconf_data.set('MANAGE_RUNDIR', 'no')
endif

configure_file(
    input: 'dinit-userservd.conf.in',
    output: 'dinit-userservd.conf',
    configuration: uconf_data,
    install: true,
    install_dir: get_option('sysconfdir'),
    install_mode: 'rw-r--r--'
)
