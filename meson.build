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

daemon = executable(
    'dinit-userservd', 'dinit-userservd.cc',
    install: true,
    dependencies: [rt_dep],
    gnu_symbol_visibility: 'hidden'
)

pam_mod = shared_module(
    'pam_dinit_userservd', 'pam_dinit_userservd.cc',
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
