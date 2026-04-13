project(
  'coova-chilli',
  'c',
  version: '1.8',
  meson_version: '>= 0.59.0',
  license: 'GPL-2.0-or-later',
  default_options: [
    'c_std=c99',
    'warning_level=2',
    'default_library=shared',
  ],
)

cc = meson.get_compiler('c')

add_project_arguments('-D_GNU_SOURCE', language: 'c')
add_project_arguments(
  '-Wall',
  '-fno-builtin',
  '-fno-strict-aliasing',
  '-fomit-frame-pointer',
  '-funroll-loops',
  '-pipe',
  language: 'c',
)

prefix = get_option('prefix')
sysconfdir = join_paths(prefix, get_option('sysconfdir'))
sbindir = join_paths(prefix, get_option('sbindir'))
localstatedir = join_paths(prefix, get_option('localstatedir'))
runstatedir = join_paths(localstatedir, 'run')

add_project_arguments(
  '-DDEFCHILLICONF="@0@"'.format(join_paths(sysconfdir, 'chilli.conf')),
  '-DDEFPIDFILE="@0@"'.format(join_paths(runstatedir, 'chilli.pid')),
  '-DDEFSTATEDIR="@0@"'.format(runstatedir),
  '-DSBINDIR="@0@"'.format(sbindir),
  language: 'c',
)

subdir('src')
subdir('conf')
subdir('doc')
subdir('www')
