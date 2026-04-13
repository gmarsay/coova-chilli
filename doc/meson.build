find_program('perl', required: true)

chilli_radius_out = join_paths(meson.current_build_dir(), 'chilli-radius.5')

c = configuration_data()
c.set('SBINDIR', sbindir)
c.set('INITDIR', join_paths(sysconfdir, 'init.d'))
c.set('VARRUN', runstatedir)
c.set('ETCCHILLI', join_paths(sysconfdir, 'chilli'))
c.set('SYSCONFDIR', sysconfdir)
c.set('PREFIX', prefix)

foreach page : [
  ['chilli.8.in', 'chilli.8', join_paths(get_option('mandir'), 'man8')],
  ['chilli.conf.5.in', 'chilli.conf.5', join_paths(get_option('mandir'), 'man5')],
  ['chilli_query.1.in', 'chilli_query.1', join_paths(get_option('mandir'), 'man1')],
  ['chilli_response.1.in', 'chilli_response.1', join_paths(get_option('mandir'), 'man1')],
  ['chilli_opt.1.in', 'chilli_opt.1', join_paths(get_option('mandir'), 'man1')],
  ['chilli_radconfig.1.in', 'chilli_radconfig.1', join_paths(get_option('mandir'), 'man1')],
]
  configure_file(
    input: page[0],
    output: page[1],
    configuration: c,
    install: true,
    install_dir: page[2],
    install_mode: 'rw-r--r--',
  )
endforeach

custom_target(
  'chilli-radius.5',
  output: 'chilli-radius.5',
  input: files('fmttxt.pl', 'attributes', 'chilli-radius.5.in'),
  command: [
    'sh',
    '-c',
    'mkdir -p "$(dirname "$2")" && cd "$1" && perl fmttxt.pl chilli-radius < attributes > "$2"',
    '_',
    meson.current_source_dir(),
    chilli_radius_out,
  ],
  install: true,
  install_dir: join_paths(get_option('mandir'), 'man5'),
  install_mode: 'rw-r--r--',
)

install_data(
  files(
    'dictionary.coovachilli',
    'attributes',
    'fmttxt.pl',
    'freeradius.users',
    'firewall.iptables',
  ),
  install_dir: join_paths(get_option('datadir'), meson.project_name()),
)
