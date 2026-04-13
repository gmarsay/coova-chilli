c = configuration_data()
c.set('SBINDIR', sbindir)
c.set('INITDIR', join_paths(sysconfdir, 'init.d'))
c.set('VARRUN', runstatedir)
c.set('ETCCHILLI', join_paths(sysconfdir, 'chilli'))
c.set('SYSCONFDIR', sysconfdir)
c.set('PREFIX', prefix)

configure_file(
  input: 'config.sh.in',
  output: 'config.sh',
  configuration: c,
  install: true,
  install_dir: join_paths(get_option('sysconfdir'), 'chilli', 'www'),
  install_mode: 'rw-r--r--',
)

install_data(
  'coova.html',
  install_dir: join_paths(get_option('sysconfdir'), 'chilli', 'www'),
)
