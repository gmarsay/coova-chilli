# Substitutions alignées sur conf/Makefile.am (sed)
c = configuration_data()
c.set('ETCDIR', sysconfdir)
c.set('SBINDIR', sbindir)
c.set('INITDIR', join_paths(sysconfdir, 'init.d'))
c.set('VARTMP', join_paths(localstatedir, 'tmp'))
c.set('VARRUN', runstatedir)
c.set('ETCCHILLI', join_paths(sysconfdir, 'chilli'))
c.set('SYSCONFDIR', sysconfdir)
c.set('PREFIX', prefix)

foreach tpl : [
  ['functions.in', 'functions', join_paths(get_option('sysconfdir'), 'chilli'), 'rwxr-xr-x'],
  ['up.sh.in', 'up.sh', join_paths(get_option('sysconfdir'), 'chilli'), 'rwxr-xr-x'],
  ['down.sh.in', 'down.sh', join_paths(get_option('sysconfdir'), 'chilli'), 'rwxr-xr-x'],
  ['newmulti.sh.in', 'newmulti.sh', join_paths(get_option('sysconfdir'), 'chilli'), 'rwxr-xr-x'],
  ['wpad.dat.in', 'wpad.dat', join_paths(get_option('sysconfdir'), 'chilli'), 'rwxr-xr-x'],
  ['chilli.in', 'chilli', join_paths(get_option('sysconfdir'), 'init.d'), 'rwxr-xr-x'],
  ['chilli.conf.in', 'chilli.conf', get_option('sysconfdir'), 'rw-r--r--'],
  ['defaults.in', 'defaults', join_paths(get_option('sysconfdir'), 'chilli'), 'rw-r--r--'],
]
  configure_file(
    input: tpl[0],
    output: tpl[1],
    configuration: c,
    install: true,
    install_dir: tpl[2],
    install_mode: tpl[3],
  )
endforeach
