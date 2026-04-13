bstring_dep = dependency('bstring', method: 'pkg-config', required: true)
json_dep = dependency('json-c', method: 'pkg-config', required: true)

# --- config.h (équivalent des tests Autoconf utiles au code) ---
conf = configuration_data()
conf.set_quoted('PACKAGE', meson.project_name())
conf.set_quoted('VERSION', meson.project_version())

# Fonctionnalités figées (configure.ac)
foreach d : [
  'ENABLE_CHILLIQUERY',
  'ENABLE_LEAKYBUCKET',
  'ENABLE_UAMUIPORT',
  'ENABLE_ACCOUNTING_ONOFF',
  'ENABLE_TCPRESET',
  'ENABLE_DEBUG',
  'ENABLE_DHCPRADIUS',
  'ENABLE_COA',
  'ENABLE_COOVACHILLICONFIG',
  'ENABLE_LARGELIMITS',
  'HAVE_SFHASH',
  'ENABLE_JSON',
]
  conf.set10(d, true)
endforeach

if get_option('nfcoova')
  conf.set10('HAVE_NETFILTER_COOVA', true)
endif

openssl_opt = get_option('openssl')
if openssl_opt
  ssl_dep = dependency('openssl', required: true)
  conf.set10('HAVE_OPENSSL', true)
  # OpenSSL 3 marque MD5/SHA1/DES/ENGINE comme dépréciés ; le code historique
  # utilise encore ces API bas niveau (EVP serait une refonte large).
  add_project_arguments('-Wno-deprecated-declarations', language: 'c')
else
  ssl_dep = declare_dependency()
endif

# strlcpy : libc ou libbsd
strlcpy_dep = declare_dependency()
if cc.has_function(
  'strlcpy',
  prefix: '#define _DEFAULT_SOURCE\n#include <string.h>',
  args: '-D_DEFAULT_SOURCE',
)
  conf.set10('HAVE_STRLCPY', true)
else
  strlcpy_dep = dependency('libbsd', required: true)
  conf.set10('HAVE_STRLCPY', true)
  conf.set10('HAVE_LIBBSD_STRLCPY', true)
endif

# En-têtes simples
foreach p : [
  ['HAVE_ARPA_INET_H', 'arpa/inet.h'],
  ['HAVE_ERRNO_H', 'errno.h'],
  ['HAVE_FCNTL_H', 'fcntl.h'],
  ['HAVE_DIRENT_H', 'dirent.h'],
  ['HAVE_INTTYPES_H', 'inttypes.h'],
  ['HAVE_LIMITS_H', 'limits.h'],
  ['HAVE_NETDB_H', 'netdb.h'],
  ['HAVE_NETINET_IN_H', 'netinet/in.h'],
  ['HAVE_NETINET_TCP_H', 'netinet/tcp.h'],
  ['HAVE_STDINT_H', 'stdint.h'],
  ['HAVE_STDDEF_H', 'stddef.h'],
  ['HAVE_STDLIB_H', 'stdlib.h'],
  ['HAVE_STRING_H', 'string.h'],
  ['HAVE_STRINGS_H', 'strings.h'],
  ['HAVE_SYS_IOCTL_H', 'sys/ioctl.h'],
  ['HAVE_SYS_SOCKET_H', 'sys/socket.h'],
  ['HAVE_LINUX_SYSINFO_H', 'linux/sysinfo.h'],
  ['HAVE_SYS_SYSINFO_H', 'sys/sysinfo.h'],
  ['HAVE_SYS_PARAM_H', 'sys/param.h'],
  ['HAVE_SYS_TIME_H', 'sys/time.h'],
  ['HAVE_TIME_H', 'time.h'],
  ['HAVE_SYS_IPC_H', 'sys/ipc.h'],
  ['HAVE_SYS_MSG_H', 'sys/msg.h'],
  ['HAVE_SIGNAL_H', 'signal.h'],
  ['HAVE_SYS_WAIT_H', 'sys/wait.h'],
  ['HAVE_SYS_UN_H', 'sys/un.h'],
  ['HAVE_IFADDRS_H', 'ifaddrs.h'],
  ['HAVE_SYS_STAT_H', 'sys/stat.h'],
  ['HAVE_SYS_TYPES_H', 'sys/types.h'],
  ['HAVE_REGEX_H', 'regex.h'],
  ['HAVE_SYSLOG_H', 'syslog.h'],
  ['HAVE_POLL_H', 'poll.h'],
  ['HAVE_SYS_EPOLL_H', 'sys/epoll.h'],
  ['HAVE_UNISTD_H', 'unistd.h'],
  ['HAVE_ENDIAN_H', 'endian.h'],
  ['HAVE_LIBGEN_H', 'libgen.h'],
  ['HAVE_ASM_TYPES_H', 'asm/types.h'],
  ['HAVE_PWD_H', 'pwd.h'],
  ['HAVE_GRP_H', 'grp.h'],
  ['HAVE_WCHAR_H', 'wchar.h'],
  ['HAVE_STDARG_H', 'stdarg.h'],
]
  if cc.has_header(p[1])
    conf.set10(p[0], true)
  endif
endforeach

net_hdr_prefix = '''#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
'''
foreach p : [
  ['HAVE_RESOLV_H', 'resolv.h'],
  ['HAVE_NET_ROUTE_H', 'net/route.h'],
  ['HAVE_NET_IF_H', 'net/if.h'],
  ['HAVE_NET_IF_ARP_H', 'net/if_arp.h'],
  ['HAVE_NET_IF_TUN_H', 'net/if_tun.h'],
  ['HAVE_NET_ETHERNET_H', 'net/ethernet.h'],
]
  if cc.has_header(p[1], prefix: net_hdr_prefix)
    conf.set10(p[0], true)
  endif
endforeach

# tpacket_stats (acsite.m4), Linux uniquement
if host_machine.system() == 'linux'
  if cc.compiles(
    '''
#include <linux/if_packet.h>
int main(void) { struct tpacket_stats s; (void)sizeof(s); return 0; }
''',
    name: 'struct tpacket_stats',
  )
    conf.set10('HAVE_TPACKET_STATS', true)
  endif
endif

# clock_gettime / HAVE_LIBRT (comportement souhaité si monotonic disponible)
tscode = '''
#define _DEFAULT_SOURCE
#include <time.h>
int main(void) {
  struct timespec ts;
  return clock_gettime(CLOCK_MONOTONIC, &ts);
}
'''
librt = cc.find_library('rt', required: false)
rt_dep = declare_dependency()
if cc.links(tscode, name: 'clock_gettime libc')
  conf.set10('HAVE_LIBRT', true)
elif librt.found() and cc.links(tscode, dependencies: librt, name: 'clock_gettime librt')
  conf.set10('HAVE_LIBRT', true)
  rt_dep = librt
endif

# res_init / -lresolv
resolv_lib = cc.find_library('resolv', required: false)
resolv_dep = declare_dependency()
rescode = '#include <resolv.h>\nint main(void) { return res_init(); }\n'
if cc.links(rescode, name: 'res_init libc')
  resolv_dep = declare_dependency()
elif resolv_lib.found() and cc.links(rescode, dependencies: resolv_lib, name: 'res_init libresolv')
  resolv_dep = resolv_lib
endif

# Fonctions (AC_CHECK_FUNCS)
gnu_src = '#define _GNU_SOURCE\n#include <stdio.h>\n#include <string.h>\n#include <stdlib.h>\n'
foreach f : [
  ['HAVE_BZERO', 'bzero', '#include <strings.h>\n'],
  ['HAVE_CLOCK_GETTIME', 'clock_gettime', '#define _DEFAULT_SOURCE\n#include <time.h>\n'],
  ['HAVE_DUP2', 'dup2', '#include <unistd.h>\n'],
  ['HAVE_GETHOSTBYNAME', 'gethostbyname', '#include <netdb.h>\n'],
  ['HAVE_GETPROTOENT', 'getprotoent', '#include <netdb.h>\n'],
  ['HAVE_GETTIMEOFDAY', 'gettimeofday', '#include <sys/time.h>\n'],
  ['HAVE_INET_NTOA', 'inet_ntoa', '#include <arpa/inet.h>\n'],
  ['HAVE_MEMCHR', 'memchr', '#include <string.h>\n'],
  ['HAVE_MEMMOVE', 'memmove', '#include <string.h>\n'],
  ['HAVE_MEMSET', 'memset', '#include <string.h>\n'],
  ['HAVE_MKDIR', 'mkdir', '#include <sys/stat.h>\n#include <sys/types.h>\n'],
  ['HAVE_MUNMAP', 'munmap', '#include <sys/mman.h>\n'],
  ['HAVE_REGCOMP', 'regcomp', '#include <regex.h>\n'],
  ['HAVE_SELECT', 'select', '#include <sys/select.h>\n'],
  ['HAVE_SETENV', 'setenv', gnu_src],
  ['HAVE_SOCKET', 'socket', '#include <sys/socket.h>\n'],
  ['HAVE_STRCASECMP', 'strcasecmp', '#include <strings.h>\n'],
  ['HAVE_STRCHR', 'strchr', '#include <string.h>\n'],
  ['HAVE_STRCSPN', 'strcspn', '#include <string.h>\n'],
  ['HAVE_STRDUP', 'strdup', '#include <string.h>\n'],
  ['HAVE_STRERROR', 'strerror', '#include <string.h>\n'],
  ['HAVE_STRNCASECMP', 'strncasecmp', '#include <strings.h>\n'],
  ['HAVE_STRNDUP', 'strndup', gnu_src],
  ['HAVE_STRRCHR', 'strrchr', '#include <string.h>\n'],
  ['HAVE_STRSPN', 'strspn', '#include <string.h>\n'],
  ['HAVE_STRSTR', 'strstr', '#include <string.h>\n'],
  ['HAVE_STRTOL', 'strtol', '#include <stdlib.h>\n'],
  ['HAVE_DIRNAME', 'dirname', '#include <libgen.h>\n'],
  ['HAVE_GLOB', 'glob', '#define _GNU_SOURCE\n#include <glob.h>\n'],
  ['HAVE_GETADDRINFO', 'getaddrinfo', '#include <sys/types.h>\n#include <sys/socket.h>\n#include <netdb.h>\n'],
  ['HAVE_GETNAMEINFO', 'getnameinfo', '#include <sys/socket.h>\n#include <netdb.h>\n'],
  ['HAVE_GETIFADDRS', 'getifaddrs', '#include <ifaddrs.h>\n'],
  ['HAVE_SYSINFO', 'sysinfo', '#include <sys/sysinfo.h>\n'],
  ['HAVE_TZSET', 'tzset', '#include <time.h>\n'],
  ['HAVE_SNPRINTF', 'snprintf', '#include <stdio.h>\n'],
  ['HAVE_VSNPRINTF', 'vsnprintf', '#include <stdio.h>\n#include <stdarg.h>\n'],
  ['HAVE_VASPRINTF', 'vasprintf', gnu_src],
]
  if cc.has_function(f[1], prefix: f[2], args: '-D_DEFAULT_SOURCE')
    conf.set10(f[0], true)
  endif
endforeach

if cc.has_function(
  'getline',
  prefix: '#define _GNU_SOURCE\n#include <stdio.h>\n',
  args: '-D_DEFAULT_SOURCE',
)
  conf.set10('HAVE_GETLINE', true)
endif

config_h = configure_file(configuration: conf, output: 'config.h', install_dir: join_paths(get_option('includedir'), 'chilli'))

# --- Génération cmdline (gengetopt + patch) ---
sh = find_program('sh')
find_program('gengetopt', required: true)
find_program('patch', required: true)

cmdline_gen = custom_target(
  'cmdline',
  input: files(
    'cmdline.ggo',
    'cmdline.patch',
    '../scripts/meson-gen-cmdline.sh',
  ),
  output: ['cmdline.c', 'cmdline.h'],
  command: [sh, files('../scripts/meson-gen-cmdline.sh'), meson.current_source_dir(), meson.current_build_dir()],
  install: true,
  install_dir: [false, join_paths(get_option('includedir'), 'chilli')],
)

lib_sources = files(
  'chilli.c',
  'tun.c',
  'ippool.c',
  'radius.c',
  'md5.c',
  'redir.c',
  'dhcp.c',
  'iphash.c',
  'lookup.c',
  'util.c',
  'options.c',
  'statusfile.c',
  'conn.c',
  'sig.c',
  'garden.c',
  'dns.c',
  'session.c',
  'pkt.c',
  'chksum.c',
  'net.c',
  'safe.c',
  'sfhash.c',
  'cmdsock.c',
)

if openssl_opt
  lib_sources += files('ssl.c', 'ms_chap.c')
endif

if get_option('nfcoova')
  lib_sources += files('kcoova.c')
endif

inc = include_directories('.')

# chilli.c référence `_options` défini dans les main.c des binaires (comportement historique libtool).
lib_deps = [bstring_dep, json_dep, strlcpy_dep, rt_dep, resolv_dep]
if openssl_opt
  lib_deps += ssl_dep
endif

libchilli = shared_library(
  'chilli',
  lib_sources,
  include_directories: inc,
  dependencies: lib_deps,
  override_options: ['b_lundef=false'],
  install: true,
)

exe_deps = [bstring_dep, json_dep, strlcpy_dep, rt_dep, resolv_dep]
if openssl_opt
  exe_deps += ssl_dep
endif

foreach e : [
  ['chilli', files('main.c')],
  ['chilli_response', files('main-response.c')],
  ['chilli_radconfig', files('main-radconfig.c')],
  ['chilli_query', files('main-query.c')],
]
  executable(
    e[0],
    e[1],
    include_directories: inc,
    link_with: libchilli,
    dependencies: exe_deps,
    install: true,
    install_dir: get_option('sbindir'),
  )
endforeach

# cmdline.c / cmdline.h attendent PACKAGE et VERSION (config.h) avant inclusion.
executable(
  'chilli_opt',
  files('main-opt.c') + [cmdline_gen],
  include_directories: inc,
  link_with: libchilli,
  dependencies: exe_deps,
  c_args: ['-include', 'config.h'],
  install: true,
  install_dir: get_option('sbindir'),
)

install_headers(
  files(
    'chilli.h',
    'session.h',
    'garden.h',
    'radius.h',
    'options.h',
    'tun.h',
    'ippool.h',
    'md5.h',
    'redir.h',
    'dhcp.h',
    'iphash.h',
    'radius_coovachilli.h',
    'ssl.h',
    'dns.h',
    'net.h',
    'pkt.h',
    'conn.h',
    'lookup.h',
    'chilli_limits.h',
    'debug.h',
    'radius_pkt.h',
    'system.h',
    'cmdsock.h',
  ),
  install_dir: join_paths(get_option('includedir'), 'chilli'),
)