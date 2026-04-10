dnl
AC_DEFUN([AC_LBL_TPACKET_STATS],
   [AC_MSG_CHECKING(if if_packet.h has tpacket_stats defined)
   AC_CACHE_VAL(ac_cv_lbl_tpacket_stats,
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#  include <linux/if_packet.h>]], [[struct tpacket_stats stats]])],[ac_cv_lbl_tpacket_stats=yes],[ac_cv_lbl_tpacket_stats=no]))
   AC_MSG_RESULT($ac_cv_lbl_tpacket_stats)
   if test $ac_cv_lbl_tpacket_stats = yes; then
       AC_DEFINE(HAVE_TPACKET_STATS,1,[if if_packet.h has tpacket_stats defined])
   fi])