set(ALLOC DYNAMIC CACHE INTERNAL "")
set(FP_PRIME 381 CACHE INTERNAL "")
set(SHLIB OFF CACHE INTERNAL "")
set(STLIB ON CACHE INTERNAL "")
set(SEED UDEV CACHE INTERNAL "")
set(RAND HASH CACHE INTERNAL "")
set(TESTS 0 CACHE INTERNAL "")
set(BENCH 0 CACHE INTERNAL "")

set(CHECK OFF CACHE INTERNAL "")
set(VERBS OFF CACHE INTERNAL "")
set(FP_PMERS OFF CACHE INTERNAL "")
set(FP_QNRES ON CACHE INTERNAL "")
set(FPX_METHD "INTEG;INTEG;LAZYR" CACHE INTERNAL "")
set(EP_PLAIN OFF CACHE INTERNAL "")
set(EP_SUPER OFF CACHE INTERNAL "")
set(PP_METHD "LAZYR;OATEP" CACHE INTERNAL "")
set(STRIP ON CACHE INTERNAL "")
set(WITH "MD;BN;DV;FP;FPX;EP;EPX;PC;PP"  CACHE INTERNAL "")


set(MD_METHD SH384 CACHE INTERNAL "")
set(MD_MAP SH384 CACHE INTERNAL "")
set(COMP "-O3 -funroll-loops -fomit-frame-pointer -finline-small-functions -march=native -mtune=native" CACHE INTERNAL "")
set(FP_METHD "INTEG;COMBA;COMBA;MONTY;MONTY;SLIDE" CACHE INTERNAL "")