
#ifndef RAWRXD_CORE_EXPORT_H
#define RAWRXD_CORE_EXPORT_H

#ifdef RAWRXD_CORE_STATIC_DEFINE
#  define RAWRXD_CORE_EXPORT
#  define RAWRXD_CORE_NO_EXPORT
#else
#  ifndef RAWRXD_CORE_EXPORT
#    ifdef RawrXD_CoreRuntime_EXPORTS
        /* We are building this library */
#      define RAWRXD_CORE_EXPORT 
#    else
        /* We are using this library */
#      define RAWRXD_CORE_EXPORT 
#    endif
#  endif

#  ifndef RAWRXD_CORE_NO_EXPORT
#    define RAWRXD_CORE_NO_EXPORT 
#  endif
#endif

#ifndef RAWRXD_CORE_DEPRECATED
#  define RAWRXD_CORE_DEPRECATED __declspec(deprecated)
#endif

#ifndef RAWRXD_CORE_DEPRECATED_EXPORT
#  define RAWRXD_CORE_DEPRECATED_EXPORT RAWRXD_CORE_EXPORT RAWRXD_CORE_DEPRECATED
#endif

#ifndef RAWRXD_CORE_DEPRECATED_NO_EXPORT
#  define RAWRXD_CORE_DEPRECATED_NO_EXPORT RAWRXD_CORE_NO_EXPORT RAWRXD_CORE_DEPRECATED
#endif

/* NOLINTNEXTLINE(readability-avoid-unconditional-preprocessor-if) */
#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef RAWRXD_CORE_NO_DEPRECATED
#    define RAWRXD_CORE_NO_DEPRECATED
#  endif
#endif

#endif /* RAWRXD_CORE_EXPORT_H */
