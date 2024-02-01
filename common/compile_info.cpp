#if defined(__osecVERSION__) && defined(__REVISION__) && defined(__DATE__) && defined(__TIME__)
    char BUILD_VERSION[] = "BUILD_INFO: " __osecVERSION__ " " __REVISION__ " " __DATE__ " " __TIME__;
#elif defined(__osecVERSION__) && defined(_REVISION__)
    char BUILD_VERSION[] = "BUILD_INFO: " __osecVERSION__ " " __REVISION__;
#elif defined(__osecVERSION__)
    char BUILD_VERSION[] = "BUILD_INFO: " __osecVERSION__;
#elif defined(__REVISION__)
    char BUILD_VERSION[] = "BUILD_INFO: " __REVISION__;
#else
    char BUILD_VERSION[] = "unknown";
#endif
