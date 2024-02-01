/*
 * includes.h
 *
 *  Created on: Apr 17, 2015
 *      Author: th
 */

#ifndef INCLUDES_H_
#define INCLUDES_H_

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <libgen.h>
//#include <asm-generic/errno.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "winport.h"
#include <dlfcn.h>
#include <new> //std::nothrow
#include <string>
#include <list>
#include <map>
#include <vector>
#include <sys/file.h>

using namespace std;
#ifndef _WINDOWS
#define override   
#define _snprintf snprintf
#define _vscprintf(a,b) vsnprintf(0,0,a,b)
#define _vscwprintf(a,b) vswprintf(0,0,a,b)
#define stricmp strcasecmp
#define sprintf_s snprintf
#endif
#endif /* INCLUDES_H_ */
