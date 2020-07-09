#ifndef _LOG_H_
#define _LOG_H_

#if defined(ENABLE_REMOTE_LOG)
#include "log.h"
#else
#define log_e(tag, _f, _a ...) printf("%s ERR %s %d: "_f, tag, __FUNCTION__, __LINE__, ##_a)
//#define log_d(tag, _f, _a ...) printf("%s DBG %s %d: "_f, tag, __FUNCTION__, __LINE__, ##_a)
#define log_d(tag, _f, _a ...)
#endif

#endif /* _LOG_H_ */

