#include <stdio.h>
#include <stdarg.h>
#include <time.h>

void logger(const char *format, ...) {
    // 获取当前时间
    time_t rawtime;
    struct tm *timeinfo;
    char time_buffer[20];

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", timeinfo);

    // 打印时间戳
    printf("[%s] ", time_buffer);

    // 打印用户提供的消息
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}