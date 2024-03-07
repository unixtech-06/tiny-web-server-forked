/*
 * This software is based on the "tiny-web-server" project by Shenfeng at
 * https://github.com/shenfeng/tiny-web-server
 *
 * MIT License
 * Copyright (c) 2023 Ryosuke
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#pragma once

#include <sys/types.h>  /* Non-local includes in brackets. */
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <paths.h>      /* System paths */

/*
 * Constants for listening queue size, maximum line length, and buffer size.
 */
constexpr auto LISTENQ = 1024;
constexpr auto MAXLINE = 1024;
constexpr auto RIO_BUFSIZE = 1024;

/*
 * Robust I/O (Rio) package buffer structure.
 */
typedef struct {
    int rio_fd;                  /* Descriptor for this internal buffer */
    int rio_cnt;                 /* Unread bytes in this internal buffer */
    char *rio_bufptr;            /* Next unread byte in this internal buffer */
    char rio_buf[RIO_BUFSIZE];   /* Internal buffer */
} rio_t;

typedef struct sockaddr SA;

/*
 * HTTP request structure.
 */
typedef struct {
    char filename[512];          /* Requested filename */
    off_t offset;                /* Offset for Range requests */
    size_t end;                  /* End byte for Range requests */
} http_request;

/*
 * MIME type mapping.
 */
typedef struct {
    const char *extension;       /* File extension */
    const char *mime_type;       /* Corresponding MIME type */
} mime_map;

/*
 * Supported MIME types.
 */
mime_map meme_types[] = {
    {".css", "text/css"},
    {".gif", "image/gif"},
    {".htm", "text/html"},
    {".html", "text/html"},
    {".jpeg", "image/jpeg"},
    {".jpg", "image/jpeg"},
    {".ico", "image/x-icon"},
    {".js", "application/javascript"},
    {".pdf", "application/pdf"},
    {".mp4", "video/mp4"},
    {".png", "image/png"},
    {".svg", "image/svg+xml"},
    {".xml", "text/xml"},
    {NULL, NULL},
};

void format_size(char *buf, const struct stat *stat);
void handle_directory_request(int out_fd, int dir_fd, char *filename);
int open_listenfd(int port);
void url_decode(const char *src, char *dest, int max);
void parse_request(int fd, http_request *req);
void log_access(int status, struct sockaddr_in *c_addr, http_request *req);
void client_error(int fd, int status, char *msg, char *longmsg);
void serve_static(int out_fd, int in_fd, const http_request *req, size_t total_size);
void process(int fd, struct sockaddr_in *clientaddr);

int main(int argc, char **argv);

/*
 * Detailed function implementations follow.
 */
