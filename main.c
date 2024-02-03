/*
* This software is based on the "tiny-web-server" project by Shenfeng at
 * https://github.com/shenfeng/tiny-web-server
 *
 * MIT License
 *
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


#include <sys/types.h>
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

#define LISTENQ 1024
#define MAXLINE 1024
#define RIO_BUFSIZE 1024

/* Constants for listening queue size, maximum line length, and buffer size */
#define LISTENQ 1024
#define MAXLINE 1024
#define RIO_BUFSIZE 1024

/* Robust I/O (Rio) package buffer structure */
typedef struct {
	int rio_fd;                  /* Descriptor for this internal buffer */
	int rio_cnt;                 /* Unread bytes in this internal buffer */
	char *rio_bufptr;            /* Next unread byte in this internal buffer */
	char rio_buf[RIO_BUFSIZE];   /* Internal buffer */
} rio_t;

typedef struct sockaddr SA;

/* HTTP request structure */
typedef struct {
	char filename[512];          /* Requested filename */
	off_t offset;                /* Offset for Range requests */
	size_t end;                  /* End byte for Range requests */
} http_request;

/* MIME type mapping */
typedef struct {
	const char *extension;       /* File extension */
	const char *mime_type;       /* Corresponding MIME type */
} mime_map;

/* Supported MIME types */
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

char *default_mime_type = "text/plain";

/* Initializes an internal buffer for the robust I/O operations */
static void 
rio_readinitb(rio_t * rp, int fd)
{
	rp->rio_fd = fd;
	rp->rio_cnt = 0;
	rp->rio_bufptr = rp->rio_buf;
}

/* Writes n bytes to a descriptor robustly */
static ssize_t 
writen(int fd, const void *usrbuf, size_t n)
{
	size_t nleft = n;
	ssize_t nwritten;
	const char *bufp = usrbuf;

	while (nleft > 0) {
		if ((nwritten = write(fd, bufp, nleft)) <= 0) {
			if (errno == EINTR)
				nwritten = 0;
			else
				return -1;
		}
		nleft -= nwritten;
		bufp += nwritten;
	}
	return n;
}

/* Reads up to n bytes from a descriptor into a buffer */
static ssize_t 
rio_read(rio_t * rp, char *usrbuf, size_t n)
{
	while (rp->rio_cnt <= 0) {
		rp->rio_cnt = read(rp->rio_fd, rp->rio_buf, RIO_BUFSIZE);
		if (rp->rio_cnt < 0) {
			if (errno != EINTR)
				return -1;
		} else if (rp->rio_cnt == 0)
			return 0;
		else
			rp->rio_bufptr = rp->rio_buf;
	}

	int cnt = n;
	if (rp->rio_cnt < n)
		cnt = rp->rio_cnt;
	memcpy(usrbuf, rp->rio_bufptr, cnt);
	rp->rio_bufptr += cnt;
	rp->rio_cnt -= cnt;
	return cnt;
}

/* Reads a line of text from a descriptor into a buffer */
static ssize_t 
rio_readlineb(rio_t * rp, void *usrbuf, size_t maxlen)
{
	int n, rc;
	char c, *bufp = usrbuf;

	for (n = 1; n < maxlen; n++) {
		if ((rc = rio_read(rp, &c, 1)) == 1) {
			*bufp++ = c;
			if (c == '\n')
				break;
		} else if (rc == 0) {
			if (n == 1)
				return 0;
			else
				break;
		} else
			return -1;
	}
	*bufp = 0;
	return n;
}

/* Formats the size of a file/directory for display */
void
format_size(char *buf, const struct stat *stat)
{
	if (S_ISDIR(stat->st_mode)) {
		sprintf(buf, "%s", "[DIR]");
	} else {
		const off_t size = stat->st_size;
		if (size < 1024) {
			sprintf(buf, "%llu", size);
		} else if (size < 1024 * 1024) {
			sprintf(buf, "%.1fK", (double)size / 1024);
		} else if (size < 1024 * 1024 * 1024) {
			sprintf(buf, "%.1fM", (double)size / 1024 / 1024);
		} else {
			sprintf(buf, "%.1fG", (double)size / 1024 / 1024 / 1024);
		}
	}
}

/* Handles directory requests by generating a dynamic HTML listing */
void
handle_directory_request(int out_fd, int dir_fd, char *filename)
{
	char buf[MAXLINE];
	struct stat statbuf;
	sprintf(buf, "HTTP/1.1 200 OK\r\n%s%s%s%s%s",
	    "Content-Type: text/html\r\n\r\n",
	    "<html><head><style>",
	    "body{font-family: monospace; font-size: 13px;}",
	    "td {padding: 1.5px 6px;}",
	    "</style></head><body><table>\n");
	writen(out_fd, buf, strlen(buf));
	DIR *d = fdopendir(dir_fd);
	struct dirent *dp;
	int ffd;
	while ((dp = readdir(d)) != NULL) {
		char size[16];
		char m_time[32];
		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, "..")) {
			continue;
		}
		if ((ffd = openat(dir_fd, dp->d_name, O_RDONLY)) == -1) {
			perror(dp->d_name);
			continue;
		}
		fstat(ffd, &statbuf);
		strftime(m_time, sizeof(m_time),
		    "%Y-%m-%d %H:%M", localtime(&statbuf.st_mtime));
		format_size(size, &statbuf);
		if (S_ISREG(statbuf.st_mode) || S_ISDIR(statbuf.st_mode)) {
			char *d = S_ISDIR(statbuf.st_mode) ? "/" : "";
			sprintf(buf, "<tr><td><a href=\"%s%s\">%s%s</a></td><td>%s</td><td>%s</td></tr>\n",
			    dp->d_name, d, dp->d_name, d, m_time, size);
			writen(out_fd, buf, strlen(buf));
		}
		close(ffd);
	}
	sprintf(buf, "</table></body></html>");
	writen(out_fd, buf, strlen(buf));
	closedir(d);
}

/* Determines the MIME type of a file based on its extension */
static const char *
get_mime_type(const char *filename)
{
	const char *dot = strrchr(filename, '.');
	if (dot) {
		//strrchar Locate last occurrence of character in string
		const mime_map * map = meme_types;
		while (map->extension) {
			if (strcmp(map->extension, dot) == 0) {
				return map->mime_type;
			}
			map++;
		}
	}
	return default_mime_type;
}

/* Opens a listening socket on the specified port */
int
open_listenfd(int port)
{
	int listenfd, optval = 1;
	struct sockaddr_in serveraddr;

	if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return -1;

	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
	    (const void *)&optval, sizeof(int)) < 0)
		return -1;

#ifdef __linux__
	if (setsockopt(listenfd, IPPROTO_TCP, TCP_CORK,
	    (const void *)&optval, sizeof(int)) < 0)
		return -1;
#elif defined(__APPLE__)
	if (setsockopt(listenfd, IPPROTO_TCP, TCP_NOPUSH,
	    (const void *)&optval, sizeof(int)) < 0)
		return -1;
#endif

	/* Listenfd will be an endpoint for all requests to port on any IP
	 * address for this host */
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons((unsigned short)port);
	if (bind(listenfd, (SA *) & serveraddr, sizeof(serveraddr)) < 0)
		return -1;

	/* Make it a listening socket ready to accept connection requests */
	if (listen(listenfd, LISTENQ) < 0)
		return -1;
	return listenfd;
}

/* Decodes URL-encoded strings */
void
url_decode(const char *src, char *dest, int max)
{
	const char *p = src;
	char code[3] = {0};
	while (*p && --max) {
		if (*p == '%') {
			memcpy(code, ++p, 2);
			*dest++ = (char)strtoul(code, NULL, 16);
			p += 2;
		} else {
			*dest++ = *p++;
		}
	}
	*dest = '\0';
}

/* Parses an HTTP request */
void
parse_request(int fd, http_request * req)
{
	rio_t rio;
	char buf[MAXLINE] = {0};
	char method[MAXLINE] = {0};
	char uri[MAXLINE] = {0};
	req->offset = 0;
	req->end = 0;		/* default */

	rio_readinitb(&rio, fd);
	rio_readlineb(&rio, buf, MAXLINE);
	sscanf(buf, "%s %s", method, uri);	/* version is not cared */
	/* read all */
	while (buf[0] != '\n' && buf[1] != '\n') {	/* \n || \r\n */
		rio_readlineb(&rio, buf, MAXLINE);
		if (buf[0] == 'R' && buf[1] == 'a' && buf[2] == 'n') {
			sscanf(buf, "Range: bytes=%llu-%zu", &req->offset, &req->end);
	//Range:	[start, end]
			    if (req->end != 0)
				req->end++;
		}
	}
	char *filename = uri;
	if (uri[0] == '/') {
		filename = uri + 1;
		const int length = strlen(filename);
		if (length == 0) {
			filename = ".";
		} else {
			for (int i = 0; i < length; ++i) {
				if (filename[i] == '?') {
					filename[i] = '\0';
					break;
				}
			}
		}
	}
	url_decode(filename, req->filename, MAXLINE);
}

/* Logs access details to stdout */
void
log_access(int status, struct sockaddr_in *c_addr, http_request * req)
{
	printf("%s:%d %d - %s\n", inet_ntoa(c_addr->sin_addr),
	    ntohs(c_addr->sin_port), status, req->filename);
}

/* Sends an error message to the client */
void
client_error(int fd, int status, char *msg, char *longmsg)
{
	char buf[MAXLINE];
	sprintf(buf, "HTTP/1.1 %d %s\r\n", status, msg);
	sprintf(buf + strlen(buf),
	    "Content-length: %lu\r\n\r\n", strlen(longmsg));
	sprintf(buf + strlen(buf), "%s", longmsg);
	writen(fd, buf, strlen(buf));
}

/* Serves static content to the client */
void
serve_static(int out_fd, int in_fd, const http_request * req, size_t total_size)
{
	char buf[512];
	off_t len = req->end - req->offset;

	if (req->offset > 0) {
		snprintf(buf, sizeof(buf), "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes %llu-%lu/%lu\r\n", req->offset, req->end - 1, total_size);
	} else {
		snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\n");
	}
	snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "Cache-Control: no-cache\r\n");
	snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "Content-Length: %lld\r\n", len);
	snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "Content-Type: %s\r\n\r\n", get_mime_type(req->filename));

	write(out_fd, buf, strlen(buf));

	off_t offset = req->offset;
	while (len > 0) {
		const ssize_t sent = sendfile(in_fd, out_fd, offset, &len, NULL, 0);
		if (sent == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			} else {
				perror("sendfile");
				break;
			}
		}
		offset += sent;
		len -= sent;
	}
}

/* Processes client requests */
void
process(int fd, struct sockaddr_in *clientaddr)
{
	printf("accept request, fd is %d, pid is %d\n", fd, getpid());
	http_request req;
	parse_request(fd, &req);

	struct stat sbuf;
	int status = 200;
	const int ffd = open(req.filename, O_RDONLY, 0);
	if (ffd <= 0) {
		status = 404;
		char *msg = "File not found";
		client_error(fd, status, "Not found", msg);
	} else {
		fstat(ffd, &sbuf);
		if (S_ISREG(sbuf.st_mode)) {
			if (req.end == 0) {
				req.end = sbuf.st_size;
			}
			if (req.offset > 0) {
				status = 206;
			}
			serve_static(fd, ffd, &req, sbuf.st_size);
		} else if (S_ISDIR(sbuf.st_mode)) {
			status = 200;
			handle_directory_request(fd, ffd, req.filename);
		} else {
			status = 400;
			char *msg = "Unknow Error";
			client_error(fd, status, "Error", msg);
		}
		close(ffd);
	}
	log_access(status, clientaddr, &req);
}

/* Main server loop */
int
main(int argc, char **argv) {
	struct sockaddr_in clientaddr;
	int default_port = 9999, connfd;
	char buf[256];
	[[maybe_unused]] const char *path = getcwd(buf, 256);
	socklen_t clientlen = sizeof clientaddr;
	if (argc == 2) {
		if (argv[1][0] >= '0' && argv[1][0] <= '9') {
			default_port = atoi(argv[1]);
		} else {
			path = argv[1];
			if (chdir(argv[1]) != 0) {
				perror(argv[1]);
				exit(1);
			}
		}
	} else if (argc == 3) {
		default_port = atoi(argv[2]);
		path = argv[1];
		if (chdir(argv[1]) != 0) {
			perror(argv[1]);
			exit(1);
		}
	}
	const int listenfd = open_listenfd(default_port);
	if (listenfd > 0) {
		printf("listen on port %d, fd is %d\n", default_port, listenfd);
	} else {
		perror("ERROR");
		exit(listenfd);
	}
	signal(SIGPIPE, SIG_IGN);

	for (int i = 0; i < 10; i++) {
		const int pid = fork();
		if (pid == 0) {
			//child
			while (1) {
				connfd = accept(listenfd, (SA *) & clientaddr, &clientlen);
				process(connfd, &clientaddr);
				close(connfd);
			}
		} else if (pid > 0) {
			//parent
			printf("child pid is %d\n", pid);
		} else {
			perror("fork");
		}
	}

	while (1) {
		connfd = accept(listenfd, (SA *) & clientaddr, &clientlen);
		process(connfd, &clientaddr);
		close(connfd);
	}

	return 0;
}