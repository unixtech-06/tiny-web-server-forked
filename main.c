/*
 * Implementation of a simple web server based on the tiny-web-server project.
 * This server handles basic HTTP requests and serves static content.
 *
 * See: https://github.com/shenfeng/tiny-web-server
 */

#include <sys/types.h>		/* Include system types first. */
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "pathname.h"

char *default_mime_type = "text/plain";

/* rio_t structure initialization function */
static void 
rio_readinitb(rio_t * rp, int fd)
{
	rp->rio_fd = fd;	/* Assign the file descriptor */
	rp->rio_cnt = 0;	/* Initialize the unread bytes count */
	rp->rio_bufptr = rp->rio_buf;	/* Initialize buffer pointer */
}

/* Robustly writes 'n' bytes (buffered) */
static ssize_t 
writen(int fd, const void *usrbuf, size_t n)
{
	size_t nleft = n;
	ssize_t nwritten;
	const char *bufp = usrbuf;

	if (fd < 0) {
		fprintf(stderr, "Invalid file descriptor\n");
		return -1;
		//Error handling for invalid file descriptor
	}

		while (nleft > 0) {
			if ((nwritten = write(fd, bufp, nleft)) <= 0) {
				if (errno == EINTR)
					nwritten = 0;	/* Call was interrupted */
				else
					return -1;	/* An error occurred */
			}
			nleft -= nwritten;
			bufp += nwritten;
		}
	return n;
}

/* Buffered read function for rio_t structure */
static ssize_t
rio_read(rio_t * rp, char *usrbuf, size_t n)
{
	while (rp->rio_cnt <= 0) {	/* Refill if buffer is empty */
		rp->rio_cnt = read(rp->rio_fd, rp->rio_buf, RIO_BUFSIZE);
		if (rp->rio_cnt < 0) {
			if (errno != EINTR)
				return -1;	/* An error occurred,
						 * not EINTR */
		} else if (rp->rio_cnt == 0) {
			return 0;	/* EOF */
		} else {
			rp->rio_bufptr = rp->rio_buf;	/* Reset buffer pointer */
		}
	}

	int cnt = n;
	if (rp->rio_cnt < n) {
		cnt = rp->rio_cnt;	/* Copy min(n, rp->rio_cnt)
					 * bytes */
	}
	memcpy(usrbuf, rp->rio_bufptr, cnt);
	rp->rio_bufptr += cnt;
	rp->rio_cnt -= cnt;
	return cnt;
}

/* Reads a line (terminated by '\n') into a buffer */
static ssize_t
rio_readlineb(rio_t * rp, void *usrbuf, size_t maxlen)
{
	int n, rc;
	char c = 0, *bufp = usrbuf;

	for  (n = 1; n < maxlen; n++) {
		if ((rc = rio_read(rp, &c, 1)) == 1) {
			*bufp++ = c;
			if (c == '\n')
				break;	/* New line is stored,
					 * including '\n' */
		} else if (rc == 0) {
			if (n == 1)
				return 0;	/* EOF, no data read */
			else
				break;	/* EOF, some data was read */
		} else
			return -1;	/* Error */
	}
	*bufp = 0;	/* Null-terminate the string */
	return n;
}

/* Formats the size of a file/directory for display */
void
format_size(char *buf, const struct stat *stat)
{
	if (S_ISDIR(stat->st_mode)) {
		sprintf(buf, "%s", "[DIR]");	/* Directory indicator */
	} else {
		const off_t size = stat->st_size;	/* File size */
		/* Format size into a human-readable string */
		if    (size < 1024) {
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
	/* Send HTTP header */
	     sprintf(buf, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><style>body{font-family: monospace; font-size: 13px;}td {padding: 1.5px 6px;}</style></head><body><table>\n");
	     writen(out_fd, buf, strlen(buf));

	DIR *d = fdopendir(dir_fd);
	struct dirent *dp;
	int ffd;
	while ((dp = readdir(d)) != NULL) {
		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, "..")) {
			continue;	/* Skip '.' and '..' */
		}
		if   ((ffd = openat(dir_fd, dp->d_name, O_RDONLY)) == -1) {
			perror(dp->d_name);
			continue;	/* Skip files that can't be
					 * opened */
		}
		fstat(ffd, &statbuf);
		/* Format modification time and size */
		char size[16], m_time[32];
		strftime(m_time, sizeof(m_time), "%Y-%m-%d %H:%M", localtime(&statbuf.st_mtime));
		format_size(size, &statbuf);
		/* Generate table row for each file/directory */
		char *d = S_ISDIR(statbuf.st_mode) ? "/" : "";
		sprintf(buf, "<tr><td><a href=\"%s%s\">%s%s</a></td><td>%s</td><td>%s</td></tr>\n", dp->d_name, d, dp->d_name, d, m_time, size);
		writen(out_fd, buf, strlen(buf));
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
	if   (dot) {
		const mime_map *map = meme_types;
		while    (map->extension) {
			if (strcmp(map->extension, dot) == 0) {
				return map->mime_type;
			}
			     map++;
		}
	}
	return default_mime_type;	/* Default MIME type if no
					 * extension matches */
}

/* Opens a listening socket on the specified port */
int
open_listenfd(int port)
{
	int listenfd, optval = 1;
	struct sockaddr_in serveraddr;

	/* Create a socket */
	if          ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		            return -1;

	/* Eliminate "Address already in use" error from bind */
	if          (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int)) < 0) {
		close(listenfd);
		return -1;
	}
	/* Additional options for performance and compatibility */
#ifdef __linux__
	if  (setsockopt(listenfd, IPPROTO_TCP, TCP_CORK, (const void *)&optval, sizeof(int)) < 0) {
		close(listenfd);
		return -1;
	}
#elif defined(__APPLE__)
	if (setsockopt(listenfd, IPPROTO_TCP, TCP_NOPUSH, (const void *)&optval, sizeof(int)) < 0) {
		close(listenfd);
		return -1;
	}
#endif

	/* Bind the socket to the address */
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons((unsigned short)port);
	if (bind(listenfd, (SA *) & serveraddr, sizeof(serveraddr)) < 0) {
		close(listenfd);
		return -1;
	}
	/* Convert the socket to a listening socket */
	if (listen(listenfd, LISTENQ) < 0) {
		close(listenfd);
		return -1;
	}
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
			memcpy(code, ++p, 2);	/* Copy the next two hex
						 * digits */
			*dest++ = (char)strtoul(code, NULL, 16);	/* Convert hex to char */
			p += 2;	/* Move past the digits */
		} else {
			*dest++ = *p++;	/* Copy the character */
		}
	}
	*dest = '\0';	/* Null-terminate the destination */
}

/* Parses an HTTP request */
void
parse_request(int fd, http_request * req)
{
	rio_t rio;
	char buf[MAXLINE] = {0};
	char method[MAXLINE] = {0}, uri[MAXLINE] = {0};
	     req->offset = 0;
	     req->end = 0;	/* Default values */

	     rio_readinitb(&rio, fd);
	     rio_readlineb(&rio, buf, MAXLINE);	/* Read the request line */
	     sscanf(buf, "%s %s", method, uri);	/* Parse method and URI */

	/* Read and ignore headers */
	while (strcmp(buf, "\n") && strcmp(buf, "\r\n")) {
		rio_readlineb(&rio, buf, MAXLINE);
		/* Look for "Range" header */
		if (!strncmp(buf, "Range: bytes=", 13)) {
			sscanf(buf, "Range: bytes=%llu-%zu", &req->offset, &req->end);
			if (req->end != 0)
				req->end++;	/* Adjust end if range
						 * is specified */
		}
	}

	/* Decode the URI to get the filename */
	char *filename = uri;
	if (uri[0] == '/') {
		filename = uri + 1;	/* Skip the leading slash */
		int length = strlen(filename);
		if (length == 0) {
			filename = ".";	/* Default filename */
		} else {
			/* Remove query string if present */
			for (int i = 0; i < length; ++i) {
				if (filename[i] == '?') {
					filename[i] = '\0';
					break;
				}
			}
		}
	}
	url_decode(filename, req->filename, MAXLINE);	/* Decode the filename */
}

/* Logs access details to stdout */
void
log_access(int status, struct sockaddr_in *c_addr, http_request * req)
{
	printf("%s:%d %d - %s\n", inet_ntoa(c_addr->sin_addr), ntohs(c_addr->sin_port), status, req->filename);
}

/* Sends an error message to the client */
void
client_error(int fd, int status, char *msg, char *longmsg)
{
	char buf[MAXLINE];
	/* Construct and send the HTTP response */
	     sprintf(buf, "HTTP/1.1 %d %s\r\n", status, msg);
	     sprintf(buf + strlen(buf), "Content-length: %lu\r\n\r\n", strlen(longmsg));
	     sprintf(buf + strlen(buf), "%s", longmsg);
	     writen(fd, buf, strlen(buf));
}

/* Serves static content to the client */
void
serve_static(int out_fd, int in_fd, const http_request * req, size_t total_size)
{
	char buf[512];
	off_t len = req->end - req->offset;	/* Calculate the content
						 * length */

	/* Construct HTTP response headers */
	if    (req->offset > 0) {
		snprintf(buf, sizeof(buf), "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes %llu-%lu/%lu\r\n", req->offset, req->end - 1, total_size);
	} else {
		snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\n");
	}
	/* Additional headers */
	snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "Cache-Control: no-cache\r\n");
	snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "Content-Length: %lld\r\n", len);
	snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "Content-Type: %s\r\n\r\n", get_mime_type(req->filename));

	write(out_fd, buf, strlen(buf));	/* Send headers */

	off_t offset = req->offset;
	while (len > 0) {
		/* Use sendfile to send the file content directly from
		 * file descriptor to socket */
		const ssize_t sent = sendfile(in_fd, out_fd, offset, &len, NULL, 0);
		if (sent == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;	/* Retry on interruption
						 * or try again */
			} else {
				perror("sendfile");
				break;	/* Break on other errors */
			}
		}
		offset += sent;
		len -= sent;
	}
}

/* Main server processing function */
void
process(int fd, struct sockaddr_in *clientaddr)
{
	printf("accept request, fd is %d, pid is %d\n", fd, getpid());
	http_request req;
	             parse_request(fd, &req);	/* Parse the HTTP
						 * request */

	struct stat sbuf;
	int status = 200;	/* Default HTTP status code */
	const int ffd = open(req.filename, O_RDONLY, 0);	/* Open the requested
								 * file */
	if  (ffd <= 0) {
		status = 404;	/* File not found */
		client_error(fd, status, "Not found", "File not found");
	} else {
		if (fstat(ffd, &sbuf) < 0) {
			perror("fstat error");
			close(ffd);	/* Close file descriptor on
					 * error */
			return;
		}
		if (S_ISREG(sbuf.st_mode)) {	/* Serve a regular file */
			if (req.end == 0) {
				req.end = sbuf.st_size;	/* Set end if not
							 * specified */
			}
			serve_static(fd, ffd, &req, sbuf.st_size);
		} else if (S_ISDIR(sbuf.st_mode)) {	/* Serve a directory
							 * listing */
			handle_directory_request(fd, ffd, req.filename);
		} else {
			status = 400;	/* Unknown error */
			client_error(fd, status, "Error", "Unknown Error");
		}
		close(ffd);	/* Close the file descriptor */
	}
	log_access(status, clientaddr, &req);	/* Log the access */
	close(fd);	/* Close the connection */
}

/* Main function: sets up listening socket and processes requests */
int
main(int argc, char **argv)
{
	int default_port = 9999;
	socklen_t clientlen;
	struct sockaddr_in clientaddr;

	if          (argc == 2) {
		default_port = atoi(argv[1]);	/* Allow port to be
						 * specified */
	}
	int listenfd = open_listenfd(default_port);	/* Open listening socket */
	if (listenfd < 0) {
		perror("ERROR opening listen socket");
		exit(1);
	}
	printf("tiny web server listening on port %d\n", default_port);

	while (1) {
		clientlen = sizeof(clientaddr);
		int connfd = accept(listenfd, (SA *) & clientaddr, &clientlen);	/* Accept connections */
		if (connfd < 0) {
			perror("ERROR on accept");
			continue;	/* Continue to accept next
					 * connection */
		}
		int pid = fork();	/* Fork a new process to
					 * handle the request */
		if (pid < 0) {
			perror("ERROR on fork");
			close(connfd);	/* Close connection on error */
			continue;
		}
		if (pid == 0) {	/* Child process */
			close(listenfd);	/* Close listening
						 * socket in child */
			process(connfd, &clientaddr);	/* Process request */
			exit(0);	/* Exit child process */
		} else {/* Parent process */
			close(connfd);	/* Close connected socket in
					 * parent */
		}
	}

	/* Should never reach here */
	//return 0;
}
