#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <netdb.h>

#include <sys/socket.h>

#define die(fmt, args...) \
do { \
	fprintf(stderr, fmt "\n", ##args); \
	exit(EXIT_FAILURE); \
} while (0)

#define fail(fmt, args...) die("Failed to " fmt, ##args)

static void usage(const char *argv0, int error_code)
{
	FILE *out = error_code == EXIT_SUCCESS ? stdout : stderr;

	fprintf(out,
"Usage: %s [OPTIONS] address port [content]\n"
"\n"
"Options:\n"
"  -h  show this message\n"
"  -n  no UDP checksum\n",
		argv0);
	exit(error_code);
}

int main(int argc, char *argv[])
{
	int sock, port, opt;
	struct sockaddr_in addr;
	bool no_check = false;
	struct hostent *he;
	char *content;
	int content_len;

	/* Parse the command line options */
	while ((opt = getopt(argc, argv, "hn")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0], EXIT_SUCCESS);
			break;
		case 'n':
			no_check = true;
			break;
		default:
			usage(argv[0], EXIT_FAILURE);
		}
	}
	if (optind + 2 != argc && optind + 3 != argc)
		usage(argv[0], EXIT_FAILURE);
	he = gethostbyname(argv[optind]);
	if (!he)
		fail("resolve name %s: %s", argv[optind], hstrerror(h_errno));
	if (he->h_addrtype != AF_INET) {
		die("Only support IPv4, but IPv6 address is returned by "
				"gethostbyname(3)");
	}
	if (he->h_length != 4)
		die("Buggy gethostbyname(3)");
	port = atoi(argv[optind + 1]);
	if (port < 0 || port > 65535)
		die("Invalid port: %s\n", argv[optind + 1]);
	if (optind + 3 == argc) {
		content = strdup(argv[optind + 2]);
		if (!content)
			die("OOM");
		content_len = strlen(content);
	} else {
		char buf[4096];
		int content_size, len;

		content = NULL;
		content_len = content_size = 0;
		while ((len = fread(buf, 1, sizeof(buf), stdin))) {
			if (content_len + len > content_size) {
				int new_size;

				new_size = content_len + len;
				if (new_size < content_size * 2)
					new_size = content_size * 2;
				content = realloc(content, new_size);
				if (!content)
					die("OOM");
				content_size = new_size;
			}
			memcpy(content + content_len, buf, len);
			content_len += len;
		}
		if (!content)
			die("No content");
	}

	sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		fail("create the sock");
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	memcpy(&addr.sin_addr, he->h_addr, sizeof(addr.sin_addr));
	addr.sin_port = htons(port);

	if (no_check) {
		int ok = 1;

		if (setsockopt(sock, SOL_SOCKET, SO_NO_CHECK, &ok, sizeof(ok)))
			fail("disable UDP checksum");
	}

	if (sendto(sock, content, content_len, 0,
			(struct sockaddr *)&addr, sizeof(addr)) < 0)
		fail("send the UDP message");

	free(content);
	close(sock);

	return EXIT_SUCCESS;
}
