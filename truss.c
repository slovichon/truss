/* $Id$ */

#include <sys/types.h>
#include <sys/queue.h>

#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "truss.h"

#define PID_MAX SHRT_MAX

#define AT_FD	0
#define AT_SC	1
#define AT_SIG	2
#define AT_MF	3

static void usage(void) __attribute__((__noreturn__));
static void add_arg(int, struct arg_head *, char *);

pid_t	 attach_pid;
int	 follow_fork;
int	 show_count;
int	 show_args;
int	 show_env;
int	 show_intr_once;
int	 datefmt;
char	*outfile;

struct arg_head	hd_sc_show, hd_sc_xshow;
struct arg_head hd_sc_stop, hd_sc_xstop;
struct arg_head hd_sc_verbose, hd_sc_xverbose;
struct arg_head hd_sc_raw, hd_sc_xraw;
struct arg_head hd_sig_show, hd_sig_xshow;
struct arg_head hd_sig_stop, hd_sig_xstop;
struct arg_head hd_mf_show, hd_mf_xshow;
struct arg_head hd_mf_stop, hd_mf_xstop;
struct arg_head hd_fd_read, hd_fd_xread;
struct arg_head hd_fd_write, hd_fd_xwrite;

int
main(int argc, char *argv[])
{
	long l;
	int c;

	while ((c = getopt(argc, argv,
	    "acDdefio:p:r:S:s:T:t:v:w:x:")) != -1) {
		switch (c) {
		case 'a':
			show_args = 1;
			break;
		case 'c':
			show_count = 1;
			break;
		case 'D':
			datefmt = DFMT_REL;
			break;
		case 'd':
			datefmt = DFMT_ABS;
			break;
		case 'e':
			show_env = 1;
			break;
		case 'f':
			follow_fork = 1;
			break;
		case 'i':
			show_intr_once = 1;
			break;
		case 'o':
			outfile = optarg;
			break;
		case 'p':
			if ((l = strtoul(optarg, NULL, 10)) < 0 ||
			     l > PID_MAX)
				errx(1, "%s: invalid pid", optarg);
			attach_pid = (pid_t)l;
			break;
		case 'r':
			if (*optarg == '!')
				add_arg(AT_FD, &hd_fd_xread, ++optarg);
			else
				add_arg(AT_FD, &hd_fd_read, optarg);
			break;
		case 'S':
			if (*optarg == '!')
				add_arg(AT_SIG, &hd_sig_xstop, ++optarg);
			else
				add_arg(AT_SIG, &hd_sig_stop, optarg);
			break;
		case 's':
			if (*optarg == '!')
				add_arg(AT_SIG, &hd_sig_xshow, ++optarg);
			else
				add_arg(AT_SIG, &hd_sig_show, optarg);
			break;
		case 'T':
			if (*optarg == '!')
				add_arg(AT_SC, &hd_sc_xstop, ++optarg);
			else
				add_arg(AT_SC, &hd_sc_stop, optarg);
			break;
		case 't':
			if (*optarg == '!')
				add_arg(AT_SC, &hd_sc_xshow, ++optarg);
			else
				add_arg(AT_SC, &hd_sc_show, optarg);
			break;
		case 'v':
			if (*optarg == '!')
				add_arg(AT_SC, &hd_sc_xverbose, ++optarg);
			else
				add_arg(AT_SC, &hd_sc_verbose, optarg);
			break;
		case 'w':
			if (*optarg == '!')
				add_arg(AT_FD, &hd_fd_xwrite, ++optarg);
			else
				add_arg(AT_FD, &hd_fd_write, optarg);
			break;
		case 'x':
			if (*optarg == '!')
				add_arg(AT_SC, &hd_sc_xraw, ++optarg);
			else
				add_arg(AT_SC, &hd_sc_raw, optarg);
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (attach_pid) {
		if (argc)
			usage();
	} else if (!argc)
		usage();
	else {
	}
	exit(0);
}

void
add_arg(int type, struct arg_head *hd, char *s)
{
	struct arg *a;
	char *p;
	long l;

	for (; s != NULL; s = p) {
		if ((a = malloc(sizeof(*a))) == NULL)
			err(1, "malloc");
		if ((p = strchr(s, ',')) != NULL)
			*p++ = '\0';
		switch (type) {
		case AT_FD:
			if ((l = strtoul(s, NULL, 10)) < 0 ||
			     l > PID_MAX)
			a->arg_fd = (pid_t)l;
			break;
		default:
			a->arg_name = s;
			break;
		}
		SLIST_INSERT_HEAD(hd, a, arg_next);
	}
}

void
usage(void)
{
	extern char *__progname;

	(void)fprintf(stderr,
	    "usage: %s [-acDdefi] [-o file] [-r fds] [-S sigs]\n"
	    "\t     [-s sigs] [-T syscalls] [-t syscalls] [-v syscalls] [-w fds]\n"
	    "\t     [-x syscalls] command [argument ...]\n"
	    "       %s [-acDdefi] [-o file] [-r fds] [-S sigs]\n"
	    "\t     [-s sigs] [-T syscalls] [-t syscalls] [-v syscalls] [-w fds]\n"
	    "\t     [-x syscalls] -p pid\n", __progname, __progname);
	exit(1);
}
