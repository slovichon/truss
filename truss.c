/* $Id$ */

#include <sys/param.h>
#include <sys/uio.h>
#include <sys/ktrace.h>
#include <sys/queue.h>

#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "truss.h"

#define PID_MAX SHRT_MAX

#define AT_FD	0
#define AT_SC	1
#define AT_SIG	2
#define AT_MF	3

void add_arg(int, struct arg_head *, char *);
void loop(int);
void pr_psig(struct ktr_psig *);
void pr_syscall(struct ktr_syscall *);
void trace(void);
void usage(void) __attribute__((__noreturn__));

pid_t	 attach_pid;
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
	int c, fds[2], flags = 0;
	long l;

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
			flags |= KTRFLAG_DESCEND;
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

	if ((attach_pid && argc) || (!attach_pid && !argc))
		usage();

	if (outfile != NULL)
		if (freopen(outfile, "w", stderr) == NULL)
			err(1, "%s", outfile);

	if (pipe(fds) == -1)
		err(1, "pipe");

	if (!attach_pid) {
		switch (attach_pid = fork()) {
		case -1:
			err(1, "fork");
			/* NOTREACHED */
		case 0:
			(void)close(fds[0]);
			if (fktrace(fds[1], KTROP_SET | flags,
			    KTRFAC_SYSCALL | KTRFAC_PSIG,
			    attach_pid) == -1)
				err(1, "fktrace");
			execvp(*argv, argv);
			err(1, "execvp");
			/* NOTREACHED */
		}
	}
	(void)close(fds[1]);
	loop(fds[0]);
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
loop(int fd)
{
	struct ktr_header khdr;
	union ktrev ktev;
	ssize_t n;

	while ((n = read(fd, &khdr, sizeof(khdr))) == sizeof(khdr)) {
		if (read(fd, &ktev, khdr.ktr_len) != khdr.ktr_len)
			err(1, "read");
		switch (khdr.ktr_type) {
		case KTR_SYSCALL:
			pr_syscall(&ktev.ktev_syscall);
			break;
		case KTR_PSIG:
			pr_psig(&ktev.ktev_psig);
			break;
		}
	}
	if (n == -1)
		err(1, "read");
}

void
pr_syscall(struct ktr_syscall *sc)
{
	struct arg *a;
	int show = 1;
	char *scnam;

	scnam = emul->sysnames[sc->ktr_code];
	if (hd_sc_show.slh_first != NULL) {
		show = 0;
		SLIST_FOREACH(a, &hd_sc_show, arg_next)
			if (strcmp(a->arg_name, scnam) == 0) {
				show = 1;
				break;
			}
	}
	if (hd_sc_xshow.slh_first != NULL) {
		SLIST_FOREACH(a, &hd_sc_xshow, arg_next)
			if (strcmp(a->arg_name, scnam) == 0) {
				show = 0;
				break;
			}
	}
	if (!show)
		return;
	(void)fprintf(stderr, "%s\n", scnam);
}

void
pr_psig(struct ktr_psig *sig)
{
}

void
usage(void)
{
	extern char *__progname;

	(void)fprintf(stderr,
	    "usage: %s [-acDdefi] [-o file] [-r fds] [-S sigs] [-s sigs] [-T syscalls]\n"
	    "\t     [-t syscalls] [-v syscalls] [-w fds] [-x syscalls] command\n"
	    "\t     [argument ...]\n"
	    "       %s [-acDdefi] [-o file] [-r fds] [-S sigs] [-s sigs] [-T syscalls]\n"
	    "\t     [-t syscalls] [-v syscalls] [-w fds] [-x syscalls] -p pid\n",
	    __progname, __progname);
	exit(1);
}
