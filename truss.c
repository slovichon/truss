/* $Id$ */

#include <sys/param.h>
#include <sys/uio.h>
#include <sys/ktrace.h>
#include <sys/queue.h>
#include <sys/syscall.h>

// #include <kern/syscalls.c>

#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PID_MAX SHRT_MAX

/* Argument types. */
#define AT_FD	0
#define AT_SC	1
#define AT_SIG	2

/* Date formats. */
#define DFMT_NONE	0
#define DFMT_ABS	1
#define DFMT_REL	2

/* Command-line argument list. */
struct arg {
	union {
		char	*argv_str;
		int	 argv_int;
	} arg_value;
	SLIST_ENTRY(arg) arg_next;
#define arg_fd	 arg_value.argv_int
#define arg_sc	 arg_value.argv_str
#define arg_sig	 arg_value.argv_str
};

SLIST_HEAD(arg_head, arg);

struct ktr_event {
	struct ktr_header		ktrev_hdr;
	union {
		struct ktr_syscall	ktrevu_syscall;
		struct ktr_psig		ktrevu_psig;
		unsigned char		ktrevu_udata[1];
	} ktrev_data;
#define ktrev_syscall	ktrev_data.ktrevu_syscall
#define ktrev_psig	ktrev_data.ktrevu_psig
#define ktrev_udata	ktrev_data.ktrevu_udata
};

static int  cmp_fd(const struct arg *, const struct arg *);
static int  cmp_sc(const struct arg *, const struct arg *);
static int  cmp_sig(const struct arg *, const struct arg *);
static int  numcmp(int, int);
static int  show(struct arg_head *, struct arg_head *, const void *,
		int (*)(const struct arg *, const struct arg *));
static void add_arg(int, struct arg_head *, char *);
static void loop(int);
static void pr_psig(struct ktr_event *);
static void pr_syscall(struct ktr_event *);
static void usage(void) __attribute__((__noreturn__));

static pid_t	  attach_pid;
static int	  show_count;
static int	  show_args;
static int	  show_env;
static int	  show_intr_once;
static int	  datefmt;
static char	 *outfn;
static char	**scnams;

static struct arg_head hd_sc_show, hd_sc_xshow;
static struct arg_head hd_sc_stop, hd_sc_xstop;
static struct arg_head hd_sc_verbose, hd_sc_xverbose;
static struct arg_head hd_sc_raw, hd_sc_xraw;
static struct arg_head hd_sig_show, hd_sig_xshow;
static struct arg_head hd_sig_stop, hd_sig_xstop;
static struct arg_head hd_mf_show, hd_mf_xshow;
static struct arg_head hd_mf_stop, hd_mf_xstop;
static struct arg_head hd_fd_read, hd_fd_xread;
static struct arg_head hd_fd_write, hd_fd_xwrite;

int
main(int argc, char *argv[])
{
	int c, fds[2], trpoints = 0, ops = 0;
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
			ops |= KTRFLAG_DESCEND;
			trpoints |= KTRFAC_INHERIT;
			break;
		case 'i':
			show_intr_once = 1;
			break;
		case 'o':
			outfn = optarg;
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

	if (outfn != NULL)
		if (freopen(outfn, "w", stderr) == NULL)
			err(1, "%s", outfn);

	if (pipe(fds) == -1)
		err(1, "pipe");
	if (attach_pid) {
		if (fktrace(fds[1], KTROP_SET | ops,
		    KTRFAC_SYSCALL | KTRFAC_PSIG | trpoints,
		    attach_pid) == -1)
			err(1, "fktrace");
	} else {
		switch (fork()) {
		case -1:
			err(1, "fork");
			/* NOTREACHED */
		case 0:
			(void)close(fds[0]);
			if (fktrace(fds[1], KTROP_SET | ops,
			    KTRFAC_SYSCALL | KTRFAC_PSIG | trpoints,
			    getpid()) == -1)
				err(1, "fktrace");
			/* (void)close(fds[1]); */
			execvp(*argv, argv);
			err(1, "execvp");
			/* NOTREACHED */
		}
	}
	(void)close(fds[1]);
	loop(fds[0]);
	exit(0);
}

/*
 * Add an argument to a list.
 */
static void
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
		case AT_SC:
			a->arg_sc = s;
			break;
		case AT_SIG:
			a->arg_sig = s;
			break;
		}
		SLIST_INSERT_HEAD(hd, a, arg_next);
	}
}

/*
 * Main system call/signal/etc. dispatcher loop.
 */
static void
loop(int fd)
{
	struct ktr_event k;
	ssize_t n;

	while ((n = read(fd, &k.ktrev_hdr, sizeof(k.ktrev_hdr))) ==
	    sizeof(k.ktrev_hdr)) {
		if (read(fd, &k.ktrev_udata,
		    k.ktrev_hdr.ktr_len) != k.ktrev_hdr.ktr_len)
			err(1, "read");
		switch (k.ktrev_hdr.ktr_type) {
		case KTR_SYSCALL:
			pr_syscall(&k);
			break;
		case KTR_PSIG:
			pr_psig(&k);
			break;
		}
	}
	if (n == -1)
		err(1, "read");
}

/*
 * Print out a system call.
 */
static void
pr_syscall(struct ktr_event *k)
{
	struct ktr_syscall sc = k->ktrev_syscall;
	char *scnam;

	scnam = scnams[sc.ktr_code];
	if (!show(&hd_sc_show, &hd_sc_xshow, scnam, cmp_sc))
		return;
	(void)fprintf(stderr, "%s\n", scnam);
}

/*
 * Determine if an event should be shown or not depending on the
 * command-line argument lists.
 */
static int
show(struct arg_head *showlh, struct arg_head *xshowlh, const void *arg,
    int (*fcmp)(const struct arg *, const struct arg *))
{
	struct arg *a;
	int show;

	show = 1;
	if (!SLIST_EMPTY(showlh)) {
		show = 0;
		SLIST_FOREACH(a, showlh, arg_next)
			if ((*fcmp)(a, arg) == 0) {
				show = 1;
				break;
			}
	}
	if (!SLIST_EMPTY(xshowlh)) {
		SLIST_FOREACH(a, xshowlh, arg_next)
			if ((*fcmp)(a, arg) == 0) {
				show = 0;
				break;
			}
	}
	return (show);
}

/*
 * Compare two system calls names.
 */
static int
cmp_sc(const struct arg *a, const struct arg *b)
{
	return (strcmp(a->arg_sc, b->arg_sc));
}

/*
 * Compare two signal names.
 */
static int
cmp_sig(const struct arg *a, const struct arg *b)
{
	return (strcmp(a->arg_sig, b->arg_sig));
}

/*
 * Compare two file descriptor numbers.
 */
static int
cmp_fd(const struct arg *a, const struct arg *b)
{
	return (numcmp(a->arg_fd, b->arg_fd));
}

/*
 * Compare two numbers.
 */
static int
numcmp(int a, int b)
{
	return (a < b ? 1 : (a == b ? 0 : -1));
}

/*
 * Print out a signal.
 */
static void
pr_psig(struct ktr_event *k)
{
	struct sig {
		int	 sig_num;
		char	*sig_nam;
	} *s, sigs[] = {
		{ SIGHUP,	"HUP" },
		{ SIGINT,	"INT" },
		{ SIGQUIT,	"QUIT" },
		{ SIGILL,	"ILL" },
		{ SIGABRT,	"ABRT" },
		{ SIGFPE,	"FPE" },
		{ SIGKILL,	"KILL" },
		{ SIGSEGV,	"SEGV" },
		{ SIGPIPE,	"PIPE" },
		{ SIGALRM,	"ARLM" },
		{ SIGTERM,	"TERM" },
		{ SIGSTOP,	"STOP" },
		{ SIGTSTP,	"TSTP" },
		{ SIGCONT,	"CONT" },
		{ SIGCHLD,	"CHLD" },
		{ SIGTTIN,	"TTIN" },
		{ SIGTTOU,	"TTOU" },
		{ SIGUSR1,	"USR1" },
		{ SIGUSR2,	"USR2" },
#ifndef _POSIX_SOURCE
		{ SIGTRAP,	"TRAP" },
		{ SIGEMT,	"EMT" },
		{ SIGBUS,	"BUS" },
		{ SIGSYS,	"SYS" },
		{ SIGURG,	"URG" },
		{ SIGIO,	"IO" },
		{ SIGXCPU,	"XCPU" },
		{ SIGXFSZ,	"XFSZ" },
		{ SIGVTALRM,	"VTARLM" },
		{ SIGPROF,	"PROF" },
		{ SIGWINCH, 	"WINCH" },
		{ SIGINFO, 	"INFO" },
#endif
		{ 0, NULL }
	};

	for (s = sigs; s->sig_nam != NULL; s++)
		if (s->sig_num == k->ktrev_psig.signo) {
			if (!show(&hd_sig_show, &hd_sig_xshow,
			    &k->ktrev_psig.signo, cmp_sig))
				return;
			(void)fprintf(stderr, "SIG%s\n", s->sig_nam);
			break;
		}
}

static void
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
