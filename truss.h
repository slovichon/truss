/* $Id$ */

#include <sys/queue.h>

#include <limits.h>

/* Date formats. */
#define DFMT_NONE	0
#define DFMT_ABS	1
#define DFMT_REL	2

struct arg {
	union {
		char			*argv_name;
		int			 argv_fd;
	} arg_value;
	SLIST_ENTRY(arg)	 	 arg_next;
#define arg_name	arg_value.argv_name
#define arg_fd		arg_value.argv_fd
};
SLIST_HEAD(arg_head, arg);

extern pid_t	 attach_pid;
extern int	 follow_fork;
extern int	 show_count;
extern int	 show_args;
extern int	 show_env;
extern int	 show_intr_once;
extern int	 datefmt;
extern char	*outfile;

extern struct arg_head hd_sc_show, hd_sc_xshow;
extern struct arg_head hd_sc_stop, hd_sc_xstop;
extern struct arg_head hd_sc_verbose, hd_sc_xverbose;
extern struct arg_head hd_sc_raw, hd_sc_xraw;
extern struct arg_head hd_sig_show, hd_sig_xshow;
extern struct arg_head hd_sig_stop, hd_sig_xstop;
extern struct arg_head hd_fd_read, hd_fd_xread;
extern struct arg_head hd_fd_write, hd_fd_xwrite;
