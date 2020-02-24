#if 0
	shc Version 4.0.1, Generic Shell Script Compiler
	GNU GPL Version 3 Md Jahidul Hamid <jahidulhamid@yahoo.com>

	shc -f backup.sh 
#endif

static  char data [] = 
#define      shll_z	10
#define      shll	((&data[1]))
	"\026\020\211\132\064\076\175\313\145\365\017\024\031"
#define      tst1_z	22
#define      tst1	((&data[16]))
	"\141\154\007\116\350\161\117\311\126\330\305\374\025\034\061\076"
	"\336\072\343\333\362\130\261\171\366\005\171\177\051"
#define      chk1_z	22
#define      chk1	((&data[46]))
	"\327\160\055\050\155\230\037\243\036\272\361\364\310\065\214\172"
	"\062\302\255\130\347\255\043\252\341\061\032\330\155"
#define      msg2_z	19
#define      msg2	((&data[73]))
	"\020\354\013\166\337\036\124\127\025\206\237\064\202\227\167\022"
	"\032\147\026\345\335\206"
#define      rlax_z	1
#define      rlax	((&data[93]))
	"\136"
#define      opts_z	1
#define      opts	((&data[94]))
	"\065"
#define      inlo_z	3
#define      inlo	((&data[95]))
	"\324\001\241"
#define      text_z	119
#define      text	((&data[117]))
	"\036\044\246\236\341\066\165\121\143\235\154\074\013\004\273\127"
	"\025\247\336\054\171\102\250\370\236\104\230\075\227\311\100\362"
	"\344\356\375\161\234\334\216\354\311\024\122\132\123\233\136\272"
	"\161\252\171\177\045\044\202\045\242\053\261\161\052\143\013\351"
	"\075\174\233\007\172\020\015\210\233\210\122\065\372\073\006\200"
	"\262\167\230\366\227\032\033\325\160\231\377\142\226\273\110\126"
	"\104\013\326\343\207\152\055\012\110\151\106\047\136\154\063\125"
	"\267\203\317\207\104\125\167\037\316\202\321\075\132\350\156\305"
	"\344\060\336\245\250\071\276\024\057\003\251\175\172\123\155\217"
	"\212\012\005\057\257\202\115\324"
#define      date_z	1
#define      date	((&data[250]))
	"\006"
#define      xecc_z	15
#define      xecc	((&data[252]))
	"\301\173\226\230\107\236\373\323\006\176\204\351\362\247\222\100"
#define      chk2_z	19
#define      chk2	((&data[269]))
	"\012\171\320\055\005\074\327\165\053\361\232\176\374\250\233\333"
	"\210\143\301\107\263\271\142\216\140"
#define      lsto_z	1
#define      lsto	((&data[292]))
	"\247"
#define      tst2_z	19
#define      tst2	((&data[295]))
	"\112\025\011\331\105\345\021\273\027\061\020\012\313\250\050\233"
	"\227\274\213\014\347\125"
#define      pswd_z	256
#define      pswd	((&data[332]))
	"\322\221\331\372\175\217\131\336\227\033\335\014\031\350\205\322"
	"\112\247\047\347\177\155\047\142\247\343\010\207\106\026\231\205"
	"\200\251\277\255\334\073\247\140\362\072\232\140\377\263\313\341"
	"\133\362\311\332\137\360\075\007\324\105\216\032\134\050\237\334"
	"\321\137\212\256\233\061\017\216\153\251\357\153\135\272\115\270"
	"\255\026\222\015\007\320\024\333\025\243\366\162\313\226\116\235"
	"\365\330\114\221\012\133\040\166\005\017\342\142\312\057\032\167"
	"\105\255\204\114\175\231\050\223\074\036\005\010\264\124\246\252"
	"\055\363\074\070\116\134\256\124\154\220\266\066\277\321\256\005"
	"\176\062\122\374\314\172\220\011\231\226\021\115\352\270\370\027"
	"\253\064\117\372\220\376\116\375\217\005\063\116\326\341\124\125"
	"\024\246\121\340\041\342\351\272\170\373\007\143\263\000\173\137"
	"\064\313\131\304\311\250\301\130\255\365\247\204\327\374\331\353"
	"\243\053\314\304\015\266\176\206\261\206\351\145\206\144\304\273"
	"\057\036\177\370\306\101\121\164\067\371\370\016\365\321\372\230"
	"\374\306\134\012\175\333\220\057\142\171\224\351\336\131\244\015"
	"\167\044\006\076\145\127\262\235\120\252\253\105\174\246\335\171"
	"\155\023"
#define      msg1_z	65
#define      msg1	((&data[598]))
	"\017\106\325\132\221\353\257\341\060\025\354\253\043\057\354\075"
	"\370\121\316\015\314\326\007\065\241\265\004\353\213\335\346\215"
	"\052\312\107\247\225\264\206\325\122\352\250\321\144\074\000\326"
	"\315\233\044\371\370\355\266\203\146\271\173\323\124\026\355\370"
	"\224\072\377\274\124\023\015\057\057\267\265\263\301\216"/* End of data[] */;
#define      hide_z	4096
#define SETUID 0	/* Define as 1 to call setuid(0) at start of script */
#define DEBUGEXEC	0	/* Define as 1 to debug execvp calls */
#define TRACEABLE	1	/* Define as 1 to enable ptrace the executable */
#define HARDENING	0	/* Define as 1 to disable ptrace/dump the executable */
#define HARDENINGSP	0	/* Define as 1 to disable bash child process */
#define BUSYBOXON	0	/* Define as 1 to enable work with busybox */

/* rtc.c */

#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* 'Alleged RC4' */

static unsigned char stte[256], indx, jndx, kndx;

/*
 * Reset arc4 stte. 
 */
void stte_0(void)
{
	indx = jndx = kndx = 0;
	do {
		stte[indx] = indx;
	} while (++indx);
}

/*
 * Set key. Can be used more than once. 
 */
void key(void * str, int len)
{
	unsigned char tmp, * ptr = (unsigned char *)str;
	while (len > 0) {
		do {
			tmp = stte[indx];
			kndx += tmp;
			kndx += ptr[(int)indx % len];
			stte[indx] = stte[kndx];
			stte[kndx] = tmp;
		} while (++indx);
		ptr += 256;
		len -= 256;
	}
}

/*
 * Crypt data. 
 */
void arc4(void * str, int len)
{
	unsigned char tmp, * ptr = (unsigned char *)str;
	while (len > 0) {
		indx++;
		tmp = stte[indx];
		jndx += tmp;
		stte[indx] = stte[jndx];
		stte[jndx] = tmp;
		tmp += stte[indx];
		*ptr ^= stte[tmp];
		ptr++;
		len--;
	}
}

/* End of ARC4 */

#if HARDENING

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/prctl.h>
#define PR_SET_PTRACER 0x59616d61

/* Seccomp Sandboxing Init */
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

#define ArchField offsetof(struct seccomp_data, arch)

#define Allow(syscall) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_##syscall, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

struct sock_filter filter[] = {
    /* validate arch */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ArchField),
    BPF_JUMP( BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

    /* load syscall */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

    /* list of allowed syscalls */
    Allow(exit_group),  /* exits a processs */
    Allow(brk),         /* for malloc(), inside libc */
    Allow(mmap),        /* also for malloc() */
    Allow(munmap),      /* for free(), inside libc */

    /* and if we don't match above, die */
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
};
struct sock_fprog filterprog = {
    .len = sizeof(filter)/sizeof(filter[0]),
    .filter = filter
};

/* Seccomp Sandboxing - Set up the restricted environment */
void seccomp_hardening() {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("Could not start seccomp:");
        exit(1);
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filterprog) == -1) {
        perror("Could not start seccomp:");
        exit(1);
    }
} 
/* End Seccomp Sandboxing Init */

void arc4_hardrun(void * str, int len) {
    //Decode locally
    char tmp2[len];
    memcpy(tmp2, str, len);

	unsigned char tmp, * ptr = (unsigned char *)tmp2;

    int lentmp = len;

#if HARDENINGSP
    //Start tracing to protect from dump & trace
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        printf("Operation not permitted\n");
        kill(getpid(), SIGKILL);
        exit(1);
    }

    //Decode Bash
    while (len > 0) {
        indx++;
        tmp = stte[indx];
        jndx += tmp;
        stte[indx] = stte[jndx];
        stte[jndx] = tmp;
        tmp += stte[indx];
        *ptr ^= stte[tmp];
        ptr++;
        len--;
    }

    //Exec bash script
    system(tmp2);

    //Empty script variable
    memcpy(tmp2, str, lentmp);

    //Sinal to detach ptrace
    ptrace(PTRACE_DETACH, 0, 0, 0);
    exit(0);

    /* Seccomp Sandboxing - Start */
    seccomp_hardening();

    exit(0);
#endif /* HARDENINGSP Exit here anyway*/

    int pid, status;
    pid = fork();

    if(pid==0) {

        //Start tracing to protect from dump & trace
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
            printf("Operation not permitted\n");
            kill(getpid(), SIGKILL);
            _exit(1);
        }

        //Decode Bash
        while (len > 0) {
            indx++;
            tmp = stte[indx];
            jndx += tmp;
            stte[indx] = stte[jndx];
            stte[jndx] = tmp;
            tmp += stte[indx];
            *ptr ^= stte[tmp];
            ptr++;
            len--;
        }

        //Exec bash script
        system(tmp2);

        //Empty script variable
        memcpy(tmp2, str, lentmp);

        //Sinal to detach ptrace
        ptrace(PTRACE_DETACH, 0, 0, 0);
        exit(0);
    }
    else {
        wait(&status);
    }

    /* Seccomp Sandboxing - Start */
    seccomp_hardening();

    exit(0);
} 
#endif /* HARDENING */

/*
 * Key with file invariants. 
 */
int key_with_file(char * file)
{
	struct stat statf[1];
	struct stat control[1];

	if (stat(file, statf) < 0)
		return -1;

	/* Turn on stable fields */
	memset(control, 0, sizeof(control));
	control->st_ino = statf->st_ino;
	control->st_dev = statf->st_dev;
	control->st_rdev = statf->st_rdev;
	control->st_uid = statf->st_uid;
	control->st_gid = statf->st_gid;
	control->st_size = statf->st_size;
	control->st_mtime = statf->st_mtime;
	control->st_ctime = statf->st_ctime;
	key(control, sizeof(control));
	return 0;
}

#if DEBUGEXEC
void debugexec(char * sh11, int argc, char ** argv)
{
	int i;
	fprintf(stderr, "shll=%s\n", sh11 ? sh11 : "<null>");
	fprintf(stderr, "argc=%d\n", argc);
	if (!argv) {
		fprintf(stderr, "argv=<null>\n");
	} else { 
		for (i = 0; i <= argc ; i++)
			fprintf(stderr, "argv[%d]=%.60s\n", i, argv[i] ? argv[i] : "<null>");
	}
}
#endif /* DEBUGEXEC */

void rmarg(char ** argv, char * arg)
{
	for (; argv && *argv && *argv != arg; argv++);
	for (; argv && *argv; argv++)
		*argv = argv[1];
}

void chkenv_end(void);

int chkenv(int argc)
{
	char buff[512];
	unsigned long mask, m;
	int l, a, c;
	char * string;
	extern char ** environ;

	mask = (unsigned long)getpid();
	stte_0();
	 key(&chkenv, (void*)&chkenv_end - (void*)&chkenv);
	 key(&data, sizeof(data));
	 key(&mask, sizeof(mask));
	arc4(&mask, sizeof(mask));
	sprintf(buff, "x%lx", mask);
	string = getenv(buff);
#if DEBUGEXEC
	fprintf(stderr, "getenv(%s)=%s\n", buff, string ? string : "<null>");
#endif
	l = strlen(buff);
	if (!string) {
		/* 1st */
		sprintf(&buff[l], "=%lu %d", mask, argc);
		putenv(strdup(buff));
		return 0;
	}
	c = sscanf(string, "%lu %d%c", &m, &a, buff);
	if (c == 2 && m == mask) {
		/* 3rd */
		rmarg(environ, &string[-l - 1]);
		return 1 + (argc - a);
	}
	return -1;
}

void chkenv_end(void){}

#if HARDENING

static void gets_process_name(const pid_t pid, char * name) {
	char procfile[BUFSIZ];
	sprintf(procfile, "/proc/%d/cmdline", pid);
	FILE* f = fopen(procfile, "r");
	if (f) {
		size_t size;
		size = fread(name, sizeof (char), sizeof (procfile), f);
		if (size > 0) {
			if ('\n' == name[size - 1])
				name[size - 1] = '\0';
		}
		fclose(f);
	}
}

void hardening() {
    prctl(PR_SET_DUMPABLE, 0);
    prctl(PR_SET_PTRACER, -1);

    int pid = getppid();
    char name[256] = {0};
    gets_process_name(pid, name);

    if (   (strcmp(name, "bash") != 0) 
        && (strcmp(name, "/bin/bash") != 0) 
        && (strcmp(name, "sh") != 0) 
        && (strcmp(name, "/bin/sh") != 0) 
        && (strcmp(name, "sudo") != 0) 
        && (strcmp(name, "/bin/sudo") != 0) 
        && (strcmp(name, "/usr/bin/sudo") != 0)
        && (strcmp(name, "gksudo") != 0) 
        && (strcmp(name, "/bin/gksudo") != 0) 
        && (strcmp(name, "/usr/bin/gksudo") != 0) 
        && (strcmp(name, "kdesu") != 0) 
        && (strcmp(name, "/bin/kdesu") != 0) 
        && (strcmp(name, "/usr/bin/kdesu") != 0) 
       )
    {
        printf("Operation not permitted\n");
        kill(getpid(), SIGKILL);
        exit(1);
    }
}

#endif /* HARDENING */

#if !TRACEABLE

#define _LINUX_SOURCE_COMPAT
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#if !defined(PT_ATTACHEXC) /* New replacement for PT_ATTACH */
   #if !defined(PTRACE_ATTACH) && defined(PT_ATTACH)
       #define PT_ATTACHEXC	PT_ATTACH
   #elif defined(PTRACE_ATTACH)
       #define PT_ATTACHEXC PTRACE_ATTACH
   #endif
#endif

void untraceable(char * argv0)
{
	char proc[80];
	int pid, mine;

	switch(pid = fork()) {
	case  0:
		pid = getppid();
		/* For problematic SunOS ptrace */
#if defined(__FreeBSD__)
		sprintf(proc, "/proc/%d/mem", (int)pid);
#else
		sprintf(proc, "/proc/%d/as",  (int)pid);
#endif
		close(0);
		mine = !open(proc, O_RDWR|O_EXCL);
		if (!mine && errno != EBUSY)
			mine = !ptrace(PT_ATTACHEXC, pid, 0, 0);
		if (mine) {
			kill(pid, SIGCONT);
		} else {
			perror(argv0);
			kill(pid, SIGKILL);
		}
		_exit(mine);
	case -1:
		break;
	default:
		if (pid == waitpid(pid, 0, 0))
			return;
	}
	perror(argv0);
	_exit(1);
}
#endif /* !TRACEABLE */

char * xsh(int argc, char ** argv)
{
	char * scrpt;
	int ret, i, j;
	char ** varg;
	char * me = argv[0];
	if (me == NULL) { me = getenv("_"); }
	if (me == 0) { fprintf(stderr, "E: neither argv[0] nor $_ works."); exit(1); }

	ret = chkenv(argc);
	stte_0();
	 key(pswd, pswd_z);
	arc4(msg1, msg1_z);
	arc4(date, date_z);
	if (date[0] && (atoll(date)<time(NULL)))
		return msg1;
	arc4(shll, shll_z);
	arc4(inlo, inlo_z);
	arc4(xecc, xecc_z);
	arc4(lsto, lsto_z);
	arc4(tst1, tst1_z);
	 key(tst1, tst1_z);
	arc4(chk1, chk1_z);
	if ((chk1_z != tst1_z) || memcmp(tst1, chk1, tst1_z))
		return tst1;
	arc4(msg2, msg2_z);
	if (ret < 0)
		return msg2;
	varg = (char **)calloc(argc + 10, sizeof(char *));
	if (!varg)
		return 0;
	if (ret) {
		arc4(rlax, rlax_z);
		if (!rlax[0] && key_with_file(shll))
			return shll;
		arc4(opts, opts_z);
#if HARDENING
	    arc4_hardrun(text, text_z);
	    exit(0);
       /* Seccomp Sandboxing - Start */
       seccomp_hardening();
#endif
		arc4(text, text_z);
		arc4(tst2, tst2_z);
		 key(tst2, tst2_z);
		arc4(chk2, chk2_z);
		if ((chk2_z != tst2_z) || memcmp(tst2, chk2, tst2_z))
			return tst2;
		/* Prepend hide_z spaces to script text to hide it. */
		scrpt = malloc(hide_z + text_z);
		if (!scrpt)
			return 0;
		memset(scrpt, (int) ' ', hide_z);
		memcpy(&scrpt[hide_z], text, text_z);
	} else {			/* Reexecute */
		if (*xecc) {
			scrpt = malloc(512);
			if (!scrpt)
				return 0;
			sprintf(scrpt, xecc, me);
		} else {
			scrpt = me;
		}
	}
	j = 0;
#if BUSYBOXON
	varg[j++] = "busybox";
	varg[j++] = "sh";
#else
	varg[j++] = argv[0];		/* My own name at execution */
#endif
	if (ret && *opts)
		varg[j++] = opts;	/* Options on 1st line of code */
	if (*inlo)
		varg[j++] = inlo;	/* Option introducing inline code */
	varg[j++] = scrpt;		/* The script itself */
	if (*lsto)
		varg[j++] = lsto;	/* Option meaning last option */
	i = (ret > 1) ? ret : 0;	/* Args numbering correction */
	while (i < argc)
		varg[j++] = argv[i++];	/* Main run-time arguments */
	varg[j] = 0;			/* NULL terminated array */
#if DEBUGEXEC
	debugexec(shll, j, varg);
#endif
	execvp(shll, varg);
	return shll;
}

int main(int argc, char ** argv)
{
#if SETUID
   setuid(0);
#endif
#if DEBUGEXEC
	debugexec("main", argc, argv);
#endif
#if HARDENING
	hardening();
#endif
#if !TRACEABLE
	untraceable(argv[0]);
#endif
	argv[1] = xsh(argc, argv);
	fprintf(stderr, "%s%s%s: %s\n", argv[0],
		errno ? ": " : "",
		errno ? strerror(errno) : "",
		argv[1] ? argv[1] : "<null>"
	);
	return 1;
}
