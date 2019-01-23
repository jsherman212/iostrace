#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/sysctl.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <mach/mach.h>

typedef struct {
	/* number of events that can fit in the buffers */
	int nkdbufs;
	/* set if trace is disabled */
	int nolog;
	/* kd_ctrl_page.flags */
	unsigned int flags;
	/* number of threads in thread map */
	int nkdthreads;
	/* the owning pid */
	int bufid;
} kbufinfo_t;

#if defined(__arm64__)
typedef uint64_t kd_buf_argtype;
#else
typedef uintptr_t kd_buf_argtype;
#endif

typedef struct {
	uint64_t timestamp;
	kd_buf_argtype arg1;
	kd_buf_argtype arg2;
	kd_buf_argtype arg3;
	kd_buf_argtype arg4;
	kd_buf_argtype arg5; /* the thread ID */
	uint32_t debugid;
/*
 * Ensure that both LP32 and LP64 variants of arm64 use the same kd_buf
 * structure.
 */
#if defined(__LP64__) || defined(__arm64__)
	uint32_t cpuid;
	kd_buf_argtype unused;
#endif
} kd_buf;

#define KDBG_CSC_MASK   (0xffff0000)
#define KDBG_FUNC_MASK    (0x00000003)
#define KDBG_EVENTID_MASK (0xfffffffc)

#define BSC_SysCall	0x040c0000
#define MACH_SysCall	0x010c0000
#define MACH_Msg 0xff000000

/* function qualifiers  */
#define DBG_FUNC_START 1
#define DBG_FUNC_END   2

#define KDBG_TYPENONE   0x80000

int initialize_ktrace_buffer(void){
	int mib[3];

	/* kdebug_enable will only be set if the buffer is initialized, see bsd/kern/kdebug.c */
	mib[0] = CTL_KERN;
	mib[1] = KERN_KDEBUG;
	mib[2] = KERN_KDSETUP;
	
	size_t needed = 0;

	return sysctl(mib, 3, NULL, &needed, NULL, 0);
}

int get_kbufinfo_buffer(kbufinfo_t *out){
	int mib[3];

	mib[0] = CTL_KERN;
	mib[1] = KERN_KDEBUG;
	mib[2] = KERN_KDGETBUF;

	size_t needed = sizeof(*out);

	return sysctl(mib, 3, out, &needed, NULL, 0);
}

int read_ktrace_buffer(kd_buf **out, size_t *needed){
	int mib[3];

	mib[0] = CTL_KERN;
	mib[1] = KERN_KDEBUG;
	mib[2] = KERN_KDREADTR;
	
	*out = malloc(*needed);

	return sysctl(mib, 3, *out, needed, NULL, 0);
}

int reset_ktrace_buffers(void){
	int mib[3];
	
	mib[0] = CTL_KERN;
	mib[1] = KERN_KDEBUG;
	mib[2] = KERN_KDREMOVE;
	
	size_t needed = 0;

	return sysctl(mib, 3, NULL, &needed, NULL, 0);
}

typedef struct {
	unsigned int type;
	unsigned int value1;
	unsigned int value2;
	unsigned int value3;
	unsigned int value4;
} kd_regtype;

int set_kdebug_trace_pid(int pid, int value){
	int mib[3];

	mib[0] = CTL_KERN;
	mib[1] = KERN_KDEBUG;
	mib[2] = KERN_KDPIDTR;

	kd_regtype kdregtype = { KDBG_TYPENONE, pid, value, 0, 0 };

	size_t needed = sizeof(kdregtype);

	return sysctl(mib, 3, &kdregtype, &needed, NULL, 0);
}

int set_kdebug_trace_excluded_pid(int pid, int value){
	int mib[3];

	mib[0] = CTL_KERN;
	mib[1] = KERN_KDEBUG;
	mib[2] = KERN_KDPIDEX;

	kd_regtype kdregtype = { KDBG_TYPENONE, pid, value, 0, 0 };

	size_t needed = sizeof(kdregtype);

	return sysctl(mib, 3, &kdregtype, &needed, NULL, 0);
}

int kdebug_wait(void){
	int mib[3];

	mib[0] = CTL_KERN;
	mib[1] = KERN_KDEBUG;
	mib[2] = KERN_KDBUFWAIT;

	size_t needed;

	return sysctl(mib, 3, NULL, &needed, NULL, 0);
}

int set_kdebug_enabled(int value){
	int mib[4];

	mib[0] = CTL_KERN;
	mib[1] = KERN_KDEBUG;
	mib[2] = KERN_KDENABLE;
	mib[3] = value;

	return sysctl(mib, 4, NULL, 0, NULL, 0);
}

int main(int argc, char **argv, const char **envp){
	FILE *tracecodes = fopen("/usr/share/misc/trace.codes", "r");

	if(!tracecodes){
		printf("Tracing not supported\n");
		return 0;
	}

	char *line = NULL;
	size_t len;

	int curline = 0;

	char **bsd_syscalls = NULL;
	char **mach_syscalls = NULL;
	char **mach_messages = NULL;

	int largest_mach_msg_entry = 0;

	while(getline(&line, &len, tracecodes) != -1){
		line[strlen(line) - 1] = '\0';

		char *linecopy = strdup(line);
		size_t linelen = strlen(line);

		int idx = 0;
		
		while(idx < linelen && !isblank(line[idx]))
			idx++;

		linecopy[idx] = '\0';

		char *code = linecopy;

		while(idx < linelen && isblank(line[idx]))
			idx++;

		char *event = &linecopy[idx];

		/* Strip any whitespace from the end. */
		while(idx < linelen && !isblank(line[idx]))
			idx++;

		linecopy[idx] = '\0';

		unsigned long codenum = strtol(code, NULL, 16);

		if(strnstr(event, "BSC", 3)){	
			int idx = (codenum & 0xfff) / 4;

			/* There's a couple more not following the "increment by 4" code pattern. */
			if(codenum > 0x40c0824){
				idx = (codenum & ~0xff00000) / 4;

				bsd_syscalls = realloc(bsd_syscalls, sizeof(char *) * (curline + idx));

				for(int i=curline; i<idx; i++)
					bsd_syscalls[i] = NULL;
			}
			else
				bsd_syscalls = realloc(bsd_syscalls, sizeof(char *) * (curline + 1));

			/* Get rid of the prefix. */
			bsd_syscalls[idx] = malloc(strlen(event + 4) + 1);
			strcpy(bsd_syscalls[idx], event + 4);
		}
		else if(strnstr(event, "MSC", 3)){
			int idx = (codenum & 0xfff) / 4;
			mach_syscalls = realloc(mach_syscalls, sizeof(char *) * (curline + 1));

			mach_syscalls[idx] = malloc(strlen(event + 4) + 1);
			strcpy(mach_syscalls[idx], event + 4);
		}
		else if(strnstr(event, "MSG", 3)){
			int idx = (codenum & ~0xff000000) / 4;

			if(idx > largest_mach_msg_entry){
				int num_ptrs_to_allocate = idx - largest_mach_msg_entry;
				int cur_array_size = largest_mach_msg_entry;

				mach_messages = realloc(mach_messages, sizeof(char *) * (cur_array_size + num_ptrs_to_allocate + 1));

				/* Fill all these new spaces with NULL, then fill them in later. */
				for(int i=cur_array_size; i<num_ptrs_to_allocate; i++)
					mach_messages[i] = NULL;

				largest_mach_msg_entry = idx;
			}

			mach_messages[idx] = malloc(strlen(event + 4) + 1);
			strcpy(mach_messages[idx], event + 4);
		}
		
		free(linecopy);

		curline++;
	}

	if(line)
		free(line);

	fclose(tracecodes);

	int numentries = curline;

	printf("PID: ");
	char *pidstr = NULL;
	size_t s;

	getline(&pidstr, &s, stdin);
	pidstr[strlen(pidstr) - 1] = '\0';

	int pid = atoi(pidstr);

	free(pidstr);
	
	initialize_ktrace_buffer();

	while(1){
		int err = set_kdebug_trace_pid(pid, 1);

		/* Target process died. */
		if(err < 0)
			return 0;

		/* Don't want the kernel tracing the above events. */
		set_kdebug_enabled(1);
		
		/* Let the kernel wake up the buffer. See bsd/kern/kdebug.c
		 * @ kernel_debug_internal
		 */
		kdebug_wait();

		kbufinfo_t kbufinfo;	
		get_kbufinfo_buffer(&kbufinfo);

		size_t needed = kbufinfo.nkdbufs * sizeof(kd_buf);
		
		kd_buf *kdbuf;
		
		/* Read kernel trace buffer. */
		read_ktrace_buffer(&kdbuf, &needed);
		
		for(int i=0; i<needed; i++){
			kd_buf current = kdbuf[i];

			/* bsd/kern/kdebug.c: kernel_debug_internal */
			int code = current.debugid & ~KDBG_FUNC_MASK;
			unsigned int etype = current.debugid & KDBG_EVENTID_MASK;
			unsigned int stype = current.debugid & KDBG_CSC_MASK;

			char *event = NULL;

			int idx = (code & 0xfff) / 4;

			if(stype == BSC_SysCall){
				if(code > 0x40c0824)
					idx = (code & ~0xff00000) / 4;
				
				event = bsd_syscalls[idx];
			}
			else if(stype == MACH_SysCall)
				event = mach_syscalls[idx];
			else if(stype == MACH_Msg){
				idx = (code & ~0xff000000) / 4;
				
				event = mach_messages[idx];

				if(!event)
					continue;
			}
			else
				continue;

			char *tidstr = NULL;
			asprintf(&tidstr, "(0x%-6.6llx) ", current.arg5);

			char *calling, *returning;
			
			asprintf(&calling, "%s%-10s", tidstr, "Calling:");
			asprintf(&returning, "%s%-10s", tidstr, "Returning:");

			if(current.debugid & DBG_FUNC_START)
				printf("\e[42m\e[30m%-*s\e[0m %-35.35s", (int)strlen(calling), calling, event);
			
			if(current.debugid & DBG_FUNC_END)
				printf("\e[46m\e[30m%-*s\e[0m %-35.35s", (int)strlen(returning), returning, event);

			free(calling);
			free(returning);

			char *arg1desc, *arg2desc, *arg3desc, *arg4desc;

			asprintf(&arg1desc, "\e[32marg1\e[0m = 0x%16.16llx", current.arg1);
			asprintf(&arg2desc, "\e[94marg2\e[0m = 0x%16.16llx", current.arg2);
			asprintf(&arg3desc, "\e[38;5;208marg3\e[0m = 0x%16.16llx", current.arg3);
			asprintf(&arg4desc, "\e[38;5;124marg4\e[0m = 0x%16.16llx", current.arg4);
			
			printf("%1s%s%2s%s%2s%s%2s%s\n", "", arg1desc, "", arg2desc, "", arg3desc, "", arg4desc);

			free(arg1desc);
			free(arg2desc);
			free(arg3desc);
			free(arg4desc);
		}

		/* Reset the kernel buffers and go again. */
		reset_ktrace_buffers();
		initialize_ktrace_buffer();
		set_kdebug_enabled(0);
	
		free(kdbuf);
	}
	
	return 0;
}
