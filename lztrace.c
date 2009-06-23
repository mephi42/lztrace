#define _GNU_SOURCE
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <elfutils/libdw.h>
#include <libelf.h>
#include <dwarf.h>
#include <assert.h>

#include <dlfcn.h>
#include <execinfo.h>
#include <signal.h>
#include <setjmp.h>

#define __untraceable __attribute__((no_instrument_function))

#define unknown			(-1)
#define pointer			0x01
#define array			0x02
#define structure		0x04
#define _unsigned		0x08
#define _float			0x10
#define double_pointer	0x20
#define triple_pointer	0x40
#define string			0x80
#define _const			0x0100

#define errloc ((void*)-1)
#define lztrace_fd 3

/*
 * TODO:
 * - add location list for subroutine parameters handling
 * - replace print_* callbacks with printing to buffer string
 * - add message string customization
 * - add optional thread and time info in trace
 * - add optional coloring of trace (+each thread tids in different colors)
 */

struct lztrace {
    Dwarf *dwarf_ptr;
    Elf *elf_ptr;
	FILE *trace_file;
} *lztrace_ptr = NULL;

typedef void (*print_func)(void *);

struct type {
	int size;
	int flags;
	print_func print_func_ptr;
	char name[256];
};

static void __untraceable init_type(struct type *type_ptr)
{
	type_ptr->size = unknown;
	type_ptr->flags = 0;
	type_ptr->print_func_ptr = NULL;
	type_ptr->name[0] = '\0';
}

static void __untraceable dwarf_perror(const char *msg)
{
	fprintf(stderr, "%s: %s\n", msg, dwarf_errmsg(dwarf_errno()));
}

static void __untraceable print_char(void *val)
{
	if (val != errloc)
		fprintf(lztrace_ptr->trace_file, "%hhd", *(char*)val);
	else
		fprintf(lztrace_ptr->trace_file, "<n/a>");
}

static void __untraceable print_short(void *val)
{
	if (val != errloc)
		fprintf(lztrace_ptr->trace_file, "%hd", (int)(*(short*)val));
	else
		fprintf(lztrace_ptr->trace_file, "<n/a>");
}

static void __untraceable print_int(void *val)
{
	if (val != errloc)
		fprintf(lztrace_ptr->trace_file, "%d", *(int*)val);
	else
		fprintf(lztrace_ptr->trace_file, "<n/a>");
}

static void __untraceable print_long_long(void *val)
{
	if (val != errloc)
		fprintf(lztrace_ptr->trace_file, "%lld", *(long long*)val);
	else
		fprintf(lztrace_ptr->trace_file, "<n/a>");
}

static void __untraceable print_unsigned_char(void *val)
{
	if (val != errloc)
		fprintf(lztrace_ptr->trace_file, "%hhu", *(unsigned char*)val);
	else
		fprintf(lztrace_ptr->trace_file, "<n/a>");
}

static void __untraceable print_unsigned_short(void *val)
{
	if (val != errloc)
		fprintf(lztrace_ptr->trace_file, "%hu", (int)(*(unsigned*)val));
	else
		fprintf(lztrace_ptr->trace_file, "<n/a>");
}

static void __untraceable print_unsigned_int(void *val)
{
	if (val != errloc)
		fprintf(lztrace_ptr->trace_file, "%u", *(unsigned int*)val);
	else
		fprintf(lztrace_ptr->trace_file, "<n/a>");
}

static void __untraceable print_unsigned_long_long(void *val)
{
	if (val != errloc)
		fprintf(lztrace_ptr->trace_file, "%llu", *(unsigned long long*)val);
	else
		fprintf(lztrace_ptr->trace_file, "<n/a>");
}

static void __untraceable print_float(void *val)
{
	if (val != errloc)
		fprintf(lztrace_ptr->trace_file, "%f", *(float*)val);
	else
		fprintf(lztrace_ptr->trace_file, "<n/a>");
}

static void __untraceable print_double(void *val)
{
	if (val != errloc)
		fprintf(lztrace_ptr->trace_file, "%lf", *(double*)val);
	else
		fprintf(lztrace_ptr->trace_file, "<n/a>");
}

static void __untraceable print_long_double(void *val)
{
	if (val != errloc)
		fprintf(lztrace_ptr->trace_file, "%Lf", *(long double*)val);
	else
		fprintf(lztrace_ptr->trace_file, "<n/a>");
}

static void __untraceable print_ptr(void *val)
{
	if (val != errloc)
		fprintf(lztrace_ptr->trace_file, "%p", *(void**)val);
	else
		fprintf(lztrace_ptr->trace_file, "<n/a>");
}

static jmp_buf stack_buf;
static void __untraceable stopit(int unused)
{
	longjmp(stack_buf, 1);
}

#define buf_size 4096
static void __untraceable print_string(void *val)
{
	sighandler_t old_sigsegv;
	char buf[buf_size];
	char *p;
	int i;

	if (val == errloc) {
		fprintf(lztrace_ptr->trace_file, "<n/a>");
		return;
	}

	p = *(void**)val;
	if (p == NULL) {
		fprintf(lztrace_ptr->trace_file, "NULL");
		return;
	}

	buf[0] = '\0';
	old_sigsegv = signal(SIGSEGV, stopit);

	if (setjmp(stack_buf) == 0) {
		for (i = 0; *p && i < buf_size; i++) {
			buf[i] = *p++;
		}
		buf[i] = 0;
		fprintf(lztrace_ptr->trace_file, "\"%.4096s\"", buf);
	}
	else {
		fprintf(lztrace_ptr->trace_file, "%p", *(void**)val);
	}

	signal(SIGSEGV, old_sigsegv);
}

static void __untraceable resolve_type(struct type *type_ptr, Dwarf_Die *die_ptr)
{
	Dwarf_Die ref;
	Dwarf_Attribute attr;
	int tag;

	tag = dwarf_tag(die_ptr);
	switch(tag) {
		case DW_TAG_pointer_type:
			if (type_ptr->flags & double_pointer)
				type_ptr->flags |= triple_pointer;
			else if (type_ptr->flags & pointer)
				type_ptr->flags |= double_pointer;
			else
				type_ptr->flags |= pointer;
			break;
		case DW_TAG_structure_type:
			type_ptr->flags |= structure;
			break;
		case DW_TAG_array_type:
			type_ptr->flags |= array;
			break;
		case DW_TAG_const_type:
			type_ptr->flags |= _const;
			break;
		case DW_TAG_base_type:
		case DW_TAG_typedef:
			break;
		default:
			return;
	}

	if (dwarf_hasattr(die_ptr, DW_AT_encoding)) {
		Dwarf_Word num;

		dwarf_attr(die_ptr, DW_AT_encoding, &attr);

		assert(dwarf_whatform(&attr) == DW_FORM_udata ||
				dwarf_whatform(&attr) == DW_FORM_sdata ||
				dwarf_whatform(&attr) == DW_FORM_data8 ||
				dwarf_whatform(&attr) == DW_FORM_data4 ||
				dwarf_whatform(&attr) == DW_FORM_data2 ||
				dwarf_whatform(&attr) == DW_FORM_data1);

		if (dwarf_formudata(&attr, &num) == 0) {
			switch(num) {
				case DW_ATE_unsigned:
					type_ptr->flags |= _unsigned;
					break;
				case DW_ATE_float:
					type_ptr->flags |= _float;
					break;
				case DW_ATE_signed_char:
				case DW_ATE_unsigned_char:
					if ((type_ptr->flags & pointer) &&
							!(type_ptr->flags & double_pointer))
						type_ptr->flags |= string;
					break;
			}
		}
	}

	if (strlen(type_ptr->name) == 0 && dwarf_diename(die_ptr))
		strncpy(type_ptr->name, dwarf_diename(die_ptr), sizeof(type_ptr->name));
	if (type_ptr->size == unknown && dwarf_bytesize(die_ptr) != -1)
		type_ptr->size = dwarf_bytesize(die_ptr);

	if (dwarf_hasattr(die_ptr, DW_AT_type)) {
		dwarf_attr(die_ptr, DW_AT_type, &attr);
		dwarf_formref_die(&attr, &ref);
		resolve_type(type_ptr, &ref);
	}
}

static int __untraceable dwarf_get_at_type(Dwarf_Die *die_ptr, struct type *type_ptr)
{
	Dwarf_Attribute attr;
	Dwarf_Die ref;

	if (dwarf_attr(die_ptr, DW_AT_type, &attr) == NULL)
		return 1;

	assert(dwarf_whatform(&attr) == DW_FORM_ref_addr ||
			dwarf_whatform(&attr) == DW_FORM_ref_udata ||
			dwarf_whatform(&attr) == DW_FORM_ref8 ||
			dwarf_whatform(&attr) == DW_FORM_ref4 ||
			dwarf_whatform(&attr) == DW_FORM_ref2 ||
			dwarf_whatform(&attr) == DW_FORM_ref1);

	if (dwarf_formref_die (&attr, &ref) == NULL) {
		return -1;
	}
	resolve_type(type_ptr, &ref);

	switch(type_ptr->size) {
		case 1:
			if (type_ptr->flags & _unsigned)
				type_ptr->print_func_ptr = print_unsigned_char;
			else
				type_ptr->print_func_ptr = print_char;
			break;
		case 2:
			if (type_ptr->flags & _unsigned)
				type_ptr->print_func_ptr = print_unsigned_short;
			else
				type_ptr->print_func_ptr = print_short;
			break;
		case 4:
			if (type_ptr->flags & pointer) {
				if (type_ptr->flags & string)
					type_ptr->print_func_ptr = print_string;
				else
					type_ptr->print_func_ptr = print_ptr;
				break;
			}
			if (type_ptr->flags & _float) {
				type_ptr->print_func_ptr = print_float;
				break;
			}
			if (type_ptr->flags & _unsigned)
				type_ptr->print_func_ptr = print_unsigned_int;
			else
				type_ptr->print_func_ptr = print_int;
			break;
		case 8:
			if (type_ptr->flags & _float) {
				type_ptr->print_func_ptr = print_double;
				break;
			}
			if (type_ptr->flags & _unsigned)
				type_ptr->print_func_ptr = print_unsigned_long_long;
			else
				type_ptr->print_func_ptr = print_long_long;
			break;
		case (sizeof(long double)):
			if (type_ptr->flags & _float)
				type_ptr->print_func_ptr = print_long_double;
			break;
	}
	return 0;
}

static void *__untraceable dwarf_get_param_location(Dwarf_Die *die_ptr, void *frame_addr)
{
	Dwarf_Attribute attr;

	if (dwarf_hasattr(die_ptr, DW_AT_location)) {
		dwarf_attr(die_ptr, DW_AT_location, &attr);
	}
	else
		return errloc;

/*	assert(dwarf_whatform(&attr) == DW_FORM_block4 ||
			dwarf_whatform(&attr) == DW_FORM_block2 ||
			dwarf_whatform(&attr) == DW_FORM_block1 ||
			dwarf_whatform(&attr) == DW_FORM_block);*/

	Dwarf_Op *ops;
	size_t op_num;
	if (dwarf_getlocation(&attr, &ops, &op_num) == 0) {
		if (op_num == 1) {
			switch(ops[0].atom) {
/*				case DW_OP_const1u:
				case DW_OP_const2u:
				case DW_OP_const4u:
				case DW_OP_constu:
				case DW_OP_addr:*/
				case DW_OP_fbreg:
/*				case DW_OP_plus_uconst:*/
					return (void*)(((char*)frame_addr) + 8 + ops[0].number);
/*					printf("|n=%d,n2=%d,off=%d|", (int)ops[0].number, (int)ops[0].number2, (int)ops[0].offset);*/
					break;
			}
		}
	}
	return errloc;
}

static void __untraceable free_lztrace()
{
	if (!lztrace_ptr)
		return;

	if (lztrace_ptr->dwarf_ptr != NULL)
		dwarf_end(lztrace_ptr->dwarf_ptr);
	if (lztrace_ptr->elf_ptr != NULL)
		elf_end(lztrace_ptr->elf_ptr);
	if (lztrace_ptr->trace_file != stderr && lztrace_ptr->trace_file != stdout)
		fclose(lztrace_ptr->trace_file);

	free(lztrace_ptr), lztrace_ptr = NULL;
}

static int __untraceable init_lztrace()
{
	int fd_self;
	int res;
    char *name = NULL;
    size_t shstrndx;
    Elf_Scn *scn = NULL;
    GElf_Shdr scnhdr_mem, *scnhdr = NULL;

	if (!lztrace_ptr) {
		lztrace_ptr = malloc(sizeof(struct lztrace));
		if (lztrace_ptr == NULL) {
			perror("init_lztrace failed on malloc");
			return -1;
		}
	}
	else
		return -1;

	lztrace_ptr->trace_file = fdopen(lztrace_fd, "w");
	if (lztrace_ptr->trace_file == NULL) {
		lztrace_ptr->trace_file = stderr;
	}

	fd_self = open("/proc/self/exe", O_RDONLY);
	if (fd_self == -1) {
		perror("open /proc/self/exe");
		exit(EXIT_FAILURE);
	}

	elf_version(EV_CURRENT);

	lztrace_ptr->elf_ptr = elf_begin(fd_self, ELF_C_READ_MMAP, NULL);
	if (lztrace_ptr->elf_ptr == NULL) {
        fprintf(stderr, "elf_begin on /proc/self/exe failed: %s\n",
			elf_errmsg(elf_errno()));
        goto cleanup;
    }

	lztrace_ptr->dwarf_ptr = dwarf_begin_elf(lztrace_ptr->elf_ptr, DWARF_C_READ, NULL);
    if (lztrace_ptr->dwarf_ptr == NULL) {
		dwarf_perror("dwarf_begin_elf");
        goto cleanup;
    }

	res = elf_getshstrndx(lztrace_ptr->elf_ptr, &shstrndx);
    if (res == -1) {
        fprintf(stderr, "elf_getshstrndx: %s\n",
			elf_errmsg(elf_errno()));
        goto cleanup;
    }

    while ((scn = elf_nextscn(lztrace_ptr->elf_ptr, scn)) != NULL) {
        scnhdr = gelf_getshdr(scn, &scnhdr_mem);
        name = elf_strptr(lztrace_ptr->elf_ptr, shstrndx, scnhdr->sh_name);
        if (strcmp(name, ".debug_info") == 0) {
			atexit(free_lztrace);
			return 0;
		}
    }

	fprintf(stderr, "cannot find .debug_info section in /proc/self/exe\n");

cleanup:
	free_lztrace();
	return -1;
}

static int __untraceable get_func(Dwarf_Die *die_ptr, const char *name, void *addr)
{
	size_t header_size;
	uint8_t address_size, offset_size;
	Dwarf_Off off = 0, next_off = 0, abbrev_offset = 0;
    Dwarf_Die cu_die;
	Dwarf_Addr lowpc_addr = 0;
	const char *die_name;
	int res;
	int tag;

	if (!name && !addr)
		return 0;

    while (dwarf_nextcu(lztrace_ptr->dwarf_ptr, off, &next_off, &header_size,
        &abbrev_offset, &address_size, &offset_size) == 0) {
        off += header_size;
        if (dwarf_offdie(lztrace_ptr->dwarf_ptr, off, &cu_die) == NULL) {
            fprintf(stderr, "Can't get CU die.\n");
			return -1;
        }
		res = dwarf_child(&cu_die, die_ptr);
		if (res == -1) {
			dwarf_perror("dwarf_child");
			return -1;
		}
		else if (res != 0) {
			off = next_off;
			continue;
		}

		do {
				tag = dwarf_tag(die_ptr);
				if (tag != DW_TAG_subprogram)
					continue;

				if (addr) {
					if (dwarf_lowpc(die_ptr, &lowpc_addr) == 0) {
						if ((unsigned long)addr == (unsigned long)lowpc_addr) {
							return 0;
						}
					}
				}
				if (name) {
					die_name = dwarf_diename(die_ptr);
					if (strcmp(die_name, name) == 0)
						return 0;
				}

		} while (!dwarf_siblingof(die_ptr, die_ptr));

		off = next_off;
    }

	return -1;
}

void __untraceable __cyg_profile_func_enter(void *this_fn, void *call_site);
void __untraceable __cyg_profile_func_exit(void *this_fn, void *call_site);

__thread int stacklevel = 0;
void __untraceable __cyg_profile_func_enter(void *this_fn, void *call_site)
{
    Dl_info this_fn_info;
	Dwarf_Die die;
	Dwarf_Die child;
	Dwarf_Addr addr = 0;
	struct type type;
	int res;
	int tag;
	int params;

	assert(this_fn != __cyg_profile_func_enter && this_fn != __cyg_profile_func_exit);

	if (!lztrace_ptr) {
		if (init_lztrace() == -1) {
			fprintf(stderr, "cannot init lztrace\n");
			exit(EXIT_FAILURE);
		}
	}

    stacklevel++;
    if (dladdr(this_fn, &this_fn_info)) {
		if (get_func(&die, this_fn_info.dli_sname, this_fn) == 0) {
			dwarf_lowpc(&die, &addr);
			init_type(&type);
			dwarf_get_at_type(&die, &type);

			fprintf(lztrace_ptr->trace_file, "%*s->[0x%.8lx] %s%s%s %s%s%s%s%s(",
				(stacklevel - 1) * 2, "",
				(long unsigned)this_fn,
				type.flags & _const ? "const " : "",
				type.flags & structure ? "struct " : "",
				strlen(type.name) == 0 ? "void": type.name,
				type.flags & pointer ? "*" : "",
				type.flags & double_pointer ? "*" : "",
				type.flags & triple_pointer ? "*" : "",
				type.flags & array ? "[]" : "",
				dwarf_diename(&die));

			res = dwarf_child(&die, &child);
			if (res == -1) {
				dwarf_perror("dwarf_child");
				return;
			}
			else if (res != 0) {
				fprintf(lztrace_ptr->trace_file, ");\n");
				return;
			}

			params = 0;
			do
			{
				tag = dwarf_tag(&child);
				if (tag != DW_TAG_formal_parameter)
					continue;

				init_type(&type);
				dwarf_get_at_type(&child, &type);

				fprintf(lztrace_ptr->trace_file, "%s%s%s%s %s%s%s%s%s",
					params ? ", " : "",
					type.flags & _const ? "const " : "",
					type.flags & structure ? "struct " : "",
					strlen(type.name) == 0 ? "void": type.name,
					type.flags & pointer ? "*" : "",
					type.flags & double_pointer ? "*" : "",
					type.flags & triple_pointer ? "*" : "",
					dwarf_diename(&child),
					type.flags & array ? "[]" : "");

				if (type.print_func_ptr) {
					fprintf(lztrace_ptr->trace_file, " = ");
					type.print_func_ptr(dwarf_get_param_location(&child, __builtin_frame_address(1)));
				}

				params = 1;

			} while (!dwarf_siblingof(&child, &child));

			fprintf(lztrace_ptr->trace_file, ")\n");
		}
		else
			fprintf(lztrace_ptr->trace_file,
					"%*s->[%p] %s()\n",
						(stacklevel - 1) * 2,
						"",
						this_fn,
						this_fn_info.dli_sname);
	}
}

void __untraceable __cyg_profile_func_exit(void *this_fn, void *call_site)
{
    Dl_info this_fn_info;
	/*
	 * FIXME:
	 * - find another way of getting return value
	 * (this one often failed)
	 */
	register int ebx asm ("ebx");
	int rval = ebx;
	int res;
	Dwarf_Die die;
	Dwarf_Addr addr = 0;
	struct type type;

	assert(this_fn != __cyg_profile_func_enter && this_fn != __cyg_profile_func_exit);

    if (dladdr(this_fn, &this_fn_info)) {
		if (get_func(&die, this_fn_info.dli_sname, this_fn) == 0) {
			dwarf_lowpc(&die, &addr);
			init_type(&type);
			res = dwarf_get_at_type(&die, &type);

			fprintf(lztrace_ptr->trace_file, "%*s<-[0x%.8lx] %s%s%s %s%s%s%s%s()",
				(stacklevel - 1) * 2, "",
				(long unsigned)addr,
				type.flags & _const ? "const " : "",
				type.flags & structure ? "struct " : "",
				strlen(type.name) == 0 ? "void": type.name,
				type.flags & pointer ? "*" : "",
				type.flags & double_pointer ? "*" : "",
				type.flags & triple_pointer ? "*" : "",
				type.flags & array ? "[]" : "",
				dwarf_diename(&die));

			if (res == 0) {
				fprintf(lztrace_ptr->trace_file, " = ");
				type.print_func_ptr(&rval);
			}
			fprintf(lztrace_ptr->trace_file, "\n");
		}
		else
	        fprintf(lztrace_ptr->trace_file,
					"%*s<-[%p] %s() = %x\n",
						(stacklevel - 1) * 2,
						"",
						this_fn,
						this_fn_info.dli_sname,
						rval);
	}
    stacklevel--;
}
