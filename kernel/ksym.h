#ifndef ANTIFORMAT_KSYM_H
#define ANTIFORMAT_KSYM_H

unsigned long my_kallsyms_lookup_name(const char *symbol_name);
void **find_syscall_table(void);

extern int protect_rodata_memory(unsigned long syscall_addr);
extern int unprotect_rodata_memory(unsigned long syscall_addr);

#endif /* ANTIFORMAT_KSYM_H */