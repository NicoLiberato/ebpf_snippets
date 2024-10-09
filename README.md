# ebpf_snippets
some experiments with ebpf

## snippet_one

tracepoint/syscalls/sys_enter_execve

```
clang -O2 -target bpf -c snippet_one.c -o snippet_one.o
```

