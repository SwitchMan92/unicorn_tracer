Unicorn Memory Tracer
==============

this is a simple python module that allows to trace memory changes during program execution in the unicorn framework.

License
-------

This project is released under the [GPL license](COPYING).


Usage
------------------

Replace any instanciation of the Uc class by the TracedUc one.
mem_map function has been redefined to take two more parameters into account: trace, continuous_tracing

the "trace" parameter activates memory tracing functionality, but without continuous_tracing parameter set to True, 
you will need to define code addresses as checkpoints in order to check memory diffs by using 
MemoryregionTracer.add_code_checkpoint(code_address), the MemoryRegionTracer is returned by the mem_map function, but
can also be retrieved by calling tracedUc.get_memory_regions() or TracedUc.get_memory_region(memory_address).

Examples:
```python
mu = TracedUc(UC_ARCH_X86, UC_MODE_32)
mem_region = mu.mem_map(0x8049000, 0x1000, trace=True, continuous_tracing=False)
mem_region.add_code_checkpoint(0x8048080) '''will check diffs in this memory segment just before the instruction at address
0x8048080 is executed.'''
```

For more examples, you can take a look at the files into the tests/ directory.