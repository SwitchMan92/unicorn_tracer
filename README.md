Unicorn Memory Tracer
==============

this is a simple python module that allows to trace memory changes during program execution in the unicorn framework.

License
-------

This project is released under the [GPL license](COPYING).


Installation
------------------

```
pip install unicorn_tracer
```

Alternative method:
```
git clone https://github.com/SwitchMan92/unicorn_tracer.git
python setup.py install
```


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
from unicorn_tracer import TracedUc


def on_changes_detected(uc, code_address, memory_mapping, memory_image1, memory_image2):
    print("At code addesss {}".format(hex(code_address)))
    diffs = memory_mapping.get_differences(memory_image1, memory_image2) '''returns memory diffs between the 
                                                                            two memory images'''
    uc.get_terminal().print_differences_light(memory_mapping, memory_image1, memory_image2) '''a litle class that
                                                                                                eases diffs printing'''
    

if __name__=="__main__":
    
    mu = TracedUc(UC_ARCH_X86, UC_MODE_32)
    mu.add_changes_handler(on_changes_detected)
    
    mem_region = mu.mem_map(0x8049000, 0x1000, trace=True, continuous_tracing=False)
    mem_region.add_code_checkpoint(0x8048080) '''will check diffs in this memory segment just before the 
    instruction at address 0x8048080 is executed.'''
```

For more examples, you can take a look at the files into the tests/ directory.