from __future__ import print_function

import logging
import traceback
from unicorn.unicorn import Uc
from unicorn.unicorn_const import UC_PROT_ALL, UC_HOOK_CODE
from config import CONFIG
from terminal import UnicornTracerTerminal


class InvalidSectionSizeException(Exception):
    def __init__(self, memory_region_tracer):
            message = "MemoryImage starting at address {} should have a size of {}".format(
                hex(memory_region_tracer.get_region_address()), hex(memory_region_tracer.get_region_size()))
            Exception.__init__(message=message)

class InvalidMemoryInstanceException(Exception):
    def __init__(self, memory_region_tracer, code_address):
        message = Exception("No memoryImage instance found at code address {} for memory address {}".format(
                hex(code_address), hex(memory_region_tracer.get_region_address())))
        Exception.__init__(message=message)

class MemoryRegionImage:
    def __init__(self, code_address, memory_image):
        self.__code_address = code_address
        self.__memory_image = memory_image

    def get_code_address(self):
        return self.__code_address

    def get_memory_image(self):
        return self.__memory_image


class MemoryRegionTracer:

    def __init__(self, address, size, continous_tracing=False):
        self.__region_address = address
        self.__region_size = size
        self.__continuous_tracing = continous_tracing
        self.__memory_images = list()
        self.__code_checkpoints = list()
        
    def is_continously_tracing(self):
        return self.__continuous_tracing
    
    def add_code_checkpoint(self, code_address):
        if code_address not in self.__code_checkpoints:
            self.__code_checkpoints.append(code_address)
            
            if self.__continuous_tracing:
                self.__continuous_tracing = False
            
    def remove_code_checkpoint(self, code_address):
        self.__code_checkpoints.remove(code_address)
    
    def get_code_checkpoints(self):
        return self.__code_checkpoints
    
    def is_code_checkpoint_defined(self, code_address):
        return code_address in self.__code_checkpoints
    
    def get_region_address(self):
        return self.__region_address

    def get_region_size(self):
        return self.__region_size

    def add_image(self, code_address, memory_image):
        if len(memory_image) != self.get_region_size():
            raise InvalidSectionSizeException(self)
        self.__memory_images.append(MemoryRegionImage(code_address, memory_image))
        return self.__memory_images[-1]

    def remove_image(self, code_address):
        if code_address not in self.__memory_images.keys():
            raise InvalidMemoryInstanceException(self, code_address) 
        self.__memory_images.remove(code_address)

    def get_images(self):
        return self.__memory_images

    def get_images_code_addresses(self):
        return [image.code_address for image in self.__memory_images]

    def get_last_image(self):
        return self.__memory_images[-1]

    def get_image(self, code_address):
        for image in self.__memory_images:
            if image.code_address == code_address:
                return image
        raise InvalidMemoryInstanceException(self, code_address) 

    def get_differences(self, memory_image1, memory_image2):

        results = dict()

        if memory_image1 == memory_image2:
            return results

        for i in range(0, self.__region_size):
            byte1 = memory_image1.get_memory_image()[i]
            byte2 = memory_image2.get_memory_image()[i]

            if byte1 != byte2:
                results[i] = byte2

        return results


class TracedUc(Uc):
    
    def get_terminal(self):
        return self.__terminal
    
    def add_changes_handler(self, function):
        self.on_changes_detected = function
    
    def hook_code(self, uc, address, size, user_data):
        for mem_mapping in self.__memory_mappings:    
            try:
                if len(mem_mapping.get_images()) == 0 or mem_mapping.is_continously_tracing() or mem_mapping.is_code_checkpoint_defined(address):
                    data = uc.mem_read(mem_mapping.get_region_address(), mem_mapping.get_region_size())
                
                    if len(mem_mapping.get_images()) == 0:
                        mem_mapping.add_image(address, data)
                        
                    elif mem_mapping.is_continously_tracing() or mem_mapping.is_code_checkpoint_defined(address):    
                        last_image = mem_mapping.get_last_image()
        
                        if data != last_image.get_memory_image():
                            mem_image = mem_mapping.add_image(address, data)
                            
                            if not self.on_changes_detected:
                                raise Exception("Please add a changes_detected handler")
                                
                            self.on_changes_detected(self, mem_mapping, last_image, mem_image)
                            
            except Exception as e:
                self.__terminal.get_logger().log(logging.ERROR, traceback.format_exc(e))

    def mem_map(self, address, size, perms=UC_PROT_ALL, trace=False, continuous_tracing=False):
        Uc.mem_map(self, address, size, perms)
        if trace:
            memory_region = MemoryRegionTracer(address, size, continous_tracing=continuous_tracing)
            self.__memory_mappings.append(memory_region)
            return memory_region
        return None


    def __init__(self, *args, **kwargs):
        self.__memory_mappings = list()
        self.__terminal = UnicornTracerTerminal()
        
        Uc.__init__(self, *args, **kwargs)
        self.hook_add(UC_HOOK_CODE, self.hook_code)
        
