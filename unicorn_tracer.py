from __future__ import print_function

from termcolor import colored
from unicorn.unicorn import Uc
from unicorn.unicorn_const import UC_PROT_ALL, UC_HOOK_CODE
from config import CONFIG

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class MemoryRegionImage:
    def __init__(self, code_address, memory_image):
        self.__code_address = code_address
        self.__memory_image = memory_image

    def get_code_address(self):
        return self.__code_address

    def get_memory_image(self):
        return self.__memory_image


class MemoryRegionTracer:

    def __init__(self, address, size):
        self.__region_address = address
        self.__region_size = size
        self.__memory_images = list()
    
    def format_char(self, value):
        if value < 0xA:
            return "0" + "{:x}".format(value)
        else:
            return "{:2x}".format(value)
    
    def get_region_address(self):
        return self.__region_address

    def get_region_size(self):
        return self.__region_size

    def add_image(self, code_address, memory_image):
        if len(memory_image) != self.get_region_size():
            raise Exception("MemoryImage starting at address {} should have a size of {}".format(
                hex(self.__region_address), hex(self.__region_size)))
        self.__memory_images.append(MemoryRegionImage(code_address, memory_image))
        return self.__memory_images[-1]

    def remove_image(self, code_address):
        if code_address not in self.__memory_images.keys():
            raise Exception("No memoryImage instance found at code address {} for memory address {}".format(
                hex(code_address), hex(self.__region_address)))
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
        raise Exception("No MemoryImage instance found at code address {} for memory address {}".format(
            hex(code_address), hex(self.__region_address)))

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

    def print_differences(self, memory_image1, memory_image2):
        diff = self.get_differences(memory_image1, memory_image2)

        if len(diff.keys()) > 0:

            for i in range(0, self.__region_size):

                if (i % 8) == 0:
                    print("\t", end="")

                if (i % 16) == 0:
                    print()
                    print(colored(hex(self.__region_address + i) + "\t", "blue"), end="")

                if i in diff.keys():
                    diff_value = diff[i]
                    print(colored(self.format_char(diff_value), "yellow"), end=" ")
                else:
                    print(self.format_char(memory_image1.get_memory_image()[i]), end=" ")

            print()
            print()


class TracedUc(Uc):

    def hook_code(self, uc, address, size, user_data):
        for mem_mapping in self.__memory_mappings:
            data = uc.mem_read(mem_mapping.get_region_address(), mem_mapping.get_region_size())

            try:
                last_image = mem_mapping.get_last_image()

                if data != last_image.get_memory_image:
                    mem_image = mem_mapping.add_image(address, data)

                    if CONFIG.DEBUG:
                        mem_mapping.print_differences(last_image, mem_image)
            except:
                mem_mapping.add_image(address, data)

    def mem_map(self, address, size, perms=UC_PROT_ALL, trace=False):
        if trace:
            self.__memory_mappings.append(MemoryRegionTracer(address, size))
        Uc.mem_map(self, address, size, perms)

    def __init__(self, *args, **kwargs):
        Uc.__init__(self, *args, **kwargs)
        self.__memory_mappings = list()
        self.hook_add(UC_HOOK_CODE, self.hook_code)

