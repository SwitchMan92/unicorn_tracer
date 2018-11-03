from __future__ import print_function

import collections
import zlib
from unicorn.unicorn import Uc
from unicorn.unicorn_const import UC_PROT_ALL, UC_HOOK_CODE


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class MemoryImage:
    def __init__(self, code_address, memory_image):
        self.__code_address = code_address
        self.__memory_image = zlib.compress(memory_image)

    def get_code_address(self):
        return self.__code_address

    def get_memory_image(self):
        return zlib.decompress(self.__memory_image)


class MemorySectionTracer:

    def __init__(self, address, size):
        self.__section_address = address
        self.__section_size = size
        self.__memory_images = list()

    def get_section_address(self):
        return self.__section_address

    def get_section_size(self):
        return self.__section_size

    def add_image(self, code_address, memory_image):
        if len(memory_image) != self.size:
            raise Exception("MemoryImage starting at address {} should have a size of {}".format(
                hex(self.__section_address), hex(self.__section_size)))
        self.__memory_images.append(MemoryImage(code_address, memory_image))
        return self.__memory_images[-1]

    def remove_image(self, code_address):
        if code_address not in self.__memory_images.keys():
            raise Exception("No memoryImage instance found at code address {} for memory address {}".format(
                hex(code_address), hex(self.__section_address)))
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
            hex(code_address), hex(self.__section_address)))

    def get_differences(self, memory_image1, memory_image2):

        results = dict()

        if memory_image1 == memory_image2:
            return results

        for i in range(0, self.__section_size):
            byte1 = memory_image1[i]
            byte2 = memory_image2[i]

            if byte1 != byte2:
                results[i] = byte2

        return results

    def print_differences(self, memory_image1, memory_image2):
        diff = self.get_differences(memory_image1, memory_image2)

        for i in range(0, self.__section_size):

            if i % 8:
                print("\t", end="")

            if i % 16:
                print("{}{}:".format(bcolors.UNDERLINE, hex(self.__section_address + i)), end="")

            if i in diff.keys():
                diff_value = diff[i]
                print("{}{}".format(bcolors.WARNING, hex(diff_value)), end=" ")

            else:
                print("{}{}".format(bcolors.ENDC, hex(memory_image1[i])), end=" ")


class TracedUc(Uc):

    def hook_code(self, uc, address, size, user_data):
        for mem_mapping in self.__memory_mappings:
            data = uc.mem_read(mem_mapping.get_section_address, mem_mapping.get_section_size)
            if data != mem_mapping.get_last_image():
                mem_image = mem_mapping.add_image(address, data)
                mem_mapping.print_differences(mem_mapping.get[-2], mem_image)

    def mem_map(self, address, size, perms=UC_PROT_ALL):
        self.__memory_mappings[address] = MemorySectionTracer(address, size)
        Uc.mem_map(self, address, size, perms)

    def __init__(self, *args, **kwargs):
        Uc.__init__(self, *args, **kwargs)
        self.__memory_mappings = dict()
        self.hook_add(UC_HOOK_CODE, self.hook_code)


if __name__=="__main__":
    pass