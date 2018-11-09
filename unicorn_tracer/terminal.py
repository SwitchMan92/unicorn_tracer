'''
Created on 4 nov. 2018

@author: switch
'''

from __future__ import print_function

import logging
from termcolor import colored
from logging import StreamHandler


class UnicornTracerTerminal():
    
    def __init__(self, logger=None):
        if logger:
            self.__logger = logger
        
        else:
            self.__logger = logging.getLogger("unicorn_tracer_terminal")
            self.__logger.setLevel(logging.DEBUG)
                
            self.__stream_handler = StreamHandler()
            self.__stream_handler.setLevel(logging.INFO)
            self.__logger.addHandler(self.__stream_handler)
    
    def setLogger(self, logger):
        self.__logger = logger
    
    def get_logger(self):
        return self.__logger
    
    def format_char(self, value):
        return "{:02X}".format(value)
     
    def print_differences(self, memory_mapping, memory_image1, memory_image2):
        diff = memory_mapping.get_differences(memory_image1, memory_image2)
        
        logger_output = ""
        
        if len(diff.keys()) > 0:

            for i in range(0, memory_mapping.get_region_size()):

                if (i % 8) == 0:
                    logger_output += "\t"

                if (i % 16) == 0:                    
                    logger_output += "\n" + colored(hex(memory_mapping.get_region_address() + i) + "\t", "blue")

                if i in diff.keys():
                    diff_value = diff[i]
                    logger_output += colored(self.format_char(diff_value), "yellow") + " "
                else:
                    logger_output += colored(self.format_char(memory_image1.get_memory_image()[i]) + " ", "green")

            logger_output += colored("\t at code address {}".format(hex(memory_image2.get_code_address())) + "\n", "grey")
        
        self.__logger.log(logging.INFO, logger_output)
            
    def print_differences_light(self, memory_mapping, memory_image1, memory_image2):
        diff = memory_mapping.get_differences(memory_image1, memory_image2)
        
        logger_output = ""
        
        current_key_index = 0
        
        while len(diff.keys()) > current_key_index:
            current_key = diff.keys()[current_key_index]
            current_offset = current_key - (current_key % 16)
            
            current_rest = (memory_mapping.get_region_size() - current_offset)
            current_rest = 16 if current_rest > 16 else current_rest
            
            logger_output += colored(hex(memory_mapping.get_region_address() + current_offset) + "\t", "blue")
            
            for i in range(current_offset, current_offset + current_rest):
                
                if (i % 8) == 0:
                    logger_output += "\t"
                
                if i in diff.keys():
                    logger_output += colored(self.format_char(diff[i]), "yellow") + " "
                    current_key_index = current_key_index+1
                else:
                    logger_output += colored(self.format_char(memory_image1.get_memory_image()[i]) + " ", "grey")


            logger_output += colored("\t at code address {}".format(hex(memory_image2.get_code_address())) + "\n", "grey")

        logger_output += "\n"
        
        self.__logger.log(logging.INFO, logger_output)
        
        