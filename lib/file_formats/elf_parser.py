from elftools.elf.elffile import ELFFile
import os
import json

class ELFParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.fd = None
        self.elf = None
        try:
            self.fd = open(file_path, 'rb')
            self.elf = ELFFile(self.fd)
        except Exception as e:
            self.error = str(e)

    def __del__(self):
        if self.fd:
            self.fd.close()

    def get_basic_info(self):
        if not self.elf:
            return {"error": self.error}

        return {
            "filename": os.path.basename(self.file_path),
            "size": os.path.getsize(self.file_path),
            "architecture": self.elf.get_machine_arch(),
            "bitness": self.elf.elfclass,
            "endianness": self.elf.little_endian,
            "entry_point": hex(self.elf.header['e_entry']),
            "type": self.elf.header['e_type'],
        }

    def get_sections(self):
        if not self.elf:
            return []
        
        sections = []
        for i in range(self.elf.num_sections()):
            section = self.elf.get_section(i)
            sections.append({
                "name": section.name,
                "type": section['sh_type'],
                "address": hex(section['sh_addr']),
                "offset": hex(section['sh_offset']),
                "size": hex(section['sh_size']),
                "entropy": self._calculate_entropy(section.data()) if section['sh_type'] != 'SHT_NOBITS' else 0
            })
        return sections

    def _calculate_entropy(self, data):
        import math
        if not data:
            return 0
        entropy = 0
        for i in range(256):
            p_i = data.count(i) / len(data)
            if p_i > 0:
                entropy += -p_i * math.log2(p_i)
        return entropy

    def get_symbols(self):
        if not self.elf:
            return []
        
        symbols = []
        symtab = self.elf.get_section_by_name('.symtab')
        if symtab:
            for symbol in symtab.iter_symbols():
                symbols.append({
                    "name": symbol.name,
                    "address": hex(symbol['st_value']),
                    "type": symbol['st_info']['type'],
                    "bind": symbol['st_info']['bind']
                })
        return symbols

    def get_all_json(self):
        return {
            "basic_info": self.get_basic_info(),
            "sections": self.get_sections(),
            "symbols": self.get_symbols()[:100] # Limit symbols for brevity
        }

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        parser = ELFParser(sys.argv[1])
        print(json.dumps(parser.get_all_json(), indent=2))
