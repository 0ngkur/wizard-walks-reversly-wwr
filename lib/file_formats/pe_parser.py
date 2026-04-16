import pefile
import os
import json
from datetime import datetime

class PEParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.pe = None
        try:
            self.pe = pefile.PE(file_path)
        except Exception as e:
            self.error = str(e)

    def get_basic_info(self):
        if not self.pe:
            return {"error": self.error}

        return {
            "filename": os.path.basename(self.file_path),
            "size": os.path.getsize(self.file_path),
            "machine": hex(self.pe.FILE_HEADER.Machine),
            "number_of_sections": self.pe.FILE_HEADER.NumberOfSections,
            "timestamp": datetime.fromtimestamp(self.pe.FILE_HEADER.TimeDateStamp).isoformat(),
            "entry_point": hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(self.pe.OPTIONAL_HEADER.ImageBase),
            "subsystem": self.pe.OPTIONAL_HEADER.Subsystem,
        }

    def get_sections(self):
        if not self.pe:
            return []
        
        sections = []
        for section in self.pe.sections:
            sections.append({
                "name": section.Name.decode().strip('\x00'),
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": hex(section.Misc_VirtualSize),
                "raw_size": hex(section.SizeOfRawData),
                "entropy": section.get_entropy(),
                "characteristics": hex(section.Characteristics)
            })
        return sections

    def get_imports(self):
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return {}
        
        imports = {}
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode()
            imports[dll_name] = []
            for imp in entry.imports:
                imports[dll_name].append({
                    "name": imp.name.decode() if imp.name else None,
                    "address": hex(imp.address),
                    "hint": imp.hint
                })
        return imports

    def get_exports(self):
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return []
        
        exports = []
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append({
                "name": exp.name.decode() if exp.name else None,
                "address": hex(self.pe.OPTIONAL_HEADER.ImageBase + exp.address),
                "ordinal": exp.ordinal
            })
        return exports

    def get_all_json(self):
        return {
            "basic_info": self.get_basic_info(),
            "sections": self.get_sections(),
            "imports": self.get_imports(),
            "exports": self.get_exports()
        }

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        parser = PEParser(sys.argv[1])
        print(json.dumps(parser.get_all_json(), indent=2))
