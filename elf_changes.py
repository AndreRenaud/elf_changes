#!/usr/bin/env python3

import re
import pprint
import subprocess
import sys
import argparse

class ElfChanges:
    def __init__(self, old_elf, new_elf, compiler_prefix=''):
        self.compiler_prefix = compiler_prefix

        old = self._capture_readelf(old_elf)
        new = self._capture_readelf(new_elf)

        self._old_sections = self._parse_readelf_sections(old)
        self._new_sections = self._parse_readelf_sections(new)

        # print("old sections")
        # pprint.pprint(self._old_sections)

        self._old_symbols = self._parse_readelf_symbols(old)
        self._new_symbols = self._parse_readelf_symbols(new)

    def _capture_readelf(self, elffile):
        s = subprocess.run(['{}readelf'.format(self.compiler_prefix), '-a', elffile], capture_output=True)
        # TODO: Check for failures
        #print("output", type(s.stdout))
        return s.stdout.decode("utf-8").split("\n")

    def _parse_readelf_sections(self, readelf_lines):
        """converts the section output of readelf -a into a more useful python map

        Assumes the output has a section that looks like:

        Section Headers:
          [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
          [ 0]                   NULL            00000000 000000 000000 00      0   0  0
          [ 1] .vectors          PROGBITS        00000000 010000 0007d0 00  AX  0   0  8
          ...

        """

        in_headers = False
        m = r'\s*\[([0-9 ]+)\]\s+([a-z_\.]+)\s+([a-z_]+)\s+([0-9a-f]+)\s+([a-f0-9]+)\s+([a-f0-9]+)'
        e = re.compile(m, re.IGNORECASE)
        sections={}
        for f in readelf_lines:
            if not in_headers:
                in_headers = "Section Headers:" in f
            else:
                if f.strip() == "":
                    in_headers = False
                #print(f)
                match = e.match(f)
                if match:
                    #print(match)
                    #print(match.group())
                    new_section = {"name": match.group(2), "type": match.group(3), "address": int(match.group(4), 16), "offset": int(match.group(5), 16), "size": int(match.group(6), 16)}
                    # print(match.group(1))
                    sections[match.group(2)] = new_section

        return sections

    def _parse_readelf_symbols(self, readelf_lines):
        """converts the symbol output of readelf -a into a more useful python map

        Assumes the output has a section that looks like:

        Symbol table '.symtab' contains 637 entries:
           Num:    Value  Size Type    Bind   Vis      Ndx Name
             0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND
             1: 00000000     0 SECTION LOCAL  DEFAULT    1
             2: 3ed00000     0 SECTION LOCAL  DEFAULT    2
             3: 3ed04af0     0 SECTION LOCAL  DEFAULT    3
             ...
           612: 3ed05f38     0 NOTYPE  GLOBAL DEFAULT    9 __tbss_end
           613: 3ed02e00    56 FUNC    GLOBAL DEFAULT    2 xTaskGetSchedulerState
           614: 3ed04b08   257 OBJECT  GLOBAL DEFAULT    5 _ctype_
           615: 3ed05f2c     0 NOTYPE  GLOBAL DEFAULT    7 __init_array_start
           616: 3ed06170     4 OBJECT  GLOBAL DEFAULT   10 ulPortInterruptNesting
           617: 3ed04a28     4 FUNC    WEAK   DEFAULT    2 _exit
           618: 3ed04960    20 FUNC    GLOBAL DEFAULT    2 FIQInterrupt
           619: 3ed0069d    92 FUNC    GLOBAL DEFAULT    2 strlen
        """
        in_table = False
        e = re.compile(r'\s+\d+:\s+([0-9a-f]+)\s+(\d+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\d+)\s+([\w\.]+)', re.IGNORECASE)
        symbols = {}
        for l in readelf_lines:
            if not in_table:
                in_table = l.startswith("Symbol table ")
            else:
                match = e.match(l)
                if match:
                    #print(match)
                    s = {"address": int(match.group(1), 16), "size": int(match.group(2)), "name": match.group(7)}
                    symbols[match.group(7)] = s

        return symbols

    def _changes(self, old_map, new_map):
        changes={}
        for s in old_map:
            old = old_map[s]
            if s in new_map:
                new = new_map[s]
                if old["size"] != new["size"]:
                    changes[s] = {"old": old["size"], "new": new["size"], "diff": new["size"] - old["size"], "change": "resize"}
            else:
                changes[s] = {"old": old["size"], "new": 0, "diff": -old["size"], "change": "removed"}
        for s in new_map:
            if not s in old_map:
                new = new_map[s]
                changes[s] = {"old": 0, "new": new["size"], "diff": new["size"], "change": "added"}
        return changes

    def symbol_changes(self):
        """Return a map indicating all symbols that have changed size, been added or removed"""
        return self._changes(self._old_symbols, self._new_symbols)

    def section_changes(self):
        """Return a map indicating all the sections that have changed size, been added or removed"""
        return self._changes(self._old_sections, self._new_sections)

    def output_text_table(self, title, map_table, keys, output=sys.stdout):
        output.write("%s\n" % (title))
        output.write("%-30s" % ("name"))
        for k in keys:
            output.write(" | %-10s" % (k))
        output.write("\n")
        output.write("------------" * (len(keys) + 3))
        output.write("\n")
        for m in map_table:
            output.write("%-30s" % (m))
            for k in keys:
                # print("k", k)
                output.write(" | {:10}".format(map_table[m][k]))
            output.write("\n")
        output.write("\n\n")

    def output_html_table(self, title, map_table, keys, output):
        output.write("<h2>{}</h2>\n".format(title))
        output.write("<table class=\"sortable\">\n")
        output.write("<tr>\n")
        output.write("<th>name</th>\n")
        for k in keys:
            output.write("<th>{}</th>\n".format(k))
        output.write("</tr>\n")
        for m in map_table:
            output.write("<tr>")
            output.write("<td>{}</td>".format(m))
            for k in keys:
                output.write("<td>{}</td>".format(map_table[m][k]))
            output.write("</tr>\n")
        output.write("</table>\n") 


def main():
    parser = argparse.ArgumentParser(description='Show differences between two elf files')
    parser.add_argument('--old', type=str, required=True, help='Old elf file')
    parser.add_argument('--new', type=str, required=True, help='New elf file')
    parser.add_argument('--prefix', type=str, help="Prefix to `readelf` binary", default="")
    parser.add_argument("--html", type=str, help="File to save HTML output to")

    args = parser.parse_args()
    e = ElfChanges(args.old, args.new, args.prefix)
    e.output_text_table("Symbol Changes", e.symbol_changes(), ["old", "new", "diff", "change"])
    e.output_text_table("Section Changes", e.section_changes(), ["old", "new", "diff", "change"])

    if args.html:
        with open(args.html, "wt") as h:
            h.write(f"""<!DOCTYPE html>
<html>
<head>
<title>Elf Changes {args.old} - {args.new}</title>""")
            h.write("""
<style>
table {
  border-spacing: 0;
  width: 100%;
  border: 1px solid #ddd;
}

th {
  cursor: pointer;
}

th, td {
  text-align: left;
  padding: 16px;
}

tr:nth-child(even) {
  background-color: #f2f2f2
}
</style>
</head>
<body>
<script src="https://www.kryogenix.org/code/browser/sorttable/sorttable.js"></script>
""")
            e.output_html_table("Symbol Changes", e.symbol_changes(), ["old", "new", "diff", "change"], h)
            e.output_html_table("Section Changes", e.section_changes(), ["old", "new", "diff", "change"], h)
            h.write("""
</body>
</html>
""")
    # TODO: Output a table of the largest symbols in new

if __name__ == '__main__':
    main()