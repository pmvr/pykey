import sys
from os.path import basename
import re

defs = """#include <stdint.h>

struct file {
    char filename[30];
    int len;
    const uint8_t *data;
};

"""
VERSION = 3

with open("fido-drive.h", "r") as fin:
    s = re.search('^const uint32_t version = (\d+)', fin.read(), re.MULTILINE)
    VERSION = int(s.group(1)) + 1
    
with open("fido-drive.h", "w") as fout:
    fout.write(defs);
    for fn in sys.argv[1:]:
        bn = basename(fn)
        fp = bn.split('.')[0]
        data = open(fn, 'rb').read()
        fout.write('const uint8_t %s_data[] = {' % fp);
        fout.write(', '.join(['0x%02x' % x for x in data]))
        fout.write('};\n')
        fout.write('const struct file file_%s = {"%s", %d, %s};\n\n' % (fp, bn, len(data), fp+'_data'))
    fout.write('const struct file *filesystem[] = {')
    fout.write(', '.join(['&file_%s' % basename(x).split('.')[0] for x in sys.argv[1:]]))
    fout.write('};\n\n')
    fout.write('const uint32_t version = %d;\n' % VERSION)
    fout.write('const struct file file_version = {"version.bin", 4, (uint8_t*)(&version)};\n')
    
