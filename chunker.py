import os

def split_file(filepath, lines=200):
    outdir = 'virustotal/chunker'
    """Split a file based on a number of lines."""
    path, filename = os.path.split(filepath)
    # filename.split('.') would not work for filenames with more than one .
    basename, ext = os.path.splitext(filename)

    if not os.path.exists(outdir):
        os.makedirs(outdir)
        with open(filepath, 'r') as f_in:
            try:
                # open the first output file
                f_out = open(os.path.join(outdir, '{}_{}{}'.format(basename, 0, ext)), 'w')
                # loop over all lines in the input file, and number them
                for i, line in enumerate(f_in):
                    # every time the current line number can be divided by the
                    # wanted number of lines, close the output file and open a
                    # new one
                    if i % lines == 0:
                        f_out.close()
                        f_out = open(os.path.join(outdir, '{}_{}{}'.format(basename, i, ext)), 'w')
                    # write the line to the output file
                    f_out.write(line)
            finally:
                # close the last output file
                f_out.close()
