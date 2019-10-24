import os
import pickle
import gc
import re
import sys
import itertools
import math
import time

from optparse import OptionParser

from collections import defaultdict
from elftools.common.py3compat import maxint, bytes2str
from elftools.dwarf.descriptions import describe_form_class
from elftools.elf.elffile import ELFFile

import logging, coloredlogs
coloredlogs.install(level=logging.DEBUG)
coloredlogs.install(level=logging.INFO)
import pprint as pp

def get_size(die):
    assert ('DW_AT_byte_size' in die)
    return die.attributes['DW_AT_byte_size'].value

def get_name(die):
    assert (has_name(die))
    return die.attributes['DW_AT_name'].value.decode()

def get_offset(die):
    return die.attributes['DW_AT_location'].value

def has_name(die):
    return 'DW_AT_name' in die.attributes

#def get_sibs(die):
#    assert ('DW_AT_sibling' in die.attributes)
#    return die.attributes['DW_AT_sibling']

def get_type(die):
    assert ('DW_AT_type' in die.attributes)
    return die.attributes['DW_AT_type'].value

def get_upper(die):
    assert ('DW_AT_upper_bound' in die.attributes)
    return die.attributes['DW_AT_upper_bound'].value

def fetch_type(die, type_map):
    assert ('DW_AT_type' in die.attributes)

    t_ret = []
    t_die = type_map[get_type(die)]
    tag = t_die.tag

    if tag == 'DW_TAG_base_type':
        t_ret.append(get_name(t_die))

    elif tag == 'DW_TAG_pointer_type':
        t_ret.append(fetch_type(t_die, type_map) + '*')

    elif tag == 'DW_TAG_array_type':
        t_ret.append(fetch_type(t_die, type_map))
        t_die = next(t_die.iter_children())
        upperbound = get_upper(t_die) + 1
        t_ret.append('[%d]' % upperbound)

    elif tag == 'DW_TAG_union_type':
        tmp = []
        for die in t_die.iter_children():
            assert(die.tag == 'DW_TAG_member')
            tmp.append(fetch_type(die, type_map) + ' ' + get_name(die))
        t_ret.append('union {%s;}' % ('; '.join(tmp)))

    elif tag == 'DW_TAG_structure_type':
        tmp = []
        for die in t_die.iter_children():
            assert(die.tag == 'DW_TAG_member')
            tmp.append(fetch_type(die, type_map) + ' ' + get_name(die))
        t_ret.append('struct {%s;}' % ('; '.join(tmp)))

    elif tag == 'DW_TAG_typedef':
        t_ret.append('{typedef %s %s}' % (fetch_type(t_die, type_map),
                                          get_name(t_die)))

    else:
        print (die)
        print (t_die)
        raise NotImplemented

    #return get_name(t_die) + ' '.join(t_ret)
    return ' '.join(t_ret)


def print_die(CU):
    # Start with the top DIE, the root for this CU's DIE tree
    top_DIE = CU.get_top_DIE()
    print('    Top DIE with tag=%s' % top_DIE.tag)

    # We're interested in the filename...
    print('    name=%s' % top_DIE.get_full_path())

    # Display DIEs recursively starting with top_DIE
    die_info_rec(top_DIE)


def die_info_rec(die, indent_level='    '):
    """ A recursive function for showing information about a DIE and its
        children.
    """
    if has_name(die):
        print(indent_level + 'DIE tag=%s, %s' % (die.tag,
                                                 get_name(die)))
    else:
        print(indent_level + 'DIE tag=%s' % (die.tag))

    child_indent = indent_level + '  '
    for child in die.iter_children():
        die_info_rec(child, child_indent)


def fetch_vars(CU):
    VARIABLE_TAGS = [
        'DW_TAG_variable',
        'DW_TAG_formal_parameter',
    #    'DW_TAG_constant',
    ]

    funcs = {}
    params = defaultdict(list)
    local_vars = defaultdict(list)
    global_vars = []
    type_map = {}
    for die in CU.iter_DIEs():
        if die.is_null():
            continue
        print(die)
        # store type into the dictionary so that it can be fetched easily
        print(die.offset)
        if 'type' in die.tag:
            type_map[die.offset] = die

        elif die.tag == 'DW_TAG_subprogram':
            try:
                func_name = get_name(die)
                funcs[func_name] = die
            except:
                print (die)
                import pdb; pdb.set_trace()

        elif die.tag in VARIABLE_TAGS:
            cur = die
            parent = None
            is_local = False
            while parent is None or \
                    not parent.tag == 'DW_TAG_compile_unit':
                parent = cur.get_parent()
                cur = parent
                if parent.tag == 'DW_TAG_subprogram':
                    is_local = True
                    break

            if is_local:
                func_name = get_name(parent)
                if die.tag == 'DW_TAG_formal_parameter':
                    params[func_name].append(die)
                elif die.tag == 'DW_TAG_variable':
                    local_vars[func_name].append(die)
                else:
                    # unimplemented
                    raise NotImplemented

            else:
                global_vars.append(die)

    return funcs, params, local_vars, global_vars, type_map


def print_vars(funcs, params, local_vars, global_vars, type_map):
    out_str = ''
    #for var in global_vars:
        #t = fetch_type(var, type_map)
        #out_str += '%s %s; \n' % (t, get_name(var))
    #out_str += '\n'

    for func_name, vars in local_vars.items():
        out_str += '%s %s' % (fetch_type(funcs[func_name], type_map),
                             func_name)
        if func_name in params:
            out_str += ' ('
            for var in params[func_name]:
                t = fetch_type(var, type_map)
                out_str += '%s %s, ' % (t, get_name(var))
            out_str = out_str.rstrip(', ') + ')'
        out_str += '\n{\n'
        for var in vars:
            t = fetch_type(var, type_map)
            out_str += '  %s %s; \n' % (t, get_name(var))
        out_str += '}\n\n'

    print (out_str)


def decode_file_line(dwarfinfo, path):
    # DW_TAG_variable
    # DW_TAG_formal_parameter
    # DW_TAG_constant

    # - DW_AT_name
    # - DW_AT_external (False for static and local variables in C/C++)
    # - DW_AT_declaration
    # - DW_AT_location
    # - DW_AT_type
    # - DW_AT_specification (for C++ structure, class, or union)
    #       this may have nested DW_TAG_variable
    # - DW_AT_variable parameter : if parameter can be modified in the callee
    # - DW_AT_const_value
    # - DW_AT_endianity
    # - - DW_END_default
    # - - DW_END_big
    # - - DW_END little

    # DW_TAG_base_type
    # - DW_AT_name
    # - DW_AT_byte_size or DW_AT_bit_size
    #

    # Go over all the line programs in the DWARF information, looking for
    # one that describes the given address.

    ret = {}
    for CU in dwarfinfo.iter_CUs():
        print_die(CU)
        funcs, params, local_vars, global_vars, type_map = fetch_vars(CU)
        print_vars(funcs, params, local_vars, global_vars, type_map)

        # TODO: line matching for each instructions and variables
        # TODO: check C++ class and objects

        lineprog = dwarfinfo.line_program_for_CU(CU)
        prevstate = None
        for entry in lineprog.get_entries():
            print (entry)

            # We're interested in those entries where a new state is assigned
            if entry.state is None or entry.state.end_sequence:
                continue
            # Looking for a range of addresses in two consecutive states that
            # contain the required address.
            # if addrs is given, check address is in the given addrs
            if prevstate:# and prevstate.address in target_addrs_by_path[path]:
                try:
                    fname = lineprog['file_entry'][prevstate.file - 1].name
                except:
                    #fname = 'unknown'
                    continue

                if isinstance(fname, bytes):
                    fname = fname.decode()

                line = prevstate.line
                ret[prevstate.address] = (fname, line)

            prevstate = entry.state

    return ret

def extract_dwarf_info(fname):
  addr_to_line = {}
  with open(fname, 'rb') as f:
    addr_to_line = decode_file_line(dwarf, fname)

if __name__ == '__main__':
  # a.dwarf = llvm-dwarfdump a > a.dwarf
  fname = "./a.dwarf"
  extract_dwarf_info(fname)
