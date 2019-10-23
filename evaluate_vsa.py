import subprocess
import os
import sys

def diff_vsa_dwarf(vsa_alocs_list, dwarf_alocs):
  index = 0
  for vsa_alocs in vsa_alocs_list:
    print ("Env %s ------------" % index )
    total_count = 0
    total_perc = 0
    for fname in vsa_alocs.keys():
      fit_count = 0
      total_count = len(dwarf_alocs[fname])
      for aloc in vsa_alocs[fname]:
        if aloc in dwarf_alocs[fname]:
          fit_count = fit_count + 1
      perc = fit_count*100/total_count
      total_perc = total_perc + perc
      print ("%s %s/%s %s%%" % (fname,fit_count,total_count,perc))
    index = index + 1
    total_perc = total_perc/len(vsa_alocs)
    print ("Total Env : %s%%" % total_perc)

def parse_vsa_info(vsa_info):
  # 4.parse aloc of vsa
  aloc_list = []
  fname = "Global"
  data_list = []
  offset = ""
  size = ""
  alocs = {} # {func : [offs, bit]}
  alocs["Global"] = []
  for line in vsa_info:
    new_line = line.strip().split(" ") #Mem,
    if len(new_line) == 1: #new env
      aloc_list.append(alocs)
      alocs = {}
      fname = ""
      data_list = []
      offset = ""
      size = ""
    if len(new_line) == 2: #global
      data = new_line[1][1:-1].split(",")
      fname = data[0]
      offset = int(data[1][:-1])
      size = int(data[2])/8
    else: #local
      data = new_line[2][1:-1].split(",")
      if data[0][1:-1] != fname: #new function
        alocs[fname] = data_list
        data_list = []
      fname = data[0][1:-1]
      fname = data[0][1:-1]
      offset = int(data[2][:-1])
      size = int(data[3])/8
      if offset >= 0:
        pass
      else:
        data_list.append([offset,size])
  aloc_list.append(alocs)

  return aloc_list



def parse_dwarf_info(dwarf_info):
  # 3.make aloc of get_dwarf (offset-16)
  # var = DW_OP_fbreg | DW_OP_addr | ...
  fname = ""
  data = []
  offset = ""
  size = ""
  alocs = {} # {func : [offs, bit]}
  alocs["Global"] = []
  for line in dwarf_info:
    if line == "\n": continue
    elif "(...)" in line: fname = line.split(" ")[2]
    elif ("{" in line): continue
    elif ("}" in line):
      if data == []:
        continue
      else:
        alocs[fname] = data
      data = []
      offset = ""
      size = ""
      fname = ""
    else:
      size = int(line.strip().split(" ")[0])
      offset = line.strip().split("(")[1]
      if "DW_OP_fbreg" in offset:
        offset = int( offset.split(" ")[1][:-1])+16
        data.append([offset,size])
      elif "DW_OP_addr" in offset:
        offset = int(offset.split(" ")[1][:-1],16)
        alocs["Global"].append([offset,size])
      elif ")" not in offset: pass
      else: data.append([offset,size])
  return alocs


def get_vsa_info(elf_path):
  # 2.save vsa
  pwd = os.getcwd()
  vsa_path = "%s/%s.vsa" % (pwd, elf_path)
  if os.path.isfile(vsa_path) == False:
    f = open(vsa_path,"a")
    cmd = ["/usr/bin/dotnet", "run", elf_path]
    proc = subprocess.Popen(cmd, stdout = f)
    proc.wait()
    f.close()
  f = open(vsa_path,"r")
  lines = f.readlines()
  f.close()

  return lines

def get_dwarf_info(elf_path):
  # 1.save the result of get_dwarf
  pwd = os.getcwd()
  dwarf_path = "%s/%s.dwarf"  % (pwd,elf_path)
  if os.path.isfile(dwarf_path) == False:
    f = open(dwarf_path,"a")
    cmd = ["/usr/bin/python", "get_dwarf_info.py", elf_path]
    proc = subprocess.Popen(cmd, stdout = f)
    proc.wait()
    f.close()
  f = open(dwarf_path,"r")
  lines = f.readlines()
  f.close()

  return lines

def evaluate_helper():
  elf_path = sys.argv[1]
  print("1.save dwarf info")
  dwarf_info = get_dwarf_info(elf_path)
  print("2.save vsa info")
  vsa_info = get_vsa_info(elf_path)
  print("3.parse dwarf info")
  dwarf_aloc = parse_dwarf_info(dwarf_info)
  print("4.parse vsa info")
  vsa_aloc = parse_vsa_info(vsa_info)
  print("5.diff vsa & dwarf")
  print("------------------")
  result = diff_vsa_dwarf(vsa_aloc, dwarf_aloc)

if __name__ == '__main__':
  # 1.save the result of get_dwarf
  # 2.save vsa
  # 3.make aloc of get_dwarf (offset-16)
  # 4.parse aloc of vsa
  # 5.diff
  evaluate_helper()
