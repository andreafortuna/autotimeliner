#!/usr/bin/env python
# encoding: utf-8

import os,shutil,sys
from glob import glob


global VOLATILITYBIN
VOLATILITYBIN = os.popen("which volatility || which vol.py").read().rstrip()



def image_identification(filename):
        volimageInfo = os.popen(VOLATILITYBIN + " -f " + filename +  " imageinfo  2>/dev/null | grep \"Suggested Profile(s)\" | awk '{print $4 $5 $6}'").read()
        volimageInfo = volimageInfo.rstrip()
        volProfiles = volimageInfo.split(",")
        for volProfile in volProfiles:
                profileCheck =  os.popen(VOLATILITYBIN + " -f " + filename +  " --profile=" + volProfile + " pslist 2>/dev/null").read()
                if "Offset" in profileCheck:
                        return volProfile
        return ""




def create_memory_timeline(filename, volProfile):
        volOutput = os.popen(VOLATILITYBIN + " -f " + filename +  " --profile=" + volProfile + " timeliner --output=body > " + filename + "-timeliner.body  2>/dev/null").read()

def create_mft_timeline(filename, volProfile):
	volOutput = os.popen(VOLATILITYBIN + " -f " + filename +  " --profile=" + volProfile + " mftparser --output=body > " + filename + "-mftparser.body  2>/dev/null").read()

def create_shellbags_timeline(filename, volProfile):
	volOutput = os.popen(VOLATILITYBIN + " -f " + filename +  " --profile=" + volProfile + " shellbags --output=body > " + filename + "-shellbags.body  2>/dev/null").read()




def combine_timelines(filename):
	filenames = [filename + '-timeliner.body', filename  + '-mftparser.body']
	with open(filename + '-combined.body', 'w') as outfile:
		for fname in filenames:
			with open(fname) as infile:
				for line in infile:
					outfile.write(line)


def filter_timeline(filename, startdate, enddate):
	if startdate != 0:
		cmdOutput = os.popen("mactime -d -b  " + filename +  "-combined.body " + startdate + ".." + enddate + " > " + filename  + "-timeline.csv").read()
	else:
		cmdOutput = os.popen("mactime -d -b  " + filename +  "-combined.body  >  " + filename  + "-timeline.csv").read()


def banner_logo():
        print """ 
                _     _______ _                _ _                 
     /\        | |   |__   __(_)              | (_)                
    /  \  _   _| |_ ___ | |   _ _ __ ___   ___| |_ _ __   ___ _ __ 
   / /\ \| | | | __/ _ \| |  | | '_ ` _ \ / _ \ | | '_ \ / _ \ '__|
  / ____ \ |_| | || (_) | |  | | | | | | |  __/ | | | | |  __/ |   
 /_/    \_\__,_|\__\___/|_|  |_|_| |_| |_|\___|_|_|_| |_|\___|_| 

- Automagically extract forensic timeline from volatile memory dump -

Andrea Fortuna
andrea@andreafortuna.org
https://www.andreafortuna.org
"""

def banner_usage():
	print " Usage:"
	print " " + sys.argv[0] + " imagefile(also wildcards) [startdate(YYYY-MM-DD)] [enddate(YYYY-MM-DD)]"




def main():
	banner_logo()
	if len(sys.argv) <2:
		banner_usage()
		return ""
	filenames = sys.argv[1]

	startdate = 0
	enddate = 0

	if len(sys.argv) == 4:
		startdate = sys.argv[2]
		enddate = sys.argv[3]

	filelist = glob(filenames)
	for filename in filelist:
                sys.stdout.write("\033[1m*** \033[0mProcessing image " + filename + "\n-------\n")
                sys.stdout.flush()
		sys.stdout.write("\033[1m*** \033[0mStarting image identification...")
		sys.stdout.flush()
		volProfile = image_identification(filename)
		sys.stdout.write("..." + volProfile + "\n")
		sys.stdout.flush()
		sys.stdout.write("\033[1m*** \033[0mCreating memory timeline...")
		sys.stdout.flush()
		create_memory_timeline(filename, volProfile)
 		sys.stdout.write("...done!\n")
		sys.stdout.flush()

	        sys.stdout.write("\033[1m*** \033[0mCreating shellbags timeline...")
	        sys.stdout.flush()
	        create_shellbags_timeline(filename, volProfile)
	        sys.stdout.write("...done!\n")
	        sys.stdout.flush()

		sys.stdout.write("\033[1m*** \033[0mCreating $MFT timeline...")
 		sys.stdout.flush()
		create_mft_timeline(filename, volProfile)
		sys.stdout.write("...done!\n")
		sys.stdout.flush()
		sys.stdout.write("\033[1m*** \033[0mMerging and filtering timelines...")
		sys.stdout.flush()
		combine_timelines(filename)
		filter_timeline(filename, startdate, enddate)
		sys.stdout.write("...done!\n")
		sys.stdout.flush()
		sys.stdout.write("Timeline saved in " +  filename  + "-timeline.csv\n")
		sys.stdout.flush()



if __name__ == '__main__':
	main()

