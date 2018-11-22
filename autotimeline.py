#!/usr/bin/env python
# encoding: utf-8

import os,shutil,sys
import argparse
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
	filenames = [filename + '-timeliner.body', filename  + '-mftparser.body', filename  + '-shellbags.body']
	with open(filename + '-combined.body', 'w') as outfile:
		for fname in filenames:
			with open(fname) as infile:
				for line in infile:
					outfile.write(line)


def filter_timeline(filename, timeframe):
	if timeframe:
		cmdOutput = os.popen("mactime -d -b  " + filename +  "-combined.body " + timeframe + " > " + filename  + "-timeline.csv").read()
	else:
		cmdOutput = os.popen("mactime -d -b  " + filename +  "-combined.body > " + filename  + "-timeline.csv").read()



def main(args):
	filenames = args["imagefile"]
	timeframe = args["timeframe"]
	customprofile = args["customprofile"]

	filelist = glob(filenames)
	for filename in filelist:
		sys.stdout.write("\033[1m*** \033[0mProcessing image " + filename + "\n-------\n")
		sys.stdout.flush()
		if customprofile:
			sys.stdout.write("\033[1m*** \033[0mUsing custom profile: "+ customprofile + "\n")
			sys.stdout.flush()
			volProfile = customprofile
		else:
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
		filter_timeline(filename, timeframe)
		sys.stdout.write("...done!\n")
		sys.stdout.flush()
		sys.stdout.write("Timeline saved in " +  filename  + "-timeline.csv\n")
		sys.stdout.flush()




if __name__ == '__main__':
    version = "1.1.0"
    print("""
                _     _______ _                _ _
     /\        | |   |__   __(_)              | (_)
    /  \  _   _| |_ ___ | |   _ _ __ ___   ___| |_ _ __   ___ _ __
   / /\ \| | | | __/ _ \| |  | | '_ ` _ \ / _ \ | | '_ \ / _ \ '__|
  / ____ \ |_| | || (_) | |  | | | | | | |  __/ | | | | |  __/ |
 /_/    \_\__,_|\__\___/|_|  |_|_| |_| |_|\___|_|_|_| |_|\___|_|

- Automagically extract forensic timeline from volatile memory dump -

Andrea Fortuna - andrea@andreafortuna.org - https://www.andreafortuna.org
""")


    args = argparse.ArgumentParser()

    args.add_argument("-f", "--imagefile", required=True, help="Memory dump file")
    args.add_argument("-t", "--timeframe", required=False, help="Timeframe used to filter the timeline (YYYY-MM-DD..YYYY-MM-DD)")
    args.add_argument("-p", "--customprofile", required=False, help="Jump image identification and use a custom memory profile")

    args = vars(args.parse_args())
    main(args)
