# AutoTimeliner

![Autotimeliner](https://i2.wp.com/www.andreafortuna.org/wp-content/uploads/2018/11/autotimeliner.gif)

Automagically extract forensic timeline from volatile memory dumps.


## Requirements

- Python 3
- Volatility
- mactime (from SleuthKit)

(Developed and tested on Debian 9.6 with **Volatility 2.6-1** and **sleuthkit 4.4.0-5**)

## How it works

AutoTimeline automates this [workflow](https://www.andreafortuna.org/dfir/forensic-timeline-creation-my-own-workflow/):

- Identify correct volatility profile for the memory image.
- Runs the **timeliner** plugin against volatile memory dump using volatility. 
- Runs the **mftparser** volatility plugin, in order to extract $MFT from memory and generate a bodyfile. 
- Runs the **shellbags** volatility plugin in order to generate a bodyfile of the user activity. (suggested by [Matteo Cantoni](https://github.com/mcantoni)). 
- Merges the **timeliner**, **mftparser** and **shellbags** output files into a single bodyfile. 
- Sorts and filters the bodyfile using **mactime** and exports data as CSV.

## Installation

Simply clone the GitHub repository:

`git clone https://github.com/andreafortuna/autotimeliner.git`


## Usage

```
autotimeline.py [-h] -f IMAGEFILE [-t TIMEFRAME] [-p CUSTOMPROFILE]

optional arguments:
  -h, --help            show this help message and exit
  -f IMAGEFILE, --imagefile IMAGEFILE
                        Memory dump file
  -t TIMEFRAME, --timeframe TIMEFRAME
                        Timeframe used to filter the timeline (YYYY-MM-DD
                        ..YYYY-MM-DD)
  -p CUSTOMPROFILE, --customprofile CUSTOMPROFILE
                        Jump image identification and use a custom memory
                        profile
```

### Examples

Extract timeline from *TargetServerMemory.raw*, limited to a timeframe from **2018-10-17** to **2018-10-21**:

`./autotimeline.py -f TargetServerMemory.raw -t 2018-10-17..2018-10-21`

Extract timeline from all images in current directory, limited to a timeframe from 2018-10-17 to 2018-10-21:

`./autotimeline.py -f ./*.raw -t 2018-10-17..2018-10-21`

Extract timeline from *TargetServerMemory.raw*, using a custom memory profile:

`./autotimeline.py -f TargetServerMemory.raw -p Win2008R2SP1x64`

All timelines will be saved as **$ORIGINALFILENAME-timeline.csv**.


## TODO

- Better image identification
- Better error trapping

