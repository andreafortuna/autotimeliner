# AutoTimeliner

Automagically extract forensic timeline from volatile memory dumps.


## Requirements

- Python
- Volatility
- mactime (from SleuthKit)

## How it works

AutoTimeline automates this workflow:

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


The script needs three parameters:

- Image file (with wildcard support)
- Start date of the timeframe (optional) 
- End date of the timeframe (optional)

### Examples

Extract timeline from *TargetServerMemory.raw*, limited to a timeframe from **2018-10-17** to **2018-10-21**:

`./autotimeline.py TargetServerMemory.raw 2018-10-17 2018-10-21`

Extract timeline from all images in current directory, limited to a timeframe from 2018-10-17 to 2018-10-21:

`./autotimeline.py ./*.raw 2018-10-17 2018-10-21`

All timelines will be saved as **$ORIGINALFILENAME-timeline.csv**.
