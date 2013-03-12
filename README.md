# OBSOLETE

I am no longer maintaining this code. Changes to the iOS 5+ sdk have made this
code obsolete on iOS. I'm leaving it up only for posterity sake since a few
folks have expressed interest in it.

# gcore-arm

This is a fork of the 'gcore' utility with a minor patch and build process
to add ARM support on darwin. The gcore command is a tool for creating 
coredumps from running processes without messing with ulimit or having
to send a quit signal and killing the target.

## Credit

The original code is by Amit Singh, which he published as bonus material for 
his book [Mac OS X Internals: A Systems Approach](http://www.osxbook.com/). 

This is a great book and you should totally get a copy if you are into 
mac or apple stuff at all.

## Build

* Prepare an arm_env.mk file (see arm_env.mk.sample for guidance).
* Compile with

        make gcore_arm

* See entitlements/README.txt for additional steps on getting it to run 
  on your target.

## License

See the file APPLE_LICENSE


