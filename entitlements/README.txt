This directory contains files for adding entitlements to the gcore program.
This is needed in order to call task_for_pid() at a bare minimum.

There are two ways to go about this depending on how you are going about
building. If you are using the SDK, you can use codesign. You will need a
signing certificate, but it can be a self-generated one.

    codesign -s "Your cert name here" --entitlements debug_ent.xcent -f gcore_arm

Alternately you can use ldid from the suarik's Cydia package. Note, however
you will need to do this on a thin binary. So configure a single architecture
for the ARM_FLAGS variable in ../arm_env.mk. Alternately you can use "lipo"
to "thin" a fat binary after it has beeen built as follows.

    lipo -thin <armv6|armv7> gcore_arm -output gcore_arm_thin
    mv gcore_arm_thin gcore_arm

With a 'thinned' binary, you can use ldid as follows

    ldid -Sdebug_ent.xml gcore_arm

