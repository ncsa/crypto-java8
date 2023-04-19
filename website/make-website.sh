#
# Run this AFTER build.sh or it will fail.
# Most recent version of Maven 3.9+ refuses to run with anything but this.
export JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk-amd64

#export JAVA_HOME=/usr/java/jdk1.8.0_231/bin/java
# Next is for testing website builds.
#export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
CRYPT8_ROOT=/home/ncsa/dev/ncsa-git/crypto-java8

# Output of everything goes to WEBSITE_ROOT
WEBSITE_ROOT=$CRYPT8_ROOT/docs


cd $CRYPT8_ROOT
mvn clean javadoc:aggregate
cd $CRYPT8_ROOT/website
mvn clean site
# Note the source directory in the next command has no apidocs subdirectory, so this overlays
# without overwriting.
cp -r $CRYPT8_ROOT/website/target/site/* $WEBSITE_ROOT # copy maven site
cp -r $CRYPT8_ROOT/target/site/* $WEBSITE_ROOT   # copy javadoc in toto
