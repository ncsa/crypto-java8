# Note you must set your JVM to java 8 or this will fail utterly.
export JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk-amd64
#export JAVA_HOME=/usr/java/jdk1.8.0_231/bin/java

SVN_ROOT=/home/ncsa/dev/ncsa-git

CRYPT8_ROOT=$SVN_ROOT/crypto-java8

cd $CRYPT8_ROOT
echo 'Changing to ' $CRYPT8_ROOT

mvn clean install javadoc:javadoc

if [[ $? -ne 0 ]] ; then
    echo "NCSA maven build failed, exiting..."
    exit 1
fi

