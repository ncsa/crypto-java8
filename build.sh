export JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk-amd64
SVN_ROOT=/home/ncsa/dev/ncsa-git

NCSA_ROOT=$SVN_ROOT/crypto-java8

cd $NCSA_ROOT
echo 'Changing to ' $NCSA_ROOT

mvn clean install

if [[ $? -ne 0 ]] ; then
    echo "NCSA maven build failed, exiting..."
    exit 1
fi

