#!/bin/sh

# uncomment it to set an individual JAVA_HOME
JAVA_HOME=/camline//java/linux/jdk1.8.0-x64
export JAVA_HOME

# Sample Rest Service port
SAMPLE_REST_SERVICE_PORT=8989

# Sample Rest Service application name
SAMPLE_REST_SERVICE_NAME=sample-rest-service

#
# check java home environment variable
#
if [ ! -x "$JAVA_HOME/bin/java" ]; then
	echo "The JAVA_HOME environment variable is not defined correctly"
	echo "This environment variable is needed to run this program"
	echo "NB: JAVA_HOME should point to a JDK not a JRE"
	exit 1
fi

#
# check java's correct version
#
REQUIRED_JAVA_VERSION=1.8
found_java_version=`$JAVA_HOME/bin/java -version 2>&1 | grep "java version" | cut -f2 -d'"'`
found_java_ok=`echo $REQUIRED_JAVA_VERSION $found_java_version | awk '{
		if ( "" $1 <= "" $2 ) {
			print "yes"
		}
		else {
			print "no"
		}
	}'`
if [ ! -z "$found_java_version" -a "$found_java_ok" != "yes" ]; then
	echo "The installed Java version is too low!"
	echo "The following Java version was found '$found_java_version',"
	echo "but the required one is '$REQUIRED_JAVA_VERSION'."
	echo
	exit
fi
