#!/bin/sh
#*------------------------------------------------------------------------*/
#*                                                                        */
#*                      camLine GmbH                                      */
#*                      Industriering 4a                                  */
#*                  D - 85238 Petershausen                                */
#*                                                                        */
#* Scope of module   : General shell script                               */
#*                                                                        */
#* File Specification: sample-rest-service.sh                             */
#*                                                                        */
#* Subsystem Control : Spring Boot Sample Rest Service                    */
#*                                                                        */
#* Software Compatibilities:  UNIX System V                               */
#*                                                                        */
#*    This software is provided as a service.  Although every reasonable  */
#*    precaution has been taken to assure its functional correctness, no  */
#*    guarantee will be given for the correct operation of this software  */
#*    in any particular application.                                      */
#*                                                                        */
#*    Copyright (C) 2019                                                  */
#*                  camLine GmbH                                          */
#*                  ALL RIGHTS RESERVED.                                  */
#*                                                                        */
#*------------------------------------------------------------------------*/

echo "SpringBoot Sample Rest Service start script"


##########################################################################
#
# General settings
#
JAVA_LIB_DIR=.lib
JAVAOPTS="-Dlogging.config=./properties/sample-rest-service-log4j2.properties"

# **********************************
# include project specific jar files
# **********************************
UBER_JAR=./lib/sample-rest-service.jar

echo "JAVA FLAGS=<$JAVAOPTS>"

#
# launching the server
#
echo "Starting the Sample Rest Service"

exec $JAVA_HOME/bin/java $JAVAOPTS -jar $UBER_JAR

