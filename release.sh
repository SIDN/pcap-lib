export JAVA_HOME=`/usr/libexec/java_home -v 17`
export MAVEN_OPTS="--add-opens=java.base/java.util=ALL-UNNAMED --add-opens=java.base/java.lang.reflect=ALL-UNNAMED --add-opens=java.base/java.text=ALL-UNNAMED --add-opens=java.desktop/java.awt.font=ALL-UNNAMED"

mvn release:clean && \
mvn release:prepare && \
mvn release:perform