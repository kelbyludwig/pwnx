javac -d ./build -classpath jsoup-1.9.2.jar *.java
jar cf ./bin/pwnx.jar -C build .
