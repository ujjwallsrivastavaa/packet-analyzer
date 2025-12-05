FROM eclipse-temurin:21-jdk
WORKDIR /app
COPY java/src/main/java ./java/src/main/java
RUN mkdir -p java/out && javac -d java/out $(find java/src/main/java -name "*.java")
EXPOSE 8080
CMD ["java", "-cp", "java/out", "com.packetanalyzer.WebAnalyzerServer"]
