FROM openjdk:8-jre-slim
MAINTAINER xuxueli

ENV PARAMS=""
ENV WORK_DIR="/home/project"
ENV TZ=PRC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR $WORK_DIR

COPY target/xxl-job-admin-*.jar app.jar
COPY target/lib  lib
COPY target/resources resources

#ADD target/xxl-job-admin-*.jar /app.jar

ENTRYPOINT ["sh","-c","java -jar $JAVA_OPTS $WORK_DIR/app.jar $PARAMS"]