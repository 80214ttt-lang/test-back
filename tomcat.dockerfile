FROM tomcat:11.0.13-jdk21-temurin-noble

ENV TZ=Asia/Taipei
EXPOSE 8080/tcp

#宣告變數war_file並設定預設值為xxx.war
ARG war_file=xxx.war
COPY ./${war_file} /usr/local/tomcat/webapps/ROOT.war

CMD ["/usr/local/tomcat/bin/catalina.sh", "run"]