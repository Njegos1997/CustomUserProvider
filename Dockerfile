FROM maven:latest AS build 
WORKDIR root
COPY ./src/main ./src/main
COPY ./target ./target
COPY ./pom.xml  ./

RUN mvn package 


FROM jboss/keycloak:latest

#COPY --from=build ./themes/evooq/ /opt/jboss/keycloak/themes/evooq
COPY --from=build  ./target/CustomUserProvider-0.0.1-SNAPSHOT.jar /opt/jboss/keycloak/standalone/deployments

