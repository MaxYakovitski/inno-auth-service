#Stage 1: Build
FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

#Stage 2: Runtime
FROM eclipse-temurin:25-jre AS runtime
WORKDIR /app
RUN addgroup --system spring && adduser --system --ingroup spring spring
COPY --from=build /app/target/*.jar app.jar
RUN chown spring:spring app.jar

USER spring
EXPOSE 8081
ENTRYPOINT ["java", "-jar", "app.jar"]