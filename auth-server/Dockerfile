FROM gradle:8.14-jdk21 AS build
WORKDIR /app
COPY . .
RUN gradle :auth-server:bootJar --no-daemon -x test

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
COPY --from=build /app/auth-server/build/libs/*.jar app.jar
USER appuser
EXPOSE 9081
ENTRYPOINT ["java", "-jar", "app.jar"]
