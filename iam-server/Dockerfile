FROM gradle:8.14-jdk21 AS build
WORKDIR /app
COPY . .
RUN gradle :iam-server:bootJar --no-daemon -x test

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
COPY --from=build /app/iam-server/build/libs/*.jar app.jar
USER appuser
EXPOSE 9083
ENTRYPOINT ["java", "-jar", "app.jar"]
