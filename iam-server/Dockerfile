FROM gradle:9.5-jdk21 AS build
WORKDIR /app
COPY . .
RUN gradle :iam-server:bootJar --no-daemon -x test

FROM eclipse-temurin:21-jre-alpine
RUN apk add --no-cache curl
WORKDIR /app
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
COPY --from=build /app/iam-server/build/libs/*.jar app.jar
USER appuser
EXPOSE 9083
ENTRYPOINT ["java", "-jar", "app.jar"]
