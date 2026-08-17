FROM gradle:9.5-jdk21 AS build
WORKDIR /app
COPY . .
RUN gradle :gateway:bootJar --no-daemon -x test

FROM eclipse-temurin:21-jre-alpine
RUN apk add --no-cache curl
WORKDIR /app
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
COPY --from=build /app/gateway/build/libs/*.jar app.jar
USER appuser
EXPOSE 9080
ENTRYPOINT ["java", "-jar", "app.jar"]
