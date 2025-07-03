FROM openjdk:17-jdk-slim
WORKDIR /app

RUN apt-get update && \
    apt-get install -y curl net-tools iputils-ping && \
    rm -rf /var/lib/apt/lists/*
# Copy config from current dir (place it next to the Dockerfile)
RUN mkdir -p /app/config

COPY src/main/resources/application.yaml /app/config/

COPY target/app-gateway-0.0.1-SNAPSHOT.jar .

CMD ["java", "-Xmx256m", "-Dspring.config.location=file:/app/config/", "-jar", "app-gateway-0.0.1-SNAPSHOT.jar"]
