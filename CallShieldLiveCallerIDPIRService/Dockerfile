# syntax=docker/dockerfile:1

FROM swift:6.0-jammy AS build

WORKDIR /src
COPY Package.swift Package.resolved ./
COPY Sources ./Sources
RUN swift build -c release --product PIRService

FROM swift:6.0-jammy AS runtime

WORKDIR /app
COPY --from=build /src/.build/release/PIRService /usr/local/bin/PIRService

EXPOSE 8080

CMD ["PIRService", "--hostname", "0.0.0.0", "--port", "8080", "/app/data/live-caller-id-pir/service-config.json"]
