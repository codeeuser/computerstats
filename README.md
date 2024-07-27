# Computer Stats with OSHI
- Computer Stats in JSON format built with Spring Boot.
- Implementation of OSHI, to view information about the system and hardware in JSON format.
- Such as OS, processes, memory, CPU, disks, devices, sensors, etc.
- Support for Linux, Windows and macOS.

[![Apache License](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

## Access URL
- http://localhost:8088/api/computer
- http://localhost:8088/api/single/{items}
- http://localhost:8088/api/single/cpu,os,system,mem,sensor,filesystem,disk,processlist,network

## Execute Java Spring Boot CLI
- ./mvnw spring-boot:run

## Packaging Project CLI
- ./mvnw clean package

## Execute JAR CLI
- java -jar computerstats-0.0.1-SNAPSHOT.jar