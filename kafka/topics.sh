#!/usr/bin/env sh
set -eu

kafka-topics --bootstrap-server kafka:9092 --create --if-not-exists --topic shank.raw.events --partitions 3 --replication-factor 1
kafka-topics --bootstrap-server kafka:9092 --create --if-not-exists --topic shank.predictions --partitions 3 --replication-factor 1
kafka-topics --bootstrap-server kafka:9092 --create --if-not-exists --topic shank.alerts --partitions 3 --replication-factor 1

