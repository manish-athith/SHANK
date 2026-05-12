from contextlib import asynccontextmanager
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.api.routes import alerts, auth, detection, health, stats, threat
from app.core.config import get_settings
from app.core.logging import configure_logging, logger
from app.core.rate_limit import limiter
from app.models.db import run_migrations
from app.services.alert_fanout import alert_fanout
from app.services.kafka_service import kafka_producer

settings = get_settings()
REQUEST_COUNT = Counter("shank_http_requests_total", "HTTP requests", ["method", "path", "status"])
REQUEST_LATENCY = Histogram("shank_http_request_seconds", "HTTP request latency", ["method", "path"])


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response


class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        with REQUEST_LATENCY.labels(request.method, path).time():
            response = await call_next(request)
        REQUEST_COUNT.labels(request.method, path, str(response.status_code)).inc()
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    if settings.environment != "test" and not os.getenv("PYTEST_CURRENT_TEST"):
        await run_migrations()
    if settings.environment == "test" or os.getenv("PYTEST_CURRENT_TEST"):
        logger.info("kafka_start_skipped_for_tests")
    else:
        try:
            await kafka_producer.start()
            await alert_fanout.start()
        except Exception as exc:  # Kafka may be unavailable during isolated unit tests.
            logger.warning("kafka_start_failed", error=str(exc))
    yield
    await alert_fanout.stop()
    await kafka_producer.stop()


app = FastAPI(
    title="SHANK Cybersecurity Intelligence API",
    description="Real-time AI phishing detection and threat analysis platform.",
    version="1.0.0",
    lifespan=lifespan,
)
app.state.limiter = limiter


async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> Response:
    return Response("Rate limit exceeded", status_code=429)


app.add_exception_handler(RateLimitExceeded, rate_limit_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(MetricsMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

for router in (health.router, auth.router, detection.router, alerts.router, stats.router, threat.router):
    app.include_router(router, prefix=settings.api_prefix)


@app.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
