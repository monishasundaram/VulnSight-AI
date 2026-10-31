FROM node:22.13-alpine AS frontend-build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./frontend/
RUN cd frontend && npm ci
COPY frontend ./frontend
COPY backend ./backend
RUN cd frontend && npm run build

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=3000
WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --system --gid 10001 vulnsight \
    && useradd --system --uid 10001 --gid vulnsight --no-create-home vulnsight
COPY alembic.ini ./alembic.ini
COPY backend ./backend
COPY frontend/public ./frontend/public
COPY --from=frontend-build /app/backend/app/static ./backend/app/static
RUN mkdir -p /app/data && chown -R vulnsight:vulnsight /app/data
USER vulnsight:vulnsight
EXPOSE 3000
CMD ["sh", "-c", "alembic -c alembic.ini upgrade head && exec uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port ${PORT:-3000}"]
