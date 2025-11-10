FROM python:3.13-alpine
COPY . /app
WORKDIR /app
RUN apk add uv --no-cache
RUN uv sync --no-group dev --group deployment --locked
ENV PATH="/app/.venv/bin:$PATH"
EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info", "--access-log"]
