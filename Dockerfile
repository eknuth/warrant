# One image for the Python services in the local stack: the gitea and postgres
# MCP resource servers and the warrant gateway. The repository is the build
# context.
#
# uv is copied from its own pinned image rather than installed with pip, because
# uv.lock is written for it and the copy is one static binary. The version is
# the one the lock file was last resolved with; a bump is its own change.
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.11.14 /uv /uvx /bin/

ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_CACHE_DIR=/opt/uv-cache

WORKDIR /app

# The dependency layer first, so a source edit does not re-resolve the lock.
# `package = false` in pyproject.toml, so this installs the dependencies and not
# the project; the services import from the working directory.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY . .

ENV PATH="/opt/venv/bin:$PATH"
EXPOSE 9100 9101 9102
CMD ["python", "-m", "warrant", "serve"]
