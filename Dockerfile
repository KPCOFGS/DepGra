FROM node:20-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
RUN pip install uv
COPY backend/requirements.txt backend/
RUN cd backend && uv venv .venv && . .venv/bin/activate && uv pip install -r requirements.txt
COPY backend/ backend/
COPY run.py .
COPY --from=frontend-build /app/frontend/dist frontend/dist
EXPOSE 5000
CMD ["backend/.venv/bin/python", "run.py", "--host", "0.0.0.0"]
