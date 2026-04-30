# syntax=docker/dockerfile:1.6

# ---- build stage ----------------------------------------------------------
FROM node:20-alpine AS build

WORKDIR /app

# VITE_API_BASE_URL is baked into the bundle at build time (Vite inlines
# import.meta.env values during `vite build`). Pass it via --build-arg or in
# docker-compose.yml `args:`.
ARG VITE_API_BASE_URL=http://localhost:8080
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# ---- runtime stage --------------------------------------------------------
FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

# nginx default CMD is fine.
