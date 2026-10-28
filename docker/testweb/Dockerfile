# Simulated Internet for the lab (spec §8). Owner: TV2 (TLS-9).
FROM nginx:1.27-alpine
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/nt140.conf
# Scripts in /docker-entrypoint.d run before nginx starts (official image convention).
COPY entrypoint.d/ /docker-entrypoint.d/
