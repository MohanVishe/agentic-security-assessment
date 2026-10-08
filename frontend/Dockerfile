# The web page. A plain web server (nginx) that serves the files in public/ and passes
# every /api/ call on to the backend container. There is no build step: the page is
# plain HTML, CSS and JavaScript modules.
FROM nginx:1.28-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY public /usr/share/nginx/html

EXPOSE 8000
