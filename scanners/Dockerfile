FROM projectdiscovery/nuclei:v3.11.1 AS nuclei

FROM python:3.12-slim

# nmap from Debian, Nikto from its upstream repo (needs Perl + SSL), Nuclei binary from its image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap perl libnet-ssleay-perl libjson-perl libxml-writer-perl git ca-certificates \
 && git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
 && rm -rf /opt/nikto/.git \
 && apt-get purge -y git && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
# Bake the templates into the image so the first scan does not start with a download.
RUN nuclei -update-templates -silent

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

EXPOSE 8001
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8001"]
