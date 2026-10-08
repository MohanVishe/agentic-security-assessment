# Practice target: OWASP Juice Shop

This folder is **not part of the product**. It holds the website the project is tested against,
kept apart from the code so nobody mixes the two up.

[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) is a shop website that is insecure
on purpose. The OWASP Foundation publishes it so people can practise security testing safely and
legally. It runs on your own machine and is reachable from your own machine only.

| File | What it is |
|---|---|
| `docker-compose.yml` | Starts the shop. The main `docker-compose.yml` includes it. |
| `target.json` | The name, address and short note shown on the "New check" page. |

## Addresses

| From | Address |
|---|---|
| Your browser | <http://localhost:3001> |
| The scanners (inside Docker) | `http://juice-shop:3000` |

To use another host port, set `JUICE_SHOP_PORT` in `.env`.

## Running without it

Remove the `include:` lines at the top of the main `docker-compose.yml`. The "New check" page
then offers only "Another website".

## Adding another practice target

1. Make a folder next to this one, for example `targets/my-app/`.
2. Put a `docker-compose.yml` in it that starts the site, and add it to `include:` in the main file.
3. Put a `target.json` in it with `name`, `url`, `badge` and `note`. The address must be the one
   the scanners can reach, which is the service name inside Docker.

The backend reads every `targets/*/target.json` when the page loads. No code change is needed.

Only add sites you own or that are published for practice. The permission box on the page is
required for practice targets too.
