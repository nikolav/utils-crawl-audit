
while read url; do
  echo "🔍 $url"

  curl -sI "$url" | grep -i 'x-robots-tag' \
    || echo "✔ no X-Robots-Tag"

  curl -s "$url" \
    | grep -i '<meta[^>]*name=["'\'']robots' \
    || echo "✔ no meta robots"

  echo "-----"
done < urls.txt
