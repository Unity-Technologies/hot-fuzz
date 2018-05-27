image=${image:-"hot-fuzz"}

docker build -t ${image} .
