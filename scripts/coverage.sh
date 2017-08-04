
ls .coverage*
coverage combine
docker run -it -v $(pwd):/repo -w /repo template/backend:template coveralls

