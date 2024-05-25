IMAGE_NAME=eyeballvul

build:
	docker build -t $(IMAGE_NAME) .

test:
	poetry run python -m pytest
